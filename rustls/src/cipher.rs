use crate::conn::ConnectionSecrets;
use crate::error::Error;
use crate::key_schedule::{derive_traffic_iv, derive_traffic_key};
use crate::msgs::base::Payload;
use crate::msgs::codec;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};
use crate::suites::Tls13CipherSuite;

use ring::{aead, hkdf};

/// Objects with this trait can decrypt TLS messages.
pub(crate) trait MessageDecrypter: Send + Sync {
    fn decrypt(&self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error>;
}

/// Objects with this trait can encrypt TLS messages.
pub(crate) trait MessageEncrypter: Send + Sync {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error>;
}

impl dyn MessageEncrypter {
    pub(crate) fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub(crate) fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

pub(crate) type MessageCipherPair = (Box<dyn MessageDecrypter>, Box<dyn MessageEncrypter>);

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;
fn make_tls12_aad(
    seq: u64,
    typ: ContentType,
    vers: ProtocolVersion,
    len: usize,
) -> ring::aead::Aad<[u8; TLS12_AAD_SIZE]> {
    let mut out = [0; TLS12_AAD_SIZE];
    codec::put_u64(seq, &mut out[0..]);
    out[8] = typ.get_u8();
    codec::put_u16(vers.get_u16(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
    ring::aead::Aad::from(out)
}

fn make_tls12_gcm_nonce(write_iv: &[u8], explicit: &[u8]) -> Iv {
    debug_assert_eq!(write_iv.len(), 4);
    debug_assert_eq!(explicit.len(), 8);

    // The GCM nonce is constructed from a 32-bit 'salt' derived
    // from the master-secret, and a 64-bit explicit part,
    // with no specified construction.  Thanks for that.
    //
    // We use the same construction as TLS1.3/ChaCha20Poly1305:
    // a starting point extracted from the key block, xored with
    // the sequence number.
    let mut iv = Iv(Default::default());
    iv.0[..4].copy_from_slice(write_iv);
    iv.0[4..].copy_from_slice(explicit);
    iv
}

pub(crate) struct AesGcm;

impl Tls12AeadAlgorithm for AesGcm {
    fn decrypter(&self, key: aead::LessSafeKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(GcmMessageDecrypter::new(key, iv))
    }

    fn encrypter(
        &self,
        key: aead::LessSafeKey,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        let nonce = make_tls12_gcm_nonce(iv, extra);
        Box::new(GcmMessageEncrypter::new(key, nonce))
    }
}

pub(crate) struct ChaCha20Poly1305;

impl Tls12AeadAlgorithm for ChaCha20Poly1305 {
    fn decrypter(&self, key: aead::LessSafeKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(ChaCha20Poly1305MessageDecrypter::new(key, Iv::copy(iv)))
    }

    fn encrypter(&self, key: aead::LessSafeKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(ChaCha20Poly1305MessageEncrypter::new(key, Iv::copy(iv)))
    }
}

pub(crate) trait Tls12AeadAlgorithm: Send + Sync + 'static {
    fn decrypter(&self, key: aead::LessSafeKey, iv: &[u8]) -> Box<dyn MessageDecrypter>;
    fn encrypter(
        &self,
        key: aead::LessSafeKey,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<dyn MessageEncrypter>;
}

/// Make a `MessageCipherPair` based on the given supported ciphersuite `scs`,
/// and the session's `secrets`.
pub(crate) fn new_tls12(secrets: &ConnectionSecrets) -> MessageCipherPair {
    fn split_key<'a>(
        key_block: &'a [u8],
        alg: &'static aead::Algorithm,
    ) -> (aead::LessSafeKey, &'a [u8]) {
        // Might panic if the key block is too small.
        let (key, rest) = key_block.split_at(alg.key_len());
        // Won't panic because its only prerequisite is that `key` is `alg.key_len()` bytes long.
        let key = aead::UnboundKey::new(alg, key).unwrap();
        (aead::LessSafeKey::new(key), rest)
    }

    // Make a key block, and chop it up.
    // nb. we don't implement any ciphersuites with nonzero mac_key_len.
    let key_block = secrets.make_key_block();

    let suite = secrets.suite();
    let scs = &suite.common;

    let (client_write_key, key_block) = split_key(&key_block, scs.aead_algorithm);
    let (server_write_key, key_block) = split_key(key_block, scs.aead_algorithm);
    let (client_write_iv, key_block) = key_block.split_at(suite.fixed_iv_len);
    let (server_write_iv, extra) = key_block.split_at(suite.fixed_iv_len);

    let (write_key, write_iv, read_key, read_iv) = if secrets.randoms.we_are_client {
        (
            client_write_key,
            client_write_iv,
            server_write_key,
            server_write_iv,
        )
    } else {
        (
            server_write_key,
            server_write_iv,
            client_write_key,
            client_write_iv,
        )
    };

    (
        suite
            .aead_alg
            .decrypter(read_key, read_iv),
        suite
            .aead_alg
            .encrypter(write_key, write_iv, extra),
    )
}

pub(crate) fn new_tls13_read(
    scs: &'static Tls13CipherSuite,
    secret: &hkdf::Prk,
) -> Box<dyn MessageDecrypter> {
    let key = derive_traffic_key(secret, scs.common.aead_algorithm);
    let iv = derive_traffic_iv(secret);

    Box::new(Tls13MessageDecrypter::new(key, iv))
}

pub(crate) fn new_tls13_write(
    scs: &'static Tls13CipherSuite,
    secret: &hkdf::Prk,
) -> Box<dyn MessageEncrypter> {
    let key = derive_traffic_key(secret, scs.common.aead_algorithm);
    let iv = derive_traffic_iv(secret);

    Box::new(Tls13MessageEncrypter::new(key, iv))
}

/// A `MessageEncrypter` for AES-GCM AEAD ciphersuites. TLS 1.2 only.
struct GcmMessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

/// A `MessageDecrypter` for AES-GCM AEAD ciphersuites.  TLS1.2 only.
struct GcmMessageDecrypter {
    dec_key: aead::LessSafeKey,
    dec_salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageDecrypter for GcmMessageDecrypter {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = &mut msg.payload.0;
        if payload.len() < GCM_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.dec_salt);
            nonce[4..].copy_from_slice(&payload[..8]);
            aead::Nonce::assume_unique_for_key(nonce)
        };

        let aad = make_tls12_aad(seq, msg.typ, msg.version, payload.len() - GCM_OVERHEAD);

        let plain_len = self
            .dec_key
            .open_within(nonce, aad, payload, GCM_EXPLICIT_NONCE_LEN..)
            .map_err(|_| Error::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

impl MessageEncrypter for GcmMessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let nonce = make_tls13_nonce(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let total_len = msg.payload.len() + self.enc_key.algorithm().tag_len();
        let mut payload = Vec::with_capacity(GCM_EXPLICIT_NONCE_LEN + total_len);
        payload.extend_from_slice(&nonce.as_ref()[4..]);
        payload.extend_from_slice(msg.payload);

        self.enc_key
            .seal_in_place_separate_tag(nonce, aad, &mut payload[GCM_EXPLICIT_NONCE_LEN..])
            .map(|tag| payload.extend(tag.as_ref()))
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        Ok(OpaqueMessage {
            typ: msg.typ,
            version: msg.version,
            payload: Payload::new(payload),
        })
    }
}

impl GcmMessageEncrypter {
    fn new(enc_key: aead::LessSafeKey, iv: Iv) -> Self {
        Self { enc_key, iv }
    }
}

impl GcmMessageDecrypter {
    fn new(dec_key: aead::LessSafeKey, dec_iv: &[u8]) -> Self {
        let mut ret = Self {
            dec_key,
            dec_salt: [0u8; 4],
        };

        debug_assert_eq!(dec_iv.len(), 4);
        ret.dec_salt.copy_from_slice(dec_iv);
        ret
    }
}

/// A TLS 1.3 write or read IV.
pub(crate) struct Iv(pub(crate) [u8; ring::aead::NONCE_LEN]);

impl Iv {
    fn new(value: [u8; ring::aead::NONCE_LEN]) -> Self {
        Self(value)
    }

    fn copy(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), ring::aead::NONCE_LEN);
        let mut iv = Self::new(Default::default());
        iv.0.copy_from_slice(value);
        iv
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &[u8; 12] {
        &self.0
    }
}

pub(crate) struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Self(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

struct Tls13MessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

struct Tls13MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

fn make_tls13_nonce(iv: &Iv, seq: u64) -> ring::aead::Nonce {
    let mut nonce = [0u8; ring::aead::NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce
        .iter_mut()
        .zip(iv.0.iter())
        .for_each(|(nonce, iv)| {
            *nonce ^= *iv;
        });

    aead::Nonce::assume_unique_for_key(nonce)
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
const TLS13_AAD_SIZE: usize = 1 + 2 + 2;
fn make_tls13_aad(len: usize) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE]> {
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x3,  // ProtocolVersion (major)
        0x3,  // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
    ])
}

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let total_len = msg.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(msg.payload);
        msg.typ.encode(&mut payload);

        let nonce = make_tls13_nonce(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        Ok(OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(payload),
        })
    }
}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let mut payload = &mut msg.payload.0;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = make_tls13_nonce(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, &mut payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.typ = unpad_tls13(&mut payload);
        if msg.typ == ContentType::Unknown(0) {
            let msg = "peer sent bad TLSInnerPlaintext".to_string();
            return Err(Error::PeerMisbehavedError(msg));
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.version = ProtocolVersion::TLSv1_3;
        Ok(msg.into_plain_message())
    }
}

impl Tls13MessageEncrypter {
    fn new(key: aead::UnboundKey, enc_iv: Iv) -> Self {
        Self {
            enc_key: aead::LessSafeKey::new(key),
            iv: enc_iv,
        }
    }
}

impl Tls13MessageDecrypter {
    fn new(key: aead::UnboundKey, dec_iv: Iv) -> Self {
        Self {
            dec_key: aead::LessSafeKey::new(key),
            iv: dec_iv,
        }
    }
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageEncrypter`.
struct ChaCha20Poly1305MessageEncrypter {
    enc_key: aead::LessSafeKey,
    enc_offset: Iv,
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageDecrypter`.
struct ChaCha20Poly1305MessageDecrypter {
    dec_key: aead::LessSafeKey,
    dec_offset: Iv,
}

impl ChaCha20Poly1305MessageEncrypter {
    fn new(enc_key: aead::LessSafeKey, enc_iv: Iv) -> Self {
        Self {
            enc_key,
            enc_offset: enc_iv,
        }
    }
}

impl ChaCha20Poly1305MessageDecrypter {
    fn new(dec_key: aead::LessSafeKey, dec_iv: Iv) -> Self {
        Self {
            dec_key,
            dec_offset: dec_iv,
        }
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

impl MessageDecrypter for ChaCha20Poly1305MessageDecrypter {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let mut payload = &mut msg.payload.0;

        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = make_tls13_nonce(&self.dec_offset, seq);
        let aad = make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, &mut payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

impl MessageEncrypter for ChaCha20Poly1305MessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let nonce = make_tls13_nonce(&self.enc_offset, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let total_len = msg.payload.len() + self.enc_key.algorithm().tag_len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(msg.payload);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        Ok(OpaqueMessage {
            typ: msg.typ,
            version: msg.version,
            payload: Payload::new(buf),
        })
    }
}

/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowedPlainMessage, _seq: u64) -> Result<OpaqueMessage, Error> {
        Err(Error::General("encrypt not yet available".to_string()))
    }
}

/// A `MessageDecrypter` which doesn't work.
struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: OpaqueMessage, _seq: u64) -> Result<PlainMessage, Error> {
        Err(Error::DecryptError)
    }
}
