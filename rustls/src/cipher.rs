use crate::error::Error;
use crate::msgs::codec;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};

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

/// A write or read IV.
#[allow(unreachable_pub)] // Only exposed as part of `crate::quic`
#[derive(Default)]
pub struct Iv(pub(crate) [u8; ring::aead::NONCE_LEN]);

impl Iv {
    #[cfg(feature = "tls12")]
    pub(crate) fn new(value: [u8; ring::aead::NONCE_LEN]) -> Self {
        Self(value)
    }

    /// Compute the nonce to use for encrypting or decrypting `packet_number`
    #[cfg(feature = "quic")]
    pub fn nonce_for(&self, packet_number: u64) -> ring::aead::Nonce {
        let mut out = [0; aead::NONCE_LEN];
        out[4..].copy_from_slice(&packet_number.to_be_bytes());
        for (out, inp) in out.iter_mut().zip(self.0.iter()) {
            *out ^= inp;
        }
        aead::Nonce::assume_unique_for_key(out)
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn copy(value: &[u8]) -> Self {
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

pub(crate) fn make_nonce(iv: &Iv, seq: u64) -> ring::aead::Nonce {
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
