use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::*;
use crate::msgs::handshake::*;

use hpke_rs::prelude::*;
use hpke_rs::{HpkeKeyPair, HpkePrivateKey, Mode};

use webpki::DnsNameRef;

#[derive(Debug)]
pub struct EchKeyPair {
    pub kem_id: KEM,
    pub key_pair: HpkeKeyPair,
}

impl EchKeyPair {
    #[allow(dead_code)]
    pub fn new(kem_id: KEM, cipher_suite: &HpkeSymmetricCipherSuite) -> EchKeyPair {
        let hpke = hpke_rs::Hpke::new(
            Mode::Base,
            HpkeKemMode::try_from(kem_id.get_u16()).unwrap(),
            HpkeKdfMode::try_from(cipher_suite.hpke_kdf_id.get_u16()).unwrap(),
            HpkeAeadMode::try_from(cipher_suite.hpke_aead_id.get_u16()).unwrap(),
        );
        EchKeyPair {
            kem_id,
            key_pair: hpke.generate_key_pair().unwrap(),
        }
    }
}

/// A private key paired with an ECHConfig, which contains the corresponding public key.
#[derive(Debug)]
pub struct EchKey {
    pub private_key: HpkePrivateKey,
    pub config: EchConfig,
}

impl EchKey {
    // TODO: Reconsider this API. This is just enough to get this feature working.
    #[allow(dead_code)]
    pub fn new(config_id: u8, ekp: EchKeyPair, domain: DnsNameRef) -> EchKey {
        let (private_key, public_key) = ekp.key_pair.into_keys();
        EchKey {
            private_key,
            config: EchConfig {
                version: EchVersion::V10,
                contents: EchConfigContents {
                    hpke_key_config: HpkeKeyConfig {
                        config_id,
                        hpke_kem_id: ekp.kem_id,
                        hpke_public_key: PayloadU16(public_key.as_slice().to_vec()),
                        hpke_symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite::default()],
                    },
                    maximum_name_length: 255,
                    public_name: domain.to_owned(),
                    extensions: PayloadU16::empty(),
                },
            },
        }
    }
}

impl Codec for EchKey {
    // TODO: This serialization is odd, but it's the way Cloudflare did it in their test values,
    // which I borrowed. This should be fixed if something like this struct is kept in the end.
    fn encode(&self, bytes: &mut Vec<u8>) {
        PayloadU16(self.private_key.as_slice().to_vec()).encode(bytes);
        let mut config_bytes = Vec::new();
        self.config.encode(&mut config_bytes);
        PayloadU16(config_bytes).encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<EchKey> {
        let private_key = PayloadU16::read(r)?;
        let config_payload = PayloadU16::read(r)?;
        let config = EchConfig::read(&mut Reader::init(&config_payload.into_inner()))?;
        Some(EchKey {
            private_key: HpkePrivateKey::from(private_key.into_inner()),
            config,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::msgs::ech::EncryptedClientHello;

    #[test]
    fn test_gen_p256() {
        let p256 = EchKeyPair::new(
            KEM::DHKEM_P256_HKDF_SHA256,
            &HpkeSymmetricCipherSuite::default(),
        );
        assert!(format!("{:?}", p256).starts_with("EchKeyPair {"));
        let (private_key, public_key) = p256.key_pair.into_keys();
        assert_eq!(private_key.as_slice().len(), 32);
        assert_eq!(public_key.as_slice().len(), 65);
    }

    #[test]
    #[should_panic]
    fn test_gen_p384() {
        let _p384 = EchKeyPair::new(
            KEM::DHKEM_P384_HKDF_SHA384,
            &HpkeSymmetricCipherSuite::default(),
        );
    }

    #[test]
    #[should_panic]
    fn test_gen_p521() {
        let _p521 = EchKeyPair::new(
            KEM::DHKEM_P521_HKDF_SHA512,
            &HpkeSymmetricCipherSuite::default(),
        );
    }

    #[test]
    fn test_gen_x25519() {
        let x25519 = EchKeyPair::new(
            KEM::DHKEM_X25519_HKDF_SHA256,
            &HpkeSymmetricCipherSuite::default(),
        );
        let (private_key, public_key) = x25519.key_pair.into_keys();

        assert_eq!(private_key.as_slice().len(), 32);
        assert_eq!(public_key.as_slice().len(), 32);
    }

    #[test]
    #[should_panic]
    fn test_gen_x448() {
        let _x448 = EchKeyPair::new(
            KEM::DHKEM_X448_HKDF_SHA512,
            &HpkeSymmetricCipherSuite::default(),
        );
    }

    #[test]
    fn test_create_default_ech_config() {
        let x25519 = EchKeyPair::new(
            KEM::DHKEM_X25519_HKDF_SHA256,
            &HpkeSymmetricCipherSuite::default(),
        );
        let domain = webpki::DnsNameRef::try_from_ascii_str("example.com").unwrap();
        let private_key = x25519
            .key_pair
            .private_key()
            .as_slice()
            .to_vec();
        let key = EchKey::new(0, x25519, domain);
        assert!(format!("{:?}", key).starts_with("EchKey {"));

        assert_eq!(key.private_key.as_slice().to_vec(), private_key);
        assert_eq!(key.config.version, EchVersion::V10);
        assert_eq!(
            key.config
                .contents
                .hpke_key_config
                .hpke_kem_id,
            KEM::DHKEM_X25519_HKDF_SHA256
        );
        let suites = key
            .config
            .contents
            .hpke_key_config
            .hpke_symmetric_cipher_suites;
        assert_eq!(suites[0].hpke_aead_id, AEAD::AES_128_GCM);
        assert_eq!(suites[0].hpke_kdf_id, KDF::HKDF_SHA256);
    }

    // Some test data from https://github.com/cloudflare/go/blob/cf/src/crypto/tls/ech_test.go
    const ECH_CONFIGS: &str = "AJD+CgBEAAAgACCLVO6NYnbfqTVUAx5GfKwpsOKDEukOz8AZ0SjArwqIGQAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAD+CgBEAQAgACBnVG7W7IZfo30dizn+kATcrBRdEMEcPQF2dryg/i5UTAAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";
    const ECH_KEYS: &str = "ACDhS0q2cTU1Qzi6hPM4BQ/HLnbEUZyWdY2GbmS0DVkumgBIAfUARAAAIAAgi1TujWJ236k1VAMeRnysKbDigxLpDs/AGdEowK8KiBkABAABAAEAAAATY2xvdWRmbGFyZS1lc25pLmNvbQAAACBmNj/zQe6OT/MR/MM39G6kwMJCJEXpdvTAkbdHErlgXwBIAfUARAEAIAAgZ1Ru1uyGX6N9HYs5/pAE3KwUXRDBHD0Bdna8oP4uVEwABAABAAEAAAATY2xvdWRmbGFyZS1lc25pLmNvbQAA";

    fn test_decode_for_kem(config: &EchConfig, kem: KEM) {
        assert_eq!(config.version, EchVersion::V10);
        assert_eq!(
            b"cloudflare-esni.com",
            config
                .contents
                .public_name
                .as_ref()
                .as_ref()
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_kem_id,
            kem
        );
        let cipher_suites = &config
            .contents
            .hpke_key_config
            .hpke_symmetric_cipher_suites;
        assert_eq!(cipher_suites.len(), 1);
        assert_eq!(cipher_suites[0].hpke_kdf_id, KDF::HKDF_SHA256);
        assert_eq!(cipher_suites[0].hpke_aead_id, AEAD::AES_128_GCM);
    }

    fn decode_ech_keys() -> Vec<EchKey> {
        let mut keys = vec![];
        let bytes = base64::decode(&ECH_KEYS).unwrap();
        let reader = &mut Reader::init(&bytes);
        while reader.any_left() {
            keys.push(EchKey::read(reader).unwrap());
        }
        keys
    }

    #[test]
    fn round_trip() {
        let keys = decode_ech_keys();
        let mut bytes = Vec::new();
        keys[0].encode(&mut bytes);
        let mut rd = Reader::init(&bytes);
        assert_eq!(
            keys[0].private_key,
            EchKey::read(&mut rd)
                .unwrap()
                .private_key
        );
    }

    #[test]
    fn test_seal_and_open() {
        let bytes = base64::decode(&ECH_CONFIGS).unwrap();
        let configs = EchConfigList::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(configs.len(), 2);
        for config in &configs {
            test_decode_for_kem(&config, KEM::DHKEM_X25519_HKDF_SHA256);
        }
        let keys = decode_ech_keys();
        assert_eq!(keys.len(), 2);

        for key in keys {
            let name = key.config.contents.public_name.clone();
            let config_list: EchConfigList = vec![key.config.clone()];
            let mut ech_bytes: Vec<u8> = Vec::new();
            config_list.encode(&mut ech_bytes);
            let config_id = key
                .config
                .contents
                .hpke_key_config
                .config_id;
            let ech =
                EncryptedClientHello::with_host_and_config_list(name.as_ref(), &ech_bytes).unwrap();
            assert_eq!(
                ech.config_contents
                    .hpke_key_config
                    .config_id,
                config_id
            );
            assert_eq!(ech.hostname, name);

            let info = b"HPKE self test info";
            let aad = b"HPKE self test aad";
            let plain_txt = b"HPKE self test plain text";
            let public_key = HpkePublicKey::from(
                key.config
                    .contents
                    .hpke_key_config
                    .hpke_public_key
                    .into_inner(),
            );
            let (encapped_secret, cipher_text) = ech
                .hpke
                .seal(&public_key, info, aad, plain_txt, None, None, None)
                .unwrap();
            let decrypted_text = ech
                .hpke
                .open(
                    &encapped_secret,
                    &key.private_key,
                    info,
                    aad,
                    &cipher_text,
                    None,
                    None,
                    None,
                )
                .unwrap();

            assert_eq!(plain_txt, decrypted_text.as_slice());
        }
    }
}
