use std::convert::{TryFrom, TryInto};
use std::io;
use std::sync::Arc;

use rustls_pemfile;

use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::{Message, OpaqueMessage, PlainMessage};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::Connection;
use rustls::Error;
use rustls::RootCertStore;
use rustls::{Certificate, PrivateKey};
use rustls::{ClientConfig, ClientConnection};
use rustls::{ServerConfig, ServerConnection};

#[cfg(feature = "dangerous_configuration")]
use rustls::client::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, WebPkiVerifier,
};
#[cfg(feature = "dangerous_configuration")]
use rustls::server::{ClientCertVerified, ClientCertVerifier};
#[cfg(feature = "dangerous_configuration")]
use rustls::{
    internal::msgs::handshake::DigitallySignedStruct, DistinguishedNames, SignatureScheme,
};

macro_rules! embed_files {
    (
        $(
            ($name:ident, $keytype:expr, $path:expr);
        )+
    ) => {
        $(
            const $name: &'static [u8] = include_bytes!(
                concat!("../../../test-ca/", $keytype, "/", $path));
        )+

        pub fn bytes_for(keytype: &str, path: &str) -> &'static [u8] {
            match (keytype, path) {
                $(
                    ($keytype, $path) => $name,
                )+
                _ => panic!("unknown keytype {} with path {}", keytype, path),
            }
        }
    }
}

embed_files! {
    (ECDSA_CA_CERT, "ecdsa", "ca.cert");
    (ECDSA_CA_DER, "ecdsa", "ca.der");
    (ECDSA_CA_KEY, "ecdsa", "ca.key");
    (ECDSA_CLIENT_CERT, "ecdsa", "client.cert");
    (ECDSA_CLIENT_CHAIN, "ecdsa", "client.chain");
    (ECDSA_CLIENT_FULLCHAIN, "ecdsa", "client.fullchain");
    (ECDSA_CLIENT_KEY, "ecdsa", "client.key");
    (ECDSA_CLIENT_REQ, "ecdsa", "client.req");
    (ECDSA_END_CERT, "ecdsa", "end.cert");
    (ECDSA_END_CHAIN, "ecdsa", "end.chain");
    (ECDSA_END_FULLCHAIN, "ecdsa", "end.fullchain");
    (ECDSA_END_KEY, "ecdsa", "end.key");
    (ECDSA_END_REQ, "ecdsa", "end.req");
    (ECDSA_INTER_CERT, "ecdsa", "inter.cert");
    (ECDSA_INTER_KEY, "ecdsa", "inter.key");
    (ECDSA_INTER_REQ, "ecdsa", "inter.req");
    (ECDSA_NISTP256_PEM, "ecdsa", "nistp256.pem");
    (ECDSA_NISTP384_PEM, "ecdsa", "nistp384.pem");

    (EDDSA_CA_CERT, "eddsa", "ca.cert");
    (EDDSA_CA_DER, "eddsa", "ca.der");
    (EDDSA_CA_KEY, "eddsa", "ca.key");
    (EDDSA_CLIENT_CERT, "eddsa", "client.cert");
    (EDDSA_CLIENT_CHAIN, "eddsa", "client.chain");
    (EDDSA_CLIENT_FULLCHAIN, "eddsa", "client.fullchain");
    (EDDSA_CLIENT_KEY, "eddsa", "client.key");
    (EDDSA_CLIENT_REQ, "eddsa", "client.req");
    (EDDSA_END_CERT, "eddsa", "end.cert");
    (EDDSA_END_CHAIN, "eddsa", "end.chain");
    (EDDSA_END_FULLCHAIN, "eddsa", "end.fullchain");
    (EDDSA_END_KEY, "eddsa", "end.key");
    (EDDSA_END_REQ, "eddsa", "end.req");
    (EDDSA_INTER_CERT, "eddsa", "inter.cert");
    (EDDSA_INTER_KEY, "eddsa", "inter.key");
    (EDDSA_INTER_REQ, "eddsa", "inter.req");

    (RSA_CA_CERT, "rsa", "ca.cert");
    (RSA_CA_DER, "rsa", "ca.der");
    (RSA_CA_KEY, "rsa", "ca.key");
    (RSA_CLIENT_CERT, "rsa", "client.cert");
    (RSA_CLIENT_CHAIN, "rsa", "client.chain");
    (RSA_CLIENT_FULLCHAIN, "rsa", "client.fullchain");
    (RSA_CLIENT_KEY, "rsa", "client.key");
    (RSA_CLIENT_REQ, "rsa", "client.req");
    (RSA_CLIENT_RSA, "rsa", "client.rsa");
    (RSA_END_CERT, "rsa", "end.cert");
    (RSA_END_CHAIN, "rsa", "end.chain");
    (RSA_END_FULLCHAIN, "rsa", "end.fullchain");
    (RSA_END_KEY, "rsa", "end.key");
    (RSA_END_REQ, "rsa", "end.req");
    (RSA_END_RSA, "rsa", "end.rsa");
    (RSA_INTER_CERT, "rsa", "inter.cert");
    (RSA_INTER_KEY, "rsa", "inter.key");
    (RSA_INTER_REQ, "rsa", "inter.req");
}

pub fn transfer(left: &mut dyn Connection, right: &mut dyn Connection) -> usize {
    let mut buf = [0u8; 262144];
    let mut total = 0;

    while left.wants_write() {
        let sz = {
            let into_buf: &mut dyn io::Write = &mut &mut buf[..];
            left.write_tls(into_buf).unwrap()
        };
        total += sz;
        if sz == 0 {
            return total;
        }

        let mut offs = 0;
        loop {
            let from_buf: &mut dyn io::Read = &mut &buf[offs..sz];
            offs += right.read_tls(from_buf).unwrap();
            if sz == offs {
                break;
            }
        }
    }

    total
}

pub fn transfer_altered<F>(
    left: &mut dyn Connection,
    filter: F,
    right: &mut dyn Connection,
) -> usize
where
    F: Fn(&mut Message),
{
    let mut buf = [0u8; 262144];
    let mut total = 0;

    while left.wants_write() {
        let sz = {
            let into_buf: &mut dyn io::Write = &mut &mut buf[..];
            left.write_tls(into_buf).unwrap()
        };
        total += sz;
        if sz == 0 {
            return total;
        }

        let mut reader = Reader::init(&buf[..sz]);
        while reader.any_left() {
            let message = OpaqueMessage::read(&mut reader).unwrap();
            let mut message = Message::try_from(message.into_plain_message()).unwrap();
            filter(&mut message);
            let message_enc = PlainMessage::from(message)
                .into_unencrypted_opaque()
                .encode();
            let message_enc_reader: &mut dyn io::Read = &mut &message_enc[..];
            let len = right
                .read_tls(message_enc_reader)
                .unwrap();
            assert_eq!(len, message_enc.len());
        }
    }

    total
}

#[derive(Clone, Copy, PartialEq)]
pub enum KeyType {
    RSA,
    ECDSA,
    ED25519,
}

pub static ALL_KEY_TYPES: [KeyType; 3] = [KeyType::RSA, KeyType::ECDSA, KeyType::ED25519];

impl KeyType {
    fn bytes_for(&self, part: &str) -> &'static [u8] {
        match self {
            KeyType::RSA => bytes_for("rsa", part),
            KeyType::ECDSA => bytes_for("ecdsa", part),
            KeyType::ED25519 => bytes_for("eddsa", part),
        }
    }

    pub fn get_chain(&self) -> Vec<Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(self.bytes_for("end.fullchain")))
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    pub fn get_key(&self) -> PrivateKey {
        PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(self.bytes_for("end.key")))
                .unwrap()[0]
                .clone(),
        )
    }

    pub fn get_client_chain(&self) -> Vec<Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(self.bytes_for("client.fullchain")))
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    fn get_client_key(&self) -> PrivateKey {
        PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                self.bytes_for("client.key"),
            ))
            .unwrap()[0]
                .clone(),
        )
    }
}

pub fn finish_server_config(
    kt: KeyType,
    conf: rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>,
) -> ServerConfig {
    conf.with_no_client_auth()
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

pub fn make_server_config(kt: KeyType) -> ServerConfig {
    finish_server_config(kt, ServerConfig::builder().with_safe_defaults())
}

pub fn make_server_config_with_versions(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ServerConfig {
    finish_server_config(
        kt,
        ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(versions)
            .unwrap(),
    )
}

pub fn make_server_config_with_kx_groups(
    kt: KeyType,
    kx_groups: &[&'static rustls::SupportedKxGroup],
) -> ServerConfig {
    finish_server_config(
        kt,
        ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_kx_groups(kx_groups)
            .with_safe_default_protocol_versions()
            .unwrap(),
    )
}

pub fn get_client_root_store(kt: KeyType) -> RootCertStore {
    let roots = kt.get_chain();
    let mut client_auth_roots = RootCertStore::empty();
    for root in roots {
        client_auth_roots.add(&root).unwrap();
    }
    client_auth_roots
}

pub fn make_server_config_with_mandatory_client_auth(kt: KeyType) -> ServerConfig {
    let client_auth_roots = get_client_root_store(kt);

    let client_auth = AllowAnyAuthenticatedClient::new(client_auth_roots);

    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

pub fn finish_client_config(
    kt: KeyType,
    config: rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>,
) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let mut rootbuf = io::BufReader::new(kt.bytes_for("ca.cert"));
    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut rootbuf).unwrap());

    config
        .with_root_certificates(root_store, &[])
        .with_no_client_auth()
}

pub fn finish_client_config_with_creds(
    kt: KeyType,
    config: rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>,
) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let mut rootbuf = io::BufReader::new(kt.bytes_for("ca.cert"));
    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut rootbuf).unwrap());

    config
        .with_root_certificates(root_store, &[])
        .with_single_cert(kt.get_client_chain(), kt.get_client_key())
        .unwrap()
}

pub fn make_client_config(kt: KeyType) -> ClientConfig {
    finish_client_config(kt, ClientConfig::builder().with_safe_defaults())
}

pub fn make_client_config_with_kx_groups(
    kt: KeyType,
    kx_groups: &[&'static rustls::SupportedKxGroup],
) -> ClientConfig {
    let builder = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_kx_groups(kx_groups)
        .with_safe_default_protocol_versions()
        .unwrap();
    finish_client_config(kt, builder)
}

pub fn make_client_config_with_versions(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    let builder = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(versions)
        .unwrap();
    finish_client_config(kt, builder)
}

pub fn make_client_config_with_auth(kt: KeyType) -> ClientConfig {
    finish_client_config_with_creds(kt, ClientConfig::builder().with_safe_defaults())
}

pub fn make_client_config_with_versions_with_auth(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    let builder = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(versions)
        .unwrap();
    finish_client_config_with_creds(kt, builder)
}

pub fn make_pair(kt: KeyType) -> (ClientConnection, ServerConnection) {
    make_pair_for_configs(make_client_config(kt), make_server_config(kt))
}

pub fn make_pair_for_configs(
    client_config: ClientConfig,
    server_config: ServerConfig,
) -> (ClientConnection, ServerConnection) {
    make_pair_for_arc_configs(&Arc::new(client_config), &Arc::new(server_config))
}

pub fn make_pair_for_arc_configs(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::clone(&client_config), dns_name("localhost")).unwrap(),
        ServerConnection::new(Arc::clone(server_config)).unwrap(),
    )
}

pub fn do_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> (usize, usize) {
    let (mut to_client, mut to_server) = (0, 0);
    while server.is_handshaking() || client.is_handshaking() {
        to_server += transfer(client, server);
        server.process_new_packets().unwrap();
        to_client += transfer(server, client);
        client.process_new_packets().unwrap();
    }
    (to_server, to_client)
}

#[cfg(feature = "dangerous_configuration")]
pub struct MockServerVerifier {
    cert_rejection_error: Option<Error>,
    tls12_signature_error: Option<Error>,
    tls13_signature_error: Option<Error>,
    wants_scts: bool,
    signature_schemes: Vec<SignatureScheme>,
}

#[cfg(feature = "dangerous_configuration")]
impl ServerCertVerifier for MockServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &rustls::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        oscp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        let scts: Vec<Vec<u8>> = scts.map(|x| x.to_owned()).collect();
        println!(
            "verify_server_cert({:?}, {:?}, {:?}, {:?}, {:?}, {:?})",
            end_entity, intermediates, server_name, scts, oscp_response, now
        );
        if let Some(error) = &self.cert_rejection_error {
            Err(error.clone())
        } else {
            Ok(ServerCertVerified::assertion())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        println!(
            "verify_tls12_signature({:?}, {:?}, {:?})",
            message, cert, dss
        );
        if let Some(error) = &self.tls12_signature_error {
            Err(error.clone())
        } else {
            Ok(HandshakeSignatureValid::assertion())
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        println!(
            "verify_tls13_signature({:?}, {:?}, {:?})",
            message, cert, dss
        );
        if let Some(error) = &self.tls13_signature_error {
            Err(error.clone())
        } else {
            Ok(HandshakeSignatureValid::assertion())
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_schemes.clone()
    }

    fn request_scts(&self) -> bool {
        println!("request_scts? {:?}", self.wants_scts);
        self.wants_scts
    }
}

#[cfg(feature = "dangerous_configuration")]
impl MockServerVerifier {
    pub fn accepts_anything() -> Self {
        MockServerVerifier {
            cert_rejection_error: None,
            ..Default::default()
        }
    }

    pub fn requests_scts() -> Self {
        MockServerVerifier {
            wants_scts: true,
            ..Default::default()
        }
    }

    pub fn rejects_certificate(err: Error) -> Self {
        MockServerVerifier {
            cert_rejection_error: Some(err),
            ..Default::default()
        }
    }

    pub fn rejects_tls12_signatures(err: Error) -> Self {
        MockServerVerifier {
            tls12_signature_error: Some(err),
            ..Default::default()
        }
    }

    pub fn rejects_tls13_signatures(err: Error) -> Self {
        MockServerVerifier {
            tls13_signature_error: Some(err),
            ..Default::default()
        }
    }

    pub fn offers_no_signature_schemes() -> Self {
        MockServerVerifier {
            signature_schemes: vec![],
            ..Default::default()
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
impl Default for MockServerVerifier {
    fn default() -> Self {
        MockServerVerifier {
            cert_rejection_error: None,
            tls12_signature_error: None,
            tls13_signature_error: None,
            wants_scts: false,
            signature_schemes: WebPkiVerifier::verification_schemes(),
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
pub struct MockClientVerifier {
    pub verified: fn() -> Result<ClientCertVerified, Error>,
    pub subjects: Option<DistinguishedNames>,
    pub mandatory: Option<bool>,
    pub offered_schemes: Option<Vec<SignatureScheme>>,
}

#[cfg(feature = "dangerous_configuration")]
impl ClientCertVerifier for MockClientVerifier {
    fn client_auth_mandatory(&self, sni: Option<&rustls::server::DnsName>) -> Option<bool> {
        // This is just an added 'test' to make sure we plumb through the SNI,
        // although its valid for it to be None, its just our tests should (as of now) always provide it
        assert!(sni.is_some());
        self.mandatory
    }

    fn client_auth_root_subjects(
        &self,
        sni: Option<&rustls::server::DnsName>,
    ) -> Option<DistinguishedNames> {
        assert!(sni.is_some());
        self.subjects.as_ref().cloned()
    }

    fn verify_client_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        sni: Option<&rustls::server::DnsName>,
        _now: std::time::SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        assert!(sni.is_some());
        (self.verified)()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if let Some(schemes) = &self.offered_schemes {
            schemes.clone()
        } else {
            WebPkiVerifier::verification_schemes()
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum ErrorFromPeer {
    Client(Error),
    Server(Error),
}

pub fn do_handshake_until_error(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), ErrorFromPeer> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server
            .process_new_packets()
            .map_err(|err| ErrorFromPeer::Server(err))?;
        transfer(server, client);
        client
            .process_new_packets()
            .map_err(|err| ErrorFromPeer::Client(err))?;
    }

    Ok(())
}

pub fn do_handshake_until_both_error(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), Vec<ErrorFromPeer>> {
    match do_handshake_until_error(client, server) {
        Err(server_err @ ErrorFromPeer::Server(_)) => {
            let mut errors = vec![server_err];
            transfer(server, client);
            let client_err = client
                .process_new_packets()
                .map_err(|err| ErrorFromPeer::Client(err))
                .expect_err("client didn't produce error after server error");
            errors.push(client_err);
            Err(errors)
        }

        Err(client_err @ ErrorFromPeer::Client(_)) => {
            let mut errors = vec![client_err];
            transfer(client, server);
            let server_err = server
                .process_new_packets()
                .map_err(|err| ErrorFromPeer::Server(err))
                .expect_err("server didn't produce error after client error");
            errors.push(server_err);
            Err(errors)
        }

        Ok(()) => Ok(()),
    }
}

pub fn dns_name(name: &'static str) -> rustls::ServerName {
    name.try_into().unwrap()
}

pub struct FailsReads {
    errkind: io::ErrorKind,
}

impl FailsReads {
    pub fn new(errkind: io::ErrorKind) -> Self {
        FailsReads { errkind }
    }
}

impl io::Read for FailsReads {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.errkind))
    }
}
