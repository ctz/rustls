//! Assorted public API tests.
use std::convert::TryFrom;
use std::env;
use std::fmt;
use std::io::{self, IoSlice, Read, Write};
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use rustls;

use rustls::client::ResolvesClientCert;
use rustls::internal::msgs::{codec::Codec, persist::ClientSessionValue};
#[cfg(feature = "quic")]
use rustls::quic::{self, ClientQuicExt, QuicExt, ServerQuicExt};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign;
use rustls::Connection;
use rustls::Error;
use rustls::KeyLog;
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};
use rustls::{ClientConfig, ClientConnection};
use rustls::{ServerConfig, ServerConnection};
use rustls::{Stream, StreamOwned};
use rustls::{SupportedCipherSuite, ALL_CIPHER_SUITES};
use rustls::{WebPkiError, WebPkiOp};

#[cfg(feature = "dangerous_configuration")]
use rustls::server::ClientCertVerified;

#[allow(dead_code)]
mod common;
use crate::common::*;

fn alpn_test_error(
    server_protos: Vec<Vec<u8>>,
    client_protos: Vec<Vec<u8>>,
    agreed: Option<&[u8]>,
    expected_error: Option<ErrorFromPeer>,
) {
    let mut server_config = make_server_config(KeyType::RSA);
    server_config.alpn_protocols = server_protos;

    let server_config = Arc::new(server_config);

    for version in rustls::ALL_VERSIONS {
        let mut client_config = make_client_config_with_versions(KeyType::RSA, &[version]);
        client_config.alpn_protocols = client_protos.clone();

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(client.alpn_protocol(), None);
        assert_eq!(server.alpn_protocol(), None);
        let error = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(client.alpn_protocol(), agreed);
        assert_eq!(server.alpn_protocol(), agreed);
        assert_eq!(error.err(), expected_error);
    }
}

fn alpn_test(server_protos: Vec<Vec<u8>>, client_protos: Vec<Vec<u8>>, agreed: Option<&[u8]>) {
    alpn_test_error(server_protos, client_protos, agreed, None)
}

#[test]
fn alpn() {
    // no support
    alpn_test(vec![], vec![], None);

    // server support
    alpn_test(vec![b"server-proto".to_vec()], vec![], None);

    // client support
    alpn_test(vec![], vec![b"client-proto".to_vec()], None);

    // no overlap
    alpn_test_error(
        vec![b"server-proto".to_vec()],
        vec![b"client-proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(Error::NoApplicationProtocol)),
    );

    // server chooses preference
    alpn_test(
        vec![b"server-proto".to_vec(), b"client-proto".to_vec()],
        vec![b"client-proto".to_vec(), b"server-proto".to_vec()],
        Some(b"server-proto"),
    );

    // case sensitive
    alpn_test_error(
        vec![b"PROTO".to_vec()],
        vec![b"proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(Error::NoApplicationProtocol)),
    );
}

fn version_test(
    client_versions: &[&'static rustls::SupportedProtocolVersion],
    server_versions: &[&'static rustls::SupportedProtocolVersion],
    result: Option<ProtocolVersion>,
) {
    let client_versions = if client_versions.is_empty() {
        &rustls::ALL_VERSIONS
    } else {
        client_versions
    };
    let server_versions = if server_versions.is_empty() {
        &rustls::ALL_VERSIONS
    } else {
        server_versions
    };

    let client_config = make_client_config_with_versions(KeyType::RSA, client_versions);
    let server_config = make_server_config_with_versions(KeyType::RSA, server_versions);

    println!(
        "version {:?} {:?} -> {:?}",
        client_versions, server_versions, result
    );

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(client.protocol_version(), None);
    assert_eq!(server.protocol_version(), None);
    if result.is_none() {
        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(err.is_err(), true);
    } else {
        do_handshake(&mut client, &mut server);
        assert_eq!(client.protocol_version(), result);
        assert_eq!(server.protocol_version(), result);
    }
}

#[test]
fn versions() {
    // default -> 1.3
    version_test(&[], &[], Some(ProtocolVersion::TLSv1_3));

    // client default, server 1.2 -> 1.2
    version_test(
        &[],
        &[&rustls::version::TLS12],
        Some(ProtocolVersion::TLSv1_2),
    );

    // client 1.2, server default -> 1.2
    version_test(
        &[&rustls::version::TLS12],
        &[],
        Some(ProtocolVersion::TLSv1_2),
    );

    // client 1.2, server 1.3 -> fail
    version_test(&[&rustls::version::TLS12], &[&rustls::version::TLS13], None);

    // client 1.3, server 1.2 -> fail
    version_test(&[&rustls::version::TLS13], &[&rustls::version::TLS12], None);

    // client 1.3, server 1.2+1.3 -> 1.3
    version_test(
        &[&rustls::version::TLS13],
        &[&rustls::version::TLS12, &rustls::version::TLS13],
        Some(ProtocolVersion::TLSv1_3),
    );

    // client 1.2+1.3, server 1.2 -> 1.2
    version_test(
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        &[&rustls::version::TLS12],
        Some(ProtocolVersion::TLSv1_2),
    );
}

fn check_read(reader: &mut dyn io::Read, bytes: &[u8]) {
    let mut buf = vec![0u8; bytes.len() + 1];
    assert_eq!(bytes.len(), reader.read(&mut buf).unwrap());
    assert_eq!(bytes, &buf[..bytes.len()]);
}

#[test]
fn config_builder_for_client_rejects_empty_kx_groups() {
    assert_eq!(
        ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_kx_groups(&[])
            .with_safe_default_protocol_versions()
            .err(),
        Some(Error::General("no kx groups configured".into()))
    );
}

#[test]
fn config_builder_for_client_rejects_empty_cipher_suites() {
    assert_eq!(
        ClientConfig::builder()
            .with_cipher_suites(&[])
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .err(),
        Some(Error::General("no usable cipher suites configured".into()))
    );
}

#[test]
fn config_builder_for_client_rejects_incompatible_cipher_suites() {
    assert_eq!(
        ClientConfig::builder()
            .with_cipher_suites(&[rustls::cipher_suite::TLS13_AES_256_GCM_SHA384.into()])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS12])
            .err(),
        Some(Error::General("no usable cipher suites configured".into()))
    );
}

#[test]
fn config_builder_for_server_rejects_empty_kx_groups() {
    assert_eq!(
        ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_kx_groups(&[])
            .with_safe_default_protocol_versions()
            .err(),
        Some(Error::General("no kx groups configured".into()))
    );
}

#[test]
fn config_builder_for_server_rejects_empty_cipher_suites() {
    assert_eq!(
        ServerConfig::builder()
            .with_cipher_suites(&[])
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .err(),
        Some(Error::General("no usable cipher suites configured".into()))
    );
}

#[test]
fn config_builder_for_server_rejects_incompatible_cipher_suites() {
    assert_eq!(
        ServerConfig::builder()
            .with_cipher_suites(&[rustls::cipher_suite::TLS13_AES_256_GCM_SHA384.into()])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS12])
            .err(),
        Some(Error::General("no usable cipher suites configured".into()))
    );
}

#[test]
fn buffered_client_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::RSA));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::RSA, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(5, client.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut server.reader(), b"hello");
    }
}

#[test]
fn buffered_server_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::RSA));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::RSA, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(5, server.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();

        check_read(&mut client.reader(), b"hello");
    }
}

#[test]
fn buffered_both_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::RSA));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::RSA, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );

        do_handshake(&mut client, &mut server);

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut client.reader(), b"from-server!");
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[test]
fn client_can_get_server_cert() {
    for kt in ALL_KEY_TYPES.iter() {
        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_configs(client_config, make_server_config(*kt));
            do_handshake(&mut client, &mut server);

            let certs = client.peer_certificates();
            assert_eq!(certs, Some(kt.get_chain().as_slice()));
        }
    }
}

#[test]
fn client_can_get_server_cert_after_resumption() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = make_server_config(*kt);
        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server);

            let original_certs = client.peer_certificates();

            let (mut client, mut server) =
                make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server);

            let resumed_certs = client.peer_certificates();

            assert_eq!(original_certs, resumed_certs);
        }
    }
}

#[test]
fn server_can_get_client_cert() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);

            let certs = server.peer_certificates();
            assert_eq!(certs, Some(kt.get_client_chain().as_slice()));
        }
    }
}

#[test]
fn server_can_get_client_cert_after_resumption() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let client_config = Arc::new(client_config);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &server_config);
            do_handshake(&mut client, &mut server);
            let original_certs = server.peer_certificates();

            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &server_config);
            do_handshake(&mut client, &mut server);
            let resumed_certs = server.peer_certificates();
            assert_eq!(original_certs, resumed_certs);
        }
    }
}

fn check_read_and_close(reader: &mut dyn io::Read, expect: &[u8]) {
    check_read(reader, expect);
    assert!(matches!(reader.read(&mut [0u8; 5]), Ok(0)));
}

#[test]
fn server_close_notify() {
    let kt = KeyType::RSA;
    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions_with_auth(kt, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that alerts don't overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );
        server.send_close_notify();

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        check_read_and_close(&mut client.reader(), b"from-server!");

        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[test]
fn client_close_notify() {
    let kt = KeyType::RSA;
    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions_with_auth(kt, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that alerts don't overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );
        client.send_close_notify();

        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read_and_close(&mut server.reader(), b"from-client!");

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        check_read(&mut client.reader(), b"from-server!");
    }
}

#[derive(Default)]
struct ServerCheckCertResolve {
    expected_sni: Option<String>,
    expected_sigalgs: Option<Vec<SignatureScheme>>,
    expected_alpn: Option<Vec<Vec<u8>>>,
}

impl ResolvesServerCert for ServerCheckCertResolve {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        if client_hello.signature_schemes().len() == 0 {
            panic!("no signature schemes shared by client");
        }

        if let Some(expected_sni) = &self.expected_sni {
            let sni: &str = client_hello
                .server_name()
                .expect("sni unexpectedly absent")
                .into();
            assert_eq!(expected_sni, sni);
        }

        if let Some(expected_sigalgs) = &self.expected_sigalgs {
            if expected_sigalgs != &client_hello.signature_schemes() {
                panic!(
                    "unexpected signature schemes (wanted {:?} got {:?})",
                    self.expected_sigalgs,
                    client_hello.signature_schemes()
                );
            }
        }

        if let Some(expected_alpn) = &self.expected_alpn {
            let alpn = client_hello
                .alpn()
                .expect("alpn unexpectedly absent");
            assert_eq!(alpn.len(), expected_alpn.len());

            for (got, wanted) in alpn.iter().zip(expected_alpn.iter()) {
                assert_eq!(got, &wanted.as_slice());
            }
        }

        None
    }
}

#[test]
fn server_cert_resolve_with_sni() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some("the-value-from-sni".into()),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), dns_name("the-value-from-sni")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(err.is_err(), true);
    }
}

#[test]
fn server_cert_resolve_with_alpn() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.alpn_protocols = vec!["foo".into(), "bar".into()];

        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_alpn: Some(vec![b"foo".to_vec(), b"bar".to_vec()]),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), dns_name("sni-value")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(err.is_err(), true);
    }
}

#[test]
fn client_trims_terminating_dot() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some("some-host.com".into()),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), dns_name("some-host.com.")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(err.is_err(), true);
    }
}

fn check_sigalgs_reduced_by_ciphersuite(
    kt: KeyType,
    suite: CipherSuite,
    expected_sigalgs: Vec<SignatureScheme>,
) {
    let client_config = finish_client_config(
        kt,
        ClientConfig::builder()
            .with_cipher_suites(&[find_suite(suite)])
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap(),
    );

    let mut server_config = make_server_config(kt);

    server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
        expected_sigalgs: Some(expected_sigalgs),
        ..Default::default()
    });

    let mut client = ClientConnection::new(Arc::new(client_config), dns_name("localhost")).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    let err = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(err.is_err(), true);
}

#[test]
fn server_cert_resolve_reduces_sigalgs_for_rsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::RSA,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        vec![
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ],
    );
}

#[test]
fn server_cert_resolve_reduces_sigalgs_for_ecdsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::ECDSA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ],
    );
}

struct ServerCheckNoSNI {}

impl ResolvesServerCert for ServerCheckNoSNI {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        assert!(client_hello.server_name().is_none());

        None
    }
}

#[test]
fn client_with_sni_disabled_does_not_send_sni() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckNoSNI {});
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config.enable_sni = false;

            let mut client =
                ClientConnection::new(Arc::new(client_config), dns_name("value-not-sent")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(err.is_err(), true);
        }
    }
}

#[test]
fn client_checks_server_certificate_with_given_name() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let mut client = ClientConnection::new(
                Arc::new(client_config),
                dns_name("not-the-right-hostname.com"),
            )
            .unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::WebPkiError(
                    WebPkiError::CertNotValidForName,
                    WebPkiOp::ValidateForDnsName,
                )))
            );
        }
    }
}

struct ClientCheckCertResolve {
    query_count: AtomicUsize,
    expect_queries: usize,
}

impl ClientCheckCertResolve {
    fn new(expect_queries: usize) -> Self {
        ClientCheckCertResolve {
            query_count: AtomicUsize::new(0),
            expect_queries,
        }
    }
}

impl Drop for ClientCheckCertResolve {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let count = self.query_count.load(Ordering::SeqCst);
            assert_eq!(count, self.expect_queries);
        }
    }
}

impl ResolvesClientCert for ClientCheckCertResolve {
    fn resolve(
        &self,
        acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        self.query_count
            .fetch_add(1, Ordering::SeqCst);

        if acceptable_issuers.len() == 0 {
            panic!("no issuers offered by server");
        }

        if sigschemes.len() == 0 {
            panic!("no signature schemes shared by server");
        }

        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn client_cert_resolve() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config.client_auth_cert_resolver = Arc::new(ClientCheckCertResolve::new(1));

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

            assert_eq!(
                do_handshake_until_error(&mut client, &mut server),
                Err(ErrorFromPeer::Server(Error::NoCertificatesPresented))
            );
        }
    }
}

#[test]
fn client_auth_works() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
mod test_clientverifier {
    use super::*;
    use crate::common::MockClientVerifier;
    use rustls::internal::msgs::enums::AlertDescription;
    use rustls::internal::msgs::enums::ContentType;

    // Client is authorized!
    fn ver_ok() -> Result<ClientCertVerified, Error> {
        Ok(rustls::server::ClientCertVerified::assertion())
    }

    // Use when we shouldn't even attempt verification
    fn ver_unreachable() -> Result<ClientCertVerified, Error> {
        unreachable!()
    }

    // Verifier that returns an error that we can expect
    fn ver_err() -> Result<ClientCertVerified, Error> {
        Err(Error::General("test err".to_string()))
    }

    fn server_config_with_verifier(
        kt: KeyType,
        client_cert_verifier: MockClientVerifier,
    ) -> ServerConfig {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(client_cert_verifier))
            .with_single_cert(kt.get_chain(), kt.get_key())
            .unwrap()
    }

    #[test]
    // Happy path, we resolve to a root, it is verified OK, should be able to connect
    fn client_verifier_works() {
        for kt in ALL_KEY_TYPES.iter() {
            let client_verifier = MockClientVerifier {
                verified: ver_ok,
                subjects: Some(get_client_root_store(*kt).subjects()),
                mandatory: Some(true),
                offered_schemes: None,
            };

            let server_config = server_config_with_verifier(*kt, client_verifier);
            let server_config = Arc::new(server_config);

            for version in rustls::ALL_VERSIONS {
                let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
                let (mut client, mut server) =
                    make_pair_for_arc_configs(&Arc::new(client_config.clone()), &server_config);
                let err = do_handshake_until_error(&mut client, &mut server);
                assert_eq!(err, Ok(()));
            }
        }
    }

    // Server offers no verification schemes
    #[test]
    fn client_verifier_no_schemes() {
        for kt in ALL_KEY_TYPES.iter() {
            let client_verifier = MockClientVerifier {
                verified: ver_ok,
                subjects: Some(get_client_root_store(*kt).subjects()),
                mandatory: Some(true),
                offered_schemes: Some(vec![]),
            };

            let server_config = server_config_with_verifier(*kt, client_verifier);
            let server_config = Arc::new(server_config);

            for version in rustls::ALL_VERSIONS {
                let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
                let (mut client, mut server) =
                    make_pair_for_arc_configs(&Arc::new(client_config.clone()), &server_config);
                let err = do_handshake_until_error(&mut client, &mut server);
                assert_eq!(
                    err,
                    Err(ErrorFromPeer::Client(Error::CorruptMessagePayload(
                        ContentType::Handshake
                    )))
                );
            }
        }
    }

    // Common case, we do not find a root store to resolve to
    #[test]
    fn client_verifier_no_root() {
        for kt in ALL_KEY_TYPES.iter() {
            let client_verifier = MockClientVerifier {
                verified: ver_ok,
                subjects: None,
                mandatory: Some(true),
                offered_schemes: None,
            };

            let server_config = server_config_with_verifier(*kt, client_verifier);
            let server_config = Arc::new(server_config);

            for version in rustls::ALL_VERSIONS {
                let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
                let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
                let mut client =
                    ClientConnection::new(Arc::new(client_config), dns_name("notlocalhost"))
                        .unwrap();
                let errs = do_handshake_until_both_error(&mut client, &mut server);
                assert_eq!(
                    errs,
                    Err(vec![
                        ErrorFromPeer::Server(Error::General(
                            "client rejected by client_auth_root_subjects".into()
                        )),
                        ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::AccessDenied))
                    ])
                );
            }
        }
    }

    // If we cannot resolve a root, we cannot decide if auth is mandatory
    #[test]
    fn client_verifier_no_auth_no_root() {
        for kt in ALL_KEY_TYPES.iter() {
            let client_verifier = MockClientVerifier {
                verified: ver_unreachable,
                subjects: None,
                mandatory: Some(true),
                offered_schemes: None,
            };

            let server_config = server_config_with_verifier(*kt, client_verifier);
            let server_config = Arc::new(server_config);

            for version in rustls::ALL_VERSIONS {
                let client_config = make_client_config_with_versions(*kt, &[version]);
                let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
                let mut client =
                    ClientConnection::new(Arc::new(client_config), dns_name("notlocalhost"))
                        .unwrap();
                let errs = do_handshake_until_both_error(&mut client, &mut server);
                assert_eq!(
                    errs,
                    Err(vec![
                        ErrorFromPeer::Server(Error::General(
                            "client rejected by client_auth_root_subjects".into()
                        )),
                        ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::AccessDenied))
                    ])
                );
            }
        }
    }

    // If we do have a root, we must do auth
    #[test]
    fn client_verifier_no_auth_yes_root() {
        for kt in ALL_KEY_TYPES.iter() {
            let client_verifier = MockClientVerifier {
                verified: ver_unreachable,
                subjects: Some(get_client_root_store(*kt).subjects()),
                mandatory: Some(true),
                offered_schemes: None,
            };

            let server_config = server_config_with_verifier(*kt, client_verifier);
            let server_config = Arc::new(server_config);

            for version in rustls::ALL_VERSIONS {
                let client_config = make_client_config_with_versions(*kt, &[version]);
                let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
                let mut client =
                    ClientConnection::new(Arc::new(client_config), dns_name("localhost")).unwrap();
                let errs = do_handshake_until_both_error(&mut client, &mut server);
                assert_eq!(
                    errs,
                    Err(vec![
                        ErrorFromPeer::Server(Error::NoCertificatesPresented),
                        ErrorFromPeer::Client(Error::AlertReceived(
                            AlertDescription::CertificateRequired
                        ))
                    ])
                );
            }
        }
    }

    #[test]
    // Triple checks we propagate the rustls::Error through
    fn client_verifier_fails_properly() {
        for kt in ALL_KEY_TYPES.iter() {
            let client_verifier = MockClientVerifier {
                verified: ver_err,
                subjects: Some(get_client_root_store(*kt).subjects()),
                mandatory: Some(true),
                offered_schemes: None,
            };

            let server_config = server_config_with_verifier(*kt, client_verifier);
            let server_config = Arc::new(server_config);

            for version in rustls::ALL_VERSIONS {
                let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
                let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
                let mut client =
                    ClientConnection::new(Arc::new(client_config), dns_name("localhost")).unwrap();
                let err = do_handshake_until_error(&mut client, &mut server);
                assert_eq!(
                    err,
                    Err(ErrorFromPeer::Server(Error::General("test err".into())))
                );
            }
        }
    }

    #[test]
    // If a verifier returns a None on Mandatory-ness, then we error out
    fn client_verifier_must_determine_client_auth_requirement_to_continue() {
        for kt in ALL_KEY_TYPES.iter() {
            let client_verifier = MockClientVerifier {
                verified: ver_ok,
                subjects: Some(get_client_root_store(*kt).subjects()),
                mandatory: None,
                offered_schemes: None,
            };

            let server_config = server_config_with_verifier(*kt, client_verifier);
            let server_config = Arc::new(server_config);

            for version in rustls::ALL_VERSIONS {
                let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
                let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
                let mut client =
                    ClientConnection::new(Arc::new(client_config), dns_name("localhost")).unwrap();
                let errs = do_handshake_until_both_error(&mut client, &mut server);
                assert_eq!(
                    errs,
                    Err(vec![
                        ErrorFromPeer::Server(Error::General(
                            "client rejected by client_auth_mandatory".into()
                        )),
                        ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::AccessDenied))
                    ])
                );
            }
        }
    }
} // mod test_clientverifier

#[cfg(feature = "dangerous_configuration")]
mod test_serververifier {
    use super::*;
    use crate::common::MockServerVerifier;
    use rustls::internal::msgs::enums::AlertDescription;

    #[test]
    fn client_can_override_certificate_verification() {
        for kt in ALL_KEY_TYPES.iter() {
            let verifier = Arc::new(MockServerVerifier::accepts_anything());

            let server_config = Arc::new(make_server_config(*kt));

            for version in rustls::ALL_VERSIONS {
                let mut client_config = make_client_config_with_versions(*kt, &[version]);
                client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                let (mut client, mut server) =
                    make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
                do_handshake(&mut client, &mut server);
            }
        }
    }

    #[test]
    fn client_can_override_certificate_verification_and_reject_certificate() {
        for kt in ALL_KEY_TYPES.iter() {
            let verifier = Arc::new(MockServerVerifier::rejects_certificate(
                Error::CorruptMessage,
            ));

            let server_config = Arc::new(make_server_config(*kt));

            for version in rustls::ALL_VERSIONS {
                let mut client_config = make_client_config_with_versions(*kt, &[version]);
                client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                let (mut client, mut server) =
                    make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
                let errs = do_handshake_until_both_error(&mut client, &mut server);
                assert_eq!(
                    errs,
                    Err(vec![
                        ErrorFromPeer::Client(Error::CorruptMessage),
                        ErrorFromPeer::Server(Error::AlertReceived(
                            AlertDescription::BadCertificate
                        ))
                    ])
                );
            }
        }
    }

    #[test]
    fn client_can_override_certificate_verification_and_reject_tls12_signatures() {
        for kt in ALL_KEY_TYPES.iter() {
            let mut client_config =
                make_client_config_with_versions(*kt, &[&rustls::version::TLS12]);
            let verifier = Arc::new(MockServerVerifier::rejects_tls12_signatures(
                Error::CorruptMessage,
            ));

            client_config
                .dangerous()
                .set_certificate_verifier(verifier);

            let server_config = Arc::new(make_server_config(*kt));

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Client(Error::CorruptMessage),
                    ErrorFromPeer::Server(Error::AlertReceived(AlertDescription::BadCertificate))
                ])
            );
        }
    }

    #[test]
    fn client_can_override_certificate_verification_and_reject_tls13_signatures() {
        for kt in ALL_KEY_TYPES.iter() {
            let mut client_config =
                make_client_config_with_versions(*kt, &[&rustls::version::TLS13]);
            let verifier = Arc::new(MockServerVerifier::rejects_tls13_signatures(
                Error::CorruptMessage,
            ));

            client_config
                .dangerous()
                .set_certificate_verifier(verifier);

            let server_config = Arc::new(make_server_config(*kt));

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Client(Error::CorruptMessage),
                    ErrorFromPeer::Server(Error::AlertReceived(AlertDescription::BadCertificate))
                ])
            );
        }
    }

    #[test]
    fn client_can_override_certificate_verification_and_offer_no_signature_schemes() {
        for kt in ALL_KEY_TYPES.iter() {
            let verifier = Arc::new(MockServerVerifier::offers_no_signature_schemes());

            let server_config = Arc::new(make_server_config(*kt));

            for version in rustls::ALL_VERSIONS {
                let mut client_config = make_client_config_with_versions(*kt, &[version]);
                client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                let (mut client, mut server) =
                    make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
                let errs = do_handshake_until_both_error(&mut client, &mut server);
                assert_eq!(
                    errs,
                    Err(vec![
                        ErrorFromPeer::Server(Error::PeerIncompatibleError(
                            "no overlapping sigschemes".into()
                        )),
                        ErrorFromPeer::Client(Error::AlertReceived(
                            AlertDescription::HandshakeFailure
                        )),
                    ])
                );
            }
        }
    }
}

#[test]
fn client_error_is_sticky() {
    let (mut client, _) = make_pair(KeyType::RSA);
    client
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = client.process_new_packets();
    assert_eq!(err.is_err(), true);
    err = client.process_new_packets();
    assert_eq!(err.is_err(), true);
}

#[test]
fn server_error_is_sticky() {
    let (_, mut server) = make_pair(KeyType::RSA);
    server
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = server.process_new_packets();
    assert_eq!(err.is_err(), true);
    err = server.process_new_packets();
    assert_eq!(err.is_err(), true);
}

#[test]
fn server_flush_does_nothing() {
    let (_, mut server) = make_pair(KeyType::RSA);
    assert!(matches!(server.writer().flush(), Ok(())));
}

#[test]
fn client_flush_does_nothing() {
    let (mut client, _) = make_pair(KeyType::RSA);
    assert!(matches!(client.writer().flush(), Ok(())));
}

#[test]
fn server_is_send_and_sync() {
    let (_, server) = make_pair(KeyType::RSA);
    &server as &dyn Send;
    &server as &dyn Sync;
}

#[test]
fn client_is_send_and_sync() {
    let (client, _) = make_pair(KeyType::RSA);
    &client as &dyn Send;
    &client as &dyn Sync;
}

#[test]
fn server_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    server.set_buffer_limit(Some(32));

    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        12
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345678901");
}

#[test]
fn server_respects_buffer_limit_pre_handshake_with_vectored_write() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    server.set_buffer_limit(Some(32));

    assert_eq!(
        server
            .writer()
            .write_vectored(&[
                IoSlice::new(b"01234567890123456789"),
                IoSlice::new(b"01234567890123456789")
            ])
            .unwrap(),
        32
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345678901");
}

#[test]
fn server_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    // this test will vary in behaviour depending on the default suites
    do_handshake(&mut client, &mut server);
    server.set_buffer_limit(Some(48));

    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        6
    );

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345");
}

#[test]
fn client_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    client.set_buffer_limit(Some(32));

    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        12
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345678901");
}

#[test]
fn client_respects_buffer_limit_pre_handshake_with_vectored_write() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    client.set_buffer_limit(Some(32));

    assert_eq!(
        client
            .writer()
            .write_vectored(&[
                IoSlice::new(b"01234567890123456789"),
                IoSlice::new(b"01234567890123456789")
            ])
            .unwrap(),
        32
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345678901");
}

#[test]
fn client_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    do_handshake(&mut client, &mut server);
    client.set_buffer_limit(Some(48));

    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        6
    );

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345");
}

struct OtherSession<'a> {
    sess: &'a mut dyn Connection,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<rustls::Error>,
}

impl<'a> OtherSession<'a> {
    fn new(sess: &'a mut dyn Connection) -> OtherSession<'a> {
        OtherSession {
            sess,
            reads: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
        }
    }

    fn new_fails(sess: &'a mut dyn Connection) -> OtherSession<'a> {
        let mut os = OtherSession::new(sess);
        os.fail_ok = true;
        os
    }
}

impl<'a> io::Read for OtherSession<'a> {
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref())
    }
}

impl<'a> io::Write for OtherSession<'a> {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        unreachable!()
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored<'b>(&mut self, b: &[io::IoSlice<'b>]) -> io::Result<usize> {
        let mut total = 0;
        let mut lengths = vec![];
        for bytes in b {
            let write_len = if self.short_writes {
                if bytes.len() > 5 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                }
            } else {
                bytes.len()
            };

            let l = self
                .sess
                .read_tls(&mut io::Cursor::new(&bytes[..write_len]))?;
            lengths.push(l);
            total += l;
            if bytes.len() != l {
                break;
            }
        }

        let rc = self.sess.process_new_packets();
        if !self.fail_ok {
            rc.unwrap();
        } else if rc.is_err() {
            self.last_error = rc.err();
        }

        self.writevs.push(lengths);
        Ok(total)
    }
}

#[test]
fn server_read_returns_wouldblock_when_no_data() {
    let (_, mut server) = make_pair(KeyType::RSA);
    assert!(matches!(server.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn client_read_returns_wouldblock_when_no_data() {
    let (mut client, _) = make_pair(KeyType::RSA);
    assert!(matches!(client.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn new_server_returns_initial_io_state() {
    let (_, mut server) = make_pair(KeyType::RSA);
    let io_state = server.process_new_packets().unwrap();
    println!("IoState is Debug {:?}", io_state);
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert_eq!(io_state.peer_has_closed(), false);
    assert_eq!(io_state.tls_bytes_to_write(), 0);
}

#[test]
fn new_client_returns_initial_io_state() {
    let (mut client, _) = make_pair(KeyType::RSA);
    let io_state = client.process_new_packets().unwrap();
    println!("IoState is Debug {:?}", io_state);
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert_eq!(io_state.peer_has_closed(), false);
    assert!(io_state.tls_bytes_to_write() > 200);
}

#[test]
fn client_complete_io_for_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    assert_eq!(true, client.is_handshaking());
    let (rdlen, wrlen) = client
        .complete_io(&mut OtherSession::new(&mut server))
        .unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert_eq!(false, client.is_handshaking());
}

#[test]
fn client_complete_io_for_handshake_eof() {
    let (mut client, _) = make_pair(KeyType::RSA);
    let mut input = io::Cursor::new(Vec::new());

    assert_eq!(true, client.is_handshaking());
    let err = client
        .complete_io(&mut input)
        .unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn client_complete_io_for_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap();
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut server);
            let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            println!("{:?}", pipe.writevs);
            assert_eq!(pipe.writevs, vec![vec![42, 42]]);
        }
        check_read(
            &mut server.reader(),
            b"0123456789012345678901234567890123456789",
        );
    }
}

#[test]
fn client_complete_io_for_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut server);
            let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut client.reader(), b"01234567890123456789");
    }
}

#[test]
fn server_complete_io_for_handshake() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        assert_eq!(true, server.is_handshaking());
        let (rdlen, wrlen) = server
            .complete_io(&mut OtherSession::new(&mut client))
            .unwrap();
        assert!(rdlen > 0 && wrlen > 0);
        assert_eq!(false, server.is_handshaking());
    }
}

#[test]
fn server_complete_io_for_handshake_eof() {
    let (_, mut server) = make_pair(KeyType::RSA);
    let mut input = io::Cursor::new(Vec::new());

    assert_eq!(true, server.is_handshaking());
    let err = server
        .complete_io(&mut input)
        .unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn server_complete_io_for_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap();
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut client);
            let (rdlen, wrlen) = server.complete_io(&mut pipe).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            assert_eq!(pipe.writevs, vec![vec![42, 42]]);
        }
        check_read(
            &mut client.reader(),
            b"0123456789012345678901234567890123456789",
        );
    }
}

#[test]
fn server_complete_io_for_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut client);
            let (rdlen, wrlen) = server.complete_io(&mut pipe).unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut server.reader(), b"01234567890123456789");
    }
}

#[test]
fn client_stream_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        {
            let mut pipe = OtherSession::new(&mut server);
            let mut stream = Stream::new(&mut client, &mut pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut server.reader(), b"hello");
    }
}

#[test]
fn client_streamowned_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (client, mut server) = make_pair(*kt);

        {
            let pipe = OtherSession::new(&mut server);
            let mut stream = StreamOwned::new(client, pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut server.reader(), b"hello");
    }
}

#[test]
fn client_stream_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        server.writer().write(b"world").unwrap();

        {
            let mut pipe = OtherSession::new(&mut server);
            let mut stream = Stream::new(&mut client, &mut pipe);
            check_read(&mut stream, b"world");
        }
    }
}

#[test]
fn client_streamowned_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (client, mut server) = make_pair(*kt);

        server.writer().write(b"world").unwrap();

        {
            let pipe = OtherSession::new(&mut server);
            let mut stream = StreamOwned::new(client, pipe);
            check_read(&mut stream, b"world");
        }
    }
}

#[test]
fn server_stream_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        {
            let mut pipe = OtherSession::new(&mut client);
            let mut stream = Stream::new(&mut server, &mut pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut client.reader(), b"hello");
    }
}

#[test]
fn server_streamowned_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, server) = make_pair(*kt);

        {
            let pipe = OtherSession::new(&mut client);
            let mut stream = StreamOwned::new(server, pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut client.reader(), b"hello");
    }
}

#[test]
fn server_stream_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        client.writer().write(b"world").unwrap();

        {
            let mut pipe = OtherSession::new(&mut client);
            let mut stream = Stream::new(&mut server, &mut pipe);
            check_read(&mut stream, b"world");
        }
    }
}

#[test]
fn server_streamowned_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, server) = make_pair(*kt);

        client.writer().write(b"world").unwrap();

        {
            let pipe = OtherSession::new(&mut client);
            let mut stream = StreamOwned::new(server, pipe);
            check_read(&mut stream, b"world");
        }
    }
}

struct FailsWrites {
    errkind: io::ErrorKind,
    after: usize,
}

impl io::Read for FailsWrites {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl io::Write for FailsWrites {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.after > 0 {
            self.after -= 1;
            Ok(b.len())
        } else {
            Err(io::Error::new(self.errkind, "oops"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stream_write_reports_underlying_io_error_before_plaintext_processed() {
    let (mut client, mut server) = make_pair(KeyType::RSA);
    do_handshake(&mut client, &mut server);

    let mut pipe = FailsWrites {
        errkind: io::ErrorKind::ConnectionAborted,
        after: 0,
    };
    client.writer().write(b"hello").unwrap();
    let mut client_stream = Stream::new(&mut client, &mut pipe);
    let rc = client_stream.write(b"world");
    assert!(rc.is_err());
    let err = rc.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
}

#[test]
fn stream_write_swallows_underlying_io_error_after_plaintext_processed() {
    let (mut client, mut server) = make_pair(KeyType::RSA);
    do_handshake(&mut client, &mut server);

    let mut pipe = FailsWrites {
        errkind: io::ErrorKind::ConnectionAborted,
        after: 1,
    };
    client.writer().write(b"hello").unwrap();
    let mut client_stream = Stream::new(&mut client, &mut pipe);
    let rc = client_stream.write(b"world");
    assert_eq!(format!("{:?}", rc), "Ok(5)");
}

fn make_disjoint_suite_configs() -> (ClientConfig, ServerConfig) {
    let kt = KeyType::RSA;
    let server_config = finish_server_config(
        kt,
        ServerConfig::builder()
            .with_cipher_suites(&[
                rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ])
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap(),
    );

    let client_config = finish_client_config(
        kt,
        ClientConfig::builder()
            .with_cipher_suites(&[rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384])
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap(),
    );

    (client_config, server_config)
}

#[test]
fn client_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    {
        let mut pipe = OtherSession::new_fails(&mut server);
        let mut client_stream = Stream::new(&mut client, &mut pipe);
        let rc = client_stream.write(b"hello");
        assert!(rc.is_err());
        assert_eq!(
            format!("{:?}", rc),
            "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
        );
        let rc = client_stream.write(b"hello");
        assert!(rc.is_err());
        assert_eq!(
            format!("{:?}", rc),
            "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
        );
    }
}

#[test]
fn client_streamowned_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (client, mut server) = make_pair_for_configs(client_config, server_config);

    let pipe = OtherSession::new_fails(&mut server);
    let mut client_stream = StreamOwned::new(client, pipe);
    let rc = client_stream.write(b"hello");
    assert!(rc.is_err());
    assert_eq!(
        format!("{:?}", rc),
        "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
    );
    let rc = client_stream.write(b"hello");
    assert!(rc.is_err());
    assert_eq!(
        format!("{:?}", rc),
        "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
    );
}

#[test]
fn server_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    client.writer().write(b"world").unwrap();

    {
        let mut pipe = OtherSession::new_fails(&mut client);
        let mut server_stream = Stream::new(&mut server, &mut pipe);
        let mut bytes = [0u8; 5];
        let rc = server_stream.read(&mut bytes);
        assert!(rc.is_err());
        assert_eq!(
            format!("{:?}", rc),
            "Err(Custom { kind: InvalidData, error: PeerIncompatibleError(\"no ciphersuites in common\") })"
        );
    }
}

#[test]
fn server_streamowned_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, server) = make_pair_for_configs(client_config, server_config);

    client.writer().write(b"world").unwrap();

    let pipe = OtherSession::new_fails(&mut client);
    let mut server_stream = StreamOwned::new(server, pipe);
    let mut bytes = [0u8; 5];
    let rc = server_stream.read(&mut bytes);
    assert!(rc.is_err());
    assert_eq!(
        format!("{:?}", rc),
        "Err(Custom { kind: InvalidData, error: PeerIncompatibleError(\"no ciphersuites in common\") })"
    );
}

#[test]
fn server_config_is_clone() {
    let _ = make_server_config(KeyType::RSA).clone();
}

#[test]
fn client_config_is_clone() {
    let _ = make_client_config(KeyType::RSA).clone();
}

#[test]
fn client_connection_is_debug() {
    let (client, _) = make_pair(KeyType::RSA);
    println!("{:?}", client);
}

#[test]
fn server_connection_is_debug() {
    let (_, server) = make_pair(KeyType::RSA);
    println!("{:?}", server);
}

#[test]
fn server_complete_io_for_handshake_ending_with_alert() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(true, server.is_handshaking());

    let mut pipe = OtherSession::new_fails(&mut client);
    let rc = server.complete_io(&mut pipe);
    assert!(rc.is_err(), "server io failed due to handshake failure");
    assert!(!server.wants_write(), "but server did send its alert");
    assert_eq!(
        format!("{:?}", pipe.last_error),
        "Some(AlertReceived(HandshakeFailure))",
        "which was received by client"
    );
}

#[test]
fn server_exposes_offered_sni() {
    let kt = KeyType::RSA;
    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut client =
            ClientConnection::new(Arc::new(client_config), dns_name("second.testserver.com"))
                .unwrap();
        let mut server = ServerConnection::new(Arc::new(make_server_config(kt))).unwrap();

        assert_eq!(None, server.sni_hostname());
        do_handshake(&mut client, &mut server);
        assert_eq!(Some("second.testserver.com"), server.sni_hostname());
    }
}

#[test]
fn server_exposes_offered_sni_smashed_to_lowercase() {
    // webpki actually does this for us in its DnsName type
    let kt = KeyType::RSA;
    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut client =
            ClientConnection::new(Arc::new(client_config), dns_name("SECOND.TESTServer.com"))
                .unwrap();
        let mut server = ServerConnection::new(Arc::new(make_server_config(kt))).unwrap();

        assert_eq!(None, server.sni_hostname());
        do_handshake(&mut client, &mut server);
        assert_eq!(Some("second.testserver.com"), server.sni_hostname());
    }
}

#[test]
fn server_exposes_offered_sni_even_if_resolver_fails() {
    let kt = KeyType::RSA;
    let resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
        let mut client =
            ClientConnection::new(Arc::new(client_config), dns_name("thisdoesNOTexist.com"))
                .unwrap();

        assert_eq!(None, server.sni_hostname());
        transfer(&mut client, &mut server);
        assert_eq!(
            server.process_new_packets(),
            Err(Error::General(
                "no server certificate chain resolved".to_string()
            ))
        );
        assert_eq!(Some("thisdoesnotexist.com"), server.sni_hostname());
    }
}

#[test]
fn sni_resolver_works() {
    let kt = KeyType::RSA;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = sign::RsaSigningKey::new(&kt.get_key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);
    resolver
        .add(
            "localhost",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()),
        )
        .unwrap();

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client1 =
        ClientConnection::new(Arc::new(make_client_config(kt)), dns_name("localhost")).unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));

    let mut server2 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client2 =
        ClientConnection::new(Arc::new(make_client_config(kt)), dns_name("notlocalhost")).unwrap();
    let err = do_handshake_until_error(&mut client2, &mut server2);
    assert_eq!(
        err,
        Err(ErrorFromPeer::Server(Error::General(
            "no server certificate chain resolved".into()
        )))
    );
}

#[test]
fn sni_resolver_rejects_wrong_names() {
    let kt = KeyType::RSA;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = sign::RsaSigningKey::new(&kt.get_key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add(
            "localhost",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())
        )
    );
    assert_eq!(
        Err(Error::General(
            "The server certificate is not valid for the given name".into()
        )),
        resolver.add(
            "not-localhost",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())
        )
    );
    assert_eq!(
        Err(Error::General("Bad DNS name".into())),
        resolver.add(
            "not ascii 🦀",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())
        )
    );
}

#[test]
fn sni_resolver_rejects_bad_certs() {
    let kt = KeyType::RSA;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = sign::RsaSigningKey::new(&kt.get_key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Err(Error::General(
            "No end-entity certificate in certificate chain".into()
        )),
        resolver.add(
            "localhost",
            sign::CertifiedKey::new(vec![], signing_key.clone())
        )
    );

    let bad_chain = vec![rustls::Certificate(vec![0xa0])];
    assert_eq!(
        Err(Error::General(
            "End-entity certificate in certificate chain is syntactically invalid".into()
        )),
        resolver.add(
            "localhost",
            sign::CertifiedKey::new(bad_chain, signing_key.clone())
        )
    );
}

fn do_exporter_test(client_config: ClientConfig, server_config: ServerConfig) {
    let mut client_secret = [0u8; 64];
    let mut server_secret = [0u8; 64];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(
        Err(Error::HandshakeNotComplete),
        client.export_keying_material(&mut client_secret, b"label", Some(b"context"))
    );
    assert_eq!(
        Err(Error::HandshakeNotComplete),
        server.export_keying_material(&mut server_secret, b"label", Some(b"context"))
    );
    do_handshake(&mut client, &mut server);

    assert_eq!(
        Ok(()),
        client.export_keying_material(&mut client_secret, b"label", Some(b"context"))
    );
    assert_eq!(
        Ok(()),
        server.export_keying_material(&mut server_secret, b"label", Some(b"context"))
    );
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());

    assert_eq!(
        Ok(()),
        client.export_keying_material(&mut client_secret, b"label", None)
    );
    assert_ne!(client_secret.to_vec(), server_secret.to_vec());
    assert_eq!(
        Ok(()),
        server.export_keying_material(&mut server_secret, b"label", None)
    );
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());
}

#[test]
fn test_tls12_exporter() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config_with_versions(*kt, &[&rustls::version::TLS12]);
        let server_config = make_server_config(*kt);

        do_exporter_test(client_config, server_config);
    }
}

#[test]
fn test_tls13_exporter() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config_with_versions(*kt, &[&rustls::version::TLS13]);
        let server_config = make_server_config(*kt);

        do_exporter_test(client_config, server_config);
    }
}

fn do_suite_test(
    client_config: ClientConfig,
    server_config: ServerConfig,
    expect_suite: SupportedCipherSuite,
    expect_version: ProtocolVersion,
) {
    println!(
        "do_suite_test {:?} {:?}",
        expect_version,
        expect_suite.suite()
    );
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(None, client.negotiated_cipher_suite());
    assert_eq!(None, server.negotiated_cipher_suite());
    assert_eq!(None, client.protocol_version());
    assert_eq!(None, server.protocol_version());
    assert_eq!(true, client.is_handshaking());
    assert_eq!(true, server.is_handshaking());

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    assert_eq!(true, client.is_handshaking());
    assert_eq!(true, server.is_handshaking());
    assert_eq!(None, client.protocol_version());
    assert_eq!(Some(expect_version), server.protocol_version());
    assert_eq!(None, client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert_eq!(false, client.is_handshaking());
    assert_eq!(false, server.is_handshaking());
    assert_eq!(Some(expect_version), client.protocol_version());
    assert_eq!(Some(expect_version), server.protocol_version());
    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());
}

fn find_suite(suite: CipherSuite) -> SupportedCipherSuite {
    for scs in ALL_CIPHER_SUITES.iter().copied() {
        if scs.suite() == suite {
            return scs;
        }
    }

    panic!("find_suite given unsupported suite");
}

static TEST_CIPHERSUITES: [(
    &'static rustls::SupportedProtocolVersion,
    KeyType,
    CipherSuite,
); 9] = [
    (
        &rustls::version::TLS13,
        KeyType::RSA,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ),
    (
        &rustls::version::TLS13,
        KeyType::RSA,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
    ),
    (
        &rustls::version::TLS13,
        KeyType::RSA,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
    ),
    (
        &rustls::version::TLS12,
        KeyType::ECDSA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ),
    (
        &rustls::version::TLS12,
        KeyType::RSA,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ),
    (
        &rustls::version::TLS12,
        KeyType::ECDSA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ),
    (
        &rustls::version::TLS12,
        KeyType::ECDSA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ),
    (
        &rustls::version::TLS12,
        KeyType::RSA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ),
    (
        &rustls::version::TLS12,
        KeyType::RSA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ),
];

#[test]
fn negotiated_ciphersuite_default() {
    for kt in ALL_KEY_TYPES.iter() {
        do_suite_test(
            make_client_config(*kt),
            make_server_config(*kt),
            find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384),
            ProtocolVersion::TLSv1_3,
        );
    }
}

#[test]
fn all_suites_covered() {
    assert_eq!(ALL_CIPHER_SUITES.len(), TEST_CIPHERSUITES.len());
}

#[test]
fn negotiated_ciphersuite_client() {
    for item in TEST_CIPHERSUITES.iter() {
        let (version, kt, suite) = *item;
        let scs = find_suite(suite);
        let client_config = finish_client_config(
            kt,
            ClientConfig::builder()
                .with_cipher_suites(&[scs])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[version])
                .unwrap(),
        );

        do_suite_test(client_config, make_server_config(kt), scs, version.version);
    }
}

#[test]
fn negotiated_ciphersuite_server() {
    for item in TEST_CIPHERSUITES.iter() {
        let (version, kt, suite) = *item;
        let scs = find_suite(suite);
        let server_config = finish_server_config(
            kt,
            ServerConfig::builder()
                .with_cipher_suites(&[scs])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[version])
                .unwrap(),
        );

        do_suite_test(make_client_config(kt), server_config, scs, version.version);
    }
}

#[derive(Debug, PartialEq)]
struct KeyLogItem {
    label: String,
    client_random: Vec<u8>,
    secret: Vec<u8>,
}

struct KeyLogToVec {
    label: &'static str,
    items: Mutex<Vec<KeyLogItem>>,
}

impl KeyLogToVec {
    fn new(who: &'static str) -> Self {
        KeyLogToVec {
            label: who,
            items: Mutex::new(vec![]),
        }
    }

    fn take(&self) -> Vec<KeyLogItem> {
        mem::replace(&mut self.items.lock().unwrap(), vec![])
    }
}

impl KeyLog for KeyLogToVec {
    fn log(&self, label: &str, client: &[u8], secret: &[u8]) {
        let value = KeyLogItem {
            label: label.into(),
            client_random: client.into(),
            secret: secret.into(),
        };

        println!("key log {:?}: {:?}", self.label, value);

        self.items.lock().unwrap().push(value);
    }
}

#[test]
fn key_log_for_tls12() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let kt = KeyType::RSA;
    let mut client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS12]);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();
    assert_eq!(client_full_log, server_full_log);
    assert_eq!(1, client_full_log.len());
    assert_eq!("CLIENT_RANDOM", client_full_log[0].label);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();
    assert_eq!(client_resume_log, server_resume_log);
    assert_eq!(1, client_resume_log.len());
    assert_eq!("CLIENT_RANDOM", client_resume_log[0].label);
    assert_eq!(client_full_log[0].secret, client_resume_log[0].secret);
}

#[test]
fn key_log_for_tls13() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let kt = KeyType::RSA;
    let mut client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();

    assert_eq!(5, client_full_log.len());
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_full_log[0].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_full_log[1].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_full_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_full_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_full_log[4].label);

    assert_eq!(client_full_log[0], server_full_log[0]);
    assert_eq!(client_full_log[1], server_full_log[1]);
    assert_eq!(client_full_log[2], server_full_log[2]);
    assert_eq!(client_full_log[3], server_full_log[3]);
    assert_eq!(client_full_log[4], server_full_log[4]);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();

    assert_eq!(5, client_resume_log.len());
    assert_eq!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        client_resume_log[0].label
    );
    assert_eq!(
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        client_resume_log[1].label
    );
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_resume_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_resume_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_resume_log[4].label);

    assert_eq!(client_resume_log[0], server_resume_log[0]);
    assert_eq!(client_resume_log[1], server_resume_log[1]);
    assert_eq!(client_resume_log[2], server_resume_log[2]);
    assert_eq!(client_resume_log[3], server_resume_log[3]);
    assert_eq!(client_resume_log[4], server_resume_log[4]);
}

#[test]
fn vectored_write_for_server_appdata() {
    let (mut client, mut server) = make_pair(KeyType::RSA);
    do_handshake(&mut client, &mut server);

    server
        .writer()
        .write(b"01234567890123456789")
        .unwrap();
    server
        .writer()
        .write(b"01234567890123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writevs, vec![vec![42, 42]]);
    }
    check_read(
        &mut client.reader(),
        b"0123456789012345678901234567890123456789",
    );
}

#[test]
fn vectored_write_for_client_appdata() {
    let (mut client, mut server) = make_pair(KeyType::RSA);
    do_handshake(&mut client, &mut server);

    client
        .writer()
        .write(b"01234567890123456789")
        .unwrap();
    client
        .writer()
        .write(b"01234567890123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writevs, vec![vec![42, 42]]);
    }
    check_read(
        &mut server.reader(),
        b"0123456789012345678901234567890123456789",
    );
}

#[test]
fn vectored_write_for_server_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    server
        .writer()
        .write(b"01234567890123456789")
        .unwrap();
    server
        .writer()
        .write(b"0123456789")
        .unwrap();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 4000); // its pretty big (contains cert chain)
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() > 3); // at least a server hello/cert/serverkx
    }

    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 177);
        assert_eq!(pipe.writevs, vec![vec![103, 42, 32]]);
    }

    assert_eq!(server.is_handshaking(), false);
    assert_eq!(client.is_handshaking(), false);
    check_read(&mut client.reader(), b"012345678901234567890123456789");
}

#[test]
fn vectored_write_for_client_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    client
        .writer()
        .write(b"01234567890123456789")
        .unwrap();
    client
        .writer()
        .write(b"0123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 200); // just the client hello
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 1); // only a client hello
    }

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 154);
        // CCS, finished, then two application datas
        assert_eq!(pipe.writevs, vec![vec![6, 74, 42, 32]]);
    }

    assert_eq!(server.is_handshaking(), false);
    assert_eq!(client.is_handshaking(), false);
    check_read(&mut server.reader(), b"012345678901234567890123456789");
}

#[test]
fn vectored_write_with_slow_client() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    client.set_buffer_limit(Some(32));

    do_handshake(&mut client, &mut server);
    server
        .writer()
        .write(b"01234567890123456789")
        .unwrap();

    {
        let mut pipe = OtherSession::new(&mut client);
        pipe.short_writes = true;
        let wrlen = server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap();
        assert_eq!(42, wrlen);
        assert_eq!(
            pipe.writevs,
            vec![vec![21], vec![10], vec![5], vec![3], vec![3]]
        );
    }
    check_read(&mut client.reader(), b"01234567890123456789");
}

struct ServerStorage {
    storage: Arc<dyn rustls::server::StoresServerSessions>,
    put_count: AtomicUsize,
    get_count: AtomicUsize,
    take_count: AtomicUsize,
}

impl ServerStorage {
    fn new() -> Self {
        ServerStorage {
            storage: rustls::server::ServerSessionMemoryCache::new(1024),
            put_count: AtomicUsize::new(0),
            get_count: AtomicUsize::new(0),
            take_count: AtomicUsize::new(0),
        }
    }

    fn puts(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }
    fn gets(&self) -> usize {
        self.get_count.load(Ordering::SeqCst)
    }
    fn takes(&self) -> usize {
        self.take_count.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for ServerStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(put: {:?}, get: {:?}, take: {:?})",
            self.put_count, self.get_count, self.take_count
        )
    }
}

impl rustls::server::StoresServerSessions for ServerStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.put_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.take_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.take(key)
    }
}

struct ClientStorage {
    storage: Arc<dyn rustls::client::StoresClientSessions>,
    put_count: AtomicUsize,
    get_count: AtomicUsize,
    last_put_key: Mutex<Option<Vec<u8>>>,
}

impl ClientStorage {
    fn new() -> Self {
        ClientStorage {
            storage: rustls::client::ClientSessionMemoryCache::new(1024),
            put_count: AtomicUsize::new(0),
            get_count: AtomicUsize::new(0),
            last_put_key: Mutex::new(None),
        }
    }

    fn puts(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }
    fn gets(&self) -> usize {
        self.get_count.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for ClientStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(puts: {:?}, gets: {:?} )",
            self.put_count, self.get_count
        )
    }
}

impl rustls::client::StoresClientSessions for ClientStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.put_count
            .fetch_add(1, Ordering::SeqCst);
        *self.last_put_key.lock().unwrap() = Some(key.clone());
        self.storage.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.get(key)
    }
}

#[test]
fn tls13_stateful_resumption() {
    let kt = KeyType::RSA;
    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(storage.puts(), 1);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server);
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 2);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 1);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed again
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 3);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 2);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );
}

#[test]
fn tls13_stateless_resumption() {
    let kt = KeyType::RSA;
    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.ticketer = rustls::Ticketer::new().unwrap();
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server);
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed again
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );
}

#[test]
fn early_data_not_available() {
    let (mut client, _) = make_pair(KeyType::RSA);
    assert!(client.early_data().is_none());
}

#[test]
fn early_data_is_available_on_resumption() {
    let kt = KeyType::RSA;
    let mut client_config = make_client_config(kt);
    client_config.enable_early_data = true;

    let storage = Arc::new(ClientStorage::new());
    client_config.session_storage = storage.clone();

    let client_config = Arc::new(client_config);

    let server_config = Arc::new(make_server_config(kt));
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    /* discover the session data in the storage, and edit it to fool the
     * client on resumption that the server supports 0rtt. */
    let session_key = storage
        .last_put_key
        .lock()
        .unwrap()
        .clone()
        .unwrap();

    let session_value_bytes = storage
        .storage
        .get(&session_key)
        .unwrap();
    let mut session_value = ClientSessionValue::read_bytes(&session_value_bytes).unwrap();
    session_value.max_early_data_size = 128;

    storage
        .storage
        .put(session_key, session_value.get_encoding());

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        128
    );
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .flush()
            .unwrap(),
        ()
    );
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(b"hello")
            .unwrap(),
        5
    );
    let err = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(err, Err(ErrorFromPeer::Server(Error::DecryptError)));
}

#[cfg(feature = "quic")]
mod test_quic {
    use super::*;

    // Returns the sender's next secrets to use, or the receiver's error.
    fn step(
        send: &mut dyn Connection,
        recv: &mut dyn Connection,
    ) -> Result<Option<quic::Keys>, Error> {
        let mut buf = Vec::new();
        let secrets = loop {
            let prev = buf.len();
            if let Some(x) = send.write_hs(&mut buf) {
                break Some(x);
            }
            if prev == buf.len() {
                break None;
            }
        };
        if let Err(e) = recv.read_hs(&buf) {
            return Err(e);
        } else {
            assert_eq!(recv.alert(), None);
        }
        Ok(secrets)
    }

    #[test]
    fn test_quic_handshake() {
        fn equal_dir_keys(x: &quic::DirectionalKeys, y: &quic::DirectionalKeys) -> bool {
            // Check that these two sets of keys are equal. The quic module's unit tests validate
            // that the IV and the keys are consistent, so we can just check the IV here.
            x.packet.iv.nonce_for(42).as_ref() == y.packet.iv.nonce_for(42).as_ref()
        }
        fn compatible_keys(x: &quic::Keys, y: &quic::Keys) -> bool {
            equal_dir_keys(&x.local, &y.remote) && equal_dir_keys(&x.remote, &y.local)
        }

        let kt = KeyType::RSA;
        let mut client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
        client_config.enable_early_data = true;
        let client_config = Arc::new(client_config);
        let mut server_config = make_server_config_with_versions(kt, &[&rustls::version::TLS13]);
        server_config.max_early_data_size = 0xffffffff;
        server_config.alpn_protocols = vec!["foo".into()];
        let server_config = Arc::new(server_config);
        let client_params = &b"client params"[..];
        let server_params = &b"server params"[..];

        // full handshake
        let mut client = ClientConnection::new_quic(
            Arc::clone(&client_config),
            quic::Version::V1,
            dns_name("localhost"),
            client_params.into(),
        )
        .unwrap();

        let mut server = ServerConnection::new_quic(
            Arc::clone(&server_config),
            quic::Version::V1,
            server_params.into(),
        )
        .unwrap();

        let client_initial = step(&mut client, &mut server).unwrap();
        assert!(client_initial.is_none());
        assert!(client.zero_rtt_keys().is_none());
        assert_eq!(server.quic_transport_parameters(), Some(client_params));
        let server_hs = step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(server.zero_rtt_keys().is_none());
        let client_hs = step(&mut client, &mut server)
            .unwrap()
            .unwrap();
        assert!(compatible_keys(&server_hs, &client_hs));
        assert!(client.is_handshaking());
        let server_1rtt = step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(!client.is_handshaking());
        assert_eq!(client.quic_transport_parameters(), Some(server_params));
        assert!(server.is_handshaking());
        let client_1rtt = step(&mut client, &mut server)
            .unwrap()
            .unwrap();
        assert!(!server.is_handshaking());
        assert!(compatible_keys(&server_1rtt, &client_1rtt));
        assert!(!compatible_keys(&server_hs, &server_1rtt));
        assert!(
            step(&mut client, &mut server)
                .unwrap()
                .is_none()
        );
        assert!(
            step(&mut server, &mut client)
                .unwrap()
                .is_none()
        );

        // 0-RTT handshake
        let mut client = ClientConnection::new_quic(
            Arc::clone(&client_config),
            quic::Version::V1,
            dns_name("localhost"),
            client_params.into(),
        )
        .unwrap();
        assert!(
            client
                .negotiated_cipher_suite()
                .is_some()
        );

        let mut server = ServerConnection::new_quic(
            Arc::clone(&server_config),
            quic::Version::V1,
            server_params.into(),
        )
        .unwrap();

        step(&mut client, &mut server).unwrap();
        assert_eq!(client.quic_transport_parameters(), Some(server_params));
        {
            let client_early = client.zero_rtt_keys().unwrap();
            let server_early = server.zero_rtt_keys().unwrap();
            assert!(equal_dir_keys(&client_early, &server_early));
        }
        step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        step(&mut client, &mut server)
            .unwrap()
            .unwrap();
        step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(client.is_early_data_accepted());

        // 0-RTT rejection
        {
            let mut client_config = (*client_config).clone();
            client_config.alpn_protocols = vec!["foo".into()];
            let mut client = ClientConnection::new_quic(
                Arc::new(client_config),
                quic::Version::V1,
                dns_name("localhost"),
                client_params.into(),
            )
            .unwrap();

            let mut server = ServerConnection::new_quic(
                Arc::clone(&server_config),
                quic::Version::V1,
                server_params.into(),
            )
            .unwrap();

            step(&mut client, &mut server).unwrap();
            assert_eq!(client.quic_transport_parameters(), Some(server_params));
            assert!(client.zero_rtt_keys().is_some());
            assert!(server.zero_rtt_keys().is_none());
            step(&mut server, &mut client)
                .unwrap()
                .unwrap();
            step(&mut client, &mut server)
                .unwrap()
                .unwrap();
            step(&mut server, &mut client)
                .unwrap()
                .unwrap();
            assert!(!client.is_early_data_accepted());
        }

        // failed handshake
        let mut client = ClientConnection::new_quic(
            client_config,
            quic::Version::V1,
            dns_name("example.com"),
            client_params.into(),
        )
        .unwrap();

        let mut server =
            ServerConnection::new_quic(server_config, quic::Version::V1, server_params.into())
                .unwrap();

        step(&mut client, &mut server).unwrap();
        step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(step(&mut server, &mut client).is_err());
        assert_eq!(
            client.alert(),
            Some(rustls::internal::msgs::enums::AlertDescription::BadCertificate)
        );
    }

    #[test]
    fn test_quic_rejects_missing_alpn() {
        let client_params = &b"client params"[..];
        let server_params = &b"server params"[..];

        for &kt in ALL_KEY_TYPES.iter() {
            let mut client_config =
                make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
            client_config.alpn_protocols = vec!["bar".into()];
            let client_config = Arc::new(client_config);

            let mut server_config =
                make_server_config_with_versions(kt, &[&rustls::version::TLS13]);
            server_config.alpn_protocols = vec!["foo".into()];
            let server_config = Arc::new(server_config);

            let mut client = ClientConnection::new_quic(
                client_config,
                quic::Version::V1,
                dns_name("localhost"),
                client_params.into(),
            )
            .unwrap();
            let mut server =
                ServerConnection::new_quic(server_config, quic::Version::V1, server_params.into())
                    .unwrap();

            assert_eq!(
                step(&mut client, &mut server)
                    .err()
                    .unwrap(),
                Error::NoApplicationProtocol
            );

            assert_eq!(
                server.alert(),
                Some(rustls::internal::msgs::enums::AlertDescription::NoApplicationProtocol)
            );
        }
    }

    #[test]
    fn test_quic_no_tls13_error() {
        let mut client_config =
            make_client_config_with_versions(KeyType::ED25519, &[&rustls::version::TLS12]);
        client_config.alpn_protocols = vec!["foo".into()];
        let client_config = Arc::new(client_config);

        assert!(
            ClientConnection::new_quic(
                client_config,
                quic::Version::V1,
                dns_name("localhost"),
                b"client params".to_vec(),
            )
            .is_err()
        );

        let mut server_config =
            make_server_config_with_versions(KeyType::ED25519, &[&rustls::version::TLS12]);
        server_config.alpn_protocols = vec!["foo".into()];
        let server_config = Arc::new(server_config);

        assert!(ServerConnection::new_quic(
            server_config,
            quic::Version::V1,
            b"server params".to_vec(),
        )
        .is_err());
    }

    #[test]
    fn test_quic_invalid_early_data_size() {
        let mut server_config =
            make_server_config_with_versions(KeyType::ED25519, &[&rustls::version::TLS13]);
        server_config.alpn_protocols = vec!["foo".into()];

        let cases = [
            (None, true),
            (Some(0u32), true),
            (Some(5), false),
            (Some(0xffff_ffff), true),
        ];

        for &(size, ok) in cases.iter() {
            println!("early data size case: {:?}", size);
            if let Some(new) = size {
                server_config.max_early_data_size = new;
            }

            let wrapped = Arc::new(server_config.clone());
            assert_eq!(
                ServerConnection::new_quic(wrapped, quic::Version::V1, b"server params".to_vec(),)
                    .is_ok(),
                ok
            );
        }
    }

    #[test]
    fn test_quic_server_no_params_received() {
        let mut server_config =
            make_server_config_with_versions(KeyType::ED25519, &[&rustls::version::TLS13]);
        server_config.alpn_protocols = vec!["foo".into()];
        let server_config = Arc::new(server_config);

        let mut server =
            ServerConnection::new_quic(server_config, quic::Version::V1, b"server params".to_vec())
                .unwrap();

        use ring::rand::SecureRandom;
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::enums::{
            CipherSuite, Compression, HandshakeType, NamedGroup, SignatureScheme,
        };
        use rustls::internal::msgs::handshake::{
            ClientHelloPayload, HandshakeMessagePayload, KeyShareEntry, Random, SessionID,
        };
        use rustls::internal::msgs::message::PlainMessage;

        let rng = ring::rand::SystemRandom::new();
        let mut random = [0; 32];
        rng.fill(&mut random).unwrap();
        let random = Random::from(random);

        let kx = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
            .unwrap()
            .compute_public_key()
            .unwrap();

        let client_hello = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(ClientHelloPayload {
                    client_version: ProtocolVersion::TLSv1_3,
                    random,
                    session_id: SessionID::random().unwrap(),
                    cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
                    compression_methods: vec![Compression::Null],
                    extensions: vec![
                        ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
                        ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
                        ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ED25519]),
                        ClientExtension::KeyShare(vec![KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(kx.as_ref().to_vec()),
                        }]),
                    ],
                }),
            }),
        };

        let buf = PlainMessage::from(client_hello)
            .into_unencrypted_opaque()
            .encode();
        server
            .read_tls(&mut buf.as_slice())
            .unwrap();
        assert_eq!(
            server.process_new_packets().err(),
            Some(Error::PeerMisbehavedError(
                "QUIC transport parameters not found".into(),
            )),
        );
    }

    #[test]
    fn test_quic_server_no_tls12() {
        let mut server_config =
            make_server_config_with_versions(KeyType::ED25519, &[&rustls::version::TLS13]);
        server_config.alpn_protocols = vec!["foo".into()];
        let server_config = Arc::new(server_config);

        use ring::rand::SecureRandom;
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::enums::{
            CipherSuite, Compression, HandshakeType, NamedGroup, SignatureScheme,
        };
        use rustls::internal::msgs::handshake::{
            ClientHelloPayload, HandshakeMessagePayload, KeyShareEntry, Random, SessionID,
        };
        use rustls::internal::msgs::message::PlainMessage;

        let rng = ring::rand::SystemRandom::new();
        let mut random = [0; 32];
        rng.fill(&mut random).unwrap();
        let random = Random::from(random);

        let kx = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
            .unwrap()
            .compute_public_key()
            .unwrap();

        let mut server =
            ServerConnection::new_quic(server_config, quic::Version::V1, b"server params".to_vec())
                .unwrap();

        let client_hello = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(ClientHelloPayload {
                    client_version: ProtocolVersion::TLSv1_2,
                    random: random.clone(),
                    session_id: SessionID::random().unwrap(),
                    cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
                    compression_methods: vec![Compression::Null],
                    extensions: vec![
                        ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
                        ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ED25519]),
                        ClientExtension::KeyShare(vec![KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(kx.as_ref().to_vec()),
                        }]),
                    ],
                }),
            }),
        };

        let buf = PlainMessage::from(client_hello)
            .into_unencrypted_opaque()
            .encode();
        server
            .read_tls(&mut buf.as_slice())
            .unwrap();
        assert_eq!(
            server.process_new_packets().err(),
            Some(Error::PeerIncompatibleError(
                "Server requires TLS1.3, but client omitted versions ext".into(),
            )),
        );
    }

    #[test]
    fn test_quic_exporter() {
        for &kt in ALL_KEY_TYPES.iter() {
            let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
            let server_config = make_server_config_with_versions(kt, &[&rustls::version::TLS13]);

            do_exporter_test(client_config, server_config);
        }
    }
} // mod test_quic

#[test]
fn test_client_does_not_offer_sha1() {
    use rustls::internal::msgs::{
        codec::Reader, enums::HandshakeType, handshake::HandshakePayload, message::MessagePayload,
        message::OpaqueMessage,
    };

    for kt in ALL_KEY_TYPES.iter() {
        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, _) = make_pair_for_configs(client_config, make_server_config(*kt));

            assert!(client.wants_write());
            let mut buf = [0u8; 262144];
            let sz = client
                .write_tls(&mut buf.as_mut())
                .unwrap();
            let msg = OpaqueMessage::read(&mut Reader::init(&buf[..sz])).unwrap();
            let msg = Message::try_from(msg.into_plain_message()).unwrap();
            assert!(msg.is_handshake_type(HandshakeType::ClientHello));

            let client_hello = match msg.payload {
                MessagePayload::Handshake(hs) => match hs.payload {
                    HandshakePayload::ClientHello(ch) => ch,
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            };

            let sigalgs = client_hello
                .get_sigalgs_extension()
                .unwrap();
            assert_eq!(
                sigalgs.contains(&SignatureScheme::RSA_PKCS1_SHA1),
                false,
                "sha1 unexpectedly offered"
            );
        }
    }
}

#[test]
fn test_client_config_keyshare() {
    let client_config =
        make_client_config_with_kx_groups(KeyType::RSA, &[&rustls::kx_group::SECP384R1]);
    let server_config =
        make_server_config_with_kx_groups(KeyType::RSA, &[&rustls::kx_group::SECP384R1]);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake_until_error(&mut client, &mut server).unwrap();
}

#[test]
fn test_client_config_keyshare_mismatch() {
    let client_config =
        make_client_config_with_kx_groups(KeyType::RSA, &[&rustls::kx_group::SECP384R1]);
    let server_config =
        make_server_config_with_kx_groups(KeyType::RSA, &[&rustls::kx_group::X25519]);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    assert!(do_handshake_until_error(&mut client, &mut server).is_err());
}

#[test]
fn test_client_sends_helloretryrequest() {
    // client sends a secp384r1 key share
    let mut client_config = make_client_config_with_kx_groups(
        KeyType::RSA,
        &[&rustls::kx_group::SECP384R1, &rustls::kx_group::X25519],
    );

    let storage = Arc::new(ClientStorage::new());
    client_config.session_storage = storage.clone();

    // but server only accepts x25519, so a HRR is required
    let server_config =
        make_server_config_with_kx_groups(KeyType::RSA, &[&rustls::kx_group::X25519]);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    // client sends hello
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200);
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0].len() == 1);
    }

    // server sends HRR
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert!(wrlen < 100); // just the hello retry request
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 2); // hello retry request and CCS
    }

    // client sends fixed hello
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200); // just the client hello retry
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 2); // only a CCS & client hello retry
    }

    // server completes handshake
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200);
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0].len() == 5); // server hello / encrypted exts / cert / cert-verify / finished
    }

    do_handshake_until_error(&mut client, &mut server).unwrap();

    // client only did two storage queries: one for a session, another for a kx type
    assert_eq!(storage.gets(), 2);
    assert_eq!(storage.puts(), 2);
}

#[test]
fn test_client_attempts_to_use_unsupported_kx_group() {
    // common to both client configs
    let shared_storage = Arc::new(ClientStorage::new());

    // first, client sends a x25519 and server agrees. x25519 is inserted
    //   into kx group cache.
    let mut client_config_1 =
        make_client_config_with_kx_groups(KeyType::RSA, &[&rustls::kx_group::X25519]);
    client_config_1.session_storage = shared_storage.clone();

    // second, client only supports secp-384 and so kx group cache
    //   contains an unusable value.
    let mut client_config_2 =
        make_client_config_with_kx_groups(KeyType::RSA, &[&rustls::kx_group::SECP384R1]);
    client_config_2.session_storage = shared_storage.clone();

    let server_config = make_server_config(KeyType::RSA);

    // first handshake
    let (mut client_1, mut server) = make_pair_for_configs(client_config_1, server_config.clone());
    do_handshake_until_error(&mut client_1, &mut server).unwrap();

    // second handshake
    let (mut client_2, mut server) = make_pair_for_configs(client_config_2, server_config);
    do_handshake_until_error(&mut client_2, &mut server).unwrap();
}

#[test]
fn test_client_mtu_reduction() {
    struct CollectWrites {
        writevs: Vec<Vec<usize>>,
    }

    impl io::Write for CollectWrites {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!()
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!()
        }
        fn write_vectored<'b>(&mut self, b: &[io::IoSlice<'b>]) -> io::Result<usize> {
            let writes = b
                .iter()
                .map(|slice| slice.len())
                .collect::<Vec<usize>>();
            let len = writes.iter().sum();
            self.writevs.push(writes);
            Ok(len)
        }
    }

    fn collect_write_lengths(client: &mut ClientConnection) -> Vec<usize> {
        let mut collector = CollectWrites { writevs: vec![] };

        client
            .write_tls(&mut collector)
            .unwrap();
        assert_eq!(collector.writevs.len(), 1);
        collector.writevs[0].clone()
    }

    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.max_fragment_size = Some(64);
        let mut client =
            ClientConnection::new(Arc::new(client_config), dns_name("localhost")).unwrap();
        let writes = collect_write_lengths(&mut client);
        println!("writes at mtu=64: {:?}", writes);
        assert!(writes.iter().all(|x| *x <= 64));
        assert!(writes.len() > 1);
    }
}

fn check_client_max_fragment_size(size: usize) -> Option<Error> {
    let mut client_config = make_client_config(KeyType::ED25519);
    client_config.max_fragment_size = Some(size);
    ClientConnection::new(Arc::new(client_config), dns_name("localhost")).err()
}

#[test]
fn bad_client_max_fragment_sizes() {
    assert_eq!(
        check_client_max_fragment_size(31),
        Some(Error::BadMaxFragmentSize)
    );
    assert_eq!(check_client_max_fragment_size(32), None);
    assert_eq!(check_client_max_fragment_size(64), None);
    assert_eq!(check_client_max_fragment_size(1460), None);
    assert_eq!(check_client_max_fragment_size(0x4000), None);
    assert_eq!(check_client_max_fragment_size(0x4005), None);
    assert_eq!(
        check_client_max_fragment_size(0x4006),
        Some(Error::BadMaxFragmentSize)
    );
    assert_eq!(
        check_client_max_fragment_size(0xffff),
        Some(Error::BadMaxFragmentSize)
    );
}

#[test]
fn exercise_key_log_file_for_client() {
    let server_config = Arc::new(make_server_config(KeyType::RSA));
    env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt");

    for version in rustls::ALL_VERSIONS {
        let mut client_config = make_client_config_with_versions(KeyType::RSA, &[version]);
        client_config.key_log = Arc::new(rustls::KeyLogFile::new());

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(5, client.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
    }
}

#[test]
fn exercise_key_log_file_for_server() {
    let mut server_config = make_server_config(KeyType::RSA);

    env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt");
    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_config = Arc::new(server_config);

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::RSA, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(5, client.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
    }
}

fn assert_lt(left: usize, right: usize) {
    if left >= right {
        panic!("expected {} < {}", left, right);
    }
}

#[test]
fn connection_types_are_not_huge() {
    // Arbitrary sizes
    assert_lt(mem::size_of::<ServerConnection>(), 1600);
    assert_lt(mem::size_of::<ClientConnection>(), 1600);
}

use rustls::internal::msgs::{
    handshake::ClientExtension, handshake::HandshakePayload, message::Message,
    message::MessagePayload,
};

#[test]
fn test_server_rejects_duplicate_sni_names() {
    fn duplicate_sni_payload(msg: &mut Message) {
        if let MessagePayload::Handshake(hs) = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut hs.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::ServerName(snr) = &mut ext {
                        snr.push(snr[0].clone());
                    }
                }
            }
        }
    }

    let (mut client, mut server) = make_pair(KeyType::RSA);
    transfer_altered(&mut client, duplicate_sni_payload, &mut server);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerMisbehavedError(
            "ClientHello SNI contains duplicate name types".into()
        ))
    );
}

#[test]
fn test_server_rejects_empty_sni_extension() {
    fn empty_sni_payload(msg: &mut Message) {
        if let MessagePayload::Handshake(hs) = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut hs.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::ServerName(snr) = &mut ext {
                        snr.clear();
                    }
                }
            }
        }
    }

    let (mut client, mut server) = make_pair(KeyType::RSA);
    transfer_altered(&mut client, empty_sni_payload, &mut server);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerMisbehavedError(
            "ClientHello SNI did not contain a hostname".into()
        ))
    );
}

#[test]
fn test_server_rejects_clients_without_any_kx_group_overlap() {
    fn different_kx_group(msg: &mut Message) {
        if let MessagePayload::Handshake(hs) = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut hs.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::NamedGroups(ngs) = &mut ext {
                        ngs.clear();
                    }
                    if let ClientExtension::KeyShare(ks) = &mut ext {
                        ks.clear();
                    }
                }
            }
        }
    }

    let (mut client, mut server) = make_pair(KeyType::RSA);
    transfer_altered(&mut client, different_kx_group, &mut server);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerIncompatibleError(
            "no kx group overlap with client".into()
        ))
    );
}
