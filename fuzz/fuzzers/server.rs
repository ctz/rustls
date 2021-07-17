#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::{ServerConfig, Connection, ServerConnection};
use rustls::server::ResolvesServerCert;

use std::io;
use std::sync::Arc;

struct Fail;

impl ResolvesServerCert for Fail {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fail)),
    );
    let mut server = ServerConnection::new(config).unwrap();
    let _ = server.read_tls(&mut io::Cursor::new(data));
});
