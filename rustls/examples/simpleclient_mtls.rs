/// This is a mTLS example derive from the simple client.
/// it loads CA certs, client cert and private rsa key, and then connects
/// to <my-host> using mTLS and issues a basic HTTP request.
/// The response is printed to stdout.
///
/// It makes use of rustls::Stream to treat the underlying TLS session as a basic
/// bi-directional stream -- the underlying IO is performed transparently.
///
/// Note that `unwrap()` is used to deal with networking errors; this is not something
/// that is sensible outside of example code.
use std::sync::Arc;

use std::fs::File;
use std::io::BufReader;
use std::io::{stdout, Read, Write};
use std::net::Shutdown;
use std::net::TcpStream;

use rustls::Session;
use std::io::ErrorKind;

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

fn main() {
    let mut config = rustls::ClientConfig::new();

    config
        .root_store
        .add(load_certs("CA.pem").get(0).unwrap())
        .unwrap();

    config
        .set_single_client_cert(load_certs("client.pem"), load_private_key("client.key"))
        .unwrap();

    let host_to_connect = "<my-host>";
    let port = "443";
    let path = "/";
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(host_to_connect).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect(host_to_connect.to_string() + ":" + port).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    let request = format!(
        "GET {} HTTP/1.1\r\n\
        Host: {}\r\n\
        Connection: close\r\n\
        Accept-Encoding: identity\r\n\
        \r\n",
        path, host_to_connect
    );
    println!("Request:\n{}", request);
    tls.write_all(request.as_bytes()).unwrap();
    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite
    )
    .unwrap();

    let mut plaintext = Vec::new();
    let reader = tls.read_to_end(&mut plaintext);
    if reader.is_err() {
        let err = reader.err().unwrap();
        if err.kind() == ErrorKind::ConnectionAborted && err.to_string().contains("CloseNotify") {
            // this is an expected error that means everything is fine.
            // Details here: https://github.com/ctz/rustls/issues/380
            println!("Server properly close the connection.");
        } else {
            panic!(err.to_string());
        }
    }
    sock.shutdown(Shutdown::Both)
        .expect("Fail to close connection");
    println!("Response:");
    stdout().write_all(&plaintext).unwrap();
}
