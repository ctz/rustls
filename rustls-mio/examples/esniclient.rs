use std::sync::Arc;

use std::net::TcpStream;
use std::io::{Read, Write, stdout};
use std::iter::FromIterator;

use rustls;
use webpki;
use webpki_roots;
use rustls::Session;
use base64::decode;

extern crate trust_dns_resolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

fn main() {
    let domain = "canbe.esni.defo.ie";
    println!("\nContacting {:?} over ESNI\n", domain);

    //let dns_config = ResolverConfig::cloudflare_https();
    let dns_config= ResolverConfig::default();
    let opts = ResolverOpts::default();
    let addr = Address::new(domain);
    let esni_bytes = resolve_esni(dns_config, opts, &addr);
    println!("esni_bytes: {:02x?}", esni_bytes);

    let esni_hs = rustls::esni::create_esni_handshake(&esni_bytes).unwrap();

    let mut config = rustls::esni::create_esni_config();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);


    let dns_name = webpki::DNSNameRef::try_from_ascii_str("canbe.esni.defo.ie").unwrap();
    let mut sess = rustls::ClientSession::new_with_esni(&Arc::new(config), dns_name, esni_hs);
    let mut sock = TcpStream::connect(domain.to_owned() + ":8443").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    match tls.write(concat!("GET /stats HTTP/1.1\r\n",
    "Host: canbe.esni.defo.ie\r\n",
    "Connection: close\r\n",
    "Accept-Encoding: identity\r\n",
    "\r\n")
        .as_bytes()) {
        Ok(size) => {
            println!("Received: {} bytes", size);
        } ,
        Err(e) => {
            println!("Error: {:?}", e);
            return;
        }
    }
    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    writeln!(&mut std::io::stderr(), "\n\nNegotiated ciphersuite: {:?}", ciphersuite.suite).unwrap();
    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Ok(success) => {
            println!("read bytes: {}", success);
        },
        Err(e) => {
            println!("failure to read the bytes: {:?}", e);
            return;
        }
    }
    stdout().write_all(&plaintext).unwrap();
}

pub fn resolve_esni(config: ResolverConfig, opts: ResolverOpts, address: &Address) -> Vec<u8> {
    let resolver = Resolver::new(config, opts).unwrap();

    let txt = resolver.txt_lookup(&address.esni_address()).unwrap();
    let text = Vec::from_iter(txt.iter());
    let mut bytes: Vec<u8> = Vec::new();
    for txt_record in text.iter() {
        for byte_slice in txt_record.txt_data().iter() {
            for byte in byte_slice.iter() {
                bytes.push(*byte);
            }
        }
    }

    let decoded = decode(&bytes).unwrap();

    println!("hmm? {:?}", decoded);
    decoded
}

pub struct Address {
    domain: String
}

impl Address {
    pub fn new(domain: &str) -> Address {
        Address {
            domain: String::from(domain)
        }
    }

    pub fn esni_address(&self) -> String {
        format!("_esni.{}.", self.domain)
    }

    pub fn dns_address(&self) -> String {
        format!("{}.", self.domain)
    }
}