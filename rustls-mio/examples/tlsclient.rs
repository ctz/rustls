use std::process;
use std::sync::{Arc, Mutex};

use mio;
use mio::net::TcpStream;

use std::collections;
use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::str;

use env_logger;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;

use rustls;
use webpki_roots;

use rustls::{Connection, OwnedTrustAnchor, RootCertStore};

const CLIENT: mio::Token = mio::Token(0);

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_conn: rustls::ClientConnection,
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        server_name: rustls::ServerName,
        cfg: Arc<rustls::ClientConfig>,
    ) -> TlsClient {
        TlsClient {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_conn: rustls::ClientConnection::new(cfg, server_name).unwrap(),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn ready(&mut self, ev: &mio::event::Event) {
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() {
            self.do_read();
        }

        if ev.is_writable() {
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_conn
            .writer()
            .write_all(&buf)
            .unwrap();
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return;
                }
                println!("TLS read error: {:?}", error);
                self.closing = true;
                return;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = Vec::new();
            plaintext.resize(io_state.plaintext_bytes_to_read(), 0u8);
            self.tls_conn
                .reader()
                .read(&mut plaintext)
                .unwrap();
            io::stdout()
                .write_all(&plaintext)
                .unwrap();
        }

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
            return;
        }
    }

    fn do_write(&mut self) {
        self.tls_conn
            .write_tls(&mut self.socket)
            .unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .register(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .reregister(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }
}
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_conn.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_conn.writer().flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.reader().read(bytes)
    }
}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    filename: Option<String>,
}

impl PersistCache {
    /// Make a new cache.  If filename is Some, load the cache
    /// from it and flush changes back to that file.
    fn new(filename: &Option<String>) -> Self {
        let cache = PersistCache {
            cache: Mutex::new(collections::HashMap::new()),
            filename: filename.clone(),
        };
        if cache.filename.is_some() {
            cache.load();
        }
        cache
    }

    /// If we have a filename, save the cache contents to it.
    fn save(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::Codec;

        if self.filename.is_none() {
            return;
        }

        let mut file =
            fs::File::create(self.filename.as_ref().unwrap()).expect("cannot open cache file");

        for (key, val) in self.cache.lock().unwrap().iter() {
            let mut item = Vec::new();
            let key_pl = PayloadU16::new(key.clone());
            let val_pl = PayloadU16::new(val.clone());
            key_pl.encode(&mut item);
            val_pl.encode(&mut item);
            file.write_all(&item).unwrap();
        }
    }

    /// We have a filename, so replace the cache contents from it.
    fn load(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::{Codec, Reader};

        let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        let mut rd = Reader::init(&data);

        while rd.any_left() {
            let key_pl = PayloadU16::read(&mut rd).unwrap();
            let val_pl = PayloadU16::read(&mut rd).unwrap();
            cache.insert(key_pl.0, val_pl.0);
        }
    }
}

impl rustls::client::StoresClientSessions for PersistCache {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache
            .lock()
            .unwrap()
            .insert(key, value);
        self.save();
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .cloned()
    }
}

const USAGE: &'static str = "
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  tlsclient [options] [--suite SUITE ...] [--proto PROTO ...] <hostname>
  tlsclient (--version | -v)
  tlsclient (--help | -h)

Options:
    -p, --port PORT     Connect to PORT [default: 443].
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
                        May be used multiple times to offer several protocols.
    --cache CACHE       Save session cache to file CACHE.
    --no-tickets        Disable session ticket support.
    --no-sni            Disable server name indication support.
    --insecure          Disable certificate verification.
    --verbose           Emit log output.
    --max-frag-size M   Limit outgoing messages to M bytes.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_http: bool,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_max_frag_size: Option<usize>,
    flag_cafile: Option<String>,
    flag_cache: Option<String>,
    flag_no_tickets: bool,
    flag_no_sni: bool,
    flag_insecure: bool,
    flag_auth_key: Option<String>,
    flag_auth_certs: Option<String>,
    arg_hostname: String,
}

// TODO: um, well, it turns out that openssl s_client/s_server
// that we use for testing doesn't do ipv6.  So we can't actually
// test ipv6 and hence kill this.
fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

/// Find a ciphersuite with the given name
fn find_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    for suite in rustls::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(*suite);
        }
    }

    None
}

/// Make a vector of ciphersuites named in `suites`
fn lookup_suites(suites: &[String]) -> Vec<rustls::SupportedCipherSuite> {
    let mut out = Vec::new();

    for csname in suites {
        let scs = find_suite(csname);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up ciphersuite '{}'", csname),
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => &rustls::version::TLS12,
            "1.3" => &rustls::version::TLS13,
            _ => panic!(
                "cannot look up version '{}', valid are '1.2' and '1.3'",
                vname
            ),
        };
        out.push(version);
    }

    out
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
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

#[cfg(feature = "dangerous_configuration")]
mod danger {
    use super::rustls;

    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
fn apply_dangerous_options(args: &Args, cfg: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }
}

#[cfg(not(feature = "dangerous_configuration"))]
fn apply_dangerous_options(args: &Args, _: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        panic!("This build does not support --insecure.");
    }
}

/// Build a `ClientConfig` from our arguments
fn make_config(args: &Args) -> Arc<rustls::ClientConfig> {
    let mut root_store = RootCertStore::empty();

    if args.flag_cafile.is_some() {
        let cafile = args.flag_cafile.as_ref().unwrap();

        let certfile = fs::File::open(&cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());
    } else {
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }),
        );
    }

    let suites = if !args.flag_suite.is_empty() {
        lookup_suites(&args.flag_suite)
    } else {
        rustls::DEFAULT_CIPHER_SUITES.to_vec()
    };

    let versions = if !args.flag_protover.is_empty() {
        lookup_versions(&args.flag_protover)
    } else {
        rustls::DEFAULT_VERSIONS.to_vec()
    };

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store, &[]);

    let mut config = match (&args.flag_auth_key, &args.flag_auth_certs) {
        (Some(key_file), Some(certs_file)) => {
            let certs = load_certs(certs_file);
            let key = load_private_key(key_file);
            config
                .with_single_cert(certs, key)
                .expect("invalid client auth certs/key")
        }
        (None, None) => config.with_no_client_auth(),
        (_, _) => {
            panic!("must provide --auth-certs and --auth-key together");
        }
    };

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if args.flag_no_tickets {
        config.enable_tickets = false;
    }

    if args.flag_no_sni {
        config.enable_sni = false;
    }

    config.session_storage = Arc::new(PersistCache::new(&args.flag_cache));

    config.alpn_protocols = args
        .flag_proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();
    config.max_fragment_size = args.flag_max_frag_size;

    apply_dangerous_options(args, &mut config);

    Arc::new(config)
}

/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    let port = args.flag_port.unwrap_or(443);
    let addr = lookup_ipv4(args.arg_hostname.as_str(), port);

    let config = make_config(&args);

    let sock = TcpStream::connect(addr).unwrap();
    let server_name = args
        .arg_hostname
        .as_str()
        .try_into()
        .expect("invalid DNS name");
    let mut tlsclient = TlsClient::new(sock, server_name, config);

    if args.flag_http {
        let httpreq = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
            args.arg_hostname
        );
        tlsclient
            .write_all(httpreq.as_bytes())
            .unwrap();
    } else {
        let mut stdin = io::stdin();
        tlsclient
            .read_source_to_end(&mut stdin)
            .unwrap();
    }

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(32);
    tlsclient.register(poll.registry());

    loop {
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
            tlsclient.ready(&ev);
            tlsclient.reregister(poll.registry());
        }
    }
}
