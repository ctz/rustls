use std::sync::Arc;

use mio;
use mio::net::{TcpListener, TcpStream};

#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;

use env_logger;

use rustls;
use rustls::server::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
};
use rustls::{Connection, RootCertStore};
use rustls_pemfile;

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

// Which mode the server operates in.
#[derive(Clone)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

    /// Forward traffic to/from given port on localhost.
    Forward(u16),
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, OpenConnection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    mode: ServerMode,
}

impl TlsServer {
    fn new(server: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> Self {
        TlsServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            mode,
        }
    }

    fn accept(&mut self, registry: &mio::Registry) -> Result<(), io::Error> {
        loop {
            match self.server.accept() {
                Ok((socket, addr)) => {
                    debug!("Accepting new connection from {:?}", addr);

                    let tls_conn =
                        rustls::ServerConnection::new(Arc::clone(&self.tls_config)).unwrap();
                    let mode = self.mode.clone();

                    let token = mio::Token(self.next_id);
                    self.next_id += 1;

                    let mut connection = OpenConnection::new(socket, token, mode, tls_conn);
                    connection.register(registry);
                    self.connections
                        .insert(token, connection);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    println!(
                        "encountered error while accepting connection; err={:?}",
                        err
                    );
                    return Err(err);
                }
            }
        }
    }

    fn conn_event(&mut self, registry: &mio::Registry, event: &mio::event::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections
                .get_mut(&token)
                .unwrap()
                .ready(registry, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level connection state, and some
/// other state/metadata.
struct OpenConnection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    mode: ServerMode,
    tls_conn: rustls::ServerConnection,
    back: Option<TcpStream>,
    sent_http_response: bool,
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::Forward(ref port) => {
            let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), *port);
            let conn = TcpStream::connect(net::SocketAddr::V4(addr)).unwrap();
            Some(conn)
        }
        _ => None,
    }
}

/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

impl OpenConnection {
    fn new(
        socket: TcpStream,
        token: mio::Token,
        mode: ServerMode,
        tls_conn: rustls::ServerConnection,
    ) -> OpenConnection {
        let back = open_back(&mode);
        OpenConnection {
            socket,
            token,
            closing: false,
            closed: false,
            mode,
            tls_conn,
            back,
            sent_http_response: false,
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, registry: &mio::Registry, ev: &mio::event::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.is_readable() {
            self.do_tls_read();
            self.try_plain_read();
            self.try_back_read();
        }

        if ev.is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing {
            let _ = self
                .socket
                .shutdown(net::Shutdown::Both);
            self.close_back();
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry);
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if self.back.is_some() {
            let back = self.back.as_mut().unwrap();
            back.shutdown(net::Shutdown::Both)
                .unwrap();
        }
        self.back = None;
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(err) => {
                if let io::ErrorKind::WouldBlock = err.kind() {
                    return;
                }

                error!("read error {:?}", err);
                self.closing = true;
                return;
            }
            Ok(0) => {
                debug!("eof");
                self.closing = true;
                return;
            }
            Ok(_) => {}
        };

        // Process newly-received TLS messages.
        if let Err(err) = self.tls_conn.process_new_packets() {
            error!("cannot process packet: {:?}", err);

            // last gasp write to send any alerts
            self.do_tls_write_and_handle_error();

            self.closing = true;
        }
    }

    fn try_plain_read(&mut self) {
        // Read and process all available plaintext.
        if let Ok(io_state) = self.tls_conn.process_new_packets() {
            if io_state.plaintext_bytes_to_read() > 0 {
                let mut buf = Vec::new();
                buf.resize(io_state.plaintext_bytes_to_read(), 0u8);

                self.tls_conn
                    .reader()
                    .read(&mut buf)
                    .unwrap();

                debug!("plaintext read {:?}", buf.len());
                self.incoming_plaintext(&buf);
            }
        }
    }

    fn try_back_read(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // If we have a successful but empty read, that's an EOF.
        // Otherwise, we shove the data into the TLS session.
        match maybe_len {
            Some(len) if len == 0 => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tls_conn
                    .writer()
                    .write_all(&buf[..len])
                    .unwrap();
            }
            None => {}
        };
    }

    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Echo => {
                self.tls_conn
                    .writer()
                    .write_all(buf)
                    .unwrap();
            }
            ServerMode::Http => {
                self.send_http_response_once();
            }
            ServerMode::Forward(_) => {
                self.back
                    .as_mut()
                    .unwrap()
                    .write_all(buf)
                    .unwrap();
            }
        }
    }

    fn send_http_response_once(&mut self) {
        let response =
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";
        if !self.sent_http_response {
            self.tls_conn
                .writer()
                .write_all(response)
                .unwrap();
            self.sent_http_response = true;
            self.tls_conn.send_close_notify();
        }
    }

    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls_conn
            .write_tls(&mut self.socket)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    fn register(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .register(&mut self.socket, self.token, event_set)
            .unwrap();

        if self.back.is_some() {
            registry
                .register(
                    self.back.as_mut().unwrap(),
                    self.token,
                    mio::Interest::READABLE,
                )
                .unwrap();
        }
    }

    fn reregister(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .reregister(&mut self.socket, self.token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, registry: &mio::Registry) {
        registry
            .deregister(&mut self.socket)
            .unwrap();

        if self.back.is_some() {
            registry
                .deregister(self.back.as_mut().unwrap())
                .unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
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
        self.closed
    }
}

const USAGE: &'static str = "
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each
connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] echo
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] http
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] forward <fport>
  tlsserver (--version | -v)
  tlsserver (--help | -h)

Options:
    -p, --port PORT     Listen on PORT [default: 443].
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA
                        private key or PKCS8-encoded private key, in PEM format.
    --ocsp OCSPFILE     Read DER-encoded OCSP response from OCSPFILE and staple
                        to certificate.  Optional.
    --auth CERTFILE     Enable client authentication, and accept certificates
                        signed by those roots provided in CERTFILE.
    --require-auth      Send a fatal alert if the client does not complete client
                        authentication.
    --resumption        Support session resumption.
    --tickets           Support tickets.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
                        May be used multiple times.
    --verbose           Emit log output.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_echo: bool,
    cmd_http: bool,
    cmd_forward: bool,
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_certs: Option<String>,
    flag_key: Option<String>,
    flag_ocsp: Option<String>,
    flag_auth: Option<String>,
    flag_require_auth: bool,
    flag_resumption: bool,
    flag_tickets: bool,
    arg_fport: Option<u16>,
}

fn find_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    for suite in rustls::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(*suite);
        }
    }

    None
}

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

fn load_ocsp(filename: &Option<String>) -> Vec<u8> {
    let mut ret = Vec::new();

    if let &Some(ref name) = filename {
        fs::File::open(name)
            .expect("cannot open ocsp file")
            .read_to_end(&mut ret)
            .unwrap();
    }

    ret
}

fn make_config(args: &Args) -> Arc<rustls::ServerConfig> {
    let client_auth = if args.flag_auth.is_some() {
        let roots = load_certs(args.flag_auth.as_ref().unwrap());
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(&root).unwrap();
        }
        if args.flag_require_auth {
            AllowAnyAuthenticatedClient::new(client_auth_roots)
        } else {
            AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
        }
    } else {
        NoClientAuth::new()
    };

    let suites = if !args.flag_suite.is_empty() {
        lookup_suites(&args.flag_suite)
    } else {
        rustls::ALL_CIPHER_SUITES.to_vec()
    };

    let versions = if !args.flag_protover.is_empty() {
        lookup_versions(&args.flag_protover)
    } else {
        rustls::ALL_VERSIONS.to_vec()
    };

    let certs = load_certs(
        args.flag_certs
            .as_ref()
            .expect("--certs option missing"),
    );
    let privkey = load_private_key(
        args.flag_key
            .as_ref()
            .expect("--key option missing"),
    );
    let ocsp = load_ocsp(&args.flag_ocsp);

    let mut config = rustls::ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(certs, privkey, ocsp, vec![])
        .expect("bad certificates/private key");

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if args.flag_resumption {
        config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
    }

    if args.flag_tickets {
        config.ticketer = rustls::Ticketer::new().unwrap();
    }

    config.alpn_protocols = args
        .flag_proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect::<Vec<_>>();

    Arc::new(config)
}

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

    let mut addr: net::SocketAddr = "0.0.0.0:443".parse().unwrap();
    addr.set_port(args.flag_port.unwrap_or(443));

    let config = make_config(&args);

    let mut listener = TcpListener::bind(addr).expect("cannot listen on port");
    let mut poll = mio::Poll::new().unwrap();
    poll.registry()
        .register(&mut listener, LISTENER, mio::Interest::READABLE)
        .unwrap();

    let mode = if args.cmd_echo {
        ServerMode::Echo
    } else if args.cmd_http {
        ServerMode::Http
    } else {
        ServerMode::Forward(args.arg_fport.expect("fport required"))
    };

    let mut tlsserv = TlsServer::new(listener, mode, config);

    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    tlsserv
                        .accept(poll.registry())
                        .expect("error accepting socket");
                }
                _ => tlsserv.conn_event(poll.registry(), &event),
            }
        }
    }
}
