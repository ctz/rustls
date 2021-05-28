use crate::conn::{Connection, ConnectionCommon, IoState, PlaintextSink, Protocol, Reader, Writer};
use crate::error::Error;
use crate::key;
use crate::keylog::KeyLog;
use crate::kx::SupportedKxGroup;
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::ech::EncryptedClientHello;
#[cfg(feature = "quic")]
use crate::msgs::enums::AlertDescription;
use crate::msgs::enums::CipherSuite;
use crate::msgs::enums::ProtocolVersion;
use crate::msgs::enums::SignatureScheme;
use crate::msgs::handshake::{CertificatePayload, ClientExtension};
use crate::sign;
use crate::suites::SupportedCipherSuite;
use crate::verify;
use crate::versions;

#[cfg(feature = "quic")]
use crate::quic;

use std::fmt;
use std::io::{self, IoSlice};
use std::mem;
use std::sync::Arc;
use webpki;

#[macro_use]
mod hs;
pub mod builder;
mod common;
pub mod handy;
mod tls12;
mod tls13;

/// A trait for the ability to store client session data.
/// The keys and values are opaque.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding session.
///
/// `put` is a mutating operation; this isn't expressed
/// in the type system to allow implementations freedom in
/// how to achieve interior mutability.  `Mutex` is a common
/// choice.
pub trait StoresClientSessions: Send + Sync {
    /// Stores a new `value` for `key`.  Returns `true`
    /// if the value was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Returns the latest value for `key`.  Returns `None`
    /// if there's no such value.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// A trait for the ability to choose a certificate chain and
/// private key for the purposes of client authentication.
pub trait ResolvesClientCert: Send + Sync {
    /// With the server-supplied acceptable issuers in `acceptable_issuers`,
    /// the server's supported signature schemes in `sigschemes`,
    /// return a certificate chain and signing key to authenticate.
    ///
    /// `acceptable_issuers` is undecoded and unverified by the rustls
    /// library, but it should be expected to contain a DER encodings
    /// of X501 NAMEs.
    ///
    /// Return None to continue the handshake without any client
    /// authentication.  The server may reject the handshake later
    /// if it requires authentication.
    fn resolve(
        &self,
        acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>>;

    /// Return true if any certificates at all are available.
    fn has_certs(&self) -> bool;
}

/// Common configuration for (typically) all connections made by
/// a program.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
#[derive(Clone)]
pub struct ClientConfig {
    /// List of ciphersuites, in preference order.
    pub cipher_suites: Vec<&'static SupportedCipherSuite>,

    /// List of supported key exchange algorithms, in preference order -- the
    /// first element is the highest priority.
    ///
    /// The first element in this list is the _default key share algorithm_,
    /// and in TLS1.3 a key share for it is sent in the client hello.
    pub kx_groups: Vec<&'static SupportedKxGroup>,

    /// Which ALPN protocols we include in our client hello.
    /// If empty, no ALPN extension is sent.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// How we store session data or tickets.
    pub session_storage: Arc<dyn StoresClientSessions>,

    /// The maximum size of TLS message we'll emit.  If None, we don't limit TLS
    /// message lengths except to the 2**16 limit specified in the standard.
    ///
    /// rustls enforces an arbitrary minimum of 32 bytes for this field.
    /// Out of range values are reported as errors from ClientConnection::new.
    ///
    /// Setting this value to the TCP MSS may improve latency for stream-y workloads.
    pub max_fragment_size: Option<usize>,

    /// How to decide what client auth certificate/keys to use.
    pub client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,

    /// Whether to support RFC5077 tickets.  You must provide a working
    /// `session_storage` member for this to have any meaningful
    /// effect.
    ///
    /// The default is true.
    pub enable_tickets: bool,

    /// Supported versions, in no particular order.  The default
    /// is all supported versions.
    pub versions: versions::EnabledVersions,

    /// Whether to send the Server Name Indication (SNI) extension
    /// during the client handshake.
    ///
    /// The default is true.
    pub enable_sni: bool,

    /// How to verify the server certificate chain.
    verifier: Arc<dyn verify::ServerCertVerifier>,

    /// How to output key material for debugging.  The default
    /// does nothing.
    pub key_log: Arc<dyn KeyLog>,

    /// Whether to send data on the first flight ("early data") in
    /// TLS 1.3 handshakes.
    ///
    /// The default is false.
    pub enable_early_data: bool,
}

impl ClientConfig {
    #[doc(hidden)]
    /// We support a given TLS version if it's quoted in the configured
    /// versions *and* at least one ciphersuite for this version is
    /// also configured.
    pub fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.versions.contains(v)
            && self
                .cipher_suites
                .iter()
                .any(|cs| cs.usable_for_version(v))
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    #[cfg(feature = "dangerous_configuration")]
    pub fn dangerous(&mut self) -> danger::DangerousClientConfig {
        danger::DangerousClientConfig { cfg: self }
    }

    fn find_cipher_suite(&self, suite: CipherSuite) -> Option<&'static SupportedCipherSuite> {
        self.cipher_suites
            .iter()
            .copied()
            .find(|&scs| scs.suite == suite)
    }
}

/// Container for unsafe APIs
#[cfg(feature = "dangerous_configuration")]
pub mod danger {
    use std::sync::Arc;

    use super::verify::ServerCertVerifier;
    use super::ClientConfig;

    /// Accessor for dangerous configuration options.
    pub struct DangerousClientConfig<'a> {
        /// The underlying ClientConfig
        pub cfg: &'a mut ClientConfig,
    }

    impl<'a> DangerousClientConfig<'a> {
        /// Overrides the default `ServerCertVerifier` with something else.
        pub fn set_certificate_verifier(&mut self, verifier: Arc<dyn ServerCertVerifier>) {
            self.cfg.verifier = verifier;
        }
    }
}

#[derive(Debug, PartialEq)]
enum EarlyDataState {
    Disabled,
    Ready,
    Accepted,
    AcceptedFinished,
    Rejected,
}

pub struct EarlyData {
    state: EarlyDataState,
    left: usize,
}

impl EarlyData {
    fn new() -> EarlyData {
        EarlyData {
            left: 0,
            state: EarlyDataState::Disabled,
        }
    }

    fn is_enabled(&self) -> bool {
        matches!(self.state, EarlyDataState::Ready | EarlyDataState::Accepted)
    }

    fn is_accepted(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Accepted | EarlyDataState::AcceptedFinished
        )
    }

    fn enable(&mut self, max_data: usize) {
        assert_eq!(self.state, EarlyDataState::Disabled);
        self.state = EarlyDataState::Ready;
        self.left = max_data;
    }

    fn rejected(&mut self) {
        trace!("EarlyData rejected");
        self.state = EarlyDataState::Rejected;
    }

    fn accepted(&mut self) {
        trace!("EarlyData accepted");
        assert_eq!(self.state, EarlyDataState::Ready);
        self.state = EarlyDataState::Accepted;
    }

    fn finished(&mut self) {
        trace!("EarlyData finished");
        self.state = match self.state {
            EarlyDataState::Accepted => EarlyDataState::AcceptedFinished,
            _ => panic!("bad EarlyData state"),
        }
    }

    fn check_write(&mut self, sz: usize) -> io::Result<usize> {
        match self.state {
            EarlyDataState::Disabled => unreachable!(),
            EarlyDataState::Ready | EarlyDataState::Accepted => {
                let take = if self.left < sz {
                    mem::replace(&mut self.left, 0)
                } else {
                    self.left -= sz;
                    sz
                };

                Ok(take)
            }
            EarlyDataState::Rejected | EarlyDataState::AcceptedFinished => {
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            }
        }
    }

    fn bytes_left(&self) -> usize {
        self.left
    }
}

/// Stub that implements io::Write and dispatches to `write_early_data`.
pub struct WriteEarlyData<'a> {
    sess: &'a mut ClientConnection,
}

impl<'a> WriteEarlyData<'a> {
    fn new(sess: &'a mut ClientConnection) -> WriteEarlyData<'a> {
        WriteEarlyData { sess }
    }

    /// How many bytes you may send.  Writes will become short
    /// once this reaches zero.
    pub fn bytes_left(&self) -> usize {
        self.sess.data.early_data.bytes_left()
    }
}

impl<'a> io::Write for WriteEarlyData<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sess.write_early_data(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Ways to identify the server the client is connecting to.
pub enum ServerIdentity {
    /// Using a DNS name
    Hostname(webpki::DnsName),
    /// Using an EncryptedClientHello (Inner and Outer DNS names)
    EncryptedClientHello(Box<EncryptedClientHello>),
}

impl ServerIdentity {
    fn get_outer_hostname(&self) -> webpki::DnsNameRef {
        match self {
            ServerIdentity::Hostname(name) => name.as_ref(),
            ServerIdentity::EncryptedClientHello(encrypted) => encrypted
                .config_contents
                .public_name
                .as_ref(),
        }
    }

    fn get_inner_hostname(&self) -> webpki::DnsNameRef {
        match self {
            ServerIdentity::Hostname(name) => name.as_ref(),
            ServerIdentity::EncryptedClientHello(encrypted) => encrypted.hostname.as_ref(),
        }
    }
}

/// This represents a single TLS client connection.
pub struct ClientConnection {
    common: ConnectionCommon,
    state: Option<hs::NextState>,
    data: ClientConnectionData,
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClientConnection")
            .finish()
    }
}

impl ClientConnection {
    /// Make a new ClientConnection.  `config` controls how
    /// we behave in the TLS protocol, `hostname` is the
    /// hostname of who we want to talk to.
    pub fn new(
        config: Arc<ClientConfig>,
        dns_name: webpki::DnsNameRef,
    ) -> Result<ClientConnection, Error> {
        Self::with_server_id(config, ServerIdentity::Hostname(dns_name.to_owned()))
    }

    /// Make a new ClientConnection.  `config` controls how
    /// we behave in the TLS protocol, `hello` configures the host we want to talk to.
    pub fn with_server_id(
        config: Arc<ClientConfig>,
        server_id: ServerIdentity,
    ) -> Result<ClientConnection, Error> {
        Self::new_inner(config, server_id, Vec::new(), Protocol::Tcp)
    }

    fn new_inner(
        config: Arc<ClientConfig>,
        server_id: ServerIdentity,
        extra_exts: Vec<ClientExtension>,
        proto: Protocol,
    ) -> Result<Self, Error> {
        if let ServerIdentity::EncryptedClientHello(_h) = &server_id {
            if !config.supports_version(ProtocolVersion::TLSv1_3) {
                return Err(Error::General("TLS 1.3 support is required for ECH".into()));
            }
        }

        let mut new = ClientConnection {
            common: ConnectionCommon::new(config.max_fragment_size, true)?,
            state: None,
            data: ClientConnectionData::new(),
        };
        new.common.protocol = proto;

        let mut cx = hs::ClientContext {
            common: &mut new.common,
            data: &mut new.data,
        };

        new.state = Some(hs::start_handshake(server_id, extra_exts, config, &mut cx)?);
        Ok(new)
    }

    /// Returns an `io::Write` implementer you can write bytes to
    /// to send TLS1.3 early data (a.k.a. "0-RTT data") to the server.
    ///
    /// This returns None in many circumstances when the capability to
    /// send early data is not available, including but not limited to:
    ///
    /// - The server hasn't been talked to previously.
    /// - The server does not support resumption.
    /// - The server does not support early data.
    /// - The resumption data for the server has expired.
    ///
    /// The server specifies a maximum amount of early data.  You can
    /// learn this limit through the returned object, and writes through
    /// it will process only this many bytes.
    ///
    /// The server can choose not to accept any sent early data --
    /// in this case the data is lost but the connection continues.  You
    /// can tell this happened using `is_early_data_accepted`.
    pub fn early_data(&mut self) -> Option<WriteEarlyData> {
        if self.data.early_data.is_enabled() {
            Some(WriteEarlyData::new(self))
        } else {
            None
        }
    }

    /// Returns True if the server signalled it will process early data.
    ///
    /// If you sent early data and this returns false at the end of the
    /// handshake then the server will not process the data.  This
    /// is not an error, but you may wish to resend the data.
    pub fn is_early_data_accepted(&self) -> bool {
        self.data.early_data.is_accepted()
    }

    fn write_early_data(&mut self, data: &[u8]) -> io::Result<usize> {
        self.data
            .early_data
            .check_write(data.len())
            .map(|sz| {
                self.common
                    .send_early_plaintext(&data[..sz])
            })
    }

    fn send_some_plaintext(&mut self, buf: &[u8]) -> usize {
        let mut st = self.state.take();
        if let Some(st) = st.as_mut() {
            st.perhaps_write_key_update(&mut self.common);
        }
        self.state = st;

        self.common.send_some_plaintext(buf)
    }
}

impl Connection for ClientConnection {
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        self.common.read_tls(rd)
    }

    /// Writes TLS messages to `wr`.
    fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        self.common.write_tls(wr)
    }

    fn process_new_packets(&mut self) -> Result<IoState, Error> {
        self.common
            .process_new_packets(&mut self.state, &mut self.data)
    }

    fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we
        // have unprocessed plaintext.  This provides back-pressure
        // to the TCP buffers.
        //
        // This also covers the handshake case, because we don't have
        // readable plaintext before handshake has completed.
        !self.common.has_readable_plaintext()
    }

    fn wants_write(&self) -> bool {
        !self.common.sendable_tls.is_empty()
    }

    fn is_handshaking(&self) -> bool {
        !self.common.traffic
    }

    fn set_buffer_limit(&mut self, len: usize) {
        self.common.set_buffer_limit(len)
    }

    fn send_close_notify(&mut self) {
        self.common.send_close_notify()
    }

    fn peer_certificates(&self) -> Option<&[key::Certificate]> {
        if self.data.server_cert_chain.is_empty() {
            return None;
        }

        Some(&self.data.server_cert_chain)
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        self.common.get_alpn_protocol()
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.common.negotiated_version
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.state
            .as_ref()
            .ok_or(Error::HandshakeNotComplete)
            .and_then(|st| st.export_keying_material(output, label, context))
    }

    fn negotiated_cipher_suite(&self) -> Option<&'static SupportedCipherSuite> {
        self.common
            .get_suite()
            .or(self.data.resumption_ciphersuite)
    }

    fn writer(&mut self) -> Writer {
        Writer::new(self)
    }

    fn reader(&mut self) -> Reader {
        self.common.reader()
    }
}

impl PlaintextSink for ClientConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(self.send_some_plaintext(buf))
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut sz = 0;
        for buf in bufs {
            sz += self.send_some_plaintext(buf);
        }
        Ok(sz)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ClientConnectionData {
    server_cert_chain: CertificatePayload,
    early_data: EarlyData,
    resumption_ciphersuite: Option<&'static SupportedCipherSuite>,
}

impl ClientConnectionData {
    fn new() -> Self {
        Self {
            server_cert_chain: Vec::new(),
            early_data: EarlyData::new(),
            resumption_ciphersuite: None,
        }
    }
}

#[cfg(feature = "quic")]
impl quic::QuicExt for ClientConnection {
    fn quic_transport_parameters(&self) -> Option<&[u8]> {
        self.common
            .quic
            .params
            .as_ref()
            .map(|v| v.as_ref())
    }

    fn zero_rtt_keys(&self) -> Option<quic::DirectionalKeys> {
        Some(quic::DirectionalKeys::new(
            self.data.resumption_ciphersuite?,
            self.common.quic.early_secret.as_ref()?,
        ))
    }

    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        quic::read_hs(&mut self.common, plaintext)?;
        self.common
            .process_new_handshake_messages(&mut self.state, &mut self.data)
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<quic::Keys> {
        quic::write_hs(&mut self.common, buf)
    }

    fn alert(&self) -> Option<AlertDescription> {
        self.common.quic.alert
    }

    fn next_1rtt_keys(&mut self) -> Option<quic::PacketKeySet> {
        quic::next_1rtt_keys(&mut self.common)
    }
}

/// Methods specific to QUIC client sessions
#[cfg(feature = "quic")]
pub trait ClientQuicExt {
    /// Make a new QUIC ClientConnection. This differs from `ClientConnection::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(
        config: Arc<ClientConfig>,
        quic_version: quic::Version,
        hostname: webpki::DnsNameRef,
        params: Vec<u8>,
    ) -> Result<ClientConnection, Error> {
        Self::quic_with_server_id(
            config,
            quic_version,
            ServerIdentity::Hostname(hostname.to_owned()),
            params,
        )
    }

    /// Make a new QUIC ClientConnection. This differs from `ClientConnection::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn quic_with_server_id(
        config: Arc<ClientConfig>,
        quic_version: quic::Version,
        server_id: ServerIdentity,
        params: Vec<u8>,
    ) -> Result<ClientConnection, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for QUIC".into(),
            ));
        }

        let ext = match quic_version {
            quic::Version::V1Draft => ClientExtension::TransportParametersDraft(params),
            quic::Version::V1 => ClientExtension::TransportParameters(params),
        };

        ClientConnection::new_inner(config, server_id, vec![ext], Protocol::Quic)
    }
}

#[cfg(feature = "quic")]
impl ClientQuicExt for ClientConnection {}
