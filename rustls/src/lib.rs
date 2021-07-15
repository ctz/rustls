//! # Rustls - a modern TLS library
//! Rustls is a TLS library that aims to provide a good level of cryptographic security,
//! requires no configuration to achieve that security, and provides no unsafe features or
//! obsolete cryptography.
//!
//! ## Current features
//!
//! * TLS1.2 and TLS1.3.
//! * ECDSA, Ed25519 or RSA server authentication by clients.
//! * ECDSA, Ed25519 or RSA server authentication by servers.
//! * Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
//! * AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
//! * ChaCha20-Poly1305 bulk encryption ([RFC7905](https://tools.ietf.org/html/rfc7905)).
//! * ALPN support.
//! * SNI support.
//! * Tunable fragment size to make TLS messages match size of underlying transport.
//! * Optional use of vectored IO to minimise system calls.
//! * TLS1.2 session resumption.
//! * TLS1.2 resumption via tickets ([RFC5077](https://tools.ietf.org/html/rfc5077)).
//! * TLS1.3 resumption via tickets or session storage.
//! * TLS1.3 0-RTT data for clients.
//! * Client authentication by clients.
//! * Client authentication by servers.
//! * Extended master secret support ([RFC7627](https://tools.ietf.org/html/rfc7627)).
//! * Exporters ([RFC5705](https://tools.ietf.org/html/rfc5705)).
//! * OCSP stapling by servers.
//! * SCT stapling by servers.
//! * SCT verification by clients.
//!
//! ## Possible future features
//!
//! * PSK support.
//! * OCSP verification by clients.
//! * Certificate pinning.
//!
//! ## Non-features
//!
//! The following things are broken, obsolete, badly designed, underspecified,
//! dangerous and/or insane. Rustls does not support:
//!
//! * SSL1, SSL2, SSL3, TLS1 or TLS1.1.
//! * RC4.
//! * DES or triple DES.
//! * EXPORT ciphersuites.
//! * MAC-then-encrypt ciphersuites.
//! * Ciphersuites without forward secrecy.
//! * Renegotiation.
//! * Kerberos.
//! * Compression.
//! * Discrete-log Diffie-Hellman.
//! * Automatic protocol version downgrade.
//! * AES-GCM with unsafe nonces.
//!
//! There are plenty of other libraries that provide these features should you
//! need them.
//!
//! ### Platform support
//!
//! Rustls uses [`ring`](https://crates.io/crates/ring) for implementing the
//! cryptography in TLS. As a result, rustls only runs on platforms
//! [supported by `ring`](https://github.com/briansmith/ring#online-automated-testing).
//! At the time of writing this means x86, x86-64, armv7, and aarch64.
//!
//! ## Design Overview
//! ### Rustls does not take care of network IO
//! It doesn't make or accept TCP connections, or do DNS, or read or write files.
//!
//! There's example client and server code which uses mio to do all needed network
//! IO.
//!
//! ### Rustls provides encrypted pipes
//! These are the [`ServerConnection`] and [`ClientConnection`] types.  You supply raw TLS traffic
//! on the left (via the [`read_tls()`] and [`write_tls()`] methods) and then read/write the
//! plaintext on the right:
//!
//! [`read_tls()`]: Connection::read_tls
//! [`write_tls()`]: Connection::read_tls
//!
//! ```text
//!          TLS                                   Plaintext
//!          ===                                   =========
//!     read_tls()      +-----------------------+      reader() as io::Read
//!                     |                       |
//!           +--------->   ClientConnection    +--------->
//!                     |          or           |
//!           <---------+   ServerConnection    <---------+
//!                     |                       |
//!     write_tls()     +-----------------------+      writer() as io::Write
//! ```
//!
//! ### Rustls takes care of server certificate verification
//! You do not need to provide anything other than a set of root certificates to trust.
//! Certificate verification cannot be turned off or disabled in the main API.
//!
//! ## Getting started
//! This is the minimum you need to do to make a TLS client connection.
//!
//! First we load some root certificates.  These are used to authenticate the server.
//! The recommended way is to depend on the `webpki_roots` crate which contains
//! the Mozilla set of root certificates.
//!
//! ```rust,ignore
//! let mut root_store = rustls::RootCertStore::empty();
//! root_store.add_server_trust_anchors(
//!     webpki_roots::TLS_SERVER_ROOTS
//!         .0
//!         .iter()
//!         .map(|ta| {
//!             rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
//!                 ta.subject,
//!                 ta.spki,
//!                 ta.name_constraints,
//!             )
//!         })
//! );
//! let trusted_ct_logs = &[];
//! ```
//!
//! Next, we make a `ClientConfig`.  You're likely to make one of these per process,
//! and use it for all connections made by that process.
//!
//! ```rust,ignore
//! let config = rustls::ClientConfig::builder()
//!     .with_safe_defaults()
//!     .with_root_certificates(root_store, trusted_ct_logs)
//!     .with_no_client_auth();
//! ```
//!
//! Now we can make a connection.  You need to provide the server's hostname so we
//! know what to expect to find in the server's certificate.
//!
//! ```
//! # use rustls;
//! # use webpki;
//! # use std::sync::Arc;
//! # use std::convert::TryInto;
//! # let mut root_store = rustls::RootCertStore::empty();
//! # root_store.add_server_trust_anchors(
//! #  webpki_roots::TLS_SERVER_ROOTS
//! #      .0
//! #      .iter()
//! #      .map(|ta| {
//! #          rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
//! #              ta.subject,
//! #              ta.spki,
//! #              ta.name_constraints,
//! #          )
//! #      })
//! # );
//! # let trusted_ct_logs = &[];
//! # let config = rustls::ClientConfig::builder()
//! #     .with_safe_defaults()
//! #     .with_root_certificates(root_store, trusted_ct_logs)
//! #     .with_no_client_auth();
//! let rc_config = Arc::new(config);
//! let example_com = "example.com".try_into().unwrap();
//! let mut client = rustls::ClientConnection::new(rc_config, example_com);
//! ```
//!
//! Now you should do appropriate IO for the `client` object.  If `client.wants_read()` yields
//! true, you should call `client.read_tls()` when the underlying connection has data.
//! Likewise, if `client.wants_write()` yields true, you should call `client.write_tls()`
//! when the underlying connection is able to send data.  You should continue doing this
//! as long as the connection is valid.
//!
//! The return types of `read_tls()` and `write_tls()` only tell you if the IO worked.  No
//! parsing or processing of the TLS messages is done.  After each `read_tls()` you should
//! therefore call `client.process_new_packets()` which parses and processes the messages.
//! Any error returned from `process_new_packets` is fatal to the connection, and will tell you
//! why.  For example, if the server's certificate is expired `process_new_packets` will
//! return `Err(WebPkiError(CertExpired, ValidateServerCert))`.  From this point on,
//! `process_new_packets` will not do any new work and will return that error continually.
//!
//! You can extract newly received data by calling `client.reader()` (which implements the
//! `io::Read` trait).  You can send data to the peer by calling `client.writer()` (which
//! implements `io::Write` trait).  Note that `client.writer().write()` buffers data you
//! send if the TLS connection is not yet established: this is useful for writing (say) a
//! HTTP request, but this is buffered so avoid large amounts of data.
//!
//! The following code uses a fictional socket IO API for illustration, and does not handle
//! errors.
//!
//! ```text
//! use std::io;
//!
//! client.writer().write(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut socket = connect("example.com", 443);
//! loop {
//!   if client.wants_read() && socket.ready_for_read() {
//!     client.read_tls(&mut socket).unwrap();
//!     client.process_new_packets().unwrap();
//!
//!     let mut plaintext = Vec::new();
//!     client.reader().read_to_end(&mut plaintext).unwrap();
//!     io::stdout().write(&plaintext).unwrap();
//!   }
//!
//!   if client.wants_write() && socket.ready_for_write() {
//!     client.write_tls(&mut socket).unwrap();
//!   }
//!
//!   socket.wait_for_something_to_happen();
//! }
//! ```
//!
//! # Examples
//! `tlsserver` and `tlsclient` are full worked examples.  These both use mio.
//!
//! # Crate features
//! Here's a list of what features are exposed by the rustls crate and what
//! they mean.
//!
//! - `logging`: this makes the rustls crate depend on the `log` crate.
//!   rustls outputs interesting protocol-level messages at `trace!` and `debug!`
//!   level, and protocol-level errors at `warn!` and `error!` level.  The log
//!   messages do not contain secret key data, and so are safe to archive without
//!   affecting session security.  This feature is in the default set.
//!
//! - `dangerous_configuration`: this feature enables a `dangerous()` method on
//!   `ClientConfig` and `ServerConfig` that allows setting inadvisable options,
//!   such as replacing the certificate verification process.  Applications
//!   requesting this feature should be reviewed carefully.
//!
//! - `quic`: this feature exposes additional constructors and functions
//!   for using rustls as a TLS library for QUIC.  See the `quic` module for
//!   details of these.  You will only need this if you're writing a QUIC
//!   implementation.
//!

// Require docs for public APIs, deny unsafe code, etc.
#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    clippy::clone_on_ref_ptr,
    clippy::use_self,
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]
// Relax these clippy lints:
// - ptr_arg: this triggers on references to type aliases that are Vec
//   underneath.
// - too_many_arguments: some things just need a lot of state, wrapping it
//   doesn't necessarily make it easier to follow what's going on
// - new_ret_no_self: we sometimes return `Arc<Self>`, which seems fine
// - single_component_path_imports: our top-level `use log` import causes
//   a false positive, https://github.com/rust-lang/rust-clippy/issues/5210
// - new_without_default: for internal constructors, the indirection is not
//   helpful
#![allow(
    clippy::too_many_arguments,
    clippy::new_ret_no_self,
    clippy::ptr_arg,
    clippy::single_component_path_imports,
    clippy::new_without_default
)]
// Enable documentation for all features on docs.rs
#![cfg_attr(docsrs, feature(doc_cfg))]

// log for logging (optional).
#[cfg(feature = "logging")]
use log;

#[cfg(not(feature = "logging"))]
#[macro_use]
mod log {
    macro_rules! trace    ( ($($tt:tt)*) => {{}} );
    macro_rules! debug    ( ($($tt:tt)*) => {{}} );
    macro_rules! warn     ( ($($tt:tt)*) => {{}} );
    macro_rules! error    ( ($($tt:tt)*) => {{}} );
}

#[allow(missing_docs)]
#[macro_use]
mod msgs;
mod anchors;
mod cipher;
mod conn;
mod error;
mod hash_hs;
mod key_schedule;
mod limited_cache;
mod prf;
mod rand;
mod record_layer;
mod stream;
mod tls12;
mod vecbuf;
mod verify;
#[cfg(test)]
mod verifybench;
mod x509;
#[macro_use]
mod check;
mod bs_debug;
mod builder;
mod client;
mod key;
mod keylog;
mod kx;
mod server;
mod suites;
mod ticketer;
mod versions;

/// Internal classes which may be useful outside the library.
/// The contents of this section DO NOT form part of the stable interface.
pub mod internal {
    /// Low-level TLS message parsing and encoding functions.
    pub mod msgs {
        pub use crate::msgs::*;
    }
}

// The public interface is:
pub use crate::anchors::{OwnedTrustAnchor, RootCertStore};
pub use crate::builder::{
    ConfigBuilder, ConfigSide, WantsCipherSuites, WantsKxGroups, WantsVerifier, WantsVersions,
};
pub use crate::client::builder::WantsClientCert;
pub use crate::client::handy::{ClientSessionMemoryCache, NoClientSessionStorage};
pub use crate::client::ResolvesClientCert;
pub use crate::client::ServerName;
pub use crate::client::StoresClientSessions;
pub use crate::client::{ClientConfig, ClientConnection, WriteEarlyData};
pub use crate::conn::{
    CommonState, Connection, ConnectionCommon, IoState, Reader, SideData, Writer,
};
pub use crate::error::Error;
pub use crate::error::WebPkiError;
pub use crate::error::WebPkiOp;
pub use crate::key::{Certificate, PrivateKey};
pub use crate::keylog::{KeyLog, KeyLogFile, NoKeyLog};
pub use crate::kx::{SupportedKxGroup, ALL_KX_GROUPS};
pub use crate::msgs::enums::CipherSuite;
pub use crate::msgs::enums::ProtocolVersion;
pub use crate::msgs::enums::SignatureScheme;
pub use crate::msgs::handshake::DistinguishedNames;
pub use crate::server::builder::WantsServerCert;
pub use crate::server::handy::ResolvesServerCertUsingSni;
pub use crate::server::handy::{NoServerSessionStorage, ServerSessionMemoryCache};
pub use crate::server::StoresServerSessions;
pub use crate::server::{ClientHello, ProducesTickets, ResolvesServerCert};
pub use crate::server::{ServerConfig, ServerConnection, ServerConnectionData};
pub use crate::stream::{Stream, StreamOwned};
pub use crate::suites::{
    BulkAlgorithm, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite, ALL_CIPHER_SUITES,
    DEFAULT_CIPHER_SUITES,
};
pub use crate::ticketer::Ticketer;
pub use crate::verify::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
};
pub use crate::versions::{SupportedProtocolVersion, ALL_VERSIONS, DEFAULT_VERSIONS};

/// All defined ciphersuites appear in this module.
///
/// [`ALL_CIPHER_SUITES`] is provided as an array of all of these values.
pub mod cipher_suite {
    pub use crate::suites::TLS13_AES_128_GCM_SHA256;
    pub use crate::suites::TLS13_AES_256_GCM_SHA384;
    pub use crate::suites::TLS13_CHACHA20_POLY1305_SHA256;
    pub use crate::suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    pub use crate::suites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    pub use crate::suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    pub use crate::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    pub use crate::suites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    pub use crate::suites::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
}

/// All defined protocol versions appear in this module.
///
/// ALL_VERSIONS is a provided as an array of all of these values.
pub mod version {
    pub use crate::versions::TLS12;
    pub use crate::versions::TLS13;
}

/// All defined key exchange groups appear in this module.
///
/// ALL_KX_GROUPS is provided as an array of all of these values.
pub mod kx_group {
    pub use crate::kx::SECP256R1;
    pub use crate::kx::SECP384R1;
    pub use crate::kx::X25519;
}

/// Message signing interfaces and implementations.
pub mod sign;

#[cfg(feature = "quic")]
#[cfg_attr(docsrs, doc(cfg(feature = "quic")))]
/// APIs for implementing QUIC TLS
pub mod quic;

#[cfg(feature = "dangerous_configuration")]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub use crate::client::danger::DangerousClientConfig;
#[cfg(feature = "dangerous_configuration")]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub use crate::verify::{
    ClientCertVerified, ClientCertVerifier, DnsName, HandshakeSignatureValid, ServerCertVerified,
    ServerCertVerifier, WebPkiVerifier,
};

/// This is the rustls manual.
pub mod manual;

/** Type renames. */
#[allow(clippy::upper_case_acronyms)]
#[doc(hidden)]
#[deprecated(since = "0.20.0", note = "Use ResolvesServerCertUsingSni")]
pub type ResolvesServerCertUsingSNI = ResolvesServerCertUsingSni;
#[allow(clippy::upper_case_acronyms)]
#[cfg(feature = "dangerous_configuration")]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
#[doc(hidden)]
#[deprecated(since = "0.20.0", note = "Use WebPkiVerifier")]
pub type WebPKIVerifier = WebPkiVerifier;
#[allow(clippy::upper_case_acronyms)]
#[doc(hidden)]
#[deprecated(since = "0.20.0", note = "Use TlsError")]
pub type TLSError = Error;
#[doc(hidden)]
#[deprecated(since = "0.20.0", note = "Use ClientConnection")]
pub type ClientSession = ClientConnection;
#[doc(hidden)]
#[deprecated(since = "0.20.0", note = "Use ServerConnection")]
pub type ServerSession = ServerConnection;

/* Apologies: would make a trait alias here, but those remain unstable.
pub trait Session = Connection;
*/
