<p align="center">
  <img width="460" height="300" src="https://raw.githubusercontent.com/ctz/rustls/main/admin/rustls-logo-web.png">
</p>

<p align="center">
Rustls is a modern TLS library written in Rust.  It uses <a href = "https://github.com/briansmith/ring"><em>ring</em></a> for cryptography and <a href = "https://github.com/briansmith/webpki">libwebpki</a> for certificate
verification.
</p>

# Status
Rustls is ready for use.  There are no major breaking interface changes
envisioned after the set included in the 0.20 release.

If you'd like to help out, please see [CONTRIBUTING.md](CONTRIBUTING.md).

[![Build Status](https://github.com/ctz/rustls/workflows/rustls/badge.svg)](https://github.com/ctz/rustls/actions)
[![Coverage Status (codecov.io)](https://codecov.io/gh/ctz/rustls/branch/main/graph/badge.svg)](https://codecov.io/gh/ctz/rustls/)
[![Documentation](https://docs.rs/rustls/badge.svg)](https://docs.rs/rustls/)

## Release history:

* Next release:
  - Planned: removal of unused signature verification schemes at link-time.
* 0.20.0-beta2 (2021-07-04)
  - *Breaking change*: internal buffers are now limited to 64 kB by default. Use
    `Connection::set_buffer_limit` to change the buffer limits to suit your application.
  - *Breaking API change*: PEM parsing now lives in the [rustls-pemfile crate](https://crates.io/crates/rustls-pemfile).
    This means `rustls::internals::pemfile` and `rustls::RootCertStore::add_pem_file` no longer exist.
  - *Breaking API change*: `ServerCertVerifier::verify_server_cert` and `ClientCertVerifier::verify_client_cert`
    pass the end-entity and intermediate certificates separately.  This means rustls deals with the case
    where the certificate chain is empty, rather than leaving that to ServerCertVerifier/ClientCertVerifier
    implementation.
  - *Breaking API change*: `SupportedCipherSuite` is now an enum with TLS 1.2 and TLS 1.3 variants. Some of its
    methods have moved to the inner `Tls12CipherSuite` and `Tls13CipherSuite` types. Instead of
    `usable_for_version()`, it now has a `version()` method. `get_hash()` has been renamed
    to `hash_algorithm()` and `usable_for_sigalg()` to `usable_for_signature_algorithm()`.
  - There are now 80% fewer unreachable unwraps in the core crate thanks to large refactoring efforts.
  - *Breaking API change*: the `WebPkiError` variant of `rustls::Error` now includes which operation failed.
  - *Breaking API changes*: These public API items have been renamed to meet naming guidelines:
    - `rustls::TLSError` to `rustls::Error`.
    - `rustls::ResolvesServerCertUsingSNI` to `rustls::ResolvesServerCertUsingSni`.
    - `rustls::WebPKIVerifier` to `rustls::WebPkiVerifier`.
    - `rustls::ciphersuites` to `rustls::cipher_suites`.
    - `rustls::ALL_CIPHERSUITES` to `ALL_CIPHER_SUITES`; `rustls::DEFAULT_CIPHERSUITES` to `DEFAULT_CIPHER_SUITES`.
    - `rustls::ClientHello::sigschemes` to `rustls::ClientHello::signature_schemes`.
    - `rustls::RootCertStore::get_subjects` to `rustls::RootCertStore::subjects`.
    - `rustls::ServerSession` to `rustls::ServerConnection`.
    - `rustls::ClientSession` to `rustls::ClientConnection`.
    - `rustls::ServerSession::get_sni_hostname` to `rustls::ServerConnection::sni_hostname`.
    - `rustls::ClientConfig::ciphersuites` to `rustls::ClientConfig::cipher_suites`.
    - `rustls::ServerConfig::ciphersuites` to `rustls::ServerConfig::cipher_suites`.
    - `rustls::ProducesTickets::get_lifetime` to `rustls::ProducesTickets::lifetime`.
    - `rustls::Session`: `get_peer_certificates` to `peer_certificates`, `get_alpn_protocol` to `alpn_protocol`,
      `get_protocol_version` to `protocol_version`, `get_negotiated_ciphersuite` to `negotiated_cipher_suite`.
  - *Breaking API change*: `ResolvesServerCert::resolve` and `ResolvesClientCert::resolve` now return
    `Option<Arc<CertifiedKey>>` instead of `Option<CertifiedKey>`.  `CertifiedKey` is now an immutable
    type.
  - *Breaking API change*: `peer_certificates` returns a borrow rather than a copy on the
    internally stored certificate chain.
  - *Breaking API change*: `ClientConnection`'s DNS name parameter is now a new enum, `ServerName`, to allow future support for ECH and servers named by IP address.
  - *Breaking API change*: `QuicExt::write_hs()` now returns a `KeyChange` type that returns handshake or 1-RTT keys. In the case of 1-RTT keys, a `KeyChange` also
    includes a `Secrets` type that must be used to derive further key updates, independent from the rustls `Connection`. The `QuicExt::next_1rtt_keys()` method
    has been removed.
  - *Breaking API change*: QUIC header protection keys now use a new type that directly exposes a masking/unmasking operation.
* 0.19.1 (2021-04-17):
  - Backport: fix security issue: there was a reachable panic in servers if a client
    sent an invalid `ClientECDiffieHellmanPublic` encoding, due to an errant `unwrap()`
    when parsing the encoding.
* 0.19.0 (2020-11-22):
  - Ensured that `get_peer_certificates` is both better documented, and works
    uniformly for both full-handshake and resumed sessions.
  - Fix bug: fully qualified hostnames should have had their trailing dot
    stripped when quoted in the SNI extension.
* 0.18.1 (2020-08-16):
  - Fix DoS vulnerability in TLS1.3 "Middlebox Compatibility Mode" CCS handling.
    This is thought to be quite minor -- see
    [this commit message](https://github.com/ctz/rustls/commit/e51bf92afcd9dfbd5f4e8154b847aa5cc380913c)
    for a full discussion.
* 0.18.0 (2020-07-04):
  - Allow custom certificate validation implementations to also
    handle handshake signature computation.  This allows uses in non-web
    contexts, where `webpki` is not likely to process the certificates
    in use.  Thanks to @DemiMarie-parity.
  - Performance improvements.  Thanks to @nviennot.
  - Fixed client authentication being unduly rejected by client when server
    uses the superseded certificate_types field of CertificateRequest.
  - *Breaking API change*: The writev_tls API has been removed, in favour
    of using vectored IO support now offered by std::io::Write.
  - Added ed25519 support for authentication; thanks to @potatosalad.
  - Support removal of unused ciphersuites at link-time.  To use this,
    call `ClientConfig::with_ciphersuites` instead of `ClientConfig::new`.

See [OLDCHANGES.md](OLDCHANGES.md) for further change history.

# Documentation
Lives here: https://docs.rs/rustls/

# Approach
Rustls is a TLS library that aims to provide a good level of cryptographic security,
requires no configuration to achieve that security, and provides no unsafe features or
obsolete cryptography.

## Current features

* TLS1.2 and TLS1.3.
* ECDSA, Ed25519 or RSA server authentication by clients.
* ECDSA, Ed25519 or RSA server authentication by servers.
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
* AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
* ChaCha20-Poly1305 bulk encryption ([RFC7905](https://tools.ietf.org/html/rfc7905)).
* ALPN support.
* SNI support.
* Tunable fragment size to make TLS messages match size of underlying transport.
* Optional use of vectored IO to minimise system calls.
* TLS1.2 session resumption.
* TLS1.2 resumption via tickets ([RFC5077](https://tools.ietf.org/html/rfc5077)).
* TLS1.3 resumption via tickets or session storage.
* TLS1.3 0-RTT data for clients.
* Client authentication by clients.
* Client authentication by servers.
* Extended master secret support ([RFC7627](https://tools.ietf.org/html/rfc7627)).
* Exporters ([RFC5705](https://tools.ietf.org/html/rfc5705)).
* OCSP stapling by servers.
* SCT stapling by servers.
* SCT verification by clients.

## Possible future features

* PSK support.
* OCSP verification by clients.
* Certificate pinning.

## Non-features

The following things are broken, obsolete, badly designed, underspecified,
dangerous and/or insane. Rustls does not support:

* SSL1, SSL2, SSL3, TLS1 or TLS1.1.
* RC4.
* DES or triple DES.
* EXPORT ciphersuites.
* MAC-then-encrypt ciphersuites.
* Ciphersuites without forward secrecy.
* Renegotiation.
* Kerberos.
* Compression.
* Discrete-log Diffie-Hellman.
* Automatic protocol version downgrade.
* AES-GCM with unsafe nonces.

There are plenty of other libraries that provide these features should you
need them.

### Platform support

Rustls uses [`ring`](https://crates.io/crates/ring) for implementing the
cryptography in TLS. As a result, rustls only runs on platforms
[supported by `ring`](https://github.com/briansmith/ring#online-automated-testing).
At the time of writing this means x86, x86-64, armv7, and aarch64.

# Example code
There are two example programs which use
[mio](https://github.com/carllerche/mio) to do asynchronous IO.

## Client example program
The client example program is named `tlsclient`.  The interface looks like:

```tlsclient
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
```

Some sample runs:

```
$ cargo run --example tlsclient -- --http mozilla-modern.badssl.com
HTTP/1.1 200 OK
Server: nginx/1.6.2 (Ubuntu)
Date: Wed, 01 Jun 2016 18:44:00 GMT
Content-Type: text/html
Content-Length: 644
(...)
```

or

```
$ cargo run --example tlsclient -- --http expired.badssl.com
TLS error: WebPkiError(CertExpired, ValidateServerCert)
Connection closed
```

## Server example program
The server example program is named `tlsserver`.  The interface looks like:

```tlsserver
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each
connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [options] echo
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [options] http
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [options] forward <fport>
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
```

Here's a sample run; we start a TLS echo server, then connect to it with
openssl and tlsclient:

```
$ cargo run --example tlsserver -- --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443 echo &
$ echo hello world | openssl s_client -ign_eof -quiet -connect localhost:8443
depth=2 CN = ponytown RSA CA
verify error:num=19:self signed certificate in certificate chain
hello world
^C
$ echo hello world | cargo run --example tlsclient -- --cafile test-ca/rsa/ca.cert -p 8443 localhost
hello world
^C
```

# License

Rustls is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.
