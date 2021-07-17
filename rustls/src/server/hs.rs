use crate::conn::{ConnectionCommon, ConnectionRandoms};
use crate::error::Error;
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::enums::{AlertDescription, ExtensionType};
use crate::msgs::enums::{CipherSuite, Compression};
use crate::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::handshake::SessionID;
use crate::msgs::handshake::{ClientHelloPayload, Random, ServerExtension};
use crate::msgs::handshake::{ConvertProtocolNameList, ConvertServerNameList};
use crate::msgs::handshake::{HandshakePayload, SupportedSignatureSchemes};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::server::{ClientHello, ServerConfig};
use crate::suites;
use crate::SupportedCipherSuite;

use crate::server::common::ActiveCertifiedKey;
use crate::server::{tls12, tls13};
use super::server_conn::ServerConnectionData;

use std::sync::Arc;

pub(super) type NextState = Box<dyn State>;
pub(super) type NextStateOrError = Result<NextState, Error>;

pub(super) trait State: Send + Sync {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message) -> NextStateOrError;

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    fn perhaps_write_key_update(&mut self, _common: &mut ConnectionCommon) {}
}

impl<'a> crate::conn::HandleState for Box<dyn State> {
    type Data = ServerConnectionData;

    fn handle(
        self,
        message: Message,
        data: &mut Self::Data,
        common: &mut ConnectionCommon,
    ) -> Result<Self, Error> {
        let mut cx = ServerContext { common, data };
        self.handle(&mut cx, message)
    }
}

pub(super) struct ServerContext<'a> {
    pub(super) common: &'a mut ConnectionCommon,
    pub(super) data: &'a mut ServerConnectionData,
}

pub(super) fn incompatible(common: &mut ConnectionCommon, why: &str) -> Error {
    common.send_fatal_alert(AlertDescription::HandshakeFailure);
    Error::PeerIncompatibleError(why.to_string())
}

fn bad_version(common: &mut ConnectionCommon, why: &str) -> Error {
    common.send_fatal_alert(AlertDescription::ProtocolVersion);
    Error::PeerIncompatibleError(why.to_string())
}

pub(super) fn decode_error(common: &mut ConnectionCommon, why: &str) -> Error {
    common.send_fatal_alert(AlertDescription::DecodeError);
    Error::PeerMisbehavedError(why.to_string())
}

pub(super) fn can_resume(
    suite: SupportedCipherSuite,
    sni: &Option<webpki::DnsName>,
    using_ems: bool,
    resumedata: &persist::ServerSessionValue,
) -> bool {
    // The RFCs underspecify what happens if we try to resume to
    // an unoffered/varying suite.  We merely don't resume in weird cases.
    //
    // RFC 6066 says "A server that implements this extension MUST NOT accept
    // the request to resume the session if the server_name extension contains
    // a different name. Instead, it proceeds with a full handshake to
    // establish a new session."
    resumedata.cipher_suite == suite.suite()
        && (resumedata.extended_ms == using_ems || (resumedata.extended_ms && !using_ems))
        && &resumedata.sni == sni
}

#[derive(Default)]
pub(super) struct ExtensionProcessing {
    // extensions to reply with
    pub(super) exts: Vec<ServerExtension>,

    pub(super) send_ticket: bool,
}

impl ExtensionProcessing {
    pub(super) fn new() -> Self {
        Default::default()
    }

    pub(super) fn process_common(
        &mut self,
        config: &ServerConfig,
        cx: &mut ServerContext<'_>,
        #[allow(unused_variables)] // #[cfg(feature = "quic")] only
        suite: SupportedCipherSuite,
        ocsp_response: &mut Option<&[u8]>,
        sct_list: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&persist::ServerSessionValue>,
        extra_exts: Vec<ServerExtension>,
    ) -> Result<(), Error> {
        // ALPN
        let our_protocols = &config.alpn_protocols;
        let maybe_their_protocols = hello.get_alpn_extension();
        if let Some(their_protocols) = maybe_their_protocols {
            let their_protocols = their_protocols.to_slices();

            if their_protocols
                .iter()
                .any(|protocol| protocol.is_empty())
            {
                return Err(Error::PeerMisbehavedError(
                    "client offered empty ALPN protocol".to_string(),
                ));
            }

            cx.common.alpn_protocol = our_protocols
                .iter()
                .find(|protocol| their_protocols.contains(&protocol.as_slice()))
                .cloned();
            if let Some(ref selected_protocol) = cx.common.alpn_protocol {
                debug!("Chosen ALPN protocol {:?}", selected_protocol);
                self.exts
                    .push(ServerExtension::make_alpn(&[selected_protocol]));
            } else if !our_protocols.is_empty() {
                cx.common
                    .send_fatal_alert(AlertDescription::NoApplicationProtocol);
                return Err(Error::NoApplicationProtocol);
            }
        }

        #[cfg(feature = "quic")]
        {
            if cx.common.is_quic() {
                match hello.get_quic_params_extension() {
                    Some(params) => cx.common.quic.params = Some(params),
                    None => {
                        return Err(cx
                            .common
                            .missing_extension("QUIC transport parameters not found"));
                    }
                }

                if let Some(resume) = resumedata {
                    if config.max_early_data_size > 0
                        && hello.early_data_extension_offered()
                        && resume.version == cx.common.negotiated_version.unwrap()
                        && resume.cipher_suite == suite.suite()
                        && resume.alpn.as_ref().map(|x| &x.0) == cx.common.alpn_protocol.as_ref()
                        && !cx.data.reject_early_data
                    {
                        self.exts
                            .push(ServerExtension::EarlyData);
                    } else {
                        // Clobber value set in tls13::emit_server_hello
                        cx.common.quic.early_secret = None;
                    }
                }
            }
        }

        let for_resume = resumedata.is_some();
        // SNI
        if !for_resume && hello.get_sni_extension().is_some() {
            self.exts
                .push(ServerExtension::ServerNameAck);
        }

        // Send status_request response if we have one.  This is not allowed
        // if we're resuming, and is only triggered if we have an OCSP response
        // to send.
        if !for_resume
            && hello
                .find_extension(ExtensionType::StatusRequest)
                .is_some()
        {
            if ocsp_response.is_some() && !cx.common.is_tls13() {
                // Only TLS1.2 sends confirmation in ServerHello
                self.exts
                    .push(ServerExtension::CertificateStatusAck);
            }
        } else {
            // Throw away any OCSP response so we don't try to send it later.
            ocsp_response.take();
        }

        if !for_resume
            && hello
                .find_extension(ExtensionType::SCT)
                .is_some()
        {
            if !cx.common.is_tls13() {
                // Take the SCT list, if any, so we don't send it later,
                // and put it in the legacy extension.
                if let Some(sct_list) = sct_list.take() {
                    self.exts
                        .push(ServerExtension::make_sct(sct_list.to_vec()));
                }
            }
        } else {
            // Throw away any SCT list so we don't send it later.
            sct_list.take();
        }

        self.exts.extend(extra_exts);

        Ok(())
    }

    pub(super) fn process_tls12(
        &mut self,
        config: &ServerConfig,
        hello: &ClientHelloPayload,
        using_ems: bool,
    ) {
        // Renegotiation.
        // (We don't do reneg at all, but would support the secure version if we did.)
        let secure_reneg_offered = hello
            .find_extension(ExtensionType::RenegotiationInfo)
            .is_some()
            || hello
                .cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        if secure_reneg_offered {
            self.exts
                .push(ServerExtension::make_empty_renegotiation_info());
        }

        // Tickets:
        // If we get any SessionTicket extension and have tickets enabled,
        // we send an ack.
        if hello
            .find_extension(ExtensionType::SessionTicket)
            .is_some()
            && config.ticketer.enabled()
        {
            self.send_ticket = true;
            self.exts
                .push(ServerExtension::SessionTicketAck);
        }

        // Confirm use of EMS if offered.
        if using_ems {
            self.exts
                .push(ServerExtension::ExtendedMasterSecretAck);
        }
    }
}

pub(super) struct ExpectClientHello {
    pub(super) config: Arc<ServerConfig>,
    pub(super) extra_exts: Vec<ServerExtension>,
    pub(super) transcript: HandshakeHashOrBuffer,
    pub(super) session_id: SessionID,
    pub(super) using_ems: bool,
    pub(super) done_retry: bool,
    pub(super) send_ticket: bool,
}

impl ExpectClientHello {
    pub(super) fn new(config: Arc<ServerConfig>, extra_exts: Vec<ServerExtension>) -> Self {
        let mut transcript_buffer = HandshakeHashBuffer::new();

        if config.verifier.offer_client_auth() {
            transcript_buffer.set_client_auth_enabled();
        }

        Self {
            config,
            extra_exts,
            transcript: HandshakeHashOrBuffer::Buffer(transcript_buffer),
            session_id: SessionID::empty(),
            using_ems: false,
            done_retry: false,
            send_ticket: false,
        }
    }
}

impl State for ExpectClientHello {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message) -> NextStateOrError {
        let client_hello =
            require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;
        let tls13_enabled = self
            .config
            .supports_version(ProtocolVersion::TLSv1_3);
        let tls12_enabled = self
            .config
            .supports_version(ProtocolVersion::TLSv1_2);
        trace!("we got a clienthello {:?}", client_hello);

        if !client_hello
            .compression_methods
            .contains(&Compression::Null)
        {
            cx.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(Error::PeerIncompatibleError(
                "client did not offer Null compression".to_string(),
            ));
        }

        if client_hello.has_duplicate_extension() {
            return Err(decode_error(
                &mut cx.common,
                "client sent duplicate extensions",
            ));
        }

        // No handshake messages should follow this one in this flight.
        cx.common.check_aligned_handshake()?;

        // Are we doing TLS1.3?
        let maybe_versions_ext = client_hello.get_versions_extension();
        let version = if let Some(versions) = maybe_versions_ext {
            if versions.contains(&ProtocolVersion::TLSv1_3) && tls13_enabled {
                ProtocolVersion::TLSv1_3
            } else if !versions.contains(&ProtocolVersion::TLSv1_2) || !tls12_enabled {
                return Err(bad_version(&mut cx.common, "TLS1.2 not offered/enabled"));
            } else if cx.common.is_quic() {
                return Err(bad_version(
                    &mut cx.common,
                    "Expecting QUIC connection, but client does not support TLSv1_3",
                ));
            } else {
                ProtocolVersion::TLSv1_2
            }
        } else if client_hello.client_version.get_u16() < ProtocolVersion::TLSv1_2.get_u16() {
            return Err(bad_version(
                &mut cx.common,
                "Client does not support TLSv1_2",
            ));
        } else if !tls12_enabled && tls13_enabled {
            return Err(bad_version(
                &mut cx.common,
                "Server requires TLS1.3, but client omitted versions ext",
            ));
        } else if cx.common.is_quic() {
            return Err(bad_version(
                &mut cx.common,
                "Expecting QUIC connection, but client does not support TLSv1_3",
            ));
        } else {
            ProtocolVersion::TLSv1_2
        };

        cx.common.negotiated_version = Some(version);

        // --- Common to TLS1.2 and TLS1.3: ciphersuite and certificate selection.

        // Extract and validate the SNI DNS name, if any, before giving it to
        // the cert resolver. In particular, if it is invalid then we should
        // send an Illegal Parameter alert instead of the Internal Error alert
        // (or whatever) that we'd send if this were checked later or in a
        // different way.
        let sni: Option<webpki::DnsName> = match client_hello.get_sni_extension() {
            Some(sni) => {
                if sni.has_duplicate_names_for_type() {
                    return Err(decode_error(
                        &mut cx.common,
                        "ClientHello SNI contains duplicate name types",
                    ));
                }

                if let Some(hostname) = sni.get_single_hostname() {
                    Some(hostname.into())
                } else {
                    return Err(cx
                        .common
                        .illegal_param("ClientHello SNI did not contain a hostname"));
                }
            }
            None => None,
        };

        // save only the first SNI
        if let (Some(sni), false) = (&sni, self.done_retry) {
            // Save the SNI into the session.
            // The SNI hostname is immutable once set.
            assert!(cx.data.sni.is_none());
            cx.data.sni = Some(sni.clone());
        } else if cx.data.sni != sni {
            return Err(Error::PeerIncompatibleError(
                "SNI differed on retry".to_string(),
            ));
        }

        // We communicate to the upper layer what kind of key they should choose
        // via the sigschemes value.  Clients tend to treat this extension
        // orthogonally to offered ciphersuites (even though, in TLS1.2 it is not).
        // So: reduce the offered sigschemes to those compatible with the
        // intersection of ciphersuites.
        let mut common_suites = self.config.cipher_suites.clone();
        common_suites.retain(|scs| {
            client_hello
                .cipher_suites
                .contains(&scs.suite())
        });

        let mut sigschemes_ext = client_hello
            .get_sigalgs_extension()
            .cloned()
            .unwrap_or_else(SupportedSignatureSchemes::default);
        sigschemes_ext
            .retain(|scheme| suites::compatible_sigscheme_for_suites(*scheme, &common_suites));

        let alpn_protocols = client_hello
            .get_alpn_extension()
            .map(|protos| protos.to_slices());

        // Choose a certificate.
        let certkey = {
            let sni_ref = sni
                .as_ref()
                .map(webpki::DnsName::as_ref);
            trace!("sni {:?}", sni_ref);
            trace!("sig schemes {:?}", sigschemes_ext);
            trace!("alpn protocols {:?}", alpn_protocols);

            let alpn_slices = alpn_protocols.as_deref();
            let client_hello = ClientHello::new(sni_ref, &sigschemes_ext, alpn_slices);

            let certkey = self
                .config
                .cert_resolver
                .resolve(client_hello);
            certkey.ok_or_else(|| {
                cx.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("no server certificate chain resolved".to_string())
            })?
        };
        let certkey = ActiveCertifiedKey::from_certified_key(&certkey);

        // Reduce our supported ciphersuites by the certificate.
        // (no-op for TLS1.3)
        let suitable_suites =
            suites::reduce_given_sigalg(&self.config.cipher_suites, certkey.get_key().algorithm());

        // And version
        let suitable_suites = suites::reduce_given_version(&suitable_suites, version);

        let suite = if self.config.ignore_client_order {
            suites::choose_ciphersuite_preferring_server(
                &client_hello.cipher_suites,
                &suitable_suites,
            )
        } else {
            suites::choose_ciphersuite_preferring_client(
                &client_hello.cipher_suites,
                &suitable_suites,
            )
        }
        .ok_or_else(|| incompatible(&mut cx.common, "no ciphersuites in common"))?;

        debug!("decided upon suite {:?}", suite);
        cx.common.suite = Some(suite);

        // Start handshake hash.
        let starting_hash = suite.hash_algorithm();
        let transcript = match self.transcript {
            HandshakeHashOrBuffer::Buffer(inner) => inner.start_hash(starting_hash),
            HandshakeHashOrBuffer::Hash(inner) if inner.algorithm() == starting_hash => inner,
            _ => {
                return Err(cx
                    .common
                    .illegal_param("hash differed on retry"));
            }
        };

        // Save their Random.
        let randoms = ConnectionRandoms::new(client_hello.random, Random::new()?, false);
        match suite {
            SupportedCipherSuite::Tls13(suite) => tls13::CompleteClientHelloHandling {
                config: self.config,
                transcript,
                suite,
                randoms,
                done_retry: self.done_retry,
                send_ticket: self.send_ticket,
                extra_exts: self.extra_exts,
            }
            .handle_client_hello(cx, certkey, &m),
            SupportedCipherSuite::Tls12(suite) => tls12::CompleteClientHelloHandling {
                config: self.config,
                transcript,
                session_id: self.session_id,
                suite,
                using_ems: self.using_ems,
                randoms,
                send_ticket: self.send_ticket,
                extra_exts: self.extra_exts,
            }
            .handle_client_hello(
                cx,
                certkey,
                &m,
                client_hello,
                sigschemes_ext,
                tls13_enabled,
            ),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum HandshakeHashOrBuffer {
    Buffer(HandshakeHashBuffer),
    Hash(HandshakeHash),
}
