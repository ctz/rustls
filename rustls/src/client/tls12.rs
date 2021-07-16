use crate::check::{check_message, inappropriate_message};
use crate::conn::{ConnectionCommon, ConnectionRandoms};
use crate::error::Error;
use crate::hash_hs::HandshakeHash;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{AlertDescription, ProtocolVersion};
use crate::msgs::enums::{ContentType, HandshakeType};
use crate::msgs::handshake::{CertificatePayload, DecomposedSignatureScheme, SCTList, SessionID};
use crate::msgs::handshake::{DigitallySignedStruct, ServerECDHParams};
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::suites::SupportedCipherSuite;
use crate::ticketer::TimeBase;
use crate::tls12::{self, ConnectionSecrets, Tls12CipherSuite};
use crate::{kx, verify};

use super::hs::ClientContext;
use crate::client::common::ClientAuthDetails;
use crate::client::common::ServerCertDetails;
use crate::client::{hs, ClientConfig, ServerName};

use ring::constant_time;

use std::mem;
use std::sync::Arc;

pub(super) use server_hello::CompleteServerHelloHandling;

mod server_hello {
    use crate::msgs::enums::ExtensionType;
    use crate::msgs::handshake::HasServerExtensions;
    use crate::msgs::handshake::ServerHelloPayload;

    use super::*;

    pub(in crate::client) struct CompleteServerHelloHandling {
        pub(in crate::client) config: Arc<ClientConfig>,
        pub(in crate::client) resuming_session:
            Option<persist::ClientSessionValueWithResolvedCipherSuite>,
        pub(in crate::client) server_name: ServerName,
        pub(in crate::client) randoms: ConnectionRandoms,
        pub(in crate::client) using_ems: bool,
        pub(in crate::client) transcript: HandshakeHash,
        pub(in crate::client) session_id: SessionID,
    }

    impl CompleteServerHelloHandling {
        pub(in crate::client) fn handle_server_hello(
            mut self,
            cx: &mut ClientContext,
            suite: &'static Tls12CipherSuite,
            server_hello: &ServerHelloPayload,
            tls13_supported: bool,
        ) -> hs::NextStateOrError {
            server_hello
                .random
                .write_slice(&mut self.randoms.server);

            // Look for TLS1.3 downgrade signal in server random
            if tls13_supported
                && self
                    .randoms
                    .has_tls12_downgrade_marker()
            {
                return Err(cx
                    .common
                    .illegal_param("downgrade to TLS1.2 when TLS1.3 is supported"));
            }

            // Doing EMS?
            self.using_ems = server_hello.ems_support_acked();

            // Might the server send a ticket?
            let must_issue_new_ticket = if server_hello
                .find_extension(ExtensionType::SessionTicket)
                .is_some()
            {
                debug!("Server supports tickets");
                true
            } else {
                false
            };

            // Might the server send a CertificateStatus between Certificate and
            // ServerKeyExchange?
            let may_send_cert_status = server_hello
                .find_extension(ExtensionType::StatusRequest)
                .is_some();
            if may_send_cert_status {
                debug!("Server may staple OCSP response");
            }

            // Save any sent SCTs for verification against the certificate.
            let server_cert_sct_list = if let Some(sct_list) = server_hello.get_sct_list() {
                debug!("Server sent {:?} SCTs", sct_list.len());

                if hs::sct_list_is_invalid(sct_list) {
                    let error_msg = "server sent invalid SCT list".to_string();
                    return Err(Error::PeerMisbehavedError(error_msg));
                }
                Some(sct_list.clone())
            } else {
                None
            };

            // See if we're successfully resuming.
            if let Some(ref resuming) = self.resuming_session {
                if resuming.session_id == self.session_id {
                    debug!("Server agreed to resume");

                    // Is the server telling lies about the ciphersuite?
                    if resuming.supported_cipher_suite() != suite.into() {
                        let error_msg =
                            "abbreviated handshake offered, but with varied cs".to_string();
                        return Err(Error::PeerMisbehavedError(error_msg));
                    }

                    // And about EMS support?
                    if resuming.extended_ms != self.using_ems {
                        let error_msg = "server varied ems support over resume".to_string();
                        return Err(Error::PeerMisbehavedError(error_msg));
                    }

                    let secrets = ConnectionSecrets::new_resume(
                        &self.randoms,
                        suite,
                        &resuming.master_secret.0,
                    );
                    self.config.key_log.log(
                        "CLIENT_RANDOM",
                        &secrets.randoms.client,
                        &secrets.master_secret,
                    );
                    cx.common
                        .start_encryption_tls12(&secrets);

                    // Since we're resuming, we verified the certificate and
                    // proof of possession in the prior session.
                    cx.data.server_cert_chain = resuming.server_cert_chain.clone();
                    let cert_verified = verify::ServerCertVerified::assertion();
                    let sig_verified = verify::HandshakeSignatureValid::assertion();

                    return if must_issue_new_ticket {
                        Ok(Box::new(ExpectNewTicket {
                            config: self.config,
                            secrets,
                            resuming_session: self.resuming_session,
                            session_id: self.session_id,
                            server_name: self.server_name,
                            using_ems: self.using_ems,
                            transcript: self.transcript,
                            resuming: true,
                            cert_verified,
                            sig_verified,
                        }))
                    } else {
                        Ok(Box::new(ExpectCcs {
                            config: self.config,
                            secrets,
                            resuming_session: self.resuming_session,
                            session_id: self.session_id,
                            server_name: self.server_name,
                            using_ems: self.using_ems,
                            transcript: self.transcript,
                            ticket: ReceivedTicketDetails::new(),
                            resuming: true,
                            cert_verified,
                            sig_verified,
                        }))
                    };
                }
            }

            Ok(Box::new(ExpectCertificate {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite,
                may_send_cert_status,
                must_issue_new_ticket,
                server_cert_sct_list,
            }))
        }
    }
}

struct ReceivedTicketDetails {
    new_ticket: Vec<u8>,
    new_ticket_lifetime: u32,
}

impl ReceivedTicketDetails {
    fn new() -> Self {
        Self::from(Vec::new(), 0)
    }

    fn from(ticket: Vec<u8>, lifetime: u32) -> Self {
        Self {
            new_ticket: ticket,
            new_ticket_lifetime: lifetime,
        }
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    pub(super) suite: &'static Tls12CipherSuite,
    may_send_cert_status: bool,
    must_issue_new_ticket: bool,
    server_cert_sct_list: Option<SCTList>,
}

impl hs::State for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);
        let server_cert_chain = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        if self.may_send_cert_status {
            Ok(Box::new(ExpectCertificateStatusOrServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert_sct_list: self.server_cert_sct_list,
                server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }))
        } else {
            let server_cert =
                ServerCertDetails::new(server_cert_chain, vec![], self.server_cert_sct_list);

            Ok(Box::new(ExpectServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }))
        }
    }
}

struct ExpectCertificateStatusOrServerKx {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_sct_list: Option<SCTList>,
    server_cert_chain: CertificatePayload,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectCertificateStatusOrServerKx {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> hs::NextStateOrError {
        check_message(
            &m,
            &[ContentType::Handshake],
            &[
                HandshakeType::ServerKeyExchange,
                HandshakeType::CertificateStatus,
            ],
        )?;

        if m.is_handshake_type(HandshakeType::ServerKeyExchange) {
            Box::new(ExpectServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: ServerCertDetails::new(
                    self.server_cert_chain,
                    vec![],
                    self.server_cert_sct_list,
                ),
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m)
        } else {
            Box::new(ExpectCertificateStatus {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert_sct_list: self.server_cert_sct_list,
                server_cert_chain: self.server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m)
        }
    }
}

struct ExpectCertificateStatus {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_sct_list: Option<SCTList>,
    server_cert_chain: CertificatePayload,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectCertificateStatus {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);
        let server_cert_ocsp_response = require_handshake_msg_move!(
            m,
            HandshakeType::CertificateStatus,
            HandshakePayload::CertificateStatus
        )?
        .into_inner();

        trace!(
            "Server stapled OCSP response is {:?}",
            &server_cert_ocsp_response
        );

        let server_cert = ServerCertDetails::new(
            self.server_cert_chain,
            server_cert_ocsp_response,
            self.server_cert_sct_list,
        );

        Ok(Box::new(ExpectServerKx {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

struct ExpectServerKx {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectServerKx {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> hs::NextStateOrError {
        let opaque_kx = require_handshake_msg!(
            m,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;
        self.transcript.add_message(&m);

        let ecdhe = opaque_kx
            .unwrap_given_kxa(&self.suite.kx)
            .ok_or_else(|| {
                cx.common
                    .send_fatal_alert(AlertDescription::DecodeError);
                Error::CorruptMessagePayload(ContentType::Handshake)
            })?;

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        ecdhe.params.encode(&mut kx_params);
        let server_kx = ServerKxDetails::new(kx_params, ecdhe.dss);

        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        {
            debug!("ECDHE curve is {:?}", ecdhe.params.curve_params);
        }

        Ok(Box::new(ExpectServerDoneOrCertReq {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

fn emit_certificate(
    transcript: &mut HandshakeHash,
    cert_chain: CertificatePayload,
    common: &mut ConnectionCommon,
) {
    let cert = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(cert_chain),
        }),
    };

    transcript.add_message(&cert);
    common.send_msg(cert, false);
}

fn emit_clientkx(
    transcript: &mut HandshakeHash,
    common: &mut ConnectionCommon,
    kxd: &kx::KeyExchangeResult,
) {
    let mut buf = Vec::new();
    let ecpoint = PayloadU8::new(Vec::from(kxd.pubkey.as_ref()));
    ecpoint.encode(&mut buf);
    let pubkey = Payload::new(buf);

    let ckx = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(pubkey),
        }),
    };

    transcript.add_message(&ckx);
    common.send_msg(ckx, false);
}

fn emit_certverify(
    transcript: &mut HandshakeHash,
    client_auth: &mut ClientAuthDetails,
    common: &mut ConnectionCommon,
) -> Result<(), Error> {
    let (signer, message) = match (client_auth.signer.take(), transcript.take_handshake_buf()) {
        (Some(signer), Some(msg)) => (signer, msg),
        (None, _) => {
            trace!("Not sending CertificateVerify, no key");
            transcript.abandon_client_auth();
            return Ok(());
        }
        (_, None) => {
            trace!("Not sending CertificateVerify, no transcript");
            return Ok(());
        }
    };

    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let body = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(body),
        }),
    };

    transcript.add_message(&m);
    common.send_msg(m, false);
    Ok(())
}

fn emit_ccs(common: &mut ConnectionCommon) {
    let ccs = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    common.send_msg(ccs, false);
}

fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    common: &mut ConnectionCommon,
) {
    let vh = transcript.get_current_hash();
    let verify_data = secrets.client_verify_data(&vh);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    transcript.add_message(&f);
    common.send_msg(f, true);
}

struct ServerKxDetails {
    kx_params: Vec<u8>,
    kx_sig: DigitallySignedStruct,
}

impl ServerKxDetails {
    fn new(params: Vec<u8>, sig: DigitallySignedStruct) -> Self {
        Self {
            kx_params: params,
            kx_sig: sig,
        }
    }
}

// --- Either a CertificateRequest, or a ServerHelloDone. ---
// Existence of the CertificateRequest tells us the server is asking for
// client auth.  Otherwise we go straight to ServerHelloDone.
struct ExpectServerDoneOrCertReq {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectServerDoneOrCertReq {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> hs::NextStateOrError {
        if require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequest
        )
        .is_ok()
        {
            Box::new(ExpectCertificateRequest {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m)
        } else {
            self.transcript.abandon_client_auth();

            Box::new(ExpectServerDone {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                client_auth: None,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m)
        }
    }
}

struct ExpectCertificateRequest {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectCertificateRequest {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        let certreq = require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequest
        )?;
        self.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        let mut client_auth = ClientAuthDetails::new();

        // The RFC jovially describes the design here as 'somewhat complicated'
        // and 'somewhat underspecified'.  So thanks for that.
        //
        // We ignore certreq.certtypes as a result, since the information it contains
        // is entirely duplicated in certreq.sigschemes.

        let canames = certreq
            .canames
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();
        let maybe_certkey = self
            .config
            .client_auth_cert_resolver
            .resolve(&canames, &certreq.sigschemes);

        if let Some(certkey) = maybe_certkey {
            let maybe_signer = certkey
                .key
                .choose_scheme(&certreq.sigschemes);

            if maybe_signer.is_some() {
                debug!("Attempting client auth");
                client_auth.certkey = Some(certkey);
            }
            client_auth.signer = maybe_signer;
        } else {
            debug!("Client auth requested but no cert/sigscheme available");
        }

        Ok(Box::new(ExpectServerDone {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

struct ExpectServerDone {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    client_auth: Option<ClientAuthDetails>,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectServerDone {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        check_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerHelloDone],
        )?;
        st.transcript.add_message(&m);

        cx.common.check_aligned_handshake()?;

        trace!("Server cert is {:?}", st.server_cert.cert_chain);
        debug!("Server DNS name is {:?}", st.server_name);

        let suite = st.suite;

        // 1. Verify the cert chain.
        // 2. Verify any SCTs provided with the certificate.
        // 3. Verify that the top certificate signed their kx.
        // 4. If doing client auth, send our Certificate.
        // 5. Complete the key exchange:
        //    a) generate our kx pair
        //    b) emit a ClientKeyExchange containing it
        //    c) if doing client auth, emit a CertificateVerify
        //    d) emit a CCS
        //    e) derive the shared keys, and start encryption
        // 6. emit a Finished, our first encrypted message under the new keys.

        // 1.
        let (end_entity, intermediates) = st
            .server_cert
            .cert_chain
            .split_first()
            .ok_or(Error::NoCertificatesPresented)?;
        let now = std::time::SystemTime::now();
        let cert_verified = st
            .config
            .verifier
            .verify_server_cert(
                end_entity,
                intermediates,
                &st.server_name,
                &mut st.server_cert.scts(),
                &st.server_cert.ocsp_response,
                now,
            )
            .map_err(|err| hs::send_cert_error_alert(cx.common, err))?;

        // 3.
        // Build up the contents of the signed message.
        // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
        let sig_verified = {
            let mut message = Vec::new();
            message.extend_from_slice(&st.randoms.client);
            message.extend_from_slice(&st.randoms.server);
            message.extend_from_slice(&st.server_kx.kx_params);

            // Check the signature is compatible with the ciphersuite.
            let sig = &st.server_kx.kx_sig;
            if !SupportedCipherSuite::from(suite).usable_for_signature_algorithm(sig.scheme.sign())
            {
                let error_message = format!(
                    "peer signed kx with wrong algorithm (got {:?} expect {:?})",
                    sig.scheme.sign(),
                    suite.sign
                );
                return Err(Error::PeerMisbehavedError(error_message));
            }

            st.config
                .verifier
                .verify_tls12_signature(&message, &st.server_cert.cert_chain[0], sig)
                .map_err(|err| hs::send_cert_error_alert(cx.common, err))?
        };
        cx.data.server_cert_chain = st.server_cert.cert_chain;

        // 4.
        if let Some(client_auth) = &mut st.client_auth {
            if let Some(cert_key) = &client_auth.certkey {
                emit_certificate(&mut st.transcript, cert_key.cert.clone(), cx.common);
            } else {
                emit_certificate(&mut st.transcript, Vec::new(), cx.common);
            }
        }

        // 5a.
        let ecdh_params =
            tls12::decode_ecdh_params::<ServerECDHParams>(cx.common, &st.server_kx.kx_params)?;
        let group =
            kx::KeyExchange::choose(ecdh_params.curve_params.named_group, &st.config.kx_groups)
                .ok_or_else(|| {
                    Error::PeerMisbehavedError("peer chose an unsupported group".to_string())
                })?;
        let kx = kx::KeyExchange::start(group).ok_or(Error::FailedToGetRandomBytes)?;
        let kxd = tls12::complete_ecdh(kx, &ecdh_params.public.0)?;

        // 5b.
        emit_clientkx(&mut st.transcript, cx.common, &kxd);
        // nb. EMS handshake hash only runs up to ClientKeyExchange.
        let handshake_hash = st.transcript.get_current_hash();

        // 5c.
        if let Some(client_auth) = &mut st.client_auth {
            emit_certverify(&mut st.transcript, client_auth, cx.common)?;
        }

        // 5d.
        emit_ccs(cx.common);

        // 5e. Now commit secrets.
        let secrets = if st.using_ems {
            ConnectionSecrets::new_ems(&st.randoms, &handshake_hash, suite, &kxd.shared_secret)
        } else {
            ConnectionSecrets::new(&st.randoms, suite, &kxd.shared_secret)
        };
        st.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        cx.common
            .start_encryption_tls12(&secrets);
        cx.common
            .record_layer
            .start_encrypting();

        // 6.
        emit_finished(&secrets, &mut st.transcript, cx.common);

        if st.must_issue_new_ticket {
            Ok(Box::new(ExpectNewTicket {
                config: st.config,
                secrets,
                resuming_session: st.resuming_session,
                session_id: st.session_id,
                server_name: st.server_name,
                using_ems: st.using_ems,
                transcript: st.transcript,
                resuming: false,
                cert_verified,
                sig_verified,
            }))
        } else {
            Ok(Box::new(ExpectCcs {
                config: st.config,
                secrets,
                resuming_session: st.resuming_session,
                session_id: st.session_id,
                server_name: st.server_name,
                using_ems: st.using_ems,
                transcript: st.transcript,
                ticket: ReceivedTicketDetails::new(),
                resuming: false,
                cert_verified,
                sig_verified,
            }))
        }
    }
}

struct ExpectNewTicket {
    config: Arc<ClientConfig>,
    secrets: ConnectionSecrets,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    using_ems: bool,
    transcript: HandshakeHash,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl hs::State for ExpectNewTicket {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);

        let nst = require_handshake_msg_move!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicket
        )?;

        Ok(Box::new(ExpectCcs {
            config: self.config,
            secrets: self.secrets,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            using_ems: self.using_ems,
            transcript: self.transcript,
            ticket: ReceivedTicketDetails::from(nst.ticket.0, nst.lifetime_hint),
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }
}

// -- Waiting for their CCS --
struct ExpectCcs {
    config: Arc<ClientConfig>,
    secrets: ConnectionSecrets,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    using_ems: bool,
    transcript: HandshakeHash,
    ticket: ReceivedTicketDetails,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl hs::State for ExpectCcs {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> hs::NextStateOrError {
        check_message(&m, &[ContentType::ChangeCipherSpec], &[])?;
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        cx.common.check_aligned_handshake()?;

        // nb. msgs layer validates trivial contents of CCS
        cx.common
            .record_layer
            .start_decrypting();

        Ok(Box::new(ExpectFinished {
            config: self.config,
            secrets: self.secrets,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            using_ems: self.using_ems,
            transcript: self.transcript,
            ticket: self.ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }
}

struct ExpectFinished {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    session_id: SessionID,
    server_name: ServerName,
    using_ems: bool,
    transcript: HandshakeHash,
    ticket: ReceivedTicketDetails,
    secrets: ConnectionSecrets,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectFinished {
    // -- Waiting for their finished --
    fn save_session(&mut self, cx: &mut ClientContext<'_>) {
        // Save a ticket.  If we got a new ticket, save that.  Otherwise, save the
        // original ticket again.
        let mut ticket = mem::take(&mut self.ticket.new_ticket);

        if ticket.is_empty() {
            if let Some(resuming_session) = &mut self.resuming_session {
                ticket = resuming_session.take_ticket();
            }
        }

        if self.session_id.is_empty() && ticket.is_empty() {
            debug!("Session not saved: server didn't allocate id or ticket");
            return;
        }

        let time_now = match TimeBase::now() {
            Ok(time_now) => time_now,
            Err(_) => {
                debug!("Session not saved: failed to get system time");
                return;
            }
        };

        let key = persist::ClientSessionKey::session_for_server_name(&self.server_name);

        let master_secret = self.secrets.get_master_secret();
        let mut value = persist::ClientSessionValueWithResolvedCipherSuite::new(
            ProtocolVersion::TLSv1_2,
            self.secrets.suite().into(),
            &self.session_id,
            ticket,
            master_secret,
            &cx.data.server_cert_chain,
            time_now,
        );
        value.set_times(self.ticket.new_ticket_lifetime, 0);
        if self.using_ems {
            value.set_extended_ms_used();
        }

        let worked = self
            .config
            .session_storage
            .put(key.get_encoding(), value.get_encoding());

        if worked {
            debug!("Session saved");
        } else {
            debug!("Session not saved");
        }
    }
}

impl hs::State for ExpectFinished {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        cx.common.check_aligned_handshake()?;

        // Work out what verify_data we expect.
        let vh = st.transcript.get_current_hash();
        let expect_verify_data = st.secrets.server_verify_data(&vh);

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        let _fin_verified =
            constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
                .map_err(|_| {
                    cx.common
                        .send_fatal_alert(AlertDescription::DecryptError);
                    Error::DecryptError
                })
                .map(|_| verify::FinishedMessageVerified::assertion())?;

        // Hash this message too.
        st.transcript.add_message(&m);

        st.save_session(cx);

        if st.resuming {
            emit_ccs(cx.common);
            cx.common
                .record_layer
                .start_encrypting();
            emit_finished(&st.secrets, &mut st.transcript, cx.common);
        }

        cx.common.start_traffic();
        Ok(Box::new(ExpectTraffic {
            secrets: st.secrets,
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified,
        }))
    }
}

// -- Traffic transit state --
struct ExpectTraffic {
    secrets: ConnectionSecrets,
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl hs::State for ExpectTraffic {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx
                .common
                .take_received_plaintext(payload),
            _ => {
                return Err(inappropriate_message(&m, &[ContentType::ApplicationData]));
            }
        }
        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.secrets
            .export_keying_material(output, label, context);
        Ok(())
    }
}
