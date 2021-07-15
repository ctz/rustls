#[cfg(feature = "quic")]
use crate::check::check_message;
use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::cipher;
use crate::conn::{ConnectionCommon, ConnectionRandoms};
use crate::error::Error;
use crate::hash_hs::HandshakeHash;
use crate::key::Certificate;
use crate::key_schedule::{KeyScheduleTraffic, KeyScheduleTrafficWithClientFinishedPending};
#[cfg(feature = "logging")]
use crate::log::{debug, trace, warn};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{AlertDescription, KeyUpdateRequest};
use crate::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::handshake::HandshakePayload;
use crate::msgs::handshake::NewSessionTicketPayloadTLS13;
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::rand;
use crate::server::ServerConfig;
use crate::suites::Tls13CipherSuite;
use crate::verify;
#[cfg(feature = "quic")]
use crate::{conn::Protocol, msgs::handshake::NewSessionTicketExtension};

use super::hs::{self, HandshakeHashOrBuffer, ServerContext};

use std::sync::Arc;

use ring::constant_time;

pub(super) use client_hello::CompleteClientHelloHandling;

mod client_hello {
    use crate::key_schedule::{KeyScheduleEarly, KeyScheduleHandshake, KeyScheduleNonSecret};
    use crate::kx;
    use crate::msgs::base::{Payload, PayloadU8};
    use crate::msgs::ccs::ChangeCipherSpecPayload;
    use crate::msgs::enums::{Compression, PSKKeyExchangeMode};
    use crate::msgs::enums::{NamedGroup, SignatureScheme};
    use crate::msgs::handshake::CertReqExtension;
    use crate::msgs::handshake::CertificateEntry;
    use crate::msgs::handshake::CertificateExtension;
    use crate::msgs::handshake::CertificatePayloadTLS13;
    use crate::msgs::handshake::CertificateRequestPayloadTLS13;
    use crate::msgs::handshake::CertificateStatus;
    use crate::msgs::handshake::ClientHelloPayload;
    use crate::msgs::handshake::DigitallySignedStruct;
    use crate::msgs::handshake::HelloRetryExtension;
    use crate::msgs::handshake::HelloRetryRequest;
    use crate::msgs::handshake::KeyShareEntry;
    use crate::msgs::handshake::Random;
    use crate::msgs::handshake::ServerExtension;
    use crate::msgs::handshake::ServerHelloPayload;
    use crate::msgs::handshake::SessionID;
    #[cfg(feature = "quic")]
    use crate::quic;
    use crate::server::common::ActiveCertifiedKey;
    use crate::sign;

    use super::*;

    pub(in crate::server) struct CompleteClientHelloHandling {
        pub(in crate::server) config: Arc<ServerConfig>,
        pub(in crate::server) transcript: HandshakeHash,
        pub(in crate::server) suite: &'static Tls13CipherSuite,
        pub(in crate::server) randoms: ConnectionRandoms,
        pub(in crate::server) done_retry: bool,
        pub(in crate::server) send_ticket: bool,
        pub(in crate::server) extra_exts: Vec<ServerExtension>,
    }

    impl CompleteClientHelloHandling {
        fn check_binder(
            &self,
            suite: &'static Tls13CipherSuite,
            client_hello: &Message,
            psk: &[u8],
            binder: &[u8],
        ) -> bool {
            let binder_plaintext = match client_hello.payload {
                MessagePayload::Handshake(ref hmp) => hmp.get_encoding_for_binder_signing(),
                _ => unreachable!(),
            };

            let handshake_hash = self
                .transcript
                .get_hash_given(&binder_plaintext);

            let key_schedule = KeyScheduleEarly::new(suite.hkdf_algorithm, psk);
            let real_binder =
                key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);

            constant_time::verify_slices_are_equal(real_binder.as_ref(), binder).is_ok()
        }

        fn attempt_tls13_ticket_decryption(
            &mut self,
            ticket: &[u8],
        ) -> Option<persist::ServerSessionValue> {
            if self.config.ticketer.enabled() {
                self.config
                    .ticketer
                    .decrypt(ticket)
                    .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
            } else {
                self.config
                    .session_storage
                    .take(ticket)
                    .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
            }
        }

        pub(in crate::server) fn handle_client_hello(
            mut self,
            cx: &mut ServerContext<'_>,
            server_key: ActiveCertifiedKey,
            chm: &Message,
        ) -> hs::NextStateOrError {
            let client_hello = require_handshake_msg!(
                chm,
                HandshakeType::ClientHello,
                HandshakePayload::ClientHello
            )?;

            if client_hello.compression_methods.len() != 1 {
                return Err(cx
                    .common
                    .illegal_param("client offered wrong compressions"));
            }

            let groups_ext = client_hello
                .get_namedgroups_extension()
                .ok_or_else(|| hs::incompatible(&mut cx.common, "client didn't describe groups"))?;

            let mut sigschemes_ext = client_hello
                .get_sigalgs_extension()
                .ok_or_else(|| {
                    hs::incompatible(&mut cx.common, "client didn't describe sigschemes")
                })?
                .clone();

            let tls13_schemes = sign::supported_sign_tls13();
            sigschemes_ext.retain(|scheme| tls13_schemes.contains(scheme));

            let shares_ext = client_hello
                .get_keyshare_extension()
                .ok_or_else(|| hs::incompatible(&mut cx.common, "client didn't send keyshares"))?;

            if client_hello.has_keyshare_extension_with_duplicates() {
                return Err(cx
                    .common
                    .illegal_param("client sent duplicate keyshares"));
            }

            // choose a share that we support
            let chosen_share = self
                .config
                .kx_groups
                .iter()
                .find_map(|group| {
                    shares_ext
                        .iter()
                        .find(|share| share.group == group.name)
                });

            let chosen_share = match chosen_share {
                Some(s) => s,
                None => {
                    // We don't have a suitable key share.  Choose a suitable group and
                    // send a HelloRetryRequest.
                    let retry_group_maybe = self
                        .config
                        .kx_groups
                        .iter()
                        .find(|group| groups_ext.contains(&group.name))
                        .cloned();

                    self.transcript.add_message(chm);

                    if let Some(group) = retry_group_maybe {
                        if self.done_retry {
                            return Err(cx
                                .common
                                .illegal_param("did not follow retry request"));
                        }

                        emit_hello_retry_request(
                            &mut self.transcript,
                            self.suite,
                            &mut cx.common,
                            group.name,
                        );
                        emit_fake_ccs(&mut cx.common);
                        return Ok(Box::new(hs::ExpectClientHello {
                            config: self.config,
                            transcript: HandshakeHashOrBuffer::Hash(self.transcript),
                            session_id: SessionID::empty(),
                            using_ems: false,
                            done_retry: true,
                            send_ticket: self.send_ticket,
                            extra_exts: self.extra_exts,
                        }));
                    }

                    return Err(hs::incompatible(
                        &mut cx.common,
                        "no kx group overlap with client",
                    ));
                }
            };

            let mut chosen_psk_index = None;
            let mut resumedata = None;
            if let Some(psk_offer) = client_hello.get_psk() {
                if !client_hello.check_psk_ext_is_last() {
                    return Err(cx
                        .common
                        .illegal_param("psk extension in wrong position"));
                }

                if psk_offer.binders.is_empty() {
                    return Err(hs::decode_error(
                        &mut cx.common,
                        "psk extension missing binder",
                    ));
                }

                if psk_offer.binders.len() != psk_offer.identities.len() {
                    return Err(cx
                        .common
                        .illegal_param("psk extension mismatched ids/binders"));
                }

                for (i, psk_id) in psk_offer.identities.iter().enumerate() {
                    let resume = match self
                        .attempt_tls13_ticket_decryption(&psk_id.identity.0)
                        .filter(|resumedata| {
                            hs::can_resume(self.suite.into(), &cx.data.sni, false, resumedata)
                        }) {
                        Some(resume) => resume,
                        None => continue,
                    };

                    if !self.check_binder(
                        self.suite,
                        chm,
                        &resume.master_secret.0,
                        &psk_offer.binders[i].0,
                    ) {
                        cx.common
                            .send_fatal_alert(AlertDescription::DecryptError);
                        return Err(Error::PeerMisbehavedError(
                            "client sent wrong binder".to_string(),
                        ));
                    }

                    chosen_psk_index = Some(i);
                    resumedata = Some(resume);
                    break;
                }
            }

            if !client_hello.psk_mode_offered(PSKKeyExchangeMode::PSK_DHE_KE) {
                debug!("Client unwilling to resume, DHE_KE not offered");
                self.send_ticket = false;
                chosen_psk_index = None;
                resumedata = None;
            } else {
                self.send_ticket = true;
            }

            if let Some(ref resume) = resumedata {
                cx.data.received_resumption_data = Some(resume.application_data.0.clone());
                cx.data.client_cert_chain = resume.client_cert_chain.clone();
            }

            let full_handshake = resumedata.is_none();
            self.transcript.add_message(chm);
            let key_schedule = emit_server_hello(
                &mut self.transcript,
                &self.randoms,
                self.suite,
                cx,
                &client_hello.session_id,
                chosen_share,
                chosen_psk_index,
                resumedata
                    .as_ref()
                    .map(|x| &x.master_secret.0[..]),
                &self.config,
            )?;
            if !self.done_retry {
                emit_fake_ccs(&mut cx.common);
            }

            let (mut ocsp_response, mut sct_list) =
                (server_key.get_ocsp(), server_key.get_sct_list());
            emit_encrypted_extensions(
                &mut self.transcript,
                self.suite,
                cx,
                &mut ocsp_response,
                &mut sct_list,
                client_hello,
                resumedata.as_ref(),
                self.extra_exts,
                &self.config,
            )?;

            let doing_client_auth = if full_handshake {
                let client_auth =
                    emit_certificate_req_tls13(&mut self.transcript, cx, &self.config)?;
                emit_certificate_tls13(
                    &mut self.transcript,
                    &mut cx.common,
                    server_key.get_cert(),
                    ocsp_response,
                    sct_list,
                );
                emit_certificate_verify_tls13(
                    &mut self.transcript,
                    &mut cx.common,
                    server_key.get_key(),
                    &sigschemes_ext,
                )?;
                client_auth
            } else {
                false
            };

            cx.common.check_aligned_handshake()?;
            let key_schedule_traffic = emit_finished_tls13(
                &mut self.transcript,
                self.suite,
                &self.randoms,
                cx,
                key_schedule,
                &self.config,
            );

            if doing_client_auth {
                Ok(Box::new(ExpectCertificate {
                    config: self.config,
                    transcript: self.transcript,
                    suite: self.suite,
                    key_schedule: key_schedule_traffic,
                    send_ticket: self.send_ticket,
                }))
            } else {
                Ok(Box::new(ExpectFinished {
                    config: self.config,
                    transcript: self.transcript,
                    suite: self.suite,
                    key_schedule: key_schedule_traffic,
                    send_ticket: self.send_ticket,
                }))
            }
        }
    }

    fn emit_server_hello(
        transcript: &mut HandshakeHash,
        randoms: &ConnectionRandoms,
        suite: &'static Tls13CipherSuite,
        cx: &mut ServerContext<'_>,
        session_id: &SessionID,
        share: &KeyShareEntry,
        chosen_psk_idx: Option<usize>,
        resuming_psk: Option<&[u8]>,
        config: &ServerConfig,
    ) -> Result<KeyScheduleHandshake, Error> {
        let mut extensions = Vec::new();

        // Do key exchange
        let kxr = kx::KeyExchange::choose(share.group, &config.kx_groups)
            .and_then(kx::KeyExchange::start)
            .ok_or(Error::FailedToGetRandomBytes)?
            .complete(&share.payload.0)
            .ok_or_else(|| Error::PeerMisbehavedError("key exchange failed".to_string()))?;

        let kse = KeyShareEntry::new(share.group, kxr.pubkey.as_ref());
        extensions.push(ServerExtension::KeyShare(kse));
        extensions.push(ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_3));

        if let Some(psk_idx) = chosen_psk_idx {
            extensions.push(ServerExtension::PresharedKey(psk_idx as u16));
        }

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHello,
                payload: HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: Random::from(randoms.server),
                    session_id: *session_id,
                    cipher_suite: suite.common.suite,
                    compression_method: Compression::Null,
                    extensions,
                }),
            }),
        };

        cx.common.check_aligned_handshake()?;

        #[cfg(feature = "quic")]
        let client_hello_hash = transcript.get_hash_given(&[]);

        trace!("sending server hello {:?}", sh);
        transcript.add_message(&sh);
        cx.common.send_msg(sh, false);

        // Start key schedule
        let key_schedule = if let Some(psk) = resuming_psk {
            let early_key_schedule = KeyScheduleEarly::new(suite.hkdf_algorithm, psk);

            #[cfg(feature = "quic")]
            {
                if cx.common.protocol == Protocol::Quic {
                    let client_early_traffic_secret = early_key_schedule
                        .client_early_traffic_secret(
                            &client_hello_hash,
                            &*config.key_log,
                            &randoms.client,
                        );
                    // If 0-RTT should be rejected, this will be clobbered by ExtensionProcessing
                    // before the application can see.
                    cx.common.quic.early_secret = Some(client_early_traffic_secret);
                }
            }

            early_key_schedule.into_handshake(&kxr.shared_secret)
        } else {
            KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&kxr.shared_secret)
        };

        let handshake_hash = transcript.get_current_hash();
        let (key_schedule, client_key, server_key) = key_schedule.derive_handshake_secrets(
            handshake_hash,
            &*config.key_log,
            &randoms.client,
        );

        // Encrypt with our own key, decrypt with the peer's key
        cx.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(suite, &server_key));
        cx.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(suite, &client_key));

        #[cfg(feature = "quic")]
        {
            cx.common.quic.hs_secrets =
                Some(quic::Secrets::new(client_key, server_key, suite, false));
        }

        Ok(key_schedule)
    }

    fn emit_fake_ccs(common: &mut ConnectionCommon) {
        if common.is_quic() {
            return;
        }
        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };
        common.send_msg(m, false);
    }

    fn emit_hello_retry_request(
        transcript: &mut HandshakeHash,
        suite: &'static Tls13CipherSuite,
        common: &mut ConnectionCommon,
        group: NamedGroup,
    ) {
        let mut req = HelloRetryRequest {
            legacy_version: ProtocolVersion::TLSv1_2,
            session_id: SessionID::empty(),
            cipher_suite: suite.common.suite,
            extensions: Vec::new(),
        };

        req.extensions
            .push(HelloRetryExtension::KeyShare(group));
        req.extensions
            .push(HelloRetryExtension::SupportedVersions(
                ProtocolVersion::TLSv1_3,
            ));

        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::HelloRetryRequest,
                payload: HandshakePayload::HelloRetryRequest(req),
            }),
        };

        trace!("Requesting retry {:?}", m);
        transcript.rollup_for_hrr();
        transcript.add_message(&m);
        common.send_msg(m, false);
    }

    fn emit_encrypted_extensions(
        transcript: &mut HandshakeHash,
        suite: &'static Tls13CipherSuite,
        cx: &mut ServerContext<'_>,
        ocsp_response: &mut Option<&[u8]>,
        sct_list: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&persist::ServerSessionValue>,
        extra_exts: Vec<ServerExtension>,
        config: &ServerConfig,
    ) -> Result<(), Error> {
        let mut ep = hs::ExtensionProcessing::new();
        ep.process_common(
            config,
            cx,
            suite.into(),
            ocsp_response,
            sct_list,
            hello,
            resumedata,
            extra_exts,
        )?;

        let ee = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::EncryptedExtensions,
                payload: HandshakePayload::EncryptedExtensions(ep.exts),
            }),
        };

        trace!("sending encrypted extensions {:?}", ee);
        transcript.add_message(&ee);
        cx.common.send_msg(ee, true);
        Ok(())
    }

    fn emit_certificate_req_tls13(
        transcript: &mut HandshakeHash,
        cx: &mut ServerContext<'_>,
        config: &ServerConfig,
    ) -> Result<bool, Error> {
        if !config.verifier.offer_client_auth() {
            return Ok(false);
        }

        let mut cr = CertificateRequestPayloadTLS13 {
            context: PayloadU8::empty(),
            extensions: Vec::new(),
        };

        let schemes = config
            .verifier
            .supported_verify_schemes();
        cr.extensions
            .push(CertReqExtension::SignatureAlgorithms(schemes.to_vec()));

        let names = config
            .verifier
            .client_auth_root_subjects(cx.data.get_sni().as_ref())
            .ok_or_else(|| {
                debug!("could not determine root subjects based on SNI");
                cx.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("client rejected by client_auth_root_subjects".into())
            })?;

        if !names.is_empty() {
            cr.extensions
                .push(CertReqExtension::AuthorityNames(names));
        }

        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateRequest,
                payload: HandshakePayload::CertificateRequestTLS13(cr),
            }),
        };

        trace!("Sending CertificateRequest {:?}", m);
        transcript.add_message(&m);
        cx.common.send_msg(m, true);
        Ok(true)
    }

    fn emit_certificate_tls13(
        transcript: &mut HandshakeHash,
        common: &mut ConnectionCommon,
        cert_chain: &[Certificate],
        ocsp_response: Option<&[u8]>,
        sct_list: Option<&[u8]>,
    ) {
        let mut cert_entries = vec![];
        for cert in cert_chain {
            let entry = CertificateEntry {
                cert: cert.to_owned(),
                exts: Vec::new(),
            };

            cert_entries.push(entry);
        }

        if let Some(end_entity_cert) = cert_entries.first_mut() {
            // Apply OCSP response to first certificate (we don't support OCSP
            // except for leaf certs).
            if let Some(ocsp) = ocsp_response {
                let cst = CertificateStatus::new(ocsp.to_owned());
                end_entity_cert
                    .exts
                    .push(CertificateExtension::CertificateStatus(cst));
            }

            // Likewise, SCT
            if let Some(sct_list) = sct_list {
                end_entity_cert
                    .exts
                    .push(CertificateExtension::make_sct(sct_list.to_owned()));
            }
        }

        let cert_body = CertificatePayloadTLS13::new(cert_entries);
        let c = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Certificate,
                payload: HandshakePayload::CertificateTLS13(cert_body),
            }),
        };

        trace!("sending certificate {:?}", c);
        transcript.add_message(&c);
        common.send_msg(c, true);
    }

    fn emit_certificate_verify_tls13(
        transcript: &mut HandshakeHash,
        common: &mut ConnectionCommon,
        signing_key: &dyn sign::SigningKey,
        schemes: &[SignatureScheme],
    ) -> Result<(), Error> {
        let message = verify::construct_tls13_server_verify_message(&transcript.get_current_hash());

        let signer = signing_key
            .choose_scheme(schemes)
            .ok_or_else(|| hs::incompatible(common, "no overlapping sigschemes"))?;

        let scheme = signer.scheme();
        let sig = signer.sign(&message)?;

        let cv = DigitallySignedStruct::new(scheme, sig);

        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateVerify,
                payload: HandshakePayload::CertificateVerify(cv),
            }),
        };

        trace!("sending certificate-verify {:?}", m);
        transcript.add_message(&m);
        common.send_msg(m, true);
        Ok(())
    }

    fn emit_finished_tls13(
        transcript: &mut HandshakeHash,
        suite: &'static Tls13CipherSuite,
        randoms: &ConnectionRandoms,
        cx: &mut ServerContext<'_>,
        key_schedule: KeyScheduleHandshake,
        config: &ServerConfig,
    ) -> KeyScheduleTrafficWithClientFinishedPending {
        let handshake_hash = transcript.get_current_hash();
        let verify_data = key_schedule.sign_server_finish(&handshake_hash);
        let verify_data_payload = Payload::new(verify_data.as_ref());

        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(verify_data_payload),
            }),
        };

        trace!("sending finished {:?}", m);
        transcript.add_message(&m);
        let hash_at_server_fin = transcript.get_current_hash();
        cx.common.send_msg(m, true);

        // Now move to application data keys.  Read key change is deferred until
        // the Finish message is received & validated.
        let (key_schedule_traffic, _client_key, server_key) = key_schedule
            .into_traffic_with_client_finished_pending(
                hash_at_server_fin,
                &*config.key_log,
                &randoms.client,
            );
        cx.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(suite, &server_key));

        #[cfg(feature = "quic")]
        {
            cx.common.quic.traffic_secrets =
                Some(quic::Secrets::new(_client_key, server_key, suite, false));
        }

        key_schedule_traffic
    }
}

struct ExpectCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_ticket: bool,
}

impl hs::State for ExpectCertificate {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message) -> hs::NextStateOrError {
        let certp = require_handshake_msg!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTLS13
        )?;
        self.transcript.add_message(&m);

        // We don't send any CertificateRequest extensions, so any extensions
        // here are illegal.
        if certp.any_entry_has_extension() {
            return Err(Error::PeerMisbehavedError(
                "client sent unsolicited cert extension".to_string(),
            ));
        }

        let client_cert = certp.convert();

        let mandatory = self
            .config
            .verifier
            .client_auth_mandatory(cx.data.get_sni().as_ref())
            .ok_or_else(|| {
                debug!("could not determine if client auth is mandatory based on SNI");
                cx.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("client rejected by client_auth_mandatory".into())
            })?;

        let (end_entity, intermediates) = match client_cert.split_first() {
            None => {
                if !mandatory {
                    debug!("client auth requested but no certificate supplied");
                    self.transcript.abandon_client_auth();
                    return Ok(Box::new(ExpectFinished {
                        config: self.config,
                        suite: self.suite,
                        key_schedule: self.key_schedule,
                        transcript: self.transcript,
                        send_ticket: self.send_ticket,
                    }));
                }

                cx.common
                    .send_fatal_alert(AlertDescription::CertificateRequired);
                return Err(Error::NoCertificatesPresented);
            }
            Some(chain) => chain,
        };

        let now = std::time::SystemTime::now();
        self.config
            .verifier
            .verify_client_cert(end_entity, intermediates, cx.data.get_sni().as_ref(), now)
            .map_err(|err| {
                hs::incompatible(&mut cx.common, "certificate invalid");
                err
            })?;

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_cert,
            send_ticket: self.send_ticket,
        }))
    }
}

struct ExpectCertificateVerify {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    client_cert: Vec<Certificate>,
    send_ticket: bool,
}

impl hs::State for ExpectCertificateVerify {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message) -> hs::NextStateOrError {
        let rc = {
            let sig = require_handshake_msg!(
                m,
                HandshakeType::CertificateVerify,
                HandshakePayload::CertificateVerify
            )?;
            let handshake_hash = self.transcript.get_current_hash();
            self.transcript.abandon_client_auth();
            let certs = &self.client_cert;
            let msg = verify::construct_tls13_client_verify_message(&handshake_hash);

            self.config
                .verifier
                .verify_tls13_signature(&msg, &certs[0], sig)
        };

        if let Err(e) = rc {
            cx.common
                .send_fatal_alert(AlertDescription::AccessDenied);
            return Err(e);
        }

        trace!("client CertificateVerify OK");
        cx.data.client_cert_chain = Some(self.client_cert);

        self.transcript.add_message(&m);
        Ok(Box::new(ExpectFinished {
            config: self.config,
            suite: self.suite,
            key_schedule: self.key_schedule,
            transcript: self.transcript,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's Finished ---
fn get_server_session_value(
    transcript: &mut HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: &KeyScheduleTraffic,
    cx: &ServerContext<'_>,
    nonce: &[u8],
) -> persist::ServerSessionValue {
    let version = ProtocolVersion::TLSv1_3;

    let handshake_hash = transcript.get_current_hash();
    let secret =
        key_schedule.resumption_master_secret_and_derive_ticket_psk(&handshake_hash, nonce);

    persist::ServerSessionValue::new(
        cx.data.sni.as_ref(),
        version,
        suite.common.suite,
        secret,
        &cx.data.client_cert_chain,
        cx.common.alpn_protocol.clone(),
        cx.data.resumption_data.clone(),
    )
}

struct ExpectFinished {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_ticket: bool,
}

impl ExpectFinished {
    fn emit_ticket(
        transcript: &mut HandshakeHash,
        suite: &'static Tls13CipherSuite,
        cx: &mut ServerContext<'_>,
        key_schedule: &KeyScheduleTraffic,
        config: &ServerConfig,
    ) -> Result<(), rand::GetRandomFailed> {
        let nonce = rand::random_vec(32)?;
        let plain =
            get_server_session_value(transcript, suite, key_schedule, cx, &nonce).get_encoding();

        let stateless = config.ticketer.enabled();
        let (ticket, lifetime) = if stateless {
            let ticket = match config.ticketer.encrypt(&plain) {
                Some(t) => t,
                None => return Ok(()),
            };
            (ticket, config.ticketer.lifetime())
        } else {
            let id = rand::random_vec(32)?;
            let stored = config
                .session_storage
                .put(id.clone(), plain);
            if !stored {
                trace!("resumption not available; not issuing ticket");
                return Ok(());
            }
            let stateful_lifetime = 24 * 60 * 60; // this is a bit of a punt
            (id, stateful_lifetime)
        };

        let age_add = rand::random_u32()?; // nb, we don't do 0-RTT data, so whatever
        #[allow(unused_mut)]
        let mut payload = NewSessionTicketPayloadTLS13::new(lifetime, age_add, nonce, ticket);
        #[cfg(feature = "quic")]
        {
            if config.max_early_data_size > 0 && cx.common.protocol == Protocol::Quic {
                payload
                    .exts
                    .push(NewSessionTicketExtension::EarlyData(
                        config.max_early_data_size,
                    ));
            }
        }
        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::NewSessionTicket,
                payload: HandshakePayload::NewSessionTicketTLS13(payload),
            }),
        };

        trace!("sending new ticket {:?} (stateless: {})", m, stateless);
        transcript.add_message(&m);
        cx.common.send_msg(m, true);
        Ok(())
    }
}

impl hs::State for ExpectFinished {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message) -> hs::NextStateOrError {
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = self.transcript.get_current_hash();
        let (key_schedule_traffic, expect_verify_data, client_key) = self
            .key_schedule
            .sign_client_finish(&handshake_hash);

        let fin = constant_time::verify_slices_are_equal(expect_verify_data.as_ref(), &finished.0)
            .map_err(|_| {
                cx.common
                    .send_fatal_alert(AlertDescription::DecryptError);
                warn!("Finished wrong");
                Error::DecryptError
            })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        // nb. future derivations include Client Finished, but not the
        // main application data keying.
        self.transcript.add_message(&m);

        cx.common.check_aligned_handshake()?;

        // Install keying to read future messages.
        cx.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(self.suite, &client_key));

        if self.send_ticket {
            Self::emit_ticket(
                &mut self.transcript,
                self.suite,
                cx,
                &key_schedule_traffic,
                &self.config,
            )?;
        }

        cx.common.start_traffic();

        #[cfg(feature = "quic")]
        {
            if cx.common.protocol == Protocol::Quic {
                return Ok(Box::new(ExpectQuicTraffic {
                    key_schedule: key_schedule_traffic,
                    _fin_verified: fin,
                }));
            }
        }

        Ok(Box::new(ExpectTraffic {
            suite: self.suite,
            key_schedule: key_schedule_traffic,
            want_write_key_update: false,
            _fin_verified: fin,
        }))
    }
}

// --- Process traffic ---
struct ExpectTraffic {
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTraffic,
    want_write_key_update: bool,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_key_update(
        &mut self,
        common: &mut ConnectionCommon,
        kur: &KeyUpdateRequest,
    ) -> Result<(), Error> {
        #[cfg(feature = "quic")]
        {
            if let Protocol::Quic = common.protocol {
                common.send_fatal_alert(AlertDescription::UnexpectedMessage);
                let msg = "KeyUpdate received in QUIC connection".to_string();
                warn!("{}", msg);
                return Err(Error::PeerMisbehavedError(msg));
            }
        }

        common.check_aligned_handshake()?;

        match kur {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => {
                self.want_write_key_update = true;
            }
            _ => {
                common.send_fatal_alert(AlertDescription::IllegalParameter);
                return Err(Error::CorruptMessagePayload(ContentType::Handshake));
            }
        }

        // Update our read-side keys.
        let new_read_key = self
            .key_schedule
            .next_client_application_traffic_secret();
        common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(self.suite, &new_read_key));

        Ok(())
    }
}

impl hs::State for ExpectTraffic {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext, m: Message) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx
                .common
                .take_received_plaintext(payload),
            MessagePayload::Handshake(payload) => match payload.payload {
                HandshakePayload::KeyUpdate(key_update) => {
                    self.handle_key_update(cx.common, &key_update)?
                }
                _ => {
                    return Err(inappropriate_handshake_message(
                        &payload,
                        &[HandshakeType::KeyUpdate],
                    ));
                }
            },
            _ => {
                return Err(inappropriate_message(
                    &m,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                ));
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
        self.key_schedule
            .export_keying_material(output, label, context)
    }

    fn perhaps_write_key_update(&mut self, common: &mut ConnectionCommon) {
        if self.want_write_key_update {
            self.want_write_key_update = false;
            common.send_msg_encrypt(Message::build_key_update_notify().into());

            let write_key = self
                .key_schedule
                .next_server_application_traffic_secret();
            common
                .record_layer
                .set_message_encrypter(cipher::new_tls13_write(self.suite, &write_key));
        }
    }
}

#[cfg(feature = "quic")]
struct ExpectQuicTraffic {
    key_schedule: KeyScheduleTraffic,
    _fin_verified: verify::FinishedMessageVerified,
}

#[cfg(feature = "quic")]
impl hs::State for ExpectQuicTraffic {
    fn handle(self: Box<Self>, _cx: &mut ServerContext<'_>, m: Message) -> hs::NextStateOrError {
        // reject all messages
        check_message(&m, &[], &[])?;
        unreachable!();
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.key_schedule
            .export_keying_material(output, label, context)
    }
}
