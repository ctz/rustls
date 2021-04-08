use crate::check::check_message;
use crate::conn::{ConnectionRandoms, ConnectionSecrets};
use crate::error::Error;
use crate::hash_hs::HandshakeHash;
use crate::key::Certificate;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::handshake::{ClientECDHParams, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::handshake::{NewSessionTicketPayload, SessionID};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::server::ServerConnection;
use crate::verify;
use crate::{kx, tls12};

use crate::server::common::ActiveCertifiedKey;
use crate::server::hs;

use ring::constant_time;

use crate::suites::Tls12CipherSuite;
pub(super) use client_hello::CompleteClientHelloHandling;

mod client_hello {
    use crate::msgs::enums::ECPointFormat;
    use crate::msgs::enums::{ClientCertificateType, Compression, SignatureScheme};
    use crate::msgs::handshake::{CertificateRequestPayload, Random};
    use crate::msgs::handshake::{
        CertificateStatus, DigitallySignedStruct, ECDHEServerKeyExchange,
    };
    use crate::msgs::handshake::{ClientExtension, SessionID};
    use crate::msgs::handshake::{ClientHelloPayload, ServerHelloPayload};
    use crate::msgs::handshake::{ECPointFormatList, ServerECDHParams, SupportedPointFormats};
    use crate::msgs::handshake::{ServerExtension, ServerKeyExchangePayload};
    use crate::sign;

    use super::*;
    use crate::suites::Tls12CipherSuite;

    pub(in crate::server) struct CompleteClientHelloHandling {
        pub(in crate::server) transcript: HandshakeHash,
        pub(in crate::server) session_id: SessionID,
        pub(in crate::server) suite: Tls12CipherSuite,
        pub(in crate::server) using_ems: bool,
        pub(in crate::server) randoms: ConnectionRandoms,
        pub(in crate::server) send_ticket: bool,
        pub(in crate::server) extra_exts: Vec<ServerExtension>,
    }

    impl CompleteClientHelloHandling {
        pub(in crate::server) fn handle_client_hello(
            mut self,
            conn: &mut ServerConnection,
            server_key: ActiveCertifiedKey,
            chm: &Message,
            client_hello: &ClientHelloPayload,
            sigschemes_ext: Vec<SignatureScheme>,
            tls13_enabled: bool,
        ) -> hs::NextStateOrError {
            // -- TLS1.2 only from hereon in --
            self.transcript.add_message(&chm);

            if client_hello.ems_support_offered() {
                self.using_ems = true;
            }

            let groups_ext = client_hello
                .get_namedgroups_extension()
                .ok_or_else(|| hs::incompatible(conn, "client didn't describe groups"))?;
            let ecpoints_ext = client_hello
                .get_ecpoints_extension()
                .ok_or_else(|| hs::incompatible(conn, "client didn't describe ec points"))?;

            trace!("namedgroups {:?}", groups_ext);
            trace!("ecpoints {:?}", ecpoints_ext);

            if !ecpoints_ext.contains(&ECPointFormat::Uncompressed) {
                conn.common
                    .send_fatal_alert(AlertDescription::IllegalParameter);
                return Err(Error::PeerIncompatibleError(
                    "client didn't support uncompressed ec points".to_string(),
                ));
            }

            // -- If TLS1.3 is enabled, signal the downgrade in the server random
            if tls13_enabled {
                self.randoms
                    .set_tls12_downgrade_marker();
            }

            // -- Check for resumption --
            // We can do this either by (in order of preference):
            // 1. receiving a ticket that decrypts
            // 2. receiving a connionid that is in our cache
            //
            // If we receive a ticket, the connionid won't be in our
            // cache, so don't check.
            //
            // If either works, we end up with a ServerConnectionValue
            // which is passed to start_resumption and concludes
            // our handling of the ClientHello.
            //
            let mut ticket_received = false;
            let resume_data = client_hello
                .get_ticket_extension()
                .and_then(|ticket_ext| match ticket_ext {
                    ClientExtension::SessionTicketOffer(ticket) => Some(ticket),
                    _ => None,
                })
                .and_then(|ticket| {
                    ticket_received = true;
                    debug!("Ticket received");
                    let data = conn.config.ticketer.decrypt(&ticket.0);
                    if data.is_none() {
                        debug!("Ticket didn't decrypt");
                    }
                    data
                })
                .or_else(|| {
                    // Perhaps resume?  If we received a ticket, the sessionid
                    // does not correspond to a real session.
                    if client_hello.session_id.is_empty() || ticket_received {
                        return None;
                    }

                    conn.config
                        .session_storage
                        .get(&client_hello.session_id.get_encoding())
                })
                .and_then(|x| persist::ServerSessionValue::read_bytes(&x))
                .filter(|resumedata| {
                    hs::can_resume(
                        self.suite.supported_suite(),
                        &conn.data.sni,
                        self.using_ems,
                        resumedata,
                    )
                });

            if let Some(data) = resume_data {
                return self.start_resumption(conn, client_hello, &client_hello.session_id, data);
            }

            // Now we have chosen a ciphersuite, we can make kx decisions.
            let sigschemes = self
                .suite
                .resolve_sig_schemes(&sigschemes_ext);

            if sigschemes.is_empty() {
                return Err(hs::incompatible(conn, "no overlapping sigschemes"));
            }

            let group = conn
                .config
                .kx_groups
                .iter()
                .find(|skxg| groups_ext.contains(&skxg.name))
                .cloned()
                .ok_or_else(|| hs::incompatible(conn, "no supported group"))?;

            let ecpoint = ECPointFormatList::supported()
                .iter()
                .find(|format| ecpoints_ext.contains(format))
                .cloned()
                .ok_or_else(|| hs::incompatible(conn, "no supported point format"))?;

            debug_assert_eq!(ecpoint, ECPointFormat::Uncompressed);

            let (mut ocsp_response, mut sct_list) =
                (server_key.get_ocsp(), server_key.get_sct_list());

            // If we're not offered a ticket or a potential connection ID,
            // allocate a connection ID.
            if self.session_id.is_empty() && !ticket_received {
                self.session_id = SessionID::random()?;
            }

            self.send_ticket = emit_server_hello(
                &mut self.transcript,
                conn,
                self.session_id,
                self.suite,
                self.using_ems,
                &mut ocsp_response,
                &mut sct_list,
                client_hello,
                None,
                &self.randoms,
                self.extra_exts,
            )?;
            emit_certificate(&mut self.transcript, conn, server_key.get_cert());
            if let Some(ocsp_response) = ocsp_response {
                emit_cert_status(&mut self.transcript, conn, ocsp_response);
            }
            let server_kx = emit_server_kx(
                &mut self.transcript,
                conn,
                sigschemes,
                group,
                server_key.get_key(),
                &self.randoms,
            )?;
            let doing_client_auth = emit_certificate_req(&mut self.transcript, conn)?;
            emit_server_hello_done(&mut self.transcript, conn);

            if doing_client_auth {
                Ok(Box::new(ExpectCertificate {
                    transcript: self.transcript,
                    randoms: self.randoms,
                    session_id: self.session_id,
                    suite: self.suite,
                    using_ems: self.using_ems,
                    server_kx,
                    send_ticket: self.send_ticket,
                }))
            } else {
                Ok(Box::new(ExpectClientKx {
                    transcript: self.transcript,
                    randoms: self.randoms,
                    session_id: self.session_id,
                    suite: self.suite,
                    using_ems: self.using_ems,
                    server_kx,
                    client_cert: None,
                    send_ticket: self.send_ticket,
                }))
            }
        }

        fn start_resumption(
            mut self,
            conn: &mut ServerConnection,
            client_hello: &ClientHelloPayload,
            id: &SessionID,
            resumedata: persist::ServerSessionValue,
        ) -> hs::NextStateOrError {
            debug!("Resuming connion");

            if resumedata.extended_ms && !self.using_ems {
                return Err(conn
                    .common
                    .illegal_param("refusing to resume without ems"));
            }

            self.session_id = *id;
            self.send_ticket = emit_server_hello(
                &mut self.transcript,
                conn,
                self.session_id,
                self.suite,
                self.using_ems,
                &mut None,
                &mut None,
                client_hello,
                Some(&resumedata),
                &self.randoms,
                self.extra_exts,
            )?;

            let secrets = ConnectionSecrets::new_resume(
                &self.randoms,
                self.suite,
                &resumedata.master_secret.0,
            );
            conn.config.key_log.log(
                "CLIENT_RANDOM",
                &secrets.randoms.client,
                &secrets.master_secret,
            );
            conn.common
                .start_encryption_tls12(&secrets);
            conn.data.client_cert_chain = resumedata.client_cert_chain;

            if self.send_ticket {
                emit_ticket(&secrets, &mut self.transcript, self.using_ems, conn);
            }
            emit_ccs(conn);
            conn.common
                .record_layer
                .start_encrypting();
            emit_finished(&secrets, &mut self.transcript, conn);

            Ok(Box::new(ExpectCcs {
                secrets,
                transcript: self.transcript,
                session_id: self.session_id,
                using_ems: self.using_ems,
                resuming: true,
                send_ticket: self.send_ticket,
            }))
        }
    }

    fn emit_server_hello(
        transcript: &mut HandshakeHash,
        conn: &mut ServerConnection,
        session_id: SessionID,
        suite: Tls12CipherSuite,
        using_ems: bool,
        ocsp_response: &mut Option<&[u8]>,
        sct_list: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&persist::ServerSessionValue>,
        randoms: &ConnectionRandoms,
        extra_exts: Vec<ServerExtension>,
    ) -> Result<bool, Error> {
        let mut ep = hs::ExtensionProcessing::new();
        ep.process_common(
            conn,
            suite.supported_suite(),
            ocsp_response,
            sct_list,
            hello,
            resumedata,
            extra_exts,
        )?;
        ep.process_tls12(conn, hello, using_ems);

        let sh = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHello,
                payload: HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: Random::from(randoms.server),
                    session_id,
                    cipher_suite: suite.supported_suite().suite,
                    compression_method: Compression::Null,
                    extensions: ep.exts,
                }),
            }),
        };

        trace!("sending server hello {:?}", sh);
        transcript.add_message(&sh);
        conn.common.send_msg(sh, false);
        Ok(ep.send_ticket)
    }

    fn emit_certificate(
        transcript: &mut HandshakeHash,
        conn: &mut ServerConnection,
        cert_chain: &[Certificate],
    ) {
        let c = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Certificate,
                payload: HandshakePayload::Certificate(cert_chain.to_owned()),
            }),
        };

        transcript.add_message(&c);
        conn.common.send_msg(c, false);
    }

    fn emit_cert_status(transcript: &mut HandshakeHash, conn: &mut ServerConnection, ocsp: &[u8]) {
        let st = CertificateStatus::new(ocsp.to_owned());

        let c = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateStatus,
                payload: HandshakePayload::CertificateStatus(st),
            }),
        };

        transcript.add_message(&c);
        conn.common.send_msg(c, false);
    }

    fn emit_server_kx(
        transcript: &mut HandshakeHash,
        conn: &mut ServerConnection,
        sigschemes: Vec<SignatureScheme>,
        skxg: &'static kx::SupportedKxGroup,
        signing_key: &dyn sign::SigningKey,
        randoms: &ConnectionRandoms,
    ) -> Result<kx::KeyExchange, Error> {
        let kx = kx::KeyExchange::start(skxg).ok_or(Error::FailedToGetRandomBytes)?;
        let secdh = ServerECDHParams::new(skxg.name, kx.pubkey.as_ref());

        let mut msg = Vec::new();
        msg.extend(&randoms.client);
        msg.extend(&randoms.server);
        secdh.encode(&mut msg);

        let signer = signing_key
            .choose_scheme(&sigschemes)
            .ok_or_else(|| Error::General("incompatible signing key".to_string()))?;
        let sigscheme = signer.get_scheme();
        let sig = signer.sign(&msg)?;

        let skx = ServerKeyExchangePayload::ECDHE(ECDHEServerKeyExchange {
            params: secdh,
            dss: DigitallySignedStruct::new(sigscheme, sig),
        });

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerKeyExchange,
                payload: HandshakePayload::ServerKeyExchange(skx),
            }),
        };

        transcript.add_message(&m);
        conn.common.send_msg(m, false);
        Ok(kx)
    }

    fn emit_certificate_req(
        transcript: &mut HandshakeHash,
        conn: &mut ServerConnection,
    ) -> Result<bool, Error> {
        let client_auth = conn.config.get_verifier();

        if !client_auth.offer_client_auth() {
            return Ok(false);
        }

        let verify_schemes = client_auth.supported_verify_schemes();

        let names = client_auth
            .client_auth_root_subjects(conn.data.get_sni())
            .ok_or_else(|| {
                debug!("could not determine root subjects based on SNI");
                conn.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("client rejected by client_auth_root_subjects".into())
            })?;

        let cr = CertificateRequestPayload {
            certtypes: vec![
                ClientCertificateType::RSASign,
                ClientCertificateType::ECDSASign,
            ],
            sigschemes: verify_schemes,
            canames: names,
        };

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateRequest,
                payload: HandshakePayload::CertificateRequest(cr),
            }),
        };

        trace!("Sending CertificateRequest {:?}", m);
        transcript.add_message(&m);
        conn.common.send_msg(m, false);
        Ok(true)
    }

    fn emit_server_hello_done(transcript: &mut HandshakeHash, conn: &mut ServerConnection) {
        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHelloDone,
                payload: HandshakePayload::ServerHelloDone,
            }),
        };

        transcript.add_message(&m);
        conn.common.send_msg(m, false);
    }
}

// --- Process client's Certificate for client auth ---
struct ExpectCertificate {
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    session_id: SessionID,
    suite: Tls12CipherSuite,
    using_ems: bool,
    server_kx: kx::KeyExchange,
    send_ticket: bool,
}

impl hs::State for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);
        let cert_chain = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        // If we can't determine if the auth is mandatory, abort
        let mandatory = conn
            .config
            .verifier
            .client_auth_mandatory(conn.data.get_sni())
            .ok_or_else(|| {
                debug!("could not determine if client auth is mandatory based on SNI");
                conn.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("client rejected by client_auth_mandatory".into())
            })?;

        trace!("certs {:?}", cert_chain);

        let client_cert = match cert_chain.split_first() {
            None if mandatory => {
                conn.common
                    .send_fatal_alert(AlertDescription::CertificateRequired);
                return Err(Error::NoCertificatesPresented);
            }
            None => {
                debug!("client auth requested but no certificate supplied");
                self.transcript.abandon_client_auth();
                None
            }
            Some((end_entity, intermediates)) => {
                let now = std::time::SystemTime::now();
                conn.config
                    .verifier
                    .verify_client_cert(end_entity, intermediates, conn.data.get_sni(), now)
                    .or_else(|err| {
                        hs::incompatible(conn, "certificate invalid");
                        Err(err)
                    })?;

                Some(cert_chain)
            }
        };

        Ok(Box::new(ExpectClientKx {
            transcript: self.transcript,
            randoms: self.randoms,
            session_id: self.session_id,
            suite: self.suite,
            using_ems: self.using_ems,
            server_kx: self.server_kx,
            client_cert,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's KeyExchange ---
struct ExpectClientKx {
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    session_id: SessionID,
    suite: Tls12CipherSuite,
    using_ems: bool,
    server_kx: kx::KeyExchange,
    client_cert: Option<Vec<Certificate>>,
    send_ticket: bool,
}

impl hs::State for ExpectClientKx {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let client_kx = require_handshake_msg!(
            m,
            HandshakeType::ClientKeyExchange,
            HandshakePayload::ClientKeyExchange
        )?;
        self.transcript.add_message(&m);

        // Complete key agreement, and set up encryption with the
        // resulting premaster secret.
        let peer_kx_params =
            tls12::decode_ecdh_params::<ClientECDHParams>(&mut conn.common, &client_kx.0)?;
        let kxd = tls12::complete_ecdh(self.server_kx, &peer_kx_params.public.0)?;

        let secrets = if self.using_ems {
            let handshake_hash = self.transcript.get_current_hash();
            ConnectionSecrets::new_ems(
                &self.randoms,
                &handshake_hash,
                self.suite,
                &kxd.shared_secret,
            )
        } else {
            ConnectionSecrets::new(&self.randoms, self.suite, &kxd.shared_secret)
        };
        conn.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        conn.common
            .start_encryption_tls12(&secrets);

        if let Some(client_cert) = self.client_cert {
            Ok(Box::new(ExpectCertificateVerify {
                secrets,
                transcript: self.transcript,
                session_id: self.session_id,
                using_ems: self.using_ems,
                client_cert,
                send_ticket: self.send_ticket,
            }))
        } else {
            Ok(Box::new(ExpectCcs {
                secrets,
                transcript: self.transcript,
                session_id: self.session_id,
                using_ems: self.using_ems,
                resuming: false,
                send_ticket: self.send_ticket,
            }))
        }
    }
}

// --- Process client's certificate proof ---
struct ExpectCertificateVerify {
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionID,
    using_ems: bool,
    client_cert: Vec<Certificate>,
    send_ticket: bool,
}

impl hs::State for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let rc = {
            let sig = require_handshake_msg!(
                m,
                HandshakeType::CertificateVerify,
                HandshakePayload::CertificateVerify
            )?;
            let handshake_msgs = self.transcript.take_handshake_buf();
            let certs = &self.client_cert;

            conn.config
                .get_verifier()
                .verify_tls12_signature(&handshake_msgs, &certs[0], sig)
        };

        if let Err(e) = rc {
            conn.common
                .send_fatal_alert(AlertDescription::AccessDenied);
            return Err(e);
        }

        trace!("client CertificateVerify OK");
        conn.data.client_cert_chain = Some(self.client_cert);

        self.transcript.add_message(&m);
        Ok(Box::new(ExpectCcs {
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            using_ems: self.using_ems,
            resuming: false,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's ChangeCipherSpec ---
struct ExpectCcs {
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionID,
    using_ems: bool,
    resuming: bool,
    send_ticket: bool,
}

impl hs::State for ExpectCcs {
    fn handle(self: Box<Self>, conn: &mut ServerConnection, m: Message) -> hs::NextStateOrError {
        check_message(&m, &[ContentType::ChangeCipherSpec], &[])?;

        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        conn.common.check_aligned_handshake()?;

        conn.common
            .record_layer
            .start_decrypting();
        Ok(Box::new(ExpectFinished {
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            using_ems: self.using_ems,
            resuming: self.resuming,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's Finished ---
fn get_server_connion_value_tls12(
    secrets: &ConnectionSecrets,
    using_ems: bool,
    conn: &ServerConnection,
) -> persist::ServerSessionValue {
    let version = ProtocolVersion::TLSv1_2;
    let secret = secrets.get_master_secret();

    let mut v = persist::ServerSessionValue::new(
        conn.data.get_sni(),
        version,
        secrets.suite().supported_suite().suite,
        secret,
        &conn.data.client_cert_chain,
        conn.common.alpn_protocol.clone(),
        conn.data.resumption_data.clone(),
    );

    if using_ems {
        v.set_extended_ms_used();
    }

    v
}

fn emit_ticket(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    using_ems: bool,
    conn: &mut ServerConnection,
) {
    // If we can't produce a ticket for some reason, we can't
    // report an error. Send an empty one.
    let plain = get_server_connion_value_tls12(secrets, using_ems, conn).get_encoding();
    let ticket = conn
        .config
        .ticketer
        .encrypt(&plain)
        .unwrap_or_else(Vec::new);
    let ticket_lifetime = conn.config.ticketer.lifetime();

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicket(NewSessionTicketPayload::new(
                ticket_lifetime,
                ticket,
            )),
        }),
    };

    transcript.add_message(&m);
    conn.common.send_msg(m, false);
}

fn emit_ccs(conn: &mut ServerConnection) {
    let m = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    conn.common.send_msg(m, false);
}

fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    conn: &mut ServerConnection,
) {
    let vh = transcript.get_current_hash();
    let verify_data = secrets.server_verify_data(&vh);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    transcript.add_message(&f);
    conn.common.send_msg(f, true);
}

struct ExpectFinished {
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionID,
    using_ems: bool,
    resuming: bool,
    send_ticket: bool,
}

impl hs::State for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        conn.common.check_aligned_handshake()?;

        let vh = self.transcript.get_current_hash();
        let expect_verify_data = self.secrets.client_verify_data(&vh);

        let _fin_verified =
            constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
                .map_err(|_| {
                    conn.common
                        .send_fatal_alert(AlertDescription::DecryptError);
                    Error::DecryptError
                })
                .map(|_| verify::FinishedMessageVerified::assertion())?;

        // Save connion, perhaps
        if !self.resuming && !self.session_id.is_empty() {
            let value = get_server_connion_value_tls12(&self.secrets, self.using_ems, conn);

            let worked = conn
                .config
                .session_storage
                .put(self.session_id.get_encoding(), value.get_encoding());
            if worked {
                debug!("Session saved");
            } else {
                debug!("Session not saved");
            }
        }

        // Send our CCS and Finished.
        self.transcript.add_message(&m);
        if !self.resuming {
            if self.send_ticket {
                emit_ticket(&self.secrets, &mut self.transcript, self.using_ems, conn);
            }
            emit_ccs(conn);
            conn.common
                .record_layer
                .start_encrypting();
            emit_finished(&self.secrets, &mut self.transcript, conn);
        }

        conn.common.start_traffic();
        Ok(Box::new(ExpectTraffic {
            secrets: self.secrets,
            _fin_verified,
        }))
    }
}

// --- Process traffic ---
struct ExpectTraffic {
    secrets: ConnectionSecrets,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {}

impl hs::State for ExpectTraffic {
    fn handle(
        self: Box<Self>,
        conn: &mut ServerConnection,
        mut m: Message,
    ) -> hs::NextStateOrError {
        check_message(&m, &[ContentType::ApplicationData], &[])?;
        conn.common
            .take_received_plaintext(m.take_opaque_payload().unwrap());
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
