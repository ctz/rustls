use crate::check::check_message;
use crate::client::ClientConnection;
use crate::conn::ConnectionRandoms;
use crate::error::Error;
use crate::hash_hs::HandshakeHash;
use crate::key_schedule::{
    KeyScheduleEarly, KeyScheduleHandshake, KeyScheduleNonSecret, KeyScheduleTraffic,
    KeyScheduleTrafficWithClientFinishedPending,
};
use crate::kx;
#[cfg(feature = "logging")]
use crate::log::{debug, trace, warn};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::enums::{AlertDescription, NamedGroup, ProtocolVersion};
use crate::msgs::enums::{ContentType, ExtensionType, HandshakeType, SignatureScheme};
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::handshake::EncryptedExtensions;
use crate::msgs::handshake::NewSessionTicketPayloadTLS13;
use crate::msgs::handshake::{CertificateEntry, CertificatePayloadTLS13};
use crate::msgs::handshake::{ClientExtension, HelloRetryRequest, KeyShareEntry};
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::handshake::{HasServerExtensions, ServerHelloPayload, SessionID};
use crate::msgs::handshake::{PresharedKeyIdentity, PresharedKeyOffer};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::sign;
use crate::ticketer;
use crate::verify;
use crate::{cipher, SupportedCipherSuite};
#[cfg(feature = "quic")]
use crate::{conn::Protocol, msgs::base::PayloadU16, quic};

use crate::client::common::ServerCertDetails;
use crate::client::common::{ClientAuthDetails, ClientHelloDetails};
use crate::client::hs;

use ring::constant_time;
use ring::digest::Digest;

// Extensions we expect in plaintext in the ServerHello.
static ALLOWED_PLAINTEXT_EXTS: &[ExtensionType] = &[
    ExtensionType::KeyShare,
    ExtensionType::PreSharedKey,
    ExtensionType::SupportedVersions,
];

// Only the intersection of things we offer, and those disallowed
// in TLS1.3
static DISALLOWED_TLS13_EXTS: &[ExtensionType] = &[
    ExtensionType::ECPointFormats,
    ExtensionType::SessionTicket,
    ExtensionType::RenegotiationInfo,
    ExtensionType::ExtendedMasterSecret,
];

pub fn validate_server_hello(
    conn: &mut ClientConnection,
    server_hello: &ServerHelloPayload,
) -> Result<(), Error> {
    for ext in &server_hello.extensions {
        if !ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type()) {
            conn.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(Error::PeerMisbehavedError(
                "server sent unexpected cleartext ext".to_string(),
            ));
        }
    }

    Ok(())
}

fn find_kx_hint(conn: &ClientConnection, dns_name: webpki::DnsNameRef) -> Option<NamedGroup> {
    let key = persist::ClientSessionKey::hint_for_dns_name(dns_name);
    let key_buf = key.get_encoding();

    let maybe_value = conn
        .config
        .session_persistence
        .get(&key_buf);
    maybe_value.and_then(|enc| NamedGroup::read_bytes(&enc))
}

fn save_kx_hint(conn: &mut ClientConnection, dns_name: webpki::DnsNameRef, group: NamedGroup) {
    let key = persist::ClientSessionKey::hint_for_dns_name(dns_name);

    conn.config
        .session_persistence
        .put(key.get_encoding(), group.get_encoding());
}

pub fn choose_kx_groups(
    conn: &ClientConnection,
    exts: &mut Vec<ClientExtension>,
    hello: &mut ClientHelloDetails,
    dns_name: webpki::DnsNameRef,
    retryreq: Option<&HelloRetryRequest>,
) {
    // Choose our groups:
    // - if we've been asked via HelloRetryRequest for a specific
    //   one, do that.
    // - if not, we might have a hint of what the server supports.
    // - if not, send just the first configured group.
    //
    let group = retryreq
        .and_then(|req| HelloRetryRequest::get_requested_key_share_group(req))
        .or_else(|| find_kx_hint(conn, dns_name))
        .unwrap_or_else(|| {
            conn.config
                .kx_groups
                .get(0)
                .expect("No kx groups configured")
                .name
        });

    let mut key_shares = vec![];

    // in reply to HelloRetryRequest, we must not alter any existing key
    // shares
    if let Some(already_offered_share) = hello.find_key_share(group) {
        key_shares.push(KeyShareEntry::new(
            group,
            already_offered_share.pubkey.as_ref(),
        ));
        hello
            .offered_key_shares
            .push(already_offered_share);
    } else if let Some(key_share) =
        kx::KeyExchange::choose(group, &conn.config.kx_groups).and_then(kx::KeyExchange::start)
    {
        key_shares.push(KeyShareEntry::new(group, key_share.pubkey.as_ref()));
        hello.offered_key_shares.push(key_share);
    }

    exts.push(ClientExtension::KeyShare(key_shares));
}

/// This implements the horrifying TLS1.3 hack where PSK binders have a
/// data dependency on the message they are contained within.
pub fn fill_in_psk_binder(
    resuming: &persist::ClientSessionValueWithResolvedCipherSuite,
    transcript: &HandshakeHash,
    hmp: &mut HandshakeMessagePayload,
) -> KeyScheduleEarly {
    // We need to know the hash function of the suite we're trying to resume into.
    let suite = resuming.supported_cipher_suite();
    let hkdf_alg = suite.hkdf_algorithm;
    let suite_hash = suite.get_hash();

    // The binder is calculated over the clienthello, but doesn't include itself or its
    // length, or the length of its container.
    let binder_plaintext = hmp.get_encoding_for_binder_signing();
    let handshake_hash = transcript.get_hash_given(suite_hash, &binder_plaintext);

    // Run a fake key_schedule to simulate what the server will do if it chooses
    // to resume.
    let key_schedule = KeyScheduleEarly::new(hkdf_alg, &resuming.master_secret.0);
    let real_binder = key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);

    if let HandshakePayload::ClientHello(ref mut ch) = hmp.payload {
        ch.set_psk_binder(real_binder.as_ref());
    };

    key_schedule
}

pub fn start_handshake_traffic(
    suite: &'static SupportedCipherSuite,
    conn: &mut ClientConnection,
    early_key_schedule: Option<KeyScheduleEarly>,
    server_hello: &ServerHelloPayload,
    resuming_session: &mut Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    dns_name: webpki::DnsNameRef,
    transcript: &mut HandshakeHash,
    hello: &mut ClientHelloDetails,
    randoms: &ConnectionRandoms,
) -> Result<(KeyScheduleHandshake, Digest), Error> {
    let their_key_share = server_hello
        .get_key_share()
        .ok_or_else(|| {
            conn.common
                .send_fatal_alert(AlertDescription::MissingExtension);
            Error::PeerMisbehavedError("missing key share".to_string())
        })?;

    let our_key_share = hello
        .find_key_share_and_discard_others(their_key_share.group)
        .ok_or_else(|| hs::illegal_param(conn, "wrong group for key share"))?;
    let shared = our_key_share
        .complete(&their_key_share.payload.0)
        .ok_or_else(|| Error::PeerMisbehavedError("key exchange failed".to_string()))?;

    let mut key_schedule = if let Some(selected_psk) = server_hello.get_psk_index() {
        if let Some(ref resuming) = resuming_session {
            if !resuming
                .supported_cipher_suite()
                .can_resume_to(suite)
            {
                return Err(hs::illegal_param(
                    conn,
                    "server resuming incompatible suite",
                ));
            }

            // If the server varies the suite here, we will have encrypted early data with
            // the wrong suite.
            if conn.early_data.is_enabled() && resuming.supported_cipher_suite() != suite {
                return Err(hs::illegal_param(
                    conn,
                    "server varied suite with early data",
                ));
            }

            if selected_psk != 0 {
                return Err(hs::illegal_param(conn, "server selected invalid psk"));
            }

            debug!("Resuming using PSK");
            // The key schedule has been initialized and set in fill_in_psk_binder()
        } else {
            return Err(Error::PeerMisbehavedError(
                "server selected unoffered psk".to_string(),
            ));
        }
        early_key_schedule
            .unwrap()
            .into_handshake(&shared.shared_secret)
    } else {
        debug!("Not resuming");
        // Discard the early data key schedule.
        conn.early_data.rejected();
        conn.common.early_traffic = false;
        resuming_session.take();
        KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&shared.shared_secret)
    };

    // Remember what KX group the server liked for next time.
    save_kx_hint(conn, dns_name, their_key_share.group);

    // If we change keying when a subsequent handshake message is being joined,
    // the two halves will have different record layer protections.  Disallow this.
    hs::check_aligned_handshake(conn)?;

    let hash_at_client_recvd_server_hello = transcript.get_current_hash();

    let _maybe_write_key = if !conn.early_data.is_enabled() {
        // Set the client encryption key for handshakes if early data is not used
        let write_key = key_schedule.client_handshake_traffic_secret(
            &hash_at_client_recvd_server_hello,
            &*conn.config.key_log,
            &randoms.client,
        );
        conn.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
        Some(write_key)
    } else {
        None
    };

    let read_key = key_schedule.server_handshake_traffic_secret(
        &hash_at_client_recvd_server_hello,
        &*conn.config.key_log,
        &randoms.client,
    );
    conn.common
        .record_layer
        .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));

    #[cfg(feature = "quic")]
    {
        conn.common.quic.hs_secrets = Some(quic::Secrets {
            server: read_key,
            client: _maybe_write_key.unwrap_or_else(|| {
                key_schedule.client_handshake_traffic_secret(
                    &hash_at_client_recvd_server_hello,
                    &*conn.config.key_log,
                    &randoms.client,
                )
            }),
        });
    }

    Ok((key_schedule, hash_at_client_recvd_server_hello))
}

pub fn prepare_resumption(
    conn: &mut ClientConnection,
    ticket: Vec<u8>,
    resuming_session: &persist::ClientSessionValueWithResolvedCipherSuite,
    exts: &mut Vec<ClientExtension>,
    doing_retry: bool,
) {
    let resuming_suite = resuming_session.supported_cipher_suite();

    conn.resumption_ciphersuite = Some(resuming_suite);
    // The EarlyData extension MUST be supplied together with the
    // PreSharedKey extension.
    let max_early_data_size = resuming_session.max_early_data_size;
    if conn.config.enable_early_data && max_early_data_size > 0 && !doing_retry {
        conn.early_data
            .enable(max_early_data_size as usize);
        exts.push(ClientExtension::EarlyData);
    }

    // Finally, and only for TLS1.3 with a ticket resumption, include a binder
    // for our ticket.  This must go last.
    //
    // Include an empty binder. It gets filled in below because it depends on
    // the message it's contained in (!!!).
    let obfuscated_ticket_age = resuming_session.get_obfuscated_ticket_age(ticketer::timebase());

    let binder_len = resuming_suite.get_hash().output_len;
    let binder = vec![0u8; binder_len];

    let psk_identity = PresharedKeyIdentity::new(ticket, obfuscated_ticket_age);
    let psk_ext = PresharedKeyOffer::new(psk_identity, binder);
    exts.push(ClientExtension::PresharedKey(psk_ext));
}

pub fn derive_early_traffic_secret(
    conn: &mut ClientConnection,
    resuming_session: &persist::ClientSessionValueWithResolvedCipherSuite,
    early_key_schedule: &KeyScheduleEarly,
    sent_tls13_fake_ccs: &mut bool,
    transcript: &HandshakeHash,
    client_random: &[u8; 32],
) {
    // For middlebox compatibility
    emit_fake_ccs(sent_tls13_fake_ccs, conn);

    let resuming_suite = resuming_session.supported_cipher_suite();

    let client_hello_hash = transcript.get_hash_given(resuming_suite.get_hash(), &[]);
    let client_early_traffic_secret = early_key_schedule.client_early_traffic_secret(
        &client_hello_hash,
        &*conn.config.key_log,
        client_random,
    );
    // Set early data encryption key
    conn.common
        .record_layer
        .set_message_encrypter(cipher::new_tls13_write(
            resuming_suite,
            &client_early_traffic_secret,
        ));

    #[cfg(feature = "quic")]
    {
        conn.common.quic.early_secret = Some(client_early_traffic_secret);
    }

    // Now the client can send encrypted early data
    conn.common.early_traffic = true;
    trace!("Starting early data traffic");
}

pub fn emit_fake_ccs(sent_tls13_fake_ccs: &mut bool, conn: &mut ClientConnection) {
    if conn.common.is_quic() {
        return;
    }

    if std::mem::replace(sent_tls13_fake_ccs, true) {
        return;
    }

    let m = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };
    conn.common.send_msg(m, false);
}

fn validate_encrypted_extensions(
    conn: &mut ClientConnection,
    hello: &ClientHelloDetails,
    exts: &EncryptedExtensions,
) -> Result<(), Error> {
    if exts.has_duplicate_extension() {
        conn.common
            .send_fatal_alert(AlertDescription::DecodeError);
        return Err(Error::PeerMisbehavedError(
            "server sent duplicate encrypted extensions".to_string(),
        ));
    }

    if hello.server_sent_unsolicited_extensions(exts, &[]) {
        conn.common
            .send_fatal_alert(AlertDescription::UnsupportedExtension);
        let msg = "server sent unsolicited encrypted extension".to_string();
        return Err(Error::PeerMisbehavedError(msg));
    }

    for ext in exts {
        if ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type())
            || DISALLOWED_TLS13_EXTS.contains(&ext.get_type())
        {
            conn.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            let msg = "server sent inappropriate encrypted extension".to_string();
            return Err(Error::PeerMisbehavedError(msg));
        }
    }

    Ok(())
}

pub struct ExpectEncryptedExtensions {
    pub resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    pub dns_name: webpki::DnsName,
    pub randoms: ConnectionRandoms,
    pub suite: &'static SupportedCipherSuite,
    pub transcript: HandshakeHash,
    pub key_schedule: KeyScheduleHandshake,
    pub hello: ClientHelloDetails,
    pub hash_at_client_recvd_server_hello: Digest,
}

impl hs::State for ExpectEncryptedExtensions {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ClientConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let exts = require_handshake_msg!(
            m,
            HandshakeType::EncryptedExtensions,
            HandshakePayload::EncryptedExtensions
        )?;
        debug!("TLS1.3 encrypted extensions: {:?}", exts);
        self.transcript.add_message(&m);

        validate_encrypted_extensions(conn, &self.hello, &exts)?;
        hs::process_alpn_protocol(conn, exts.get_alpn_protocol())?;

        #[cfg(feature = "quic")]
        {
            // QUIC transport parameters
            if let Some(params) = exts.get_quic_params_extension() {
                conn.common.quic.params = Some(params);
            }
        }

        if let Some(resuming_session) = self.resuming_session {
            let was_early_traffic = conn.common.early_traffic;
            if was_early_traffic {
                if exts.early_data_extension_offered() {
                    conn.early_data.accepted();
                } else {
                    conn.early_data.rejected();
                    conn.common.early_traffic = false;
                }
            }

            if was_early_traffic && !conn.common.early_traffic {
                // If no early traffic, set the encryption key for handshakes
                let write_key = self
                    .key_schedule
                    .client_handshake_traffic_secret(
                        &self.hash_at_client_recvd_server_hello,
                        &*conn.config.key_log,
                        &self.randoms.client,
                    );
                conn.common
                    .record_layer
                    .set_message_encrypter(cipher::new_tls13_write(self.suite, &write_key));
            }

            conn.server_cert_chain = resuming_session
                .server_cert_chain
                .clone();

            // We *don't* reverify the certificate chain here: resumption is a
            // continuation of the previous session in terms of security policy.
            let cert_verified = verify::ServerCertVerified::assertion();
            let sig_verified = verify::HandshakeSignatureValid::assertion();
            Ok(Box::new(ExpectFinished {
                dns_name: self.dns_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                cert_verified,
                sig_verified,
                hash_at_client_recvd_server_hello: self.hash_at_client_recvd_server_hello,
            }))
        } else {
            if exts.early_data_extension_offered() {
                let msg = "server sent early data extension without resumption".to_string();
                return Err(Error::PeerMisbehavedError(msg));
            }
            Ok(Box::new(ExpectCertificateOrCertReq {
                dns_name: self.dns_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                may_send_sct_list: self.hello.server_may_send_sct_list(),
                hash_at_client_recvd_server_hello: self.hash_at_client_recvd_server_hello,
            }))
        }
    }
}

struct ExpectCertificate {
    dns_name: webpki::DnsName,
    randoms: ConnectionRandoms,
    suite: &'static SupportedCipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    may_send_sct_list: bool,
    client_auth: Option<ClientAuthDetails>,
    hash_at_client_recvd_server_hello: Digest,
}

impl hs::State for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ClientConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let decompressed_cert_chain = if m.is_handshake_type(HandshakeType::CompressedCertificate) {
            let compressed_cert_chain = require_handshake_msg!(
                m,
                HandshakeType::CompressedCertificate,
                HandshakePayload::CompressedCertificate
            )?;

            conn.common
                .certificate_compression_algorithm = Some(compressed_cert_chain.algorithm);

            let cert_chain = if let Some(decompress) = &conn
                .config
                .certificate_compression_algorithms
                .iter()
                .find(|cc| cc.alg == compressed_cert_chain.algorithm)
                .map(|v| &v.decompress)
            {
                compressed_cert_chain.decompress(decompress)
            } else {
                Err(Error::UnknownCertCompressionAlg)
            };

            if cert_chain.is_err() {
                conn.common
                    .send_fatal_alert(AlertDescription::BadCertificate);
            }

            cert_chain?
        } else {
            None
        };

        let cert_chain = if let Some(cert_chain) = decompressed_cert_chain.as_ref() {
            cert_chain
        } else {
            require_handshake_msg!(
                m,
                HandshakeType::Certificate,
                HandshakePayload::CertificateTLS13
            )?
        };

        self.transcript.add_message(&m);

        // This is only non-empty for client auth.
        if !cert_chain.context.0.is_empty() {
            warn!("certificate with non-empty context during handshake");
            conn.common
                .send_fatal_alert(AlertDescription::DecodeError);
            return Err(Error::CorruptMessagePayload(ContentType::Handshake));
        }

        if cert_chain.any_entry_has_duplicate_extension()
            || cert_chain.any_entry_has_unknown_extension()
        {
            warn!("certificate chain contains unsolicited/unknown extension");
            conn.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(Error::PeerMisbehavedError(
                "bad cert chain extensions".to_string(),
            ));
        }

        let server_cert = ServerCertDetails::new(
            cert_chain.convert(),
            cert_chain.get_end_entity_ocsp(),
            cert_chain.get_end_entity_scts(),
        );

        if let Some(sct_list) = server_cert.scts.as_ref() {
            if hs::sct_list_is_invalid(sct_list) {
                let error_msg = "server sent invalid SCT list".to_string();
                return Err(Error::PeerMisbehavedError(error_msg));
            }

            if !self.may_send_sct_list {
                let error_msg = "server sent unsolicited SCT list".to_string();
                return Err(Error::PeerMisbehavedError(error_msg));
            }
        }

        Ok(Box::new(ExpectCertificateVerify {
            dns_name: self.dns_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            server_cert,
            client_auth: self.client_auth,
            hash_at_client_recvd_server_hello: self.hash_at_client_recvd_server_hello,
        }))
    }
}

struct ExpectCertificateOrCertReq {
    dns_name: webpki::DnsName,
    randoms: ConnectionRandoms,
    suite: &'static SupportedCipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    may_send_sct_list: bool,
    hash_at_client_recvd_server_hello: Digest,
}

impl hs::State for ExpectCertificateOrCertReq {
    fn handle(self: Box<Self>, conn: &mut ClientConnection, m: Message) -> hs::NextStateOrError {
        check_message(
            &m,
            &[ContentType::Handshake],
            &[
                HandshakeType::Certificate,
                HandshakeType::CompressedCertificate,
                HandshakeType::CertificateRequest,
            ],
        )?;
        if m.is_handshake_type(HandshakeType::Certificate)
            || m.is_handshake_type(HandshakeType::CompressedCertificate)
        {
            Box::new(ExpectCertificate {
                dns_name: self.dns_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                may_send_sct_list: self.may_send_sct_list,
                client_auth: None,
                hash_at_client_recvd_server_hello: self.hash_at_client_recvd_server_hello,
            })
            .handle(conn, m)
        } else {
            Box::new(ExpectCertificateRequest {
                dns_name: self.dns_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                may_send_sct_list: self.may_send_sct_list,
                hash_at_client_recvd_server_hello: self.hash_at_client_recvd_server_hello,
            })
            .handle(conn, m)
        }
    }
}

// --- TLS1.3 CertificateVerify ---
struct ExpectCertificateVerify {
    dns_name: webpki::DnsName,
    randoms: ConnectionRandoms,
    suite: &'static SupportedCipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
    hash_at_client_recvd_server_hello: Digest,
}

fn send_cert_error_alert(conn: &mut ClientConnection, err: Error) -> Error {
    match err {
        Error::WebPkiError(webpki::Error::BadDer, _) => {
            conn.common
                .send_fatal_alert(AlertDescription::DecodeError);
        }
        Error::PeerMisbehavedError(_) => {
            conn.common
                .send_fatal_alert(AlertDescription::IllegalParameter);
        }
        _ => {
            conn.common
                .send_fatal_alert(AlertDescription::BadCertificate);
        }
    };

    err
}

impl hs::State for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ClientConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let cert_verify = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        trace!("Server cert is {:?}", self.server_cert.cert_chain);

        // 1. Verify the certificate chain.
        let (end_entity, intermediates) = self
            .server_cert
            .cert_chain
            .split_first()
            .ok_or(Error::NoCertificatesPresented)?;
        let now = std::time::SystemTime::now();
        let cert_verified = conn
            .config
            .get_verifier()
            .verify_server_cert(
                end_entity,
                intermediates,
                self.dns_name.as_ref(),
                &mut self.server_cert.scts(),
                &self.server_cert.ocsp_response,
                now,
            )
            .map_err(|err| send_cert_error_alert(conn, err))?;

        // 2. Verify their signature on the handshake.
        let handshake_hash = self.transcript.get_current_hash();
        let sig_verified = conn
            .config
            .get_verifier()
            .verify_tls13_signature(
                &verify::construct_tls13_server_verify_message(&handshake_hash),
                &self.server_cert.cert_chain[0],
                &cert_verify,
            )
            .map_err(|err| send_cert_error_alert(conn, err))?;

        conn.server_cert_chain = self.server_cert.cert_chain;
        self.transcript.add_message(&m);

        Ok(Box::new(ExpectFinished {
            dns_name: self.dns_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_auth: self.client_auth,
            cert_verified,
            sig_verified,
            hash_at_client_recvd_server_hello: self.hash_at_client_recvd_server_hello,
        }))
    }
}

// TLS1.3 version of CertificateRequest handling.  We then move to expecting the server
// Certificate. Unfortunately the CertificateRequest type changed in an annoying way
// in TLS1.3.
struct ExpectCertificateRequest {
    dns_name: webpki::DnsName,
    randoms: ConnectionRandoms,
    suite: &'static SupportedCipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    may_send_sct_list: bool,
    hash_at_client_recvd_server_hello: Digest,
}

impl hs::State for ExpectCertificateRequest {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ClientConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let certreq = &require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequestTLS13
        )?;
        self.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        // Fortunately the problems here in TLS1.2 and prior are corrected in
        // TLS1.3.

        // Must be empty during handshake.
        if !certreq.context.0.is_empty() {
            warn!("Server sent non-empty certreq context");
            conn.common
                .send_fatal_alert(AlertDescription::DecodeError);
            return Err(Error::CorruptMessagePayload(ContentType::Handshake));
        }

        let tls13_sign_schemes = sign::supported_sign_tls13();
        let no_sigschemes = Vec::new();
        let compat_sigschemes = certreq
            .get_sigalgs_extension()
            .unwrap_or(&no_sigschemes)
            .iter()
            .cloned()
            .filter(|scheme| tls13_sign_schemes.contains(scheme))
            .collect::<Vec<SignatureScheme>>();

        if compat_sigschemes.is_empty() {
            conn.common
                .send_fatal_alert(AlertDescription::HandshakeFailure);
            return Err(Error::PeerIncompatibleError(
                "server sent bad certreq schemes".to_string(),
            ));
        }

        let no_canames = Vec::new();
        let canames = certreq
            .get_authorities_extension()
            .unwrap_or(&no_canames)
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();
        let maybe_certkey = conn
            .config
            .client_auth_cert_resolver
            .resolve(&canames, &compat_sigschemes);

        let mut client_auth = ClientAuthDetails::new();
        if let Some(certkey) = maybe_certkey {
            debug!("Attempting client auth");
            let maybe_signer = certkey
                .key
                .choose_scheme(&compat_sigschemes);
            client_auth.certkey = Some(certkey);
            client_auth.signer = maybe_signer;
            client_auth.auth_context = Some(certreq.context.0.clone());
        } else {
            debug!("Client auth requested but no cert selected");
        }

        Ok(Box::new(ExpectCertificate {
            dns_name: self.dns_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            may_send_sct_list: self.may_send_sct_list,
            client_auth: Some(client_auth),
            hash_at_client_recvd_server_hello: self.hash_at_client_recvd_server_hello,
        }))
    }
}

fn emit_certificate_tls13(
    transcript: &mut HandshakeHash,
    client_auth: &mut ClientAuthDetails,
    conn: &mut ClientConnection,
) -> Result<(), Error> {
    let context = client_auth
        .auth_context
        .take()
        .unwrap_or_else(Vec::new);

    let mut cert_payload = CertificatePayloadTLS13 {
        context: PayloadU8::new(context),
        entries: Vec::new(),
    };

    if let Some(cert_key) = &client_auth.certkey {
        for cert in &cert_key.cert {
            cert_payload
                .entries
                .push(CertificateEntry::new(cert.clone()));
        }
    }


    let payload = if let Some(certificate_compression_algorithm) = conn
        .common
        .certificate_compression_algorithm
    {
        let compressed_cert_payload = if let Some(compressor) = &conn
            .config
            .certificate_compression_algorithms
            .iter()
            .find(|cc| cc.alg == certificate_compression_algorithm)
            .map(|v| &v.compress)
        {
            cert_payload.compress_with(certificate_compression_algorithm, compressor)
        } else {
            Err(Error::UnknownCertCompressionAlg)
        }?;

        MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CompressedCertificate,
            payload: HandshakePayload::CompressedCertificate(compressed_cert_payload),
        })
    } else {
        MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(cert_payload),
        })
    };

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload,
    };

    transcript.add_message(&m);
    conn.common.send_msg(m, true);

    Ok(())
}

fn emit_certverify_tls13(
    transcript: &mut HandshakeHash,
    client_auth: &mut ClientAuthDetails,
    conn: &mut ClientConnection,
) -> Result<(), Error> {
    let signer = match client_auth.signer.take() {
        Some(s) => s,
        None => {
            debug!("Skipping certverify message (no client scheme/key)");
            return Ok(());
        }
    };

    let message = verify::construct_tls13_client_verify_message(&transcript.get_current_hash());

    let scheme = signer.get_scheme();
    let sig = signer.sign(&message)?;
    let dss = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(dss),
        }),
    };

    transcript.add_message(&m);
    conn.common.send_msg(m, true);
    Ok(())
}

fn emit_finished_tls13(
    transcript: &mut HandshakeHash,
    key_schedule: &KeyScheduleTrafficWithClientFinishedPending,
    conn: &mut ClientConnection,
) {
    let handshake_hash = transcript.get_current_hash();
    let verify_data = key_schedule.sign_client_finish(&handshake_hash);
    let verify_data_payload = Payload::new(verify_data.as_ref());

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    transcript.add_message(&m);
    conn.common.send_msg(m, true);
}

fn emit_end_of_early_data_tls13(transcript: &mut HandshakeHash, conn: &mut ClientConnection) {
    if conn.common.is_quic() {
        return;
    }

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::EndOfEarlyData,
            payload: HandshakePayload::EndOfEarlyData,
        }),
    };

    transcript.add_message(&m);
    conn.common.send_msg(m, true);
}

struct ExpectFinished {
    dns_name: webpki::DnsName,
    randoms: ConnectionRandoms,
    suite: &'static SupportedCipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
    hash_at_client_recvd_server_hello: Digest,
}

impl hs::State for ExpectFinished {
    fn handle(self: Box<Self>, conn: &mut ClientConnection, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = st.transcript.get_current_hash();
        let expect_verify_data = st
            .key_schedule
            .sign_server_finish(&handshake_hash);

        let fin = constant_time::verify_slices_are_equal(expect_verify_data.as_ref(), &finished.0)
            .map_err(|_| {
                conn.common
                    .send_fatal_alert(AlertDescription::DecryptError);
                Error::DecryptError
            })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        let maybe_write_key = if conn.common.early_traffic {
            /* Derive the client-to-server encryption key before key schedule update */
            let key = st
                .key_schedule
                .client_handshake_traffic_secret(
                    &st.hash_at_client_recvd_server_hello,
                    &*conn.config.key_log,
                    &st.randoms.client,
                );
            Some(key)
        } else {
            None
        };

        st.transcript.add_message(&m);

        let hash_after_handshake = st.transcript.get_current_hash();
        /* The EndOfEarlyData message to server is still encrypted with early data keys,
         * but appears in the transcript after the server Finished. */
        if let Some(write_key) = maybe_write_key {
            emit_end_of_early_data_tls13(&mut st.transcript, conn);
            conn.common.early_traffic = false;
            conn.early_data.finished();
            conn.common
                .record_layer
                .set_message_encrypter(cipher::new_tls13_write(st.suite, &write_key));
        }

        /* Send our authentication/finished messages.  These are still encrypted
         * with our handshake keys. */
        if let Some(client_auth) = &mut st.client_auth {
            emit_certificate_tls13(&mut st.transcript, client_auth, conn)?;
            emit_certverify_tls13(&mut st.transcript, client_auth, conn)?;
        }

        let mut key_schedule_finished = st
            .key_schedule
            .into_traffic_with_client_finished_pending();
        emit_finished_tls13(&mut st.transcript, &key_schedule_finished, conn);

        /* Now move to our application traffic keys. */
        hs::check_aligned_handshake(conn)?;

        /* Traffic from server is now decrypted with application data keys. */
        let read_key = key_schedule_finished.server_application_traffic_secret(
            &hash_after_handshake,
            &*conn.config.key_log,
            &st.randoms.client,
        );
        conn.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(st.suite, &read_key));

        key_schedule_finished.exporter_master_secret(
            &hash_after_handshake,
            &*conn.config.key_log,
            &st.randoms.client,
        );

        let write_key = key_schedule_finished.client_application_traffic_secret(
            &hash_after_handshake,
            &*conn.config.key_log,
            &st.randoms.client,
        );
        conn.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(st.suite, &write_key));

        let key_schedule_traffic = key_schedule_finished.into_traffic();
        conn.common.start_traffic();

        let st = ExpectTraffic {
            dns_name: st.dns_name,
            suite: st.suite,
            transcript: st.transcript,
            key_schedule: key_schedule_traffic,
            want_write_key_update: false,
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified: fin,
        };

        #[cfg(feature = "quic")]
        {
            if conn.common.protocol == Protocol::Quic {
                conn.common.quic.traffic_secrets = Some(quic::Secrets {
                    client: write_key,
                    server: read_key,
                });
                return Ok(Box::new(ExpectQUICTraffic(st)));
            }
        }

        Ok(Box::new(st))
    }
}

// -- Traffic transit state (TLS1.3) --
// In this state we can be sent tickets, keyupdates,
// and application data.
struct ExpectTraffic {
    dns_name: webpki::DnsName,
    suite: &'static SupportedCipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleTraffic,
    want_write_key_update: bool,
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    #[allow(clippy::unnecessary_wraps)] // returns Err for #[cfg(feature = "quic")]
    fn handle_new_ticket_tls13(
        &mut self,
        conn: &mut ClientConnection,
        nst: &NewSessionTicketPayloadTLS13,
    ) -> Result<(), Error> {
        let handshake_hash = self.transcript.get_current_hash();
        let secret = self
            .key_schedule
            .resumption_master_secret_and_derive_ticket_psk(&handshake_hash, &nst.nonce.0);

        let mut value = persist::ClientSessionValueWithResolvedCipherSuite::new(
            ProtocolVersion::TLSv1_3,
            self.suite,
            &SessionID::empty(),
            nst.ticket.0.clone(),
            secret,
            &conn.server_cert_chain,
        );
        value.set_times(ticketer::timebase(), nst.lifetime, nst.age_add);

        if let Some(sz) = nst.get_max_early_data_size() {
            value.set_max_early_data_size(sz);
            #[cfg(feature = "quic")]
            {
                if conn.common.protocol == Protocol::Quic {
                    if sz != 0 && sz != 0xffff_ffff {
                        return Err(Error::PeerMisbehavedError(
                            "invalid max_early_data_size".into(),
                        ));
                    }
                }
            }
        }

        let key = persist::ClientSessionKey::session_for_dns_name(self.dns_name.as_ref());
        #[allow(unused_mut)]
        let mut ticket = value.get_encoding();

        #[cfg(feature = "quic")]
        {
            if conn.common.protocol == Protocol::Quic {
                PayloadU16::encode_slice(
                    conn.common
                        .quic
                        .params
                        .as_ref()
                        .unwrap(),
                    &mut ticket,
                );
            }
        }

        let worked = conn
            .config
            .session_persistence
            .put(key.get_encoding(), ticket);

        if worked {
            debug!("Ticket saved");
        } else {
            debug!("Ticket not saved");
        }
        Ok(())
    }

    fn handle_key_update(
        &mut self,
        conn: &mut ClientConnection,
        kur: &KeyUpdateRequest,
    ) -> Result<(), Error> {
        #[cfg(feature = "quic")]
        {
            if let Protocol::Quic = conn.common.protocol {
                conn.common
                    .send_fatal_alert(AlertDescription::UnexpectedMessage);
                let msg = "KeyUpdate received in QUIC connection".to_string();
                warn!("{}", msg);
                return Err(Error::PeerMisbehavedError(msg));
            }
        }

        // Mustn't be interleaved with other handshake messages.
        hs::check_aligned_handshake(conn)?;

        match kur {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => {
                self.want_write_key_update = true;
            }
            _ => {
                conn.common
                    .send_fatal_alert(AlertDescription::IllegalParameter);
                return Err(Error::CorruptMessagePayload(ContentType::Handshake));
            }
        }

        // Update our read-side keys.
        let new_read_key = self
            .key_schedule
            .next_server_application_traffic_secret();
        conn.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(self.suite, &new_read_key));

        Ok(())
    }
}

impl hs::State for ExpectTraffic {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ClientConnection,
        mut m: Message,
    ) -> hs::NextStateOrError {
        if m.is_content_type(ContentType::ApplicationData) {
            conn.common
                .take_received_plaintext(m.take_opaque_payload().unwrap());
        } else if let Ok(ref new_ticket) = require_handshake_msg!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicketTLS13
        ) {
            self.handle_new_ticket_tls13(conn, new_ticket)?;
        } else if let Ok(ref key_update) =
            require_handshake_msg!(m, HandshakeType::KeyUpdate, HandshakePayload::KeyUpdate)
        {
            self.handle_key_update(conn, key_update)?;
        } else {
            check_message(
                &m,
                &[ContentType::ApplicationData, ContentType::Handshake],
                &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
            )?;
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

    fn perhaps_write_key_update(&mut self, conn: &mut ClientConnection) {
        if self.want_write_key_update {
            self.want_write_key_update = false;
            conn.common
                .send_msg_encrypt(Message::build_key_update_notify());

            let write_key = self
                .key_schedule
                .next_client_application_traffic_secret();
            conn.common
                .record_layer
                .set_message_encrypter(cipher::new_tls13_write(self.suite, &write_key));
        }
    }
}

#[cfg(feature = "quic")]
pub struct ExpectQUICTraffic(ExpectTraffic);

#[cfg(feature = "quic")]
impl hs::State for ExpectQUICTraffic {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ClientConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let nst = require_handshake_msg!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicketTLS13
        )?;
        self.0
            .handle_new_ticket_tls13(conn, nst)?;
        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.0
            .export_keying_material(output, label, context)
    }
}
