#[cfg(feature = "logging")]
use crate::bs_debug;
use crate::check::check_message;
use crate::conn::{ConnectionCommon, ConnectionRandoms};
use crate::error::Error;
use crate::hash_hs::HandshakeHash;
use crate::key_schedule::KeyScheduleEarly;
use crate::kx;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, CipherSuite, Compression, ProtocolVersion};
use crate::msgs::enums::{ContentType, ExtensionType, HandshakeType};
use crate::msgs::enums::{ECPointFormat, PSKKeyExchangeMode};
use crate::msgs::handshake::{CertificateStatusRequest, SCTList};
use crate::msgs::handshake::{ClientExtension, HasServerExtensions};
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::handshake::{ConvertProtocolNameList, ProtocolNameList};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{HelloRetryRequest, KeyShareEntry};
use crate::msgs::handshake::{Random, SessionID};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::ticketer::TimeBase;
use crate::SupportedCipherSuite;

use crate::client::common::ClientHelloDetails;
use crate::client::{tls12, tls13, ClientConfig, ClientConnectionData, ServerIdentity};

use std::sync::Arc;

pub(super) type NextState = Box<dyn State>;
pub(super) type NextStateOrError = Result<NextState, Error>;

pub(super) trait State: Send + Sync {
    /// Each handle() implementation consumes a whole TLS message, and returns
    /// either an error or the next state.
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError;

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

impl crate::conn::HandleState for Box<dyn State> {
    type Data = ClientConnectionData;

    fn handle(
        self,
        message: Message,
        data: &mut Self::Data,
        common: &mut ConnectionCommon,
    ) -> Result<Self, Error> {
        let mut cx = ClientContext { common, data };
        self.handle(&mut cx, message)
    }
}

pub(super) struct ClientContext<'a> {
    pub(super) common: &'a mut ConnectionCommon,
    pub(super) data: &'a mut ClientConnectionData,
}

fn find_session(
    dns_name: webpki::DnsNameRef,
    config: &ClientConfig,
    #[cfg(feature = "quic")] cx: &mut ClientContext<'_>,
) -> Option<persist::ClientSessionValueWithResolvedCipherSuite> {
    let key = persist::ClientSessionKey::session_for_dns_name(dns_name);
    let key_buf = key.get_encoding();

    let value = config
        .session_storage
        .get(&key_buf)
        .or_else(|| {
            debug!("No cached session for {:?}", dns_name);
            None
        })?;

    let mut reader = Reader::init(&value[..]);
    let result = persist::ClientSessionValue::read(&mut reader).and_then(|csv| {
        let time = TimeBase::now().ok()?;
        csv.resolve_cipher_suite(&config.cipher_suites, time)
    });
    if let Some(result) = result {
        if result.has_expired() {
            None
        } else {
            #[cfg(feature = "quic")]
            {
                use crate::msgs::base::PayloadU16;
                if cx.common.is_quic() {
                    let params = PayloadU16::read(&mut reader)?;
                    cx.common.quic.params = Some(params.0);
                }
            }
            Some(result)
        }
    } else {
        None
    }
}

pub(super) fn start_handshake(
    server_id: ServerIdentity,
    extra_exts: Vec<ClientExtension>,
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError {
    let mut transcript = HandshakeHash::new();
    if config
        .client_auth_cert_resolver
        .has_certs()
    {
        transcript.set_client_auth_enabled();
    }

    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut session_id: Option<SessionID> = None;
    let hostname = server_id.get_inner_hostname();
    let mut resuming_session = find_session(
        hostname,
        &config,
        #[cfg(feature = "quic")]
        cx,
    );

    let key_share = if support_tls13 {
        Some(tls13::initial_key_share(&config, hostname)?)
    } else {
        None
    };

    if let Some(resuming) = &mut resuming_session {
        if resuming.version == ProtocolVersion::TLSv1_2 {
            // If we have a ticket, we use the sessionid as a signal that
            // we're  doing an abbreviated handshake.  See section 3.4 in
            // RFC5077.
            if !resuming.ticket.0.is_empty() {
                resuming.set_session_id(SessionID::random()?);
            }
            session_id = Some(resuming.session_id);
        }

        debug!("Resuming session");
    } else {
        debug!("Not resuming any session");
    }

    // https://tools.ietf.org/html/rfc8446#appendix-D.4
    // https://tools.ietf.org/html/draft-ietf-quic-tls-34#section-8.4
    if session_id.is_none() && !cx.common.is_quic() {
        session_id = Some(SessionID::random()?);
    }

    let randoms = ConnectionRandoms::for_client()?;
    let hello_details = ClientHelloDetails::new();
    let sent_tls13_fake_ccs = false;
    let may_send_sct_list = config.verifier.request_scts();
    Ok(emit_client_hello_for_retry(
        config,
        cx,
        resuming_session,
        randoms,
        false,
        transcript,
        sent_tls13_fake_ccs,
        hello_details,
        session_id,
        None,
        server_id,
        key_share,
        extra_exts,
        may_send_sct_list,
        None,
    ))
}

struct ExpectServerHello {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    server_id: ServerIdentity,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    early_key_schedule: Option<KeyScheduleEarly>,
    hello_details: ClientHelloDetails,
    offered_key_share: Option<kx::KeyExchange>,
    session_id: SessionID,
    sent_tls13_fake_ccs: bool,
    suite: Option<&'static SupportedCipherSuite>,
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
    extra_exts: Vec<ClientExtension>,
}

fn emit_client_hello_for_retry(
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
    resuming_session: Option<persist::ClientSessionValueWithResolvedCipherSuite>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    mut transcript: HandshakeHash,
    mut sent_tls13_fake_ccs: bool,
    mut hello_details: ClientHelloDetails,
    session_id: Option<SessionID>,
    retryreq: Option<&HelloRetryRequest>,
    mut server_id: ServerIdentity,
    key_share: Option<kx::KeyExchange>,
    extra_exts: Vec<ClientExtension>,
    may_send_sct_list: bool,
    suite: Option<&'static SupportedCipherSuite>,
) -> NextState {
    // Do we have a SessionID or ticket cached for this host?
    let (ticket, resume_version) = if let Some(resuming) = &resuming_session {
        (resuming.ticket.0.clone(), resuming.version)
    } else {
        (Vec::new(), ProtocolVersion::Unknown(0))
    };

    let support_tls12 = config.supports_version(ProtocolVersion::TLSv1_2)
        && !cx.common.is_quic()
        && match server_id {
            ServerIdentity::Hostname(_) => true,
            ServerIdentity::EncryptedClientHello(_) => false,
        };
    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    let mut exts = Vec::new();
    if !supported_versions.is_empty() {
        exts.push(ClientExtension::SupportedVersions(supported_versions));
    }
    if config.enable_sni {
        exts.push(ClientExtension::make_sni(server_id.get_outer_hostname()));
    }
    exts.push(ClientExtension::ECPointFormats(
        ECPointFormatList::supported(),
    ));
    exts.push(ClientExtension::NamedGroups(
        config
            .kx_groups
            .iter()
            .map(|skxg| skxg.name)
            .collect(),
    ));
    exts.push(ClientExtension::SignatureAlgorithms(
        config
            .verifier
            .supported_verify_schemes(),
    ));
    exts.push(ClientExtension::ExtendedMasterSecretRequest);
    exts.push(ClientExtension::CertificateStatusRequest(
        CertificateStatusRequest::build_ocsp(),
    ));

    if may_send_sct_list {
        exts.push(ClientExtension::SignedCertificateTimestampRequest);
    }

    if let Some(key_share) = &key_share {
        debug_assert!(support_tls13);
        let key_share = KeyShareEntry::new(key_share.group(), key_share.pubkey.as_ref());
        exts.push(ClientExtension::KeyShare(vec![key_share]));
    }

    if let Some(cookie) = retryreq.and_then(HelloRetryRequest::get_cookie) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    if support_tls13 && config.enable_tickets {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        let psk_modes = vec![PSKKeyExchangeMode::PSK_DHE_KE];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    if !config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_slices(
            &config
                .alpn_protocols
                .iter()
                .map(|proto| &proto[..])
                .collect::<Vec<_>>(),
        )));
    }

    // Extra extensions must be placed before the PSK extension
    exts.extend(extra_exts.iter().cloned());

    let fill_in_binder = if support_tls13
        && config.enable_tickets
        && resume_version == ProtocolVersion::TLSv1_3
        && !ticket.is_empty()
    {
        resuming_session
            .as_ref()
            .filter(|resuming| match suite {
                Some(suite) => suite.can_resume_to(&resuming.supported_cipher_suite()),
                None => true,
            })
            .map(|resuming| {
                tls13::prepare_resumption(
                    &config,
                    cx,
                    ticket,
                    resuming,
                    &mut exts,
                    retryreq.is_some(),
                );
                resuming
            })
    } else if config.enable_tickets {
        // If we have a ticket, include it.  Otherwise, request one.
        if ticket.is_empty() {
            exts.push(ClientExtension::SessionTicketRequest);
        } else {
            exts.push(ClientExtension::SessionTicketOffer(Payload::new(ticket)));
        }
        None
    } else {
        None
    };

    // Note what extensions we sent.
    hello_details.sent_extensions = exts
        .iter()
        .map(ClientExtension::get_type)
        .collect();

    let session_id = session_id.unwrap_or_else(SessionID::empty);
    let mut cipher_suites: Vec<_> = config
        .cipher_suites
        .iter()
        .map(|cs| cs.suite)
        .collect();
    // We don't do renegotiation at all, in fact.
    cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    let initial_payload = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from(randoms.client),
        session_id,
        cipher_suites,
        compression_methods: vec![Compression::Null],
        extensions: exts,
    };

    let mut chp = match server_id {
        ServerIdentity::Hostname(_) => HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(initial_payload),
        },
        ServerIdentity::EncryptedClientHello(ref mut ech) => ech.encode(initial_payload),
    };

    let early_key_schedule = if let Some(resuming) = fill_in_binder {
        let schedule = tls13::fill_in_psk_binder(&resuming, &transcript, &mut chp);
        Some((resuming, schedule))
    } else {
        None
    };


    let ch = Message {
        // "This value MUST be set to 0x0303 for all records generated
        //  by a TLS 1.3 implementation other than an initial ClientHello
        //  (i.e., one not generated after a HelloRetryRequest)"
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::Handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut sent_tls13_fake_ccs, cx.common);
    }

    trace!("Sending ClientHello {:#?}", ch);

    transcript.add_message(&ch);
    cx.common.send_msg(ch, false);

    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    let early_key_schedule = early_key_schedule.map(|(resuming, schedule)| {
        if !cx.data.early_data.is_enabled() {
            return schedule;
        }

        tls13::derive_early_traffic_secret(
            &*config.key_log,
            cx,
            resuming,
            &schedule,
            &mut sent_tls13_fake_ccs,
            &transcript,
            &randoms.client,
        );
        schedule
    });

    let next = ExpectServerHello {
        config,
        resuming_session,
        server_id,
        randoms,
        using_ems,
        transcript,
        early_key_schedule,
        hello_details,
        offered_key_share: key_share,
        session_id,
        sent_tls13_fake_ccs,
        suite,
    };

    if support_tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest { next, extra_exts })
    } else {
        Box::new(next)
    }
}

pub(super) fn process_alpn_protocol(
    cx: &mut ClientContext<'_>,
    config: &ClientConfig,
    proto: Option<&[u8]>,
) -> Result<(), Error> {
    cx.common.alpn_protocol = proto.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &cx.common.alpn_protocol {
        if !config
            .alpn_protocols
            .contains(alpn_protocol)
        {
            return Err(cx
                .common
                .illegal_param("server sent non-offered ALPN protocol"));
        }
    }

    debug!(
        "ALPN protocol is {:?}",
        cx.common
            .alpn_protocol
            .as_ref()
            .map(|v| bs_debug::BsDebug(&v))
    );
    Ok(())
}

pub fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() || scts.iter().any(|sct| sct.0.is_empty())
}

impl State for ExpectServerHello {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {:#?}", server_hello);

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let tls13_supported = self.config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .get_supported_versions()
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        let version = match server_version {
            TLSv1_3 if tls13_supported => TLSv1_3,
            TLSv1_2 if self.config.supports_version(TLSv1_2) => {
                if cx.data.early_data.is_enabled() && cx.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(Error::PeerMisbehavedError(
                        "server chose v1.2 when offering 0-rtt".to_string(),
                    ));
                }

                if server_hello
                    .get_supported_versions()
                    .is_some()
                {
                    return Err(cx
                        .common
                        .illegal_param("server chose v1.2 using v1.3 extension"));
                }

                TLSv1_2
            }
            _ => {
                cx.common
                    .send_fatal_alert(AlertDescription::ProtocolVersion);
                return Err(Error::PeerIncompatibleError(
                    "server does not support TLS v1.2/v1.3".to_string(),
                ));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err(cx
                .common
                .illegal_param("server chose non-Null compression"));
        }

        if server_hello.has_duplicate_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::DecodeError);
            return Err(Error::PeerMisbehavedError(
                "server sent duplicate extensions".to_string(),
            ));
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .hello_details
            .server_sent_unsolicited_extensions(&server_hello.extensions, &allowed_unsolicited)
        {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(Error::PeerMisbehavedError(
                "server sent unsolicited extension".to_string(),
            ));
        }

        cx.common.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !cx.common.is_tls13() {
            process_alpn_protocol(cx, &self.config, server_hello.get_alpn_protocol())?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
            if !point_fmts.contains(&ECPointFormat::Uncompressed) {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                return Err(Error::PeerMisbehavedError(
                    "server does not support uncompressed points".to_string(),
                ));
            }
        }

        let suite = self
            .config
            .find_cipher_suite(server_hello.cipher_suite)
            .ok_or_else(|| {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                Error::PeerMisbehavedError("server chose non-offered ciphersuite".to_string())
            })?;

        match self.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err(cx
                    .common
                    .illegal_param("server varied selected ciphersuite"));
            }
            _ => {
                debug!("Using ciphersuite {:?}", suite);
                self.suite = Some(suite);
                cx.common.suite = Some(suite);
            }
        }

        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        if cx.common.is_tls13() {
            let server_message = match &m.payload {
                MessagePayload::Handshake(hs) => Ok(hs.get_encoding()),
                _ => Err(Error::General("wrong payload".to_string())),
            }?;

            tls13::handle_server_hello(
                server_message,
                self.config,
                cx,
                server_hello,
                self.resuming_session,
                self.server_id,
                self.randoms,
                suite,
                self.transcript,
                self.early_key_schedule,
                self.hello_details,
                // We always send a key share when TLS 1.3 is enabled.
                self.offered_key_share.unwrap(),
                self.sent_tls13_fake_ccs,
            )
        } else {
            self.transcript
                .start_hash(&suite.get_hash());
            self.transcript.add_message(&m);
            tls12::CompleteServerHelloHandling {
                config: self.config,
                resuming_session: self.resuming_session,
                dns_name: self
                    .server_id
                    .get_outer_hostname()
                    .to_owned(),
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                session_id: server_hello.session_id,
            }
            .handle_server_hello(cx, suite, &server_hello, tls13_supported)
        }
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState {
        Box::new(self.next)
    }

    fn handle_hello_retry_request(
        mut self,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> NextStateOrError {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {:?}", hrr);

        cx.common.check_aligned_handshake()?;

        let cookie = hrr.get_cookie();
        let req_group = hrr.get_requested_key_share_group();

        // We always send a key share when TLS 1.3 is enabled.
        let offered_key_share = self.next.offered_key_share.unwrap();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if cookie.is_none() && req_group == Some(offered_key_share.group()) {
            return Err(cx
                .common
                .illegal_param("server requested hrr with our group"));
        }

        // Or has an empty cookie.
        if let Some(cookie) = cookie {
            if cookie.0.is_empty() {
                return Err(cx
                    .common
                    .illegal_param("server requested hrr with empty cookie"));
            }
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(Error::PeerIncompatibleError(
                "server sent hrr with unhandled extension".to_string(),
            ));
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(cx
                .common
                .illegal_param("server send duplicate hrr extensions"));
        }

        // Or asks us to change nothing.
        if cookie.is_none() && req_group.is_none() {
            return Err(cx
                .common
                .illegal_param("server requested hrr with no changes"));
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                cx.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(cx
                    .common
                    .illegal_param("server requested unsupported version in hrr"));
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let maybe_cs = self
            .next
            .config
            .find_cipher_suite(hrr.cipher_suite);
        let cs = match maybe_cs {
            Some(cs) => cs,
            None => {
                return Err(cx
                    .common
                    .illegal_param("server requested unsupported cs in hrr"));
            }
        };

        // HRR selects the ciphersuite.
        cx.common.suite = Some(cs);

        // This is the draft19 change where the transcript became a tree
        self.next
            .transcript
            .start_hash(cs.get_hash());
        self.next.transcript.rollup_for_hrr();
        self.next.transcript.add_message(&m);

        // Early data is not allowed after HelloRetryrequest
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }

        let may_send_sct_list = self
            .next
            .hello_details
            .server_may_send_sct_list();

        let key_share = match req_group {
            Some(group) if group != offered_key_share.group() => {
                let group = kx::KeyExchange::choose(group, &self.next.config.kx_groups)
                    .ok_or_else(|| {
                        cx.common
                            .illegal_param("server requested hrr with bad group")
                    })?;
                kx::KeyExchange::start(group).ok_or(Error::FailedToGetRandomBytes)?
            }
            _ => offered_key_share,
        };

        Ok(emit_client_hello_for_retry(
            self.next.config,
            cx,
            self.next.resuming_session,
            self.next.randoms,
            self.next.using_ems,
            self.next.transcript,
            self.next.sent_tls13_fake_ccs,
            self.next.hello_details,
            Some(self.next.session_id),
            Some(&hrr),
            self.next.server_id,
            Some(key_share),
            self.extra_exts,
            may_send_sct_list,
            Some(cs),
        ))
    }
}

impl State for ExpectServerHelloOrHelloRetryRequest {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {
        check_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
        )?;
        if m.is_handshake_type(HandshakeType::ServerHello) {
            self.into_expect_server_hello()
                .handle(cx, m)
        } else {
            self.handle_hello_retry_request(cx, m)
        }
    }
}

pub(super) fn send_cert_error_alert(common: &mut ConnectionCommon, err: Error) -> Error {
    match err {
        Error::WebPkiError(webpki::Error::BadDer, _) => {
            common.send_fatal_alert(AlertDescription::DecodeError);
        }
        Error::PeerMisbehavedError(_) => {
            common.send_fatal_alert(AlertDescription::IllegalParameter);
        }
        _ => {
            common.send_fatal_alert(AlertDescription::BadCertificate);
        }
    };

    err
}
