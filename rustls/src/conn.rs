use crate::cipher;
use crate::error::Error;
use crate::key;
#[cfg(feature = "logging")]
use crate::log::{debug, error, trace, warn};
use crate::msgs::base::Payload;
use crate::msgs::codec::Codec;
use crate::msgs::deframer::MessageDeframer;
use crate::msgs::enums::CertificateCompressionAlgorithm;
use crate::msgs::enums::{AlertDescription, AlertLevel, ContentType, ProtocolVersion};
use crate::msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use crate::msgs::hsjoiner::HandshakeJoiner;
use crate::msgs::message::{BorrowMessage, Message, MessagePayload};
use crate::prf;
use crate::quic;
use crate::rand;
use crate::record_layer;
use crate::suites::SupportedCipherSuite;
use crate::vecbuf::ChunkVecBuffer;

use ring::digest::Digest;

use std::collections::VecDeque;
use std::io;

/// Values of this structure are returned from `Session::process_new_packets`
/// and tell the caller the current I/O state of the TLS connection.
#[derive(Debug, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
    peer_has_closed: bool,
}

impl IoState {
    /// How many bytes could be written by `write_tls` if called
    /// right now.  A non-zero value implies `wants_write`.
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// How many plaintext bytes could be obtained via `std::io::Read`
    /// without further I/O.
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }

    /// True if the peer has sent us a close_notify alert.  This is
    /// the TLS mechanism to security half-close a TLS connection,
    /// and signifies that the peer will not send any further data
    /// on this connection.
    ///
    /// This is also signalled via returning `Ok(0)` from
    /// `std::io::Read`, after all the received bytes have been
    /// retrieved.
    pub fn peer_has_closed(&self) -> bool {
        self.peer_has_closed
    }
}

/// A structure that implements `std::io::Read` for reading plaintext.
pub struct Reader<'a> {
    common: &'a mut ConnectionCommon,
}

impl<'a> io::Read for Reader<'a> {
    /// Obtain plaintext data received from the peer over this TLS connection.
    ///
    /// If the peer closes the TLS session cleanly, this returns `Ok(0)`  once all
    /// the pending data has been read. No further data can be received on that
    /// connection, so the underlying TCP connection should half-closed too.
    ///
    /// Note that support `close_notify` varies in peer TLS libraries: many do not
    /// support it and uncleanly close the TCP connection (this might be
    /// vulnerable to truncation attacks depending on the application protocol).
    /// This means applications using rustls must both handle EOF
    /// from this function, *and* unexpected EOF of the underlying TCP connection.
    ///
    /// If there are no bytes to read, this returns `Err(ErrorKind::WouldBlock.into())`.
    ///
    /// You may learn the number of bytes available at any time by inspecting
    /// the return of `process_new_packets()`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.common.read(buf)
    }
}

/// Internal trait implemented by the `ServerConnection`/`ClientConnection` allowing
/// them to be the subject of a `Writer`.
pub trait PlaintextSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize>;
    fn flush(&mut self) -> io::Result<()>;
}

/// A structure that implements `std::io::Write` for writing plaintext.
pub struct Writer<'a> {
    sink: &'a mut dyn PlaintextSink,
}

impl<'a> Writer<'a> {
    /// Create a new Writer.
    ///
    /// This is not an external interface.  Get one of these objects
    /// from `Connection::writer()`.
    #[doc(hidden)]
    pub fn new(sink: &'a mut dyn PlaintextSink) -> Writer<'a> {
        Writer { sink }
    }
}

impl<'a> io::Write for Writer<'a> {
    /// Send the plaintext `buf` to the peer, encrypting
    /// and authenticating it.  Once this function succeeds
    /// you should call `write_tls` which will output the
    /// corresponding TLS records.
    ///
    /// This function buffers plaintext sent before the
    /// TLS handshake completes, and sends it as soon
    /// as it can.  This buffer is of *unlimited size* so
    /// writing much data before it can be sent will
    /// cause excess memory usage.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.sink.write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

/// Generalises `ClientConnection` and `ServerConnection`
pub trait Connection: quic::QuicExt + Send + Sync {
    /// Read TLS content from `rd`.  This method does internal
    /// buffering, so `rd` can supply TLS messages in arbitrary-
    /// sized chunks (like a socket or pipe might).
    ///
    /// You should call `process_new_packets` each time a call to
    /// this function succeeds.
    ///
    /// The returned error only relates to IO on `rd`.  TLS-level
    /// errors are emitted from `process_new_packets`.
    ///
    /// This function returns `Ok(0)` when the underlying `rd` does
    /// so.  This typically happens when a socket is cleanly closed,
    /// or a file is at EOF.
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error>;

    /// Writes TLS messages to `wr`.
    ///
    /// On success the function returns `Ok(n)` where `n` is a number
    /// of bytes written to `wr`, number of bytes after encoding and
    /// encryption.
    ///
    /// Note that after function return the connection buffer maybe not
    /// yet fully flushed. [`wants_write`] function can be used
    /// to check if output buffer is not empty.
    ///
    /// [`wants_write`]: #tymethod.wants_write
    fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error>;

    /// Returns an object that allows reading plaintext.
    fn reader(&mut self) -> Reader;

    /// Returns an object that allows writing plaintext.
    fn writer(&mut self) -> Writer;

    /// Processes any new packets read by a previous call to `read_tls`.
    ///
    /// Errors from this function relate to TLS protocol errors, and
    /// are fatal to the connection.  Future calls after an error will do
    /// no new work and will return the same error. After an error is
    /// received from process_new_packets, you should not call read_tls
    /// any more (it will fill up buffers to no purpose). However, you
    /// may call the other methods on the connection, including write,
    /// send_close_notify, and write_tls. Most likely you will want to
    /// call write_tls to send any alerts queued by the error and then
    /// close the underlying connection.
    ///
    /// Success from this function comes with some sundry state data
    /// about the connection.
    fn process_new_packets(&mut self) -> Result<IoState, Error>;

    /// Returns true if the caller should call `read_tls` as soon
    /// as possible.
    fn wants_read(&self) -> bool;

    /// Returns true if the caller should call `write_tls` as soon
    /// as possible.
    fn wants_write(&self) -> bool;

    /// Returns true if the connection is currently performing the TLS
    /// handshake.  During this time plaintext written to the
    /// connection is buffered in memory.
    fn is_handshaking(&self) -> bool;

    /// Sets a limit on the internal buffers used to buffer
    /// unsent plaintext (prior to completing the TLS handshake)
    /// and unsent TLS records.
    ///
    /// By default, there is no limit.  The limit can be set
    /// at any time, even if the current buffer use is higher.
    fn set_buffer_limit(&mut self, limit: usize);

    /// Queues a close_notify fatal alert to be sent in the next
    /// `write_tls` call.  This informs the peer that the
    /// connection is being closed.
    fn send_close_notify(&mut self);

    /// Retrieves the certificate chain used by the peer to authenticate.
    ///
    /// The order of the certificate chain is as it appears in the TLS
    /// protocol: the first certificate relates to the peer, the
    /// second certifies the first, the third certifies the second, and
    /// so on.
    ///
    /// For clients, this is the certificate chain of the server.
    ///
    /// For servers, this is the certificate chain of the client,
    /// if client authentication was completed.
    ///
    /// The return value is None until this value is available.
    fn peer_certificates(&self) -> Option<Vec<key::Certificate>>;

    /// Retrieves the protocol agreed with the peer via ALPN.
    ///
    /// A return value of None after handshake completion
    /// means no protocol was agreed (because no protocols
    /// were offered or accepted by the peer).
    fn alpn_protocol(&self) -> Option<&[u8]>;

    /// Retrieves the protocol version agreed with the peer.
    ///
    /// This returns None until the version is agreed.
    fn protocol_version(&self) -> Option<ProtocolVersion>;

    /// Derives key material from the agreed connection secrets.
    ///
    /// This function fills in `output` with `output.len()` bytes of key
    /// material derived from the master session secret using `label`
    /// and `context` for diversification.
    ///
    /// See RFC5705 for more details on what this does and is for.
    ///
    /// For TLS1.3 connections, this function does not use the
    /// "early" exporter at any point.
    ///
    /// This function fails if called prior to the handshake completing;
    /// check with `is_handshaking()` first.
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error>;

    /// Retrieves the ciphersuite agreed with the peer.
    ///
    /// This returns None until the ciphersuite is agreed.
    fn negotiated_cipher_suite(&self) -> Option<&'static SupportedCipherSuite>;

    /// This function uses `io` to complete any outstanding IO for
    /// this connection.
    ///
    /// This is a convenience function which solely uses other parts
    /// of the public API.
    ///
    /// What this means depends on the connection  state:
    ///
    /// - If the connection `is_handshaking()`, then IO is performed until
    ///   the handshake is complete.
    /// - Otherwise, if `wants_write` is true, `write_tls` is invoked
    ///   until it is all written.
    /// - Otherwise, if `wants_read` is true, `read_tls` is invoked
    ///   once.
    ///
    /// The return value is the number of bytes read from and written
    /// to `io`, respectively.
    ///
    /// This function will block if `io` blocks.
    ///
    /// Errors from TLS record handling (i.e., from `process_new_packets()`)
    /// are wrapped in an `io::ErrorKind::InvalidData`-kind error.
    fn complete_io<T>(&mut self, io: &mut T) -> Result<(usize, usize), io::Error>
    where
        Self: Sized,
        T: io::Read + io::Write,
    {
        let until_handshaked = self.is_handshaking();
        let mut eof = false;
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            while self.wants_write() {
                wrlen += self.write_tls(io)?;
            }

            if !until_handshaked && wrlen > 0 {
                return Ok((rdlen, wrlen));
            }

            if !eof && self.wants_read() {
                match self.read_tls(io)? {
                    0 => eof = true,
                    n => rdlen += n,
                }
            }

            match self.process_new_packets() {
                Ok(_) => {}
                Err(e) => {
                    // In case we have an alert to send describing this error,
                    // try a last-gasp write -- but don't predate the primary
                    // error.
                    let _ignored = self.write_tls(io);

                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            };

            match (eof, until_handshaked, self.is_handshaking()) {
                (_, true, false) => return Ok((rdlen, wrlen)),
                (_, false, _) => return Ok((rdlen, wrlen)),
                (true, true, true) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                (..) => {}
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Protocol {
    Tls13,
    #[cfg(feature = "quic")]
    Quic,
}

#[derive(Clone, Debug)]
pub struct ConnectionRandoms {
    pub we_are_client: bool,
    pub client: [u8; 32],
    pub server: [u8; 32],
}

static TLS12_DOWNGRADE_SENTINEL: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];

impl ConnectionRandoms {
    pub fn for_server() -> Result<ConnectionRandoms, rand::GetRandomFailed> {
        let mut ret = ConnectionRandoms {
            we_are_client: false,
            client: [0u8; 32],
            server: [0u8; 32],
        };

        rand::fill_random(&mut ret.server)?;
        Ok(ret)
    }

    pub fn for_client() -> Result<ConnectionRandoms, rand::GetRandomFailed> {
        let mut ret = ConnectionRandoms {
            we_are_client: true,
            client: [0u8; 32],
            server: [0u8; 32],
        };

        rand::fill_random(&mut ret.client)?;
        Ok(ret)
    }

    pub fn set_tls12_downgrade_marker(&mut self) {
        assert!(!self.we_are_client);
        self.server[24..].copy_from_slice(&TLS12_DOWNGRADE_SENTINEL);
    }

    pub fn has_tls12_downgrade_marker(&mut self) -> bool {
        assert!(self.we_are_client);
        // both the server random and TLS12_DOWNGRADE_SENTINEL are
        // public values and don't require constant time comparison
        self.server[24..] == TLS12_DOWNGRADE_SENTINEL
    }
}

fn join_randoms(first: &[u8; 32], second: &[u8; 32]) -> [u8; 64] {
    let mut randoms = [0u8; 64];
    randoms[..32].copy_from_slice(first);
    randoms[32..].copy_from_slice(second);
    randoms
}

/// TLS1.2 per-connection keying material
pub struct ConnectionSecrets {
    pub randoms: ConnectionRandoms,
    suite: &'static SupportedCipherSuite,
    pub master_secret: [u8; 48],
}

impl ConnectionSecrets {
    pub fn new(
        randoms: &ConnectionRandoms,
        suite: &'static SupportedCipherSuite,
        pms: &[u8],
    ) -> ConnectionSecrets {
        let mut ret = ConnectionSecrets {
            randoms: randoms.clone(),
            suite,
            master_secret: [0u8; 48],
        };

        let randoms = join_randoms(&ret.randoms.client, &ret.randoms.server);
        prf::prf(
            &mut ret.master_secret,
            suite.hmac_algorithm(),
            pms,
            b"master secret",
            &randoms,
        );
        ret
    }

    pub fn new_ems(
        randoms: &ConnectionRandoms,
        hs_hash: &Digest,
        suite: &'static SupportedCipherSuite,
        pms: &[u8],
    ) -> ConnectionSecrets {
        let mut ret = ConnectionSecrets {
            randoms: randoms.clone(),
            master_secret: [0u8; 48],
            suite,
        };

        prf::prf(
            &mut ret.master_secret,
            suite.hmac_algorithm(),
            pms,
            b"extended master secret",
            hs_hash.as_ref(),
        );
        ret
    }

    pub fn new_resume(
        randoms: &ConnectionRandoms,
        suite: &'static SupportedCipherSuite,
        master_secret: &[u8],
    ) -> ConnectionSecrets {
        let mut ret = ConnectionSecrets {
            randoms: randoms.clone(),
            suite,
            master_secret: [0u8; 48],
        };
        ret.master_secret
            .copy_from_slice(master_secret);
        ret
    }

    pub fn make_key_block(&self, scs: &SupportedCipherSuite) -> Vec<u8> {
        let len = (scs.aead_algorithm.key_len() + scs.fixed_iv_len) * 2 + scs.explicit_nonce_len;

        let mut out = Vec::new();
        out.resize(len, 0u8);

        // NOTE: opposite order to above for no good reason.
        // Don't design security protocols on drugs, kids.
        let randoms = join_randoms(&self.randoms.server, &self.randoms.client);
        prf::prf(
            &mut out,
            self.suite.hmac_algorithm(),
            &self.master_secret,
            b"key expansion",
            &randoms,
        );

        out
    }

    pub fn suite(&self) -> &'static SupportedCipherSuite {
        self.suite
    }

    pub fn get_master_secret(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend_from_slice(&self.master_secret);
        ret
    }

    pub fn make_verify_data(&self, handshake_hash: &Digest, label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(12, 0u8);

        prf::prf(
            &mut out,
            self.suite.hmac_algorithm(),
            &self.master_secret,
            label,
            handshake_hash.as_ref(),
        );
        out
    }

    pub fn client_verify_data(&self, handshake_hash: &Digest) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"client finished")
    }

    pub fn server_verify_data(&self, handshake_hash: &Digest) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"server finished")
    }

    pub fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: Option<&[u8]>) {
        let mut randoms = Vec::new();
        randoms.extend_from_slice(&self.randoms.client);
        randoms.extend_from_slice(&self.randoms.server);
        if let Some(context) = context {
            assert!(context.len() <= 0xffff);
            (context.len() as u16).encode(&mut randoms);
            randoms.extend_from_slice(context);
        }

        prf::prf(
            output,
            self.suite.hmac_algorithm(),
            &self.master_secret,
            label,
            &randoms,
        )
    }
}

// --- Common (to client and server) connection functions ---

enum Limit {
    Yes,
    No,
}

/// For TLS1.3 middlebox compatibility mode, how to handle
/// a received ChangeCipherSpec message.
pub enum MiddleboxCcs {
    /// process the message as normal
    Process,

    /// just ignore it
    Drop,
}

pub struct ConnectionCommon {
    pub negotiated_version: Option<ProtocolVersion>,
    pub is_client: bool,
    pub record_layer: record_layer::RecordLayer,
    pub suite: Option<&'static SupportedCipherSuite>,
    pub alpn_protocol: Option<Vec<u8>>,
    peer_eof: bool,
    pub traffic: bool,
    pub early_traffic: bool,
    sent_fatal_alert: bool,
    received_middlebox_ccs: bool,
    pub error: Option<Error>,
    pub message_deframer: MessageDeframer,
    pub handshake_joiner: HandshakeJoiner,
    pub message_fragmenter: MessageFragmenter,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    pub sendable_tls: ChunkVecBuffer,
    pub certificate_compression_algorithm: Option<CertificateCompressionAlgorithm>,
    /// Protocol whose key schedule should be used. Unused for TLS < 1.3.
    pub protocol: Protocol,
    #[cfg(feature = "quic")]
    pub(crate) quic: Quic,
}

impl ConnectionCommon {
    pub fn new(mtu: Option<usize>, client: bool) -> ConnectionCommon {
        ConnectionCommon {
            negotiated_version: None,
            is_client: client,
            record_layer: record_layer::RecordLayer::new(),
            suite: None,
            alpn_protocol: None,
            peer_eof: false,
            traffic: false,
            early_traffic: false,
            sent_fatal_alert: false,
            received_middlebox_ccs: false,
            error: None,
            message_deframer: MessageDeframer::new(),
            handshake_joiner: HandshakeJoiner::new(),
            message_fragmenter: MessageFragmenter::new(mtu.unwrap_or(MAX_FRAGMENT_LEN)),
            received_plaintext: ChunkVecBuffer::new(),
            sendable_plaintext: ChunkVecBuffer::new(),
            sendable_tls: ChunkVecBuffer::new(),
            certificate_compression_algorithm: None,
            protocol: Protocol::Tls13,
            #[cfg(feature = "quic")]
            quic: Quic::new(),
        }
    }

    pub fn reader(&mut self) -> Reader {
        Reader { common: self }
    }

    pub(crate) fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
            peer_has_closed: self.peer_eof,
        }
    }

    pub fn is_tls13(&self) -> bool {
        matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
    }

    pub fn process_msg(
        &mut self,
        mut msg: Message,
        ignore_corrupt_payload: bool,
    ) -> Result<Option<MessageType>, Error> {
        // TLS1.3: drop CCS at any time during handshaking
        if let MiddleboxCcs::Drop = self.filter_tls13_ccs(&msg)? {
            trace!("Dropping CCS");
            return Ok(None);
        }

        // Decrypt if demanded by current state.
        if self.record_layer.is_decrypting() {
            let dm = self.decrypt_incoming(msg)?;
            msg = dm;
        }

        // For handshake messages, we need to join them before parsing
        // and processing.
        if self.handshake_joiner.want_message(&msg) {
            self.handshake_joiner
                .take_message(msg)
                .ok_or_else(|| {
                    self.send_fatal_alert(AlertDescription::DecodeError);
                    Error::CorruptMessagePayload(ContentType::Handshake)
                })?;
            return Ok(Some(MessageType::Handshake));
        }

        // Now we can fully parse the message payload. We only return an error
        // on the client, or we fail a bogo test (WrongMessageType-TLS13-ServerHello-TLS).
        if !msg.decode_payload() && !ignore_corrupt_payload {
            return Err(Error::CorruptMessagePayload(msg.typ));
        }

        // For alerts, we have separate logic.
        if msg.is_content_type(ContentType::Alert) {
            return self.process_alert(msg).map(|()| None);
        }

        Ok(Some(MessageType::Data(msg)))
    }

    pub fn get_suite(&self) -> Option<&'static SupportedCipherSuite> {
        self.suite
    }

    pub fn get_alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol
            .as_ref()
            .map(AsRef::as_ref)
    }

    pub fn filter_tls13_ccs(&mut self, msg: &Message) -> Result<MiddleboxCcs, Error> {
        // pass message to handshake state machine if any of these are true:
        // - TLS1.2 (where it's part of the state machine),
        // - prior to determining the version (it's illegal as a first message)
        // - if it's not a CCS at all
        // - if we've finished the handshake
        if !self.is_tls13() || !msg.is_content_type(ContentType::ChangeCipherSpec) || self.traffic {
            return Ok(MiddleboxCcs::Process);
        }

        if self.received_middlebox_ccs {
            Err(Error::PeerMisbehavedError(
                "illegal middlebox CCS received".into(),
            ))
        } else {
            self.received_middlebox_ccs = true;
            Ok(MiddleboxCcs::Drop)
        }
    }

    pub fn decrypt_incoming(&mut self, encr: Message) -> Result<Message, Error> {
        if self
            .record_layer
            .wants_close_before_decrypt()
        {
            self.send_close_notify();
        }

        let rc = self.record_layer.decrypt_incoming(encr);
        if let Err(Error::PeerSentOversizedRecord) = rc {
            self.send_fatal_alert(AlertDescription::RecordOverflow);
        }
        rc
    }

    pub fn has_readable_plaintext(&self) -> bool {
        !self.received_plaintext.is_empty()
    }

    pub fn set_buffer_limit(&mut self, limit: usize) {
        self.sendable_plaintext.set_limit(limit);
        self.sendable_tls.set_limit(limit);
    }

    pub fn process_alert(&mut self, msg: Message) -> Result<(), Error> {
        if let MessagePayload::Alert(ref alert) = msg.payload {
            // Reject unknown AlertLevels.
            if let AlertLevel::Unknown(_) = alert.level {
                self.send_fatal_alert(AlertDescription::IllegalParameter);
            }

            // If we get a CloseNotify, make a note to declare EOF to our
            // caller.
            if alert.description == AlertDescription::CloseNotify {
                self.peer_eof = true;
                return Ok(());
            }

            // Warnings are nonfatal for TLS1.2, but outlawed in TLS1.3
            // (except, for no good reason, user_cancelled).
            if alert.level == AlertLevel::Warning {
                if self.is_tls13() && alert.description != AlertDescription::UserCanceled {
                    self.send_fatal_alert(AlertDescription::DecodeError);
                } else {
                    warn!("TLS alert warning received: {:#?}", msg);
                    return Ok(());
                }
            }

            error!("TLS alert received: {:#?}", msg);
            Err(Error::AlertReceived(alert.description))
        } else {
            Err(Error::CorruptMessagePayload(ContentType::Alert))
        }
    }

    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    pub fn send_msg_encrypt(&mut self, m: Message) {
        let mut plain_messages = VecDeque::new();
        self.message_fragmenter
            .fragment(m, &mut plain_messages);

        for m in plain_messages {
            self.send_single_fragment(m.to_borrowed());
        }
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    fn send_appdata_encrypt(&mut self, payload: &[u8], limit: Limit) -> usize {
        // Here, the limit on sendable_tls applies to encrypted data,
        // but we're respecting it for plaintext data -- so we'll
        // be out by whatever the cipher+record overhead is.  That's a
        // constant and predictable amount, so it's not a terrible issue.
        let len = match limit {
            Limit::Yes => self
                .sendable_tls
                .apply_limit(payload.len()),
            Limit::No => payload.len(),
        };

        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment_borrow(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &payload[..len],
            &mut plain_messages,
        );

        for m in plain_messages {
            self.send_single_fragment(m);
        }

        len
    }

    fn send_single_fragment(&mut self, m: BorrowMessage) {
        // Close connection once we start to run out of
        // sequence space.
        if self
            .record_layer
            .wants_close_before_encrypt()
        {
            self.send_close_notify();
        }

        // Refuse to wrap counter at all costs.  This
        // is basically untestable unfortunately.
        if self.record_layer.encrypt_exhausted() {
            return;
        }

        let em = self.record_layer.encrypt_outgoing(m);
        self.queue_tls_message(em);
    }

    /// Are we done? i.e., have we processed all received messages,
    /// and received a close_notify to indicate that no new messages
    /// will arrive?
    pub fn connection_at_eof(&self) -> bool {
        self.peer_eof && !self.message_deframer.has_pending()
    }

    /// Read TLS content from `rd`.  This method does internal
    /// buffering, so `rd` can supply TLS messages in arbitrary-
    /// sized chunks (like a socket or pipe might).
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        self.message_deframer.read(rd)
    }

    pub fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        self.sendable_tls.write_to(wr)
    }

    /// Send plaintext application data, fragmenting and
    /// encrypting it as it goes out.
    ///
    /// If internal buffers are too small, this function will not accept
    /// all the data.
    pub fn send_some_plaintext(&mut self, data: &[u8]) -> usize {
        self.send_plain(data, Limit::Yes)
    }

    pub fn send_early_plaintext(&mut self, data: &[u8]) -> usize {
        debug_assert!(self.early_traffic);
        debug_assert!(self.record_layer.is_encrypting());

        if data.is_empty() {
            // Don't send empty fragments.
            return 0;
        }

        self.send_appdata_encrypt(data, Limit::Yes)
    }

    /// Encrypt and send some plaintext `data`.  `limit` controls
    /// whether the per-connection buffer limits apply.
    ///
    /// Returns the number of bytes written from `data`: this might
    /// be less than `data.len()` if buffer limits were exceeded.
    fn send_plain(&mut self, data: &[u8], limit: Limit) -> usize {
        if !self.traffic {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            let len = match limit {
                Limit::Yes => self
                    .sendable_plaintext
                    .append_limited_copy(data),
                Limit::No => self
                    .sendable_plaintext
                    .append(data.to_vec()),
            };
            return len;
        }

        debug_assert!(self.record_layer.is_encrypting());

        if data.is_empty() {
            // Don't send empty fragments.
            return 0;
        }

        self.send_appdata_encrypt(data, limit)
    }

    pub fn start_traffic(&mut self) {
        self.traffic = true;
        self.flush_plaintext();
    }

    /// Send any buffered plaintext.  Plaintext is buffered if
    /// written during handshake.
    fn flush_plaintext(&mut self) {
        if !self.traffic {
            return;
        }

        while let Some(buf) = self.sendable_plaintext.pop() {
            self.send_plain(&buf, Limit::No);
        }
    }

    // Put m into sendable_tls for writing.
    fn queue_tls_message(&mut self, m: Message) {
        self.sendable_tls
            .append(m.get_encoding());
    }

    /// Send a raw TLS message, fragmenting it if needed.
    pub fn send_msg(&mut self, m: Message, must_encrypt: bool) {
        #[cfg(feature = "quic")]
        {
            if let Protocol::Quic = self.protocol {
                if let MessagePayload::Alert(alert) = m.payload {
                    self.quic.alert = Some(alert.description);
                } else {
                    debug_assert!(
                        if let MessagePayload::Handshake(_) = m.payload {
                            true
                        } else {
                            false
                        },
                        "QUIC uses TLS for the cryptographic handshake only"
                    );
                    let mut bytes = Vec::new();
                    m.payload.encode(&mut bytes);
                    self.quic
                        .hs_queue
                        .push_back((must_encrypt, bytes));
                }
                return;
            }
        }
        if !must_encrypt {
            let mut to_send = VecDeque::new();
            self.message_fragmenter
                .fragment(m, &mut to_send);
            for mm in to_send {
                self.queue_tls_message(mm);
            }
        } else {
            self.send_msg_encrypt(m);
        }
    }

    pub fn take_received_plaintext(&mut self, bytes: Payload) {
        self.received_plaintext.append(bytes.0);
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.received_plaintext.read(buf)?;

        if len == 0 && !buf.is_empty() {
            // no bytes available:
            // - if we received a close_notify, this is a genuine permanent EOF
            // - otherwise say EWOULDBLOCK
            if !self.connection_at_eof() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }

        Ok(len)
    }

    pub fn start_encryption_tls12(&mut self, secrets: &ConnectionSecrets) {
        let (dec, enc) = cipher::new_tls12(secrets.suite(), secrets);
        self.record_layer
            .prepare_message_encrypter(enc);
        self.record_layer
            .prepare_message_decrypter(dec);
    }

    pub fn send_warning_alert(&mut self, desc: AlertDescription) {
        warn!("Sending warning alert {:?}", desc);
        self.send_warning_alert_no_log(desc);
    }

    pub fn send_fatal_alert(&mut self, desc: AlertDescription) {
        warn!("Sending fatal alert {:?}", desc);
        debug_assert!(!self.sent_fatal_alert);
        let m = Message::build_alert(AlertLevel::Fatal, desc);
        self.send_msg(m, self.record_layer.is_encrypting());
        self.sent_fatal_alert = true;
    }

    pub fn send_close_notify(&mut self) {
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.send_warning_alert_no_log(AlertDescription::CloseNotify);
    }

    fn send_warning_alert_no_log(&mut self, desc: AlertDescription) {
        let m = Message::build_alert(AlertLevel::Warning, desc);
        self.send_msg(m, self.record_layer.is_encrypting());
    }

    pub fn is_quic(&self) -> bool {
        #[cfg(feature = "quic")]
        {
            self.protocol == Protocol::Quic
        }
        #[cfg(not(feature = "quic"))]
        false
    }
}

pub enum MessageType {
    Handshake,
    Data(Message),
}

#[cfg(feature = "quic")]
pub(crate) struct Quic {
    /// QUIC transport parameters received from the peer during the handshake
    pub params: Option<Vec<u8>>,
    pub alert: Option<AlertDescription>,
    pub hs_queue: VecDeque<(bool, Vec<u8>)>,
    pub early_secret: Option<ring::hkdf::Prk>,
    pub hs_secrets: Option<quic::Secrets>,
    pub traffic_secrets: Option<quic::Secrets>,
    /// Whether keys derived from traffic_secrets have been passed to the QUIC implementation
    pub returned_traffic_keys: bool,
}

#[cfg(feature = "quic")]
impl Quic {
    pub fn new() -> Self {
        Self {
            params: None,
            alert: None,
            hs_queue: VecDeque::new(),
            early_secret: None,
            hs_secrets: None,
            traffic_secrets: None,
            returned_traffic_keys: false,
        }
    }
}
