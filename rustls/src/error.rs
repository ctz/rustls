use crate::msgs::enums::{AlertDescription, ContentType, HandshakeType};
use crate::rand;

use std::error::Error as StdError;
use std::fmt;
use std::time::SystemTimeError;

/// The reason WebPKI operation was performed, used in [`Error`].
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum WebPkiOp {
    /// Validate server certificate.
    ValidateServerCert,
    /// Validate client certificate.
    ValidateClientCert,
    /// Validate certificate for DNS name
    ValidateForDnsName,
    /// Parse end entity certificate.
    ParseEndEntity,
    /// Verify message signature using the certificate.
    VerifySignature,
}

impl fmt::Display for WebPkiOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebPkiOp::ValidateServerCert => write!(f, "validate server certificate"),
            WebPkiOp::ValidateClientCert => write!(f, "validate client certificate"),
            WebPkiOp::ValidateForDnsName => write!(f, "validate certificate for DNS name"),
            WebPkiOp::ParseEndEntity => write!(f, "parse end entity certificate"),
            WebPkiOp::VerifySignature => write!(f, "verify signature"),
        }
    }
}

/// rustls reports protocol errors using this type.
#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// We received a TLS message that isn't valid right now.
    /// `expect_types` lists the message types we can expect right now.
    /// `got_type` is the type we found.  This error is typically
    /// caused by a buggy TLS stack (the peer or this one), a broken
    /// network, or an attack.
    InappropriateMessage {
        /// Which types we expected
        expect_types: Vec<ContentType>,
        /// What type we received
        got_type: ContentType,
    },

    /// We received a TLS handshake message that isn't valid right now.
    /// `expect_types` lists the handshake message types we can expect
    /// right now.  `got_type` is the type we found.
    InappropriateHandshakeMessage {
        /// Which handshake type we expected
        expect_types: Vec<HandshakeType>,
        /// What handshake type we received
        got_type: HandshakeType,
    },

    /// The peer sent us a syntactically incorrect TLS message.
    CorruptMessage,

    /// The peer sent us a TLS message with invalid contents.
    CorruptMessagePayload(ContentType),

    /// The peer didn't give us any certificates.
    NoCertificatesPresented,

    /// We couldn't decrypt a message.  This is invariably fatal.
    DecryptError,

    /// The peer doesn't support a protocol version/feature we require.
    /// The parameter gives a hint as to what version/feature it is.
    PeerIncompatibleError(String),

    /// The peer deviated from the standard TLS protocol.
    /// The parameter gives a hint where.
    PeerMisbehavedError(String),

    /// We received a fatal alert.  This means the peer is unhappy.
    AlertReceived(AlertDescription),

    /// The presented certificate chain is invalid.
    WebPkiError(webpki::Error, WebPkiOp),

    /// The presented SCT(s) were invalid.
    InvalidSct(sct::Error),

    /// A catch-all error for unlikely errors.
    General(String),

    /// We failed to figure out what time it currently is.
    FailedToGetCurrentTime,

    /// We failed to acquire random bytes from the system.
    FailedToGetRandomBytes,

    /// This function doesn't work until the TLS handshake
    /// is complete.
    HandshakeNotComplete,

    /// The peer sent an oversized record/fragment.
    PeerSentOversizedRecord,

    /// An incoming connection did not support any known application protocol.
    NoApplicationProtocol,

    /// Couldn't find a suitable HPKE cipher suite for ECH
    NoHpkeConfig,

    /// The `max_fragment_size` value supplied in configuration was too small,
    /// or too large.
    BadMaxFragmentSize,
}

fn join<T: fmt::Debug>(items: &[T]) -> String {
    items
        .iter()
        .map(|x| format!("{:?}", x))
        .collect::<Vec<String>>()
        .join(" or ")
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InappropriateMessage {
                ref expect_types,
                ref got_type,
            } => write!(
                f,
                "received unexpected message: got {:?} when expecting {}",
                got_type,
                join::<ContentType>(expect_types)
            ),
            Error::InappropriateHandshakeMessage {
                ref expect_types,
                ref got_type,
            } => write!(
                f,
                "received unexpected handshake message: got {:?} when expecting {}",
                got_type,
                join::<HandshakeType>(expect_types)
            ),
            Error::CorruptMessagePayload(ref typ) => {
                write!(f, "received corrupt message of type {:?}", typ)
            }
            Error::PeerIncompatibleError(ref why) => write!(f, "peer is incompatible: {}", why),
            Error::PeerMisbehavedError(ref why) => write!(f, "peer misbehaved: {}", why),
            Error::AlertReceived(ref alert) => write!(f, "received fatal alert: {:?}", alert),
            Error::WebPkiError(ref err, ref reason) => {
                write!(f, "certificate error in operation: {}: {:?}", reason, err)
            }
            Error::CorruptMessage => write!(f, "received corrupt message"),
            Error::NoCertificatesPresented => write!(f, "peer sent no certificates"),
            Error::DecryptError => write!(f, "cannot decrypt peer's message"),
            Error::PeerSentOversizedRecord => write!(f, "peer sent excess record size"),
            Error::HandshakeNotComplete => write!(f, "handshake not complete"),
            Error::NoApplicationProtocol => write!(f, "peer doesn't support any known protocol"),
            Error::NoHpkeConfig => write!(f, "peer doesn't support any known HPKE config"),
            Error::InvalidSct(ref err) => write!(f, "invalid certificate timestamp: {:?}", err),
            Error::FailedToGetCurrentTime => write!(f, "failed to get current time"),
            Error::FailedToGetRandomBytes => write!(f, "failed to get random bytes"),
            Error::BadMaxFragmentSize => {
                write!(f, "the supplied max_fragment_size was too small or large")
            }
            Error::General(ref err) => write!(f, "unexpected error: {}", err), // (please file a bug)
        }
    }
}

impl From<SystemTimeError> for Error {
    #[inline]
    fn from(_: SystemTimeError) -> Self {
        Self::FailedToGetCurrentTime
    }
}

impl StdError for Error {}

impl From<rand::GetRandomFailed> for Error {
    fn from(_: rand::GetRandomFailed) -> Self {
        Self::FailedToGetRandomBytes
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        use super::Error;
        use super::WebPkiOp;
        use crate::msgs::enums::{AlertDescription, ContentType, HandshakeType};
        use sct;
        use webpki;

        let all = vec![
            Error::InappropriateMessage {
                expect_types: vec![ContentType::Alert],
                got_type: ContentType::Handshake,
            },
            Error::InappropriateHandshakeMessage {
                expect_types: vec![HandshakeType::ClientHello, HandshakeType::Finished],
                got_type: HandshakeType::ServerHello,
            },
            Error::CorruptMessage,
            Error::CorruptMessagePayload(ContentType::Alert),
            Error::NoCertificatesPresented,
            Error::DecryptError,
            Error::PeerIncompatibleError("no tls1.2".to_string()),
            Error::PeerMisbehavedError("inconsistent something".to_string()),
            Error::AlertReceived(AlertDescription::ExportRestriction),
            Error::WebPkiError(
                webpki::Error::ExtensionValueInvalid,
                WebPkiOp::ParseEndEntity,
            ),
            Error::InvalidSct(sct::Error::MalformedSct),
            Error::General("undocumented error".to_string()),
            Error::FailedToGetCurrentTime,
            Error::FailedToGetRandomBytes,
            Error::HandshakeNotComplete,
            Error::PeerSentOversizedRecord,
            Error::NoApplicationProtocol,
            Error::NoHpkeConfig,
            Error::BadMaxFragmentSize,
        ];

        for err in all {
            println!("{:?}:", err);
            println!("  fmt '{}'", err);
        }
    }
}
