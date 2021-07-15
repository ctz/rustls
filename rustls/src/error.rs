use crate::msgs::enums::{AlertDescription, ContentType, HandshakeType};
use crate::rand;

use std::error::Error as StdError;
use std::fmt;
use std::time::SystemTimeError;

/// Reasons for a WebPKI operation to fail, used in [`Error`].
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum WebPkiError {
    /// Encountered an illegal encoding.
    BadEncoding,

    /// Encountered an illegal encoding of a time field.
    BadTimeEncoding,

    /// A CA certificate was used as an end-entity.
    CaUsedAsEndEntity,

    /// A certificate was expired, ie the verification time was after
    /// the notAfter instant.
    CertExpired,

    /// A certificate was not issued for the given name.
    CertNotValidForName,

    /// A certificate was not yet valid, ie the verification time was before
    /// the notBefore instant.
    CertNotValidYet,

    /// An end-entity certificate was used as a CA
    EndEntityUsedAsCa,

    /// An X.509 extension had an invalid value
    ExtensionValueInvalid,

    /// An X.509 certificate had an illegal validity period; for example
    /// notBefore was after notAfter
    InvalidCertValidity,

    /// The given signature is invalid.
    InvalidSignatureForPublicKey,

    /// A certificate violated name constraits required by its issuing path.
    NameConstraintViolation,

    /// A certificate violated path length constraits required by its issuing path.
    PathLenConstraintViolation,

    /// A certificate contained inconsistent signature algorithms.
    SignatureAlgorithmMismatch,

    /// A certificate did not contain the the required extended key usage bits.
    RequiredEkuNotFound,

    /// It wasn't possible to construct a path from the given end-entity
    /// certificate to one of the trusted issuers.
    UnknownIssuer,

    /// An X.509 certificate was encountered that had an illegal version, or
    /// a version other than 3.
    UnsupportedCertVersion,

    /// An X.509 extension was encountered that had a missing or malformed extensions.
    MissingOrMalformedExtension,

    /// An X.509 unrecognized extension was encountered with the critical bit set.
    UnsupportedCriticalExtension,

    /// The given certified public key cannot verify signatures of this type.
    UnsupportedSignatureAlgorithmForPublicKey,

    /// The given signature algorithm is not supported.
    UnsupportedSignatureAlgorithm,
}

impl From<webpki::Error> for WebPkiError {
    fn from(e: webpki::Error) -> Self {
        use webpki::Error;
        match e {
            Error::BadDer => Self::BadEncoding,
            Error::BadDerTime => Self::BadTimeEncoding,
            Error::CaUsedAsEndEntity => Self::CaUsedAsEndEntity,
            Error::CertExpired => Self::CertExpired,
            Error::CertNotValidForName => Self::CertNotValidForName,
            Error::CertNotValidYet => Self::CertNotValidYet,
            Error::EndEntityUsedAsCa => Self::EndEntityUsedAsCa,
            Error::ExtensionValueInvalid => Self::ExtensionValueInvalid,
            Error::InvalidCertValidity => Self::InvalidCertValidity,
            Error::InvalidSignatureForPublicKey => Self::InvalidSignatureForPublicKey,
            Error::NameConstraintViolation => Self::NameConstraintViolation,
            Error::PathLenConstraintViolated => Self::PathLenConstraintViolation,
            Error::SignatureAlgorithmMismatch => Self::SignatureAlgorithmMismatch,
            Error::RequiredEkuNotFound => Self::RequiredEkuNotFound,
            Error::UnknownIssuer => Self::UnknownIssuer,
            Error::UnsupportedCertVersion => Self::UnsupportedCertVersion,
            Error::MissingOrMalformedExtensions => Self::MissingOrMalformedExtension,
            Error::UnsupportedCriticalExtension => Self::UnsupportedCriticalExtension,
            Error::UnsupportedSignatureAlgorithmForPublicKey => {
                Self::UnsupportedSignatureAlgorithmForPublicKey
            }
            Error::UnsupportedSignatureAlgorithm => Self::UnsupportedSignatureAlgorithm,
        }
    }
}

impl fmt::Display for WebPkiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebPkiError::BadEncoding => write!(f, "bad DER encoding"),
            WebPkiError::BadTimeEncoding => write!(f, "bad DER encoding of time"),
            WebPkiError::CaUsedAsEndEntity => write!(f, "CA certificate used as end-entity"),
            WebPkiError::CertExpired => write!(f, "certificate expired"),
            WebPkiError::CertNotValidForName => write!(f, "certificate not valid for name"),
            WebPkiError::CertNotValidYet => write!(f, "certificate not yet valid"),
            WebPkiError::EndEntityUsedAsCa => write!(f, "end-entity certificate used as CA"),
            WebPkiError::ExtensionValueInvalid => write!(f, "invalid X.509 extension value"),
            WebPkiError::InvalidCertValidity => write!(f, "invalid certificate validity period"),
            WebPkiError::InvalidSignatureForPublicKey => {
                write!(f, "invalid signature for certified key")
            }
            WebPkiError::NameConstraintViolation => {
                write!(f, "certificate violates name constraint")
            }
            WebPkiError::PathLenConstraintViolation => {
                write!(f, "certificate violates path length constraint")
            }
            WebPkiError::SignatureAlgorithmMismatch => {
                write!(f, "certificate contains inconsistent signature algorithm")
            }
            WebPkiError::RequiredEkuNotFound => {
                write!(f, "certificate does not have a required extended key usage")
            }
            WebPkiError::UnknownIssuer => write!(
                f,
                "a valid path from an end-entity to a CA certificate could not be found"
            ),
            WebPkiError::UnsupportedCertVersion => {
                write!(f, "certificate has a version other than v3")
            }
            WebPkiError::MissingOrMalformedExtension => {
                write!(f, "certificate has a missing or malformed X.509 extension")
            }
            WebPkiError::UnsupportedCriticalExtension => {
                write!(f, "certificate has an unrecognized critical extension")
            }
            WebPkiError::UnsupportedSignatureAlgorithmForPublicKey => write!(
                f,
                "type mismatch between certified key and signature algorithm"
            ),
            WebPkiError::UnsupportedSignatureAlgorithm => {
                write!(f, "unsupported signature algorithm")
            }
        }
    }
}

/// Which WebPKI operation was performed, used in [`Error`].
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

    /// The certificate verifier doesn't support the given type of name.
    UnsupportedNameType,

    /// We couldn't decrypt a message.  This is invariably fatal.
    DecryptError,

    /// We couldn't encrypt a message because it was larger than the allowed message size.
    /// This should never happen if the application is using valid record sizes.
    EncryptError,

    /// The peer doesn't support a protocol version/feature we require.
    /// The parameter gives a hint as to what version/feature it is.
    PeerIncompatibleError(String),

    /// The peer deviated from the standard TLS protocol.
    /// The parameter gives a hint where.
    PeerMisbehavedError(String),

    /// We received a fatal alert.  This means the peer is unhappy.
    AlertReceived(AlertDescription),

    /// The presented certificate chain is invalid.
    WebPkiError(WebPkiError, WebPkiOp),

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
                write!(f, "certificate error in operation: ")
                    .and_then(|_| reason.fmt(f))
                    .and_then(|_| write!(f, ": "))
                    .and_then(|_| err.fmt(f))
            }
            Error::CorruptMessage => write!(f, "received corrupt message"),
            Error::NoCertificatesPresented => write!(f, "peer sent no certificates"),
            Error::UnsupportedNameType => write!(f, "presented server name type wasn't supported"),
            Error::DecryptError => write!(f, "cannot decrypt peer's message"),
            Error::EncryptError => write!(f, "cannot encrypt message"),
            Error::PeerSentOversizedRecord => write!(f, "peer sent excess record size"),
            Error::HandshakeNotComplete => write!(f, "handshake not complete"),
            Error::NoApplicationProtocol => write!(f, "peer doesn't support any known protocol"),
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
    use super::Error;
    use super::{WebPkiError, WebPkiOp};

    #[test]
    fn smoke() {
        use crate::msgs::enums::{AlertDescription, ContentType, HandshakeType};
        use sct;

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
                WebPkiError::ExtensionValueInvalid,
                WebPkiOp::ValidateServerCert,
            ),
            Error::WebPkiError(WebPkiError::BadEncoding, WebPkiOp::ValidateClientCert),
            Error::WebPkiError(WebPkiError::BadTimeEncoding, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(WebPkiError::CaUsedAsEndEntity, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(WebPkiError::CertExpired, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(
                WebPkiError::CertNotValidForName,
                WebPkiOp::ValidateForDnsName,
            ),
            Error::WebPkiError(WebPkiError::CertNotValidYet, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(WebPkiError::EndEntityUsedAsCa, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(WebPkiError::ExtensionValueInvalid, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(WebPkiError::InvalidCertValidity, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(
                WebPkiError::InvalidSignatureForPublicKey,
                WebPkiOp::VerifySignature,
            ),
            Error::WebPkiError(
                WebPkiError::NameConstraintViolation,
                WebPkiOp::ParseEndEntity,
            ),
            Error::WebPkiError(
                WebPkiError::PathLenConstraintViolation,
                WebPkiOp::ParseEndEntity,
            ),
            Error::WebPkiError(
                WebPkiError::SignatureAlgorithmMismatch,
                WebPkiOp::ParseEndEntity,
            ),
            Error::WebPkiError(WebPkiError::RequiredEkuNotFound, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(WebPkiError::UnknownIssuer, WebPkiOp::ParseEndEntity),
            Error::WebPkiError(
                WebPkiError::UnsupportedCertVersion,
                WebPkiOp::ParseEndEntity,
            ),
            Error::WebPkiError(
                WebPkiError::MissingOrMalformedExtension,
                WebPkiOp::ParseEndEntity,
            ),
            Error::WebPkiError(
                WebPkiError::UnsupportedCriticalExtension,
                WebPkiOp::ParseEndEntity,
            ),
            Error::WebPkiError(
                WebPkiError::UnsupportedSignatureAlgorithmForPublicKey,
                WebPkiOp::ParseEndEntity,
            ),
            Error::WebPkiError(
                WebPkiError::UnsupportedSignatureAlgorithm,
                WebPkiOp::ParseEndEntity,
            ),
            Error::InvalidSct(sct::Error::MalformedSct),
            Error::General("undocumented error".to_string()),
            Error::FailedToGetCurrentTime,
            Error::FailedToGetRandomBytes,
            Error::HandshakeNotComplete,
            Error::PeerSentOversizedRecord,
            Error::NoApplicationProtocol,
            Error::BadMaxFragmentSize,
        ];

        for err in all {
            println!("{:?}:", err);
            println!("  fmt '{}'", err);
        }
    }

    #[test]
    fn webpki_mappings() {
        use webpki::Error;

        fn check(err: Error, expect: WebPkiError) {
            let got: WebPkiError = err.into();
            assert_eq!(got, expect);
        }

        check(Error::BadDer, WebPkiError::BadEncoding);
        check(Error::BadDerTime, WebPkiError::BadTimeEncoding);
        check(Error::CaUsedAsEndEntity, WebPkiError::CaUsedAsEndEntity);
        check(Error::CertExpired, WebPkiError::CertExpired);
        check(Error::CertNotValidForName, WebPkiError::CertNotValidForName);
        check(Error::CertNotValidYet, WebPkiError::CertNotValidYet);
        check(Error::EndEntityUsedAsCa, WebPkiError::EndEntityUsedAsCa);
        check(
            Error::ExtensionValueInvalid,
            WebPkiError::ExtensionValueInvalid,
        );
        check(Error::InvalidCertValidity, WebPkiError::InvalidCertValidity);
        check(
            Error::InvalidSignatureForPublicKey,
            WebPkiError::InvalidSignatureForPublicKey,
        );
        check(
            Error::NameConstraintViolation,
            WebPkiError::NameConstraintViolation,
        );
        check(
            Error::PathLenConstraintViolated,
            WebPkiError::PathLenConstraintViolation,
        );
        check(
            Error::SignatureAlgorithmMismatch,
            WebPkiError::SignatureAlgorithmMismatch,
        );
        check(Error::RequiredEkuNotFound, WebPkiError::RequiredEkuNotFound);
        check(Error::UnknownIssuer, WebPkiError::UnknownIssuer);
        check(
            Error::UnsupportedCertVersion,
            WebPkiError::UnsupportedCertVersion,
        );
        check(
            Error::MissingOrMalformedExtensions,
            WebPkiError::MissingOrMalformedExtension,
        );
        check(
            Error::UnsupportedCriticalExtension,
            WebPkiError::UnsupportedCriticalExtension,
        );
        check(
            Error::UnsupportedSignatureAlgorithmForPublicKey,
            WebPkiError::UnsupportedSignatureAlgorithmForPublicKey,
        );
        check(
            Error::UnsupportedSignatureAlgorithm,
            WebPkiError::UnsupportedSignatureAlgorithm,
        );
    }

    #[test]
    fn rand_error_mapping() {
        use super::rand;
        let err: Error = rand::GetRandomFailed.into();
        assert_eq!(err, Error::FailedToGetRandomBytes);
    }

    #[test]
    fn time_error_mapping() {
        use std::time::SystemTime;

        let time_error = SystemTime::UNIX_EPOCH
            .duration_since(SystemTime::now())
            .unwrap_err();
        let err: Error = time_error.into();
        assert_eq!(err, Error::FailedToGetCurrentTime);
    }
}
