use crate::error::Error;
#[cfg(feature = "logging")]
use crate::log::warn;
use crate::msgs::enums::{ContentType, HandshakeType};
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::message::{Message, MessagePayload};

/// For a Message $m, and a HandshakePayload enum member $payload_type,
/// return Ok(payload) if $m is both a handshake message and one that
/// has the given $payload_type.  If not, return Err(rustls::Error) quoting
/// $handshake_type as the expected handshake type.
macro_rules! require_handshake_msg(
  ( $m:expr, $handshake_type:path, $payload_type:path ) => (
    match $m.payload {
        MessagePayload::Handshake(ref hsp) => match hsp.payload {
            $payload_type(ref hm) => Ok(hm),
            _ => Err(Error::InappropriateHandshakeMessage {
                     expect_types: vec![ $handshake_type ],
                     got_type: hsp.typ})
        }
        _ => Err(Error::InappropriateMessage {
                 expect_types: vec![ ContentType::Handshake ],
                 got_type: $m.payload.content_type()})
    }
  )
);

/// Like require_handshake_msg, but moves the payload out of $m.
#[cfg(feature = "tls12")]
macro_rules! require_handshake_msg_move(
  ( $m:expr, $handshake_type:path, $payload_type:path ) => (
    match $m.payload {
        MessagePayload::Handshake(hsp) => match hsp.payload {
            $payload_type(hm) => Ok(hm),
            _ => Err(Error::InappropriateHandshakeMessage {
                     expect_types: vec![ $handshake_type ],
                     got_type: hsp.typ})
        }
        _ => Err(Error::InappropriateMessage {
                 expect_types: vec![ ContentType::Handshake ],
                 got_type: $m.payload.content_type()})
    }
  )
);

/// Validate the message `m`: return an error if:
///
/// - the type of m does not appear in `content_types`.
/// - if m is a handshake message, the handshake message type does
///   not appear in `handshake_types`.
pub(crate) fn check_message(
    m: &Message,
    content_types: &[ContentType],
    handshake_types: &[HandshakeType],
) -> Result<(), Error> {
    if !content_types.contains(&m.payload.content_type()) {
        return Err(inappropriate_message(m, content_types));
    }

    if let MessagePayload::Handshake(ref hsp) = m.payload {
        if !handshake_types.is_empty() && !handshake_types.contains(&hsp.typ) {
            return Err(inappropriate_handshake_message(hsp, handshake_types));
        }
    }

    Ok(())
}

pub(crate) fn inappropriate_message(m: &Message, content_types: &[ContentType]) -> Error {
    warn!(
        "Received a {:?} message while expecting {:?}",
        m.payload.content_type(),
        content_types
    );
    Error::InappropriateMessage {
        expect_types: content_types.to_vec(),
        got_type: m.payload.content_type(),
    }
}

pub(crate) fn inappropriate_handshake_message(
    hsp: &HandshakeMessagePayload,
    handshake_types: &[HandshakeType],
) -> Error {
    warn!(
        "Received a {:?} handshake message while expecting {:?}",
        hsp.typ, handshake_types
    );
    Error::InappropriateHandshakeMessage {
        expect_types: handshake_types.to_vec(),
        got_type: hsp.typ,
    }
}
