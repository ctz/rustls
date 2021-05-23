use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::PlainMessage;
use crate::Error;
use std::collections::VecDeque;

pub const MAX_FRAGMENT_LEN: usize = 16384;
pub const PACKET_OVERHEAD: usize = 1 + 2 + 2;
pub const MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN + PACKET_OVERHEAD;

pub struct MessageFragmenter {
    max_frag: usize,
}

impl MessageFragmenter {
    /// Make a new fragmenter.
    ///
    /// `max_fragment_size` is the maximum fragment size that will be produced --
    /// this includes overhead. A `max_fragment_size` of 10 will produce TLS fragments
    /// up to 10 bytes.
    pub fn new(max_fragment_size: Option<usize>) -> Result<MessageFragmenter, Error> {
        let max_fragment_len = match max_fragment_size {
            Some(sz @ 32..=MAX_FRAGMENT_SIZE) => sz - PACKET_OVERHEAD,
            None => MAX_FRAGMENT_LEN,
            _ => return Err(Error::BadMaxFragmentSize),
        };

        Ok(MessageFragmenter {
            max_frag: max_fragment_len,
        })
    }

    /// Take the Message `msg` and re-fragment it into new
    /// messages whose fragment is no more than max_frag.
    /// The new messages are appended to the `out` deque.
    /// Payloads are copied.
    pub fn fragment(&self, msg: PlainMessage<'static>, out: &mut VecDeque<PlainMessage<'static>>) {
        // Non-fragment path
        if msg.payload.len() <= self.max_frag {
            out.push_back(msg);
            return;
        }

        for chunk in msg.payload.chunks(self.max_frag) {
            out.push_back(PlainMessage {
                typ: msg.typ,
                version: msg.version,
                payload: chunk.to_vec().into(),
            });
        }
    }

    /// Enqueue borrowed fragments of (version, typ, payload) which
    /// are no longer than max_frag onto the `out` deque.
    pub fn fragment_borrow<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: &'a [u8],
        out: &mut VecDeque<PlainMessage<'a>>,
    ) {
        for chunk in payload.chunks(self.max_frag) {
            let cm = PlainMessage {
                typ,
                version,
                payload: chunk.into(),
            };
            out.push_back(cm);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageFragmenter, PACKET_OVERHEAD};
    use crate::msgs::enums::{ContentType, ProtocolVersion};
    use crate::msgs::message::PlainMessage;
    use std::collections::VecDeque;

    fn msg_eq(
        mm: Option<PlainMessage<'_>>,
        total_len: usize,
        typ: &ContentType,
        version: &ProtocolVersion,
        bytes: &[u8],
    ) {
        let m = mm.unwrap();
        assert_eq!(&m.typ, typ);
        assert_eq!(&m.version, version);
        assert_eq!(m.payload, bytes.to_vec());

        let buf = m.into_unencrypted_opaque().encode();
        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let m = PlainMessage {
            typ,
            version,
            payload: (1..70u8).collect::<Vec<_>>().into(),
        };

        let frag = MessageFragmenter::new(Some(32)).unwrap();
        let mut q = VecDeque::new();
        frag.fragment(m, &mut q);
        msg_eq(
            q.pop_front(),
            32,
            &typ,
            &version,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27,
            ],
        );
        msg_eq(
            q.pop_front(),
            32,
            &typ,
            &version,
            &[
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54,
            ],
        );
        msg_eq(
            q.pop_front(),
            20,
            &typ,
            &version,
            &[55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69],
        );
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn non_fragment() {
        let m = PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"\x01\x02\x03\x04\x05\x06\x07\x08"[..].into(),
        };

        let frag = MessageFragmenter::new(Some(32)).unwrap();
        let mut q = VecDeque::new();
        frag.fragment(m, &mut q);
        msg_eq(
            q.pop_front(),
            PACKET_OVERHEAD + 8,
            &ContentType::Handshake,
            &ProtocolVersion::TLSv1_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        );
        assert_eq!(q.len(), 0);
    }
}
