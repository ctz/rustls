use crate::conn::CommonState;
use crate::kx;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, ContentType};
use crate::Error;

pub(crate) fn decode_ecdh_params<T: Codec>(
    conn: &mut CommonState,
    kx_params: &[u8],
) -> Result<T, Error> {
    decode_ecdh_params_::<T>(kx_params).ok_or_else(|| {
        conn.send_fatal_alert(AlertDescription::DecodeError);
        Error::CorruptMessagePayload(ContentType::Handshake)
    })
}

fn decode_ecdh_params_<T: Codec>(kx_params: &[u8]) -> Option<T> {
    let mut rd = Reader::init(kx_params);
    let ecdh_params = T::read(&mut rd)?;
    match rd.any_left() {
        false => Some(ecdh_params),
        true => None,
    }
}

pub(crate) fn complete_ecdh(
    mine: kx::KeyExchange,
    peer_pub_key: &[u8],
) -> Result<kx::KeyExchangeResult, Error> {
    mine.complete(peer_pub_key)
        .ok_or_else(|| Error::PeerMisbehavedError("key agreement failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::handshake::{ClientECDHParams, ServerECDHParams};

    #[test]
    fn server_ecdhe_remaining_bytes() {
        let key = kx::KeyExchange::start(&kx::X25519).unwrap();
        let server_params = ServerECDHParams::new(key.group(), key.pubkey.as_ref());
        let mut server_buf = Vec::new();
        server_params.encode(&mut server_buf);
        server_buf.push(34);
        assert!(decode_ecdh_params_::<ServerECDHParams>(&server_buf).is_none());
    }

    #[test]
    fn client_ecdhe_invalid() {
        assert!(decode_ecdh_params_::<ClientECDHParams>(&[34]).is_none());
    }
}
