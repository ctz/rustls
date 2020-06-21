
/// The single place where we generate random material
/// for our own use.  These functions never fail,
/// they panic on error.

use ring::rand::{SystemRandom, SecureRandom};
use crate::msgs::codec;

/// Fill the whole slice with random material.
pub fn fill_random(bytes: &mut [u8]) {
    SystemRandom::new()
        .fill(bytes)
        .unwrap();
}

/// Make a Vec<u8> of the given size
/// containing random material.
pub fn random_vec(len: usize) -> Vec<u8> {
    let mut v = vec![0; len];
    fill_random(&mut v);
    v
}

/// Return a uniformly random u8.
pub fn random_u8() -> u8 {
    let mut buf = [0u8; 1];
    fill_random(&mut buf);
    buf[0]
}

/// Return a uniformly random u32.
pub fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    fill_random(&mut buf);
    codec::decode_u32(&buf)
        .unwrap()
}
