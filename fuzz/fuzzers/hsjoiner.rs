#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use std::convert::TryFrom;
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::hsjoiner;
use rustls::internal::msgs::message;

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    let msg = match message::OpaqueMessage::read(&mut rdr) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    let mut jnr = hsjoiner::HandshakeJoiner::new();
    if jnr.want_message(&msg) {
        jnr.take_message(msg);
    }

    let (mut iter, _) = jnr.iter();
    while let Some(msg) = iter.pop() {
        if let Ok(msg) = msg {
            message::Message::try_from(msg).unwrap();
        }
    }
});
