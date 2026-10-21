//! Every decoder that sees network bytes before any authentication.
#![no_main]

use libfuzzer_sys::fuzz_target;
use privmsg_node::wire::{decode, Envelope, Payload};

fuzz_target!(|data: &[u8]| {
    let _ = decode::<Envelope>(data);
    let _ = decode::<Payload>(data);
    let _ = privmsg_crypto::message_group_id(data);
    let _ = privmsg_crypto::decode_key_package(data);
});
