//! Transport frames straight off the mixnet.
#![no_main]

use libfuzzer_sys::fuzz_target;
use privmsg_transport::{pad, unpad, MAX_PAYLOAD, PAD_BLOCK};

fuzz_target!(|data: &[u8]| {
    // Odd sizes are refused at once; zero-fill the input to a whole number
    // of blocks as well, so the length prefix and bounds get exercised.
    let mut frame = data.to_vec();
    frame.resize(data.len().div_ceil(PAD_BLOCK).max(1) * PAD_BLOCK, 0);
    for input in [data, &frame[..]] {
        if let Ok(payload) = unpad(input) {
            assert!(payload.len() <= MAX_PAYLOAD);
            // Whatever unpads must pad back to a frame that unpads the same.
            assert_eq!(unpad(&pad(&payload).unwrap()).unwrap(), payload);
        }
    }
});
