//! Invite codes, as pasted by users.
#![no_main]

use libfuzzer_sys::fuzz_target;
use privmsg_node::wire::Invite;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(invite) = Invite::from_code(text) {
        let again = Invite::from_code(&invite.to_code().unwrap()).unwrap();
        assert_eq!(again, invite);
        let _ = privmsg_crypto::decode_key_package(&invite.key_package);
    }
});
