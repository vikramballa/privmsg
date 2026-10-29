//! What privmsg puts on the wire, and the invite code users exchange.
//!
//! ```text
//! transport frame (padded, Sphinx-wrapped by Nym)
//!   └─ Envelope::Join { welcome, hello }   first contact
//!      Envelope::Mls(ciphertext)           everything after
//!         └─ MLS-encrypted Payload::Hello / Text / Rotate / RotateAck / Timer
//!                                  / Delete / Clear
//!      Envelope::Decoy(random)             cover, discarded on arrival
//! ```
//!
//! Nothing identifying travels outside MLS encryption: the joiner's return
//! address and the invite tag ride inside the encrypted `Hello`, and contact
//! nicknames never leave the device.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const INVITE_PREFIX: &str = "privmsg1:";

/// Bound on any decoded structure, so a hostile frame can't make us allocate
/// more than one transport payload's worth of memory.
const DECODE_LIMIT: u64 = privmsg_transport::MAX_PAYLOAD as u64;

fn codec() -> impl Options {
    bincode::DefaultOptions::new().with_limit(DECODE_LIMIT)
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    codec().serialize(value).context("encode")
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    codec().deserialize(bytes).context("decode")
}

/// Everything a contact needs to start a conversation with us. Shared out of
/// band (in person, QR code, an existing secure channel). It is single-use:
/// the key package inside can be consumed once, and the tag is forgotten
/// after the first join.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Invite {
    /// Our mix address.
    pub address: String,
    /// TLS-encoded MLS KeyPackage.
    pub key_package: Vec<u8>,
    /// Random; proves a Join came from someone holding this invite.
    pub tag: [u8; 16],
}

impl Invite {
    pub fn to_code(&self) -> Result<String> {
        Ok(format!(
            "{INVITE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(encode(self)?)
        ))
    }

    /// Whitespace anywhere is ignored, so a code that was wrapped across
    /// lines when copied still works.
    pub fn from_code(code: &str) -> Result<Self> {
        let code: String = code.split_whitespace().collect();
        let body = code.strip_prefix(INVITE_PREFIX).ok_or_else(|| {
            anyhow!("not a privmsg invite (expected it to start with {INVITE_PREFIX})")
        })?;
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| anyhow!("invite code is damaged (bad base64)"))?;
        decode(&bytes).context("invite code is damaged")
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Envelope {
    /// First contact: the MLS Welcome plus an MLS-encrypted `Hello`, bundled
    /// in one frame so the mixnet can't deliver them out of order.
    Join { welcome: Vec<u8>, hello: Vec<u8> },
    /// An MLS application message for an existing conversation.
    Mls(Vec<u8>),
    /// Random filler sent instead of a real message when decoys are on.
    /// Sphinx encryption makes it look like any other packet to everyone
    /// but the recipient, who throws it away.
    Decoy(Vec<u8>),
}

/// Plaintext carried inside MLS application messages.
#[derive(Serialize, Deserialize, Debug)]
pub enum Payload {
    Hello {
        reply_to: String,
        invite_tag: [u8; 16],
    },
    Text(String),
    /// "From now on, write to me at `reply_to`." Sent when we rotate the
    /// address we receive this conversation on.
    Rotate {
        reply_to: String,
    },
    /// Sent to our new address on receiving a `Rotate`, so the old one can
    /// be retired.
    RotateAck,
    /// "Delete our messages once they are this many seconds old" (`None` =
    /// keep them). Both sides apply it to the whole conversation.
    Timer {
        after: Option<u64>,
    },
    /// "Delete this message I sent, for you too." Removes only a message
    /// from the sender of the `Delete`.
    Delete {
        id: MessageId,
    },
    /// "I emptied our chat, for both of us." `yours`: the newest message
    /// the sender had from the receiver, so the receiver's messages still
    /// on their way survive on both sides; `mine`: the newest one the
    /// sender sent, in case the `Clear` overtakes it.
    Clear {
        yours: Option<MessageId>,
        mine: Option<MessageId>,
    },
}

/// Both sides' name for one message, without sending one: each side hashes
/// the same MLS ciphertext, the sender after encrypting, the receiver
/// before decrypting.
pub type MessageId = [u8; 16];

pub fn message_id(ciphertext: &[u8]) -> MessageId {
    let digest = Sha256::new()
        .chain_update(b"privmsg message id\0")
        .chain_update(ciphertext)
        .finalize();
    digest[..16].try_into().expect("16 of 32 bytes")
}

/// Plausibility check for a mix address received from a peer. The transport
/// does the real parsing when we send; this keeps junk out of the profile.
pub fn valid_address(address: &str) -> bool {
    !address.is_empty() && address.len() <= 512 && address.chars().all(|c| c.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> Invite {
        Invite {
            address: "addr.gateway@id".into(),
            key_package: vec![5; 300],
            tag: [7; 16],
        }
    }

    #[test]
    fn invite_code_roundtrip() -> Result<()> {
        let code = invite().to_code()?;
        assert!(code.starts_with(INVITE_PREFIX));
        assert_eq!(Invite::from_code(&format!("  {code}\n"))?, invite());
        let (a, b) = code.split_at(30);
        assert_eq!(
            Invite::from_code(&format!("{a}\n  {b}"))?,
            invite(),
            "wrapped"
        );
        Ok(())
    }

    #[test]
    fn damaged_invite_codes_are_rejected() -> Result<()> {
        let code = invite().to_code()?;
        assert!(Invite::from_code("hello").is_err());
        assert!(Invite::from_code(&code[..code.len() - 10]).is_err());
        assert!(Invite::from_code(&format!("{code}!!")).is_err());
        Ok(())
    }

    #[test]
    fn hostile_length_prefix_does_not_allocate() {
        // A varint claiming a multi-gigabyte Vec must fail cleanly.
        let mut evil = vec![1u8]; // Envelope::Mls
        evil.extend_from_slice(&[0xfd, 0xff, 0xff, 0xff, 0xff]);
        assert!(decode::<Envelope>(&evil).is_err());
    }

    #[test]
    fn trailing_garbage_is_rejected() -> Result<()> {
        let mut bytes = encode(&Payload::Text("hi".into()))?;
        bytes.push(0);
        assert!(decode::<Payload>(&bytes).is_err());
        Ok(())
    }
}
