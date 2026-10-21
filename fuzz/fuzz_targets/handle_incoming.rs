//! `Node::handle_incoming`, the one entry point for everything that arrives.
//!
//! Random bytes almost never get past MLS, so besides raw frames the input
//! also drives a real peer ("alice", driven through the crypto layer
//! directly) that encrypts fuzzer-chosen plaintexts, corrupts real frames, or
//! joins with a fuzzer-chosen Hello. Bob's node persists across inputs, as a
//! long-running node does.
#![no_main]

use std::sync::{Mutex, OnceLock};

use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use privmsg_crypto::{decode_key_package, Identity, Session};
use privmsg_node::app::Node;
use privmsg_node::wire::{encode, Envelope, Invite, Payload};
use privmsg_transport::memory::MemoryNetwork;
use privmsg_transport::{Mux, Network};

const ALICE: &str = "alice-fuzz-address";

struct World {
    _dir: tempfile::TempDir,
    net: MemoryNetwork,
    bob: Node,
    mux: Mux<MemoryNetwork>,
    alice: Identity,
    session: Session,
    joins: u64,
}

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let net = MemoryNetwork::default();
        let mut bob = Node::create(&dir.path().join("bob"), "fuzz passphrase").unwrap();
        let mut mux = Mux::new(net.clone());
        let alice = Identity::new("alice").unwrap();
        let (session, join) = block_on(start_join(&mut bob, &mut mux, &alice, "alice", None));
        let slot = invite_slot(&bob);
        block_on(bob.handle_incoming(&mut mux, &slot, &join)).unwrap();
        World {
            _dir: dir,
            net,
            bob,
            mux,
            alice,
            session,
            joins: 0,
        }
    }

    fn alice_slot(&self) -> String {
        self.bob.contact("alice").unwrap().slot.id.clone()
    }

    fn mls(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ct = self.session.encrypt(&self.alice, plaintext).unwrap();
        encode(&Envelope::Mls(ct)).unwrap()
    }
}

fn invite_slot(bob: &Node) -> String {
    bob.invites().last().unwrap().slot.id.clone()
}

/// Bob invites `name`; `joiner` builds the Join, with `hello` as the Hello
/// plaintext if given (otherwise a correct one).
async fn start_join(
    bob: &mut Node,
    mux: &mut Mux<MemoryNetwork>,
    joiner: &Identity,
    name: &str,
    hello: Option<&[u8]>,
) -> (Session, Vec<u8>) {
    let invite = Invite::from_code(&bob.create_invite(mux, name).await.unwrap()).unwrap();
    let mut session = Session::create(joiner).unwrap();
    let kp = decode_key_package(&invite.key_package).unwrap();
    let welcome = session.add_member(joiner, kp).unwrap();
    let plaintext = match hello {
        Some(bytes) => bytes.to_vec(),
        None => encode(&Payload::Hello {
            reply_to: ALICE.into(),
            invite_tag: invite.tag,
        })
        .unwrap(),
    };
    let hello = session.encrypt(joiner, &plaintext).unwrap();
    let frame = encode(&Envelope::Join { welcome, hello }).unwrap();
    (session, frame)
}

fn world() -> &'static Mutex<World> {
    static WORLD: OnceLock<Mutex<World>> = OnceLock::new();
    WORLD.get_or_init(|| Mutex::new(World::new()))
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else {
        return;
    };
    let mut guard = world().lock().unwrap();
    let w = &mut *guard;
    block_on(async {
        match kind % 4 {
            // Raw bytes on Bob's conversation address, an invite-less
            // address, or a made-up one.
            0 => {
                let slot = match rest.first().map(|b| b % 3) {
                    Some(0) => w.alice_slot(),
                    Some(1) => "no-such-slot".to_string(),
                    _ => w.bob.contacts()[0].slot.id.clone(),
                };
                let _ = w.bob.handle_incoming(&mut w.mux, &slot, rest).await;
            }
            // Authentic MLS message with a fuzzer-chosen plaintext.
            1 => {
                let frame = w.mls(rest);
                let slot = w.alice_slot();
                let _ = w.bob.handle_incoming(&mut w.mux, &slot, &frame).await;
            }
            // A real text message, corrupted at fuzzer-chosen positions.
            2 => {
                let mut frame = w.mls(&encode(&Payload::Text("hi".into())).unwrap());
                for pair in rest.chunks_exact(3) {
                    let at = u16::from_le_bytes([pair[0], pair[1]]) as usize % frame.len();
                    frame[at] ^= pair[2];
                }
                let slot = w.alice_slot();
                let _ = w.bob.handle_incoming(&mut w.mux, &slot, &frame).await;
            }
            // A Join to a fresh invite with a fuzzer-chosen Hello.
            _ => {
                w.joins += 1;
                let name = format!("joiner{}", w.joins);
                let joiner = Identity::new("joiner").unwrap();
                let hello = (!rest.is_empty()).then_some(rest);
                let (_, frame) = start_join(&mut w.bob, &mut w.mux, &joiner, &name, hello).await;
                let slot = invite_slot(&w.bob);
                let _ = w.bob.handle_incoming(&mut w.mux, &slot, &frame).await;
                w.bob.remove(&mut w.mux, &name).await.unwrap();
            }
        }
    });
    // Bob may now write to a fuzzer-chosen address (a Rotate); drop what
    // piles up there so memory stays flat.
    let address = w.bob.contact("alice").unwrap().address.clone();
    if address != ALICE {
        w.net.forget(&address).unwrap();
    }
    w.net.forget(ALICE).unwrap();
    assert_eq!(w.bob.contacts().len(), 1, "fuzz joins are removed again");
    assert!(w.bob.invites().is_empty());
});
