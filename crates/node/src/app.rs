//! The messenger itself: contacts, invites, and the rules for what to do
//! with each incoming frame. Written against the `Transport` trait, so the
//! same code runs over the Nym mixnet and over the in-memory test network.
//!
//! Conversation setup (Bob invites, Alice joins):
//!
//! ```text
//! Bob:   invite <alice>  ─► code = { bob's mix address, KeyPackage, tag }
//!        ...code handed to Alice out of band...
//! Alice: add <bob> code  ─► create MLS group, add Bob's KeyPackage
//!                           Envelope::Join { Welcome, MLS(Hello{alice addr, tag}) } ─► Bob
//! Bob:   on Join         ─► join group, decrypt Hello, match tag to an open
//!                           invite (then forget it), save Alice's address
//! ```
//!
//! After that both sides exchange `Envelope::Mls` frames. Every state change
//! is saved immediately: the MLS ratchet moves on each message, and losing
//! that state would make later messages undecryptable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use privmsg_crypto::{decode_key_package, encode_key_package, message_group_id, Identity, Session};
use privmsg_transport::{MixAddress, Transport};

use crate::store::{Contact, HistoryEntry, PendingInvite, Profile, State, HISTORY_LIMIT};
use crate::wire::{decode, encode, Envelope, Invite, Payload};

/// Early messages buffered while waiting for their Join. Bounded so a
/// stranger who knows our address can't grow the profile without limit.
const PENDING_LIMIT: usize = 64;

#[derive(Debug, PartialEq)]
pub enum Event {
    Joined { contact: String },
    Message { contact: String, text: String },
}

pub struct Node {
    profile: Profile,
    state: State,
    identity: Identity,
    sessions: HashMap<Vec<u8>, Session>,
}

impl Node {
    /// Create a new profile with a fresh identity.
    pub fn create(dir: &Path, passphrase: &str) -> Result<Self> {
        let profile = Profile::create(dir, passphrase)?;
        // The MLS credential carries a random label, not a user-chosen name,
        // so nothing in a KeyPackage identifies the person behind it.
        let identity = Identity::new(&hex(&random::<16>()))?;
        let mut node = Self {
            profile,
            state: State::default(),
            identity,
            sessions: HashMap::new(),
        };
        node.save()?;
        Ok(node)
    }

    /// Unlock an existing profile and reopen every conversation.
    pub fn open(dir: &Path, passphrase: &str) -> Result<Self> {
        let (profile, state) = Profile::open(dir, passphrase)?;
        let identity = Identity::restore(&state.identity)?;
        let mut sessions = HashMap::new();
        for contact in &state.contacts {
            let session = Session::load(&identity, &contact.group_id)
                .with_context(|| format!("reopen conversation with {}", contact.name))?;
            sessions.insert(contact.group_id.clone(), session);
        }
        Ok(Self {
            profile,
            state,
            identity,
            sessions,
        })
    }

    pub fn nym_dir(&self) -> PathBuf {
        self.profile.nym_dir()
    }

    pub fn contacts(&self) -> &[Contact] {
        &self.state.contacts
    }

    pub fn invites(&self) -> &[PendingInvite] {
        &self.state.invites
    }

    pub fn contact(&self, name: &str) -> Result<&Contact> {
        self.state
            .contacts
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| anyhow!("no contact named {name:?} (see `privmsg contacts`)"))
    }

    /// Mint a one-time invite. Whoever uses it becomes the contact `name`.
    pub fn create_invite(&mut self, my_address: &MixAddress, name: &str) -> Result<String> {
        self.ensure_name_free(name)?;
        let tag = random::<16>();
        let code = Invite {
            address: my_address.0.clone(),
            key_package: encode_key_package(&self.identity.key_package()?)?,
            tag,
        }
        .to_code()?;
        self.state.invites.push(PendingInvite {
            tag,
            name: name.to_string(),
        });
        self.save()?;
        Ok(code)
    }

    /// Use someone's invite: start a conversation and save them as `name`.
    pub async fn accept_invite<T: Transport>(
        &mut self,
        transport: &mut T,
        code: &str,
        name: &str,
    ) -> Result<()> {
        self.ensure_name_free(name)?;
        let invite = Invite::from_code(code)?;
        let my_address = transport.address();
        if invite.address == my_address.0 {
            bail!("that invite is your own");
        }
        let key_package = decode_key_package(&invite.key_package)?;

        let mut session = Session::create(&self.identity)?;
        let welcome = session.add_member(&self.identity, key_package)?;
        let hello = Payload::Hello {
            reply_to: my_address.0,
            invite_tag: invite.tag,
        };
        let hello = session.encrypt(&self.identity, &encode(&hello)?)?;
        let frame = encode(&Envelope::Join { welcome, hello })?;

        if let Err(e) = transport
            .send(&MixAddress(invite.address.clone()), &frame)
            .await
        {
            session.delete(&self.identity)?;
            return Err(e);
        }
        self.add_contact(name, session, invite.address);
        self.save()
    }

    pub async fn send_text<T: Transport>(
        &mut self,
        transport: &mut T,
        name: &str,
        text: &str,
    ) -> Result<()> {
        let contact = self.contact(name)?;
        let group_id = contact.group_id.clone();
        let to = MixAddress(contact.address.clone());
        let session = self
            .sessions
            .get_mut(&group_id)
            .ok_or_else(|| anyhow!("conversation state for {name:?} is missing"))?;

        let ciphertext = session.encrypt(&self.identity, &encode(&Payload::Text(text.into()))?)?;
        let sent = transport
            .send(&to, &encode(&Envelope::Mls(ciphertext))?)
            .await;
        if sent.is_ok() {
            self.record(&group_id, true, text);
        }
        // The ratchet advanced whether or not the send went through.
        self.save()?;
        sent
    }

    /// Process one frame from the transport. Errors mean the frame was
    /// rejected (malformed, forged, replayed, unknown invite); the node stays
    /// usable either way.
    pub fn handle_incoming(&mut self, payload: &[u8]) -> Result<Vec<Event>> {
        match decode::<Envelope>(payload).context("malformed frame")? {
            Envelope::Join { welcome, hello } => self.handle_join(&welcome, &hello),
            Envelope::Mls(ciphertext) => self.handle_mls(ciphertext),
        }
    }

    fn handle_join(&mut self, welcome: &[u8], hello: &[u8]) -> Result<Vec<Event>> {
        let mut session = Session::join(&self.identity, welcome)?;
        let group_id = session.group_id();

        let matched = match session
            .decrypt(&self.identity, hello)
            .and_then(|pt| decode::<Payload>(&pt))
        {
            Ok(Payload::Hello {
                reply_to,
                invite_tag,
            }) => self
                .state
                .invites
                .iter()
                .position(|i| i.tag == invite_tag)
                .map(|idx| (idx, reply_to)),
            _ => None,
        };
        let Some((idx, reply_to)) = matched else {
            session.delete(&self.identity)?;
            self.save()?;
            bail!("refused a join that does not match any open invite");
        };

        let name = self.state.invites.remove(idx).name;
        self.add_contact(&name, session, reply_to);
        let mut events = vec![Event::Joined {
            contact: name.clone(),
        }];

        // Messages that overtook this Join in the mixnet.
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.state.pending)
            .into_iter()
            .partition(|ct| message_group_id(ct).is_ok_and(|g| g == group_id));
        self.state.pending = waiting;
        for ct in ready {
            match self.decrypt_into_history(&group_id, &ct) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => {}
                Err(e) => tracing::warn!("dropping early message from {name}: {e:#}"),
            }
        }
        self.save()?;
        Ok(events)
    }

    fn handle_mls(&mut self, ciphertext: Vec<u8>) -> Result<Vec<Event>> {
        let group_id = message_group_id(&ciphertext)?;
        if !self.sessions.contains_key(&group_id) {
            if self.state.pending.len() >= PENDING_LIMIT {
                self.state.pending.remove(0);
            }
            self.state.pending.push(ciphertext);
            self.save()?;
            return Ok(vec![]);
        }
        let event = self.decrypt_into_history(&group_id, &ciphertext)?;
        self.save()?;
        Ok(event.into_iter().collect())
    }

    fn decrypt_into_history(
        &mut self,
        group_id: &[u8],
        ciphertext: &[u8],
    ) -> Result<Option<Event>> {
        let session = self
            .sessions
            .get_mut(group_id)
            .ok_or_else(|| anyhow!("unknown conversation"))?;
        let plaintext = session.decrypt(&self.identity, ciphertext)?;
        match decode::<Payload>(&plaintext)? {
            Payload::Text(text) => {
                let contact = self.record(group_id, false, &text);
                Ok(Some(Event::Message { contact, text }))
            }
            // A repeated Hello carries nothing new.
            Payload::Hello { .. } => Ok(None),
        }
    }

    fn ensure_name_free(&self, name: &str) -> Result<()> {
        if name.trim().is_empty() || name.chars().any(char::is_control) {
            bail!("contact names must be non-empty printable text");
        }
        let taken = self.state.contacts.iter().any(|c| c.name == name)
            || self.state.invites.iter().any(|i| i.name == name);
        if taken {
            bail!("the name {name:?} is already used by a contact or open invite");
        }
        Ok(())
    }

    fn add_contact(&mut self, name: &str, session: Session, address: String) {
        let group_id = session.group_id();
        self.state.contacts.push(Contact {
            name: name.to_string(),
            group_id: group_id.clone(),
            address,
            history: Vec::new(),
        });
        self.sessions.insert(group_id, session);
    }

    /// Append to a contact's history; returns the contact's name.
    fn record(&mut self, group_id: &[u8], outgoing: bool, text: &str) -> String {
        let contact = self
            .state
            .contacts
            .iter_mut()
            .find(|c| c.group_id == group_id)
            .expect("every session belongs to a contact");
        contact.history.push(HistoryEntry {
            outgoing,
            text: text.to_string(),
            at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        });
        let excess = contact.history.len().saturating_sub(HISTORY_LIMIT);
        contact.history.drain(..excess);
        contact.name.clone()
    }

    fn save(&mut self) -> Result<()> {
        self.state.identity = self.identity.snapshot()?;
        self.profile.save(&self.state)
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use privmsg_transport::memory::{MemoryNetwork, MemoryTransport};
    use tempfile::TempDir;

    const PW: &str = "test passphrase";

    struct Peer {
        _dir: TempDir,
        path: PathBuf,
        node: Node,
        net: MemoryTransport,
    }

    impl Peer {
        fn new(network: &MemoryNetwork, addr: &str) -> Result<Self> {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("profile");
            Ok(Self {
                node: Node::create(&path, PW)?,
                net: network.connect(addr)?,
                path,
                _dir: dir,
            })
        }

        async fn recv(&mut self) -> Result<Vec<Event>> {
            let msg = self.net.recv().await?;
            self.node.handle_incoming(&msg.payload)
        }

        /// Simulate quitting and restarting: the old node (and its profile
        /// lock) is dropped before the profile is reopened from disk.
        fn reopen(self) -> Result<Self> {
            let Peer {
                _dir,
                path,
                node,
                net,
            } = self;
            drop(node);
            Ok(Peer {
                node: Node::open(&path, PW)?,
                _dir,
                path,
                net,
            })
        }
    }

    /// Bob invites Alice; Alice joins; Bob processes the Join.
    async fn connected(net: &MemoryNetwork) -> Result<(Peer, Peer)> {
        let mut alice = Peer::new(net, "alice-addr")?;
        let mut bob = Peer::new(net, "bob-addr")?;
        let code = bob.node.create_invite(&bob.net.address(), "alice")?;
        alice
            .node
            .accept_invite(&mut alice.net, &code, "bob")
            .await?;
        assert_eq!(
            bob.recv().await?,
            vec![Event::Joined {
                contact: "alice".into()
            }]
        );
        Ok((alice, bob))
    }

    #[tokio::test]
    async fn invite_join_and_chat_both_ways() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        assert!(bob.node.invites().is_empty(), "invite is used up");

        alice
            .node
            .send_text(&mut alice.net, "bob", "hi bob")
            .await?;
        assert_eq!(
            bob.recv().await?,
            vec![Event::Message {
                contact: "alice".into(),
                text: "hi bob".into()
            }]
        );
        bob.node
            .send_text(&mut bob.net, "alice", "hi alice")
            .await?;
        assert_eq!(
            alice.recv().await?,
            vec![Event::Message {
                contact: "bob".into(),
                text: "hi alice".into()
            }]
        );

        let history = &alice.node.contact("bob")?.history;
        assert_eq!(history.len(), 2);
        assert!(history[0].outgoing && !history[1].outgoing);
        Ok(())
    }

    #[tokio::test]
    async fn conversation_survives_restart() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        alice.node.send_text(&mut alice.net, "bob", "one").await?;
        bob.recv().await?;

        let mut alice = alice.reopen()?;
        let mut bob = bob.reopen()?;
        assert_eq!(bob.node.contact("alice")?.history[0].text, "one");

        alice.node.send_text(&mut alice.net, "bob", "two").await?;
        assert_eq!(
            bob.recv().await?,
            vec![Event::Message {
                contact: "alice".into(),
                text: "two".into()
            }]
        );
        bob.node.send_text(&mut bob.net, "alice", "three").await?;
        assert_eq!(alice.recv().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn invite_works_after_inviter_restarts() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut alice = Peer::new(&net, "alice-addr")?;
        let mut bob = Peer::new(&net, "bob-addr")?;
        let code = bob.node.create_invite(&bob.net.address(), "alice")?;
        let mut bob = bob.reopen()?;
        alice
            .node
            .accept_invite(&mut alice.net, &code, "bob")
            .await?;
        assert_eq!(bob.recv().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn invite_is_single_use() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut alice = Peer::new(&net, "alice-addr")?;
        let mut carol = Peer::new(&net, "carol-addr")?;
        let mut bob = Peer::new(&net, "bob-addr")?;
        let code = bob.node.create_invite(&bob.net.address(), "alice")?;

        alice
            .node
            .accept_invite(&mut alice.net, &code, "bob")
            .await?;
        bob.recv().await?;
        carol
            .node
            .accept_invite(&mut carol.net, &code, "bob")
            .await?;
        assert!(bob.recv().await.is_err(), "second use is refused");
        assert_eq!(bob.node.contacts().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn message_that_overtakes_its_join_is_delivered() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut alice = Peer::new(&net, "alice-addr")?;
        let mut bob = Peer::new(&net, "bob-addr")?;
        let code = bob.node.create_invite(&bob.net.address(), "alice")?;
        alice
            .node
            .accept_invite(&mut alice.net, &code, "bob")
            .await?;
        alice.node.send_text(&mut alice.net, "bob", "early").await?;

        // Deliver in the wrong order, as the mixnet may.
        let join = bob.net.recv().await?.payload;
        let text = bob.net.recv().await?.payload;
        assert!(bob.node.handle_incoming(&text)?.is_empty(), "buffered");
        let events = bob.node.handle_incoming(&join)?;
        assert_eq!(
            events,
            vec![
                Event::Joined {
                    contact: "alice".into()
                },
                Event::Message {
                    contact: "alice".into(),
                    text: "early".into()
                }
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn garbage_and_replays_are_rejected_without_breaking_the_node() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        assert!(bob.node.handle_incoming(b"garbage").is_err());

        alice.node.send_text(&mut alice.net, "bob", "once").await?;
        let frame = bob.net.recv().await?.payload;
        assert_eq!(bob.node.handle_incoming(&frame)?.len(), 1);
        assert!(bob.node.handle_incoming(&frame).is_err(), "replay refused");

        alice
            .node
            .send_text(&mut alice.net, "bob", "still fine")
            .await?;
        assert_eq!(bob.recv().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn names_must_be_unique_and_own_invite_is_refused() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut bob = Peer::new(&net, "bob-addr")?;
        let code = bob.node.create_invite(&bob.net.address(), "alice")?;
        assert!(bob.node.create_invite(&bob.net.address(), "alice").is_err());
        assert!(bob.node.create_invite(&bob.net.address(), "  ").is_err());
        let err = bob
            .node
            .accept_invite(&mut bob.net, &code, "me")
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("your own"));
        assert!(bob
            .node
            .send_text(&mut bob.net, "nobody", "x")
            .await
            .is_err());
        Ok(())
    }
}
