//! The messenger itself: contacts, invites, address rotation, and the rules
//! for what to do with each incoming frame. Written against the transport's
//! `Network`/`Mux`, so the same code runs over the Nym mixnet and over the
//! in-memory test network.
//!
//! Every conversation has its own *slot*: a mix address of ours used for
//! that conversation alone. Invites carry a fresh one, so two people holding
//! invites from the same person can't tell by address.
//!
//! Conversation setup (Bob invites, Alice joins):
//!
//! ```text
//! Bob:   invite <alice>  ─► new slot B1; code = { B1's address, KeyPackage, tag }
//!        ...code handed to Alice out of band...
//! Alice: add <bob> code  ─► new slot A1; create MLS group, add Bob's KeyPackage
//!                           Envelope::Join { Welcome, MLS(Hello{A1, tag}) } ─► B1
//! Bob:   on Join at B1   ─► check the tag belongs to B1's invite (then forget
//!                           it), join the group, save A1 as Alice's address
//! ```
//!
//! Address rotation (either side, for the address it receives on):
//!
//! ```text
//! Bob:   new slot B2; MLS(Rotate{B2}) ─► A1      B1 still listened on
//! Alice: address for Bob := B2; MLS(RotateAck) ─► B2
//! Bob:   anything arriving at B2 confirms the switch; B1 is retired a
//!        grace period later
//! ```
//!
//! A message is accepted only on a slot that belongs to its conversation,
//! so nobody can probe whether two addresses lead to the same person.
//!
//! Every state change is saved immediately: the MLS ratchet moves on each
//! message, and losing that state would make later messages undecryptable.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use privmsg_crypto::{decode_key_package, encode_key_package, message_group_id, Identity, Session};
use privmsg_transport::{MixAddress, Mux, Network};

use crate::store::{
    Contact, HistoryEntry, OldSlot, PendingInvite, PendingMessage, Profile, Settings, Slot, State,
    HISTORY_LIMIT,
};
use crate::wire::{decode, encode, valid_address, Envelope, Invite, Payload};

/// Longest message text, in bytes, sent or accepted. It keeps every message
/// to a few padded blocks and bounds what one contact can add to the profile.
pub const MAX_TEXT: usize = 16 * 1024;

/// Early messages buffered while waiting for their Join. Bounded so a
/// stranger who knows an invite address can't grow the profile without limit.
const PENDING_LIMIT: usize = 64;

/// How long one address serves a conversation before it is replaced.
pub const ROTATE_EVERY: u64 = 7 * 24 * 3600;

/// How long an old address keeps listening after the contact has confirmed
/// the switch, for messages that were already on their way.
pub const RETIRE_GRACE: u64 = 24 * 3600;

/// An old address is retired only once it has been connected this long in
/// the current session, so its gateway has handed over anything it stored.
const DRAIN_TIME: Duration = Duration::from_secs(60);

/// Disappearing-message timers offered to the user, in seconds, with the
/// words used for each.
pub const TIMERS: [(u64, &str); 4] = [
    (5 * 60, "5m"),
    (3600, "1h"),
    (24 * 3600, "1d"),
    (7 * 24 * 3600, "1w"),
];

/// Bounds on a timer set by the contact.
const TIMER_RANGE: std::ops::RangeInclusive<u64> = 60..=365 * 24 * 3600;

/// `"off"` or one of [`TIMERS`]' words.
pub fn parse_timer(word: &str) -> Result<Option<u64>> {
    if word == "off" {
        return Ok(None);
    }
    TIMERS
        .iter()
        .find(|(_, w)| *w == word)
        .map(|(secs, _)| Some(*secs))
        .ok_or_else(|| anyhow!("use off, 5m, 1h, 1d or 1w"))
}

/// A timer in words, for the user.
pub fn describe_timer(after: Option<u64>) -> String {
    let Some(secs) = after else {
        return "off".into();
    };
    match secs {
        s if s % (7 * 24 * 3600) == 0 => plural(s / (7 * 24 * 3600), "week"),
        s if s % (24 * 3600) == 0 => plural(s / (24 * 3600), "day"),
        s if s % 3600 == 0 => plural(s / 3600, "hour"),
        s => plural(s.div_ceil(60), "minute"),
    }
}

fn plural(n: u64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

/// The timer after `current` in [`TIMERS`], wrapping round through off.
pub fn next_timer(current: Option<u64>) -> Option<u64> {
    match current {
        None => Some(TIMERS[0].0),
        Some(secs) => TIMERS.iter().map(|(s, _)| *s).find(|s| *s > secs),
    }
}

#[derive(Debug, PartialEq)]
pub enum Event {
    Joined {
        contact: String,
    },
    Message {
        contact: String,
        text: String,
    },
    /// The contact changed the conversation's disappearing-message timer.
    Timer {
        contact: String,
        after: Option<u64>,
    },
}

pub struct Node {
    profile: Profile,
    state: State,
    identity: Identity,
    sessions: HashMap<Vec<u8>, Session>,
    /// When each slot was opened in this session.
    opened: HashMap<String, Instant>,
    /// Conversations whose unconfirmed rotation was re-sent this session.
    rotation_resent: HashSet<Vec<u8>>,
}

impl Node {
    /// Create a new profile with a fresh identity.
    pub fn create(dir: &Path, passphrase: &str) -> Result<Self> {
        let profile = Profile::create(dir, passphrase)?;
        // The MLS credential carries a random label, not a user-chosen name,
        // so nothing in a KeyPackage identifies the person behind it.
        let identity = Identity::new(&hex(&random::<16>()))?;
        let mut node = Self::assemble(profile, State::default(), identity, HashMap::new());
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
        let mut node = Self::assemble(profile, state, identity, sessions);
        node.expire()?;
        Ok(node)
    }

    fn assemble(
        profile: Profile,
        state: State,
        identity: Identity,
        sessions: HashMap<Vec<u8>, Session>,
    ) -> Self {
        Self {
            profile,
            state,
            identity,
            sessions,
            opened: HashMap::new(),
            rotation_resent: HashSet::new(),
        }
    }

    pub fn profile_dir(&self) -> &Path {
        self.profile.dir()
    }

    pub fn slots_dir(&self) -> PathBuf {
        self.profile.slots_dir()
    }

    pub fn tor_dir(&self) -> PathBuf {
        self.profile.tor_dir()
    }

    pub fn contacts(&self) -> &[Contact] {
        &self.state.contacts
    }

    pub fn invites(&self) -> &[PendingInvite] {
        &self.state.invites
    }

    pub fn settings(&self) -> &Settings {
        &self.state.settings
    }

    pub fn set_settings(&mut self, settings: Settings) -> Result<()> {
        self.state.settings = settings;
        self.save()
    }

    pub fn contact(&self, name: &str) -> Result<&Contact> {
        self.state
            .contacts
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| anyhow!("no contact named {name:?} (see `privmsg contacts`)"))
    }

    /// Our slots for `name`: the current one first, then any being retired.
    pub fn slots_for(&self, name: &str) -> Result<Vec<String>> {
        let c = self.contact(name)?;
        Ok(std::iter::once(&c.slot)
            .chain(c.old_slots.iter().map(|o| &o.slot))
            .map(|s| s.id.clone())
            .collect())
    }

    /// Every slot something may arrive on: all conversations and invites.
    pub fn all_slots(&self) -> Vec<String> {
        let mut slots: Vec<String> = Vec::new();
        for id in self.slots().map(|s| &s.id) {
            if !slots.contains(id) {
                slots.push(id.clone());
            }
        }
        slots
    }

    /// Bring `slots` online, recording addresses learned for the first time.
    pub async fn connect<N: Network>(&mut self, mux: &mut Mux<N>, slots: &[String]) -> Result<()> {
        let addresses = mux.open(slots).await?;
        let now = Instant::now();
        for (id, address) in slots.iter().zip(addresses) {
            self.opened.entry(id.clone()).or_insert(now);
            for slot in self
                .slots_mut()
                .filter(|s| s.id == *id && s.address.is_empty())
            {
                slot.address = address.0.clone();
            }
        }
        self.save()
    }

    /// Mint a one-time invite on a fresh address. Whoever uses it becomes
    /// the contact `name`.
    pub async fn create_invite<N: Network>(
        &mut self,
        mux: &mut Mux<N>,
        name: &str,
    ) -> Result<String> {
        self.ensure_name_free(name)?;
        let slot = self.new_slot(mux).await?;
        let tag = random::<16>();
        let code = Invite {
            address: slot.address.clone(),
            key_package: encode_key_package(&self.identity.key_package()?)?,
            tag,
        }
        .to_code()?;
        self.state.invites.push(PendingInvite {
            tag,
            name: name.to_string(),
            slot,
        });
        self.save()?;
        Ok(code)
    }

    /// Use someone's invite: start a conversation on a fresh address of
    /// ours and save them as `name`.
    pub async fn accept_invite<N: Network>(
        &mut self,
        mux: &mut Mux<N>,
        code: &str,
        name: &str,
    ) -> Result<()> {
        self.ensure_name_free(name)?;
        let invite = Invite::from_code(code)?;
        if !valid_address(&invite.address) {
            bail!("invite code is damaged (bad address)");
        }
        if self.slots().any(|s| s.address == invite.address) {
            bail!("that invite is your own");
        }
        let key_package = decode_key_package(&invite.key_package)?;

        let slot = self.new_slot(mux).await?;
        let mut session = Session::create(&self.identity)?;
        let sent = async {
            let welcome = session.add_member(&self.identity, key_package)?;
            let hello = Payload::Hello {
                reply_to: slot.address.clone(),
                invite_tag: invite.tag,
            };
            let hello = session.encrypt(&self.identity, &encode(&hello)?)?;
            let frame = encode(&Envelope::Join { welcome, hello })?;
            mux.send(&MixAddress(invite.address.clone()), &frame).await
        }
        .await;
        if let Err(e) = sent {
            session.delete(&self.identity)?;
            mux.forget(&slot.id).await?;
            return Err(e);
        }
        self.add_contact(name, session, invite.address, slot);
        self.save()
    }

    pub async fn send_text<N: Network>(
        &mut self,
        mux: &mut Mux<N>,
        name: &str,
        text: &str,
    ) -> Result<()> {
        if text.len() > MAX_TEXT {
            bail!(
                "message is {} bytes; the limit is {MAX_TEXT}. Split it into several messages.",
                text.len()
            );
        }
        let group_id = self.contact(name)?.group_id.clone();
        self.send_payload(mux, &group_id, &Payload::Text(text.into()))
            .await?;
        self.record(&group_id, true, text);
        self.save()
    }

    /// Send a decoy to `name`: on the wire it looks like a short message;
    /// the receiver discards it.
    pub async fn send_decoy<N: Network>(&mut self, mux: &mut Mux<N>, name: &str) -> Result<()> {
        let to = MixAddress(self.contact(name)?.address.clone());
        // Real short messages are a few hundred bytes of MLS ciphertext; any
        // length up to one padding block costs the same on the wire.
        let mut filler = vec![0u8; 64 + (OsRng.next_u32() % 960) as usize];
        OsRng.fill_bytes(&mut filler);
        mux.send(&to, &encode(&Envelope::Decoy(filler))?).await
    }

    /// Set how long messages with `name` live, here and (by telling them)
    /// on their side. Messages already older than that go at once.
    pub async fn set_timer<N: Network>(
        &mut self,
        mux: &mut Mux<N>,
        name: &str,
        after: Option<u64>,
    ) -> Result<()> {
        let idx = self.index(name)?;
        let group_id = self.state.contacts[idx].group_id.clone();
        self.send_payload(mux, &group_id, &Payload::Timer { after })
            .await?;
        self.state.contacts[idx].disappear_after = after;
        self.expire()?;
        self.save()
    }

    /// Delete messages that have outlived their conversation's timer.
    pub fn expire(&mut self) -> Result<()> {
        let now = unix_now();
        let mut changed = false;
        for contact in &mut self.state.contacts {
            let Some(after) = contact.disappear_after else {
                continue;
            };
            let before = contact.history.len();
            contact.history.retain(|e| e.at.saturating_add(after) > now);
            if contact.history.len() != before {
                changed = true;
                let incoming = contact.history.iter().filter(|e| !e.outgoing).count();
                contact.unread = contact.unread.min(incoming as u32);
            }
        }
        if changed {
            self.save()?;
        }
        Ok(())
    }

    /// Replace the address `name` writes to us at. The old one keeps
    /// listening until they confirm, plus [`RETIRE_GRACE`].
    pub async fn rotate<N: Network>(&mut self, mux: &mut Mux<N>, name: &str) -> Result<()> {
        let idx = self.index(name)?;
        if self.state.contacts[idx]
            .old_slots
            .iter()
            .any(|o| o.retire_at.is_none())
        {
            bail!("{name} has not confirmed the last address change yet; try again after they have been online");
        }
        self.rotate_index(mux, idx).await
    }

    async fn rotate_index<N: Network>(&mut self, mux: &mut Mux<N>, idx: usize) -> Result<()> {
        let new = self.new_slot(mux).await?;
        let reply_to = new.address.clone();
        let contact = &mut self.state.contacts[idx];
        let old = std::mem::replace(&mut contact.slot, new);
        contact.old_slots.push(OldSlot {
            slot: old,
            retire_at: None,
        });
        contact.rotated_at = unix_now();
        let group_id = contact.group_id.clone();
        // Switch first: if the Rotate is lost, `maintain` sends it again.
        self.save()?;
        self.rotation_resent.insert(group_id.clone());
        self.send_payload(mux, &group_id, &Payload::Rotate { reply_to })
            .await
    }

    /// Housekeeping, to run now and then while connected: delete expired
    /// messages, retire old addresses that are drained and confirmed,
    /// re-send unconfirmed rotations once per session, and rotate addresses
    /// that are due.
    /// Only conversations whose current address is open are touched.
    pub async fn maintain<N: Network>(&mut self, mux: &mut Mux<N>) -> Result<()> {
        self.expire()?;
        let now = unix_now();
        for idx in 0..self.state.contacts.len() {
            let drained: Vec<String> = self.state.contacts[idx]
                .old_slots
                .iter()
                .filter(|o| o.retire_at.is_some_and(|t| t <= now))
                .filter(|o| {
                    self.opened
                        .get(&o.slot.id)
                        .is_some_and(|t| t.elapsed() >= DRAIN_TIME)
                })
                .map(|o| o.slot.id.clone())
                .collect();
            for id in drained {
                self.state.contacts[idx]
                    .old_slots
                    .retain(|o| o.slot.id != id);
                self.release_slot(mux, &id).await?;
                self.save()?;
            }

            let contact = &self.state.contacts[idx];
            if !mux.is_open(&contact.slot.id) {
                continue;
            }
            let (name, group_id) = (contact.name.clone(), contact.group_id.clone());
            let result = if contact.old_slots.iter().any(|o| o.retire_at.is_none()) {
                if self.rotation_resent.insert(group_id.clone()) {
                    let reply_to = contact.slot.address.clone();
                    self.send_payload(mux, &group_id, &Payload::Rotate { reply_to })
                        .await
                } else {
                    Ok(())
                }
            } else if now.saturating_sub(contact.rotated_at) >= ROTATE_EVERY {
                self.rotate_index(mux, idx).await
            } else {
                Ok(())
            };
            if let Err(e) = result {
                tracing::warn!("address rotation for {name} did not go out: {e:#}");
            }
        }
        Ok(())
    }

    /// Forget a contact (or an unused invite) and destroy its addresses.
    /// The other side is not told.
    pub async fn remove<N: Network>(&mut self, mux: &mut Mux<N>, name: &str) -> Result<()> {
        let slots = if let Ok(idx) = self.index(name) {
            let contact = self.state.contacts.remove(idx);
            if let Some(session) = self.sessions.remove(&contact.group_id) {
                session.delete(&self.identity)?;
            }
            std::iter::once(contact.slot)
                .chain(contact.old_slots.into_iter().map(|o| o.slot))
                .collect()
        } else if let Some(idx) = self.state.invites.iter().position(|i| i.name == name) {
            vec![self.state.invites.remove(idx).slot]
        } else {
            bail!("no contact or open invite named {name:?}");
        };
        for slot in slots {
            self.release_slot(mux, &slot.id).await?;
        }
        self.save()
    }

    /// The contact has seen everything that arrived so far.
    pub fn mark_read(&mut self, name: &str) -> Result<()> {
        let idx = self.index(name)?;
        if self.state.contacts[idx].unread > 0 {
            self.state.contacts[idx].unread = 0;
            self.save()?;
        }
        Ok(())
    }

    /// Process one frame that arrived on `slot`. Errors mean the frame was
    /// rejected (malformed, forged, replayed, wrong address, unknown
    /// invite); the node stays usable either way.
    pub async fn handle_incoming<N: Network>(
        &mut self,
        mux: &mut Mux<N>,
        slot: &str,
        payload: &[u8],
    ) -> Result<Vec<Event>> {
        match decode::<Envelope>(payload).context("malformed frame")? {
            Envelope::Join { welcome, hello } => self.handle_join(slot, &welcome, &hello),
            Envelope::Mls(ciphertext) => self.handle_mls(mux, slot, ciphertext).await,
            Envelope::Decoy(_) => Ok(vec![]),
        }
    }

    fn handle_join(&mut self, slot: &str, welcome: &[u8], hello: &[u8]) -> Result<Vec<Event>> {
        // Checked before touching MLS, so a stray Join costs nothing.
        if !self.state.invites.iter().any(|i| i.slot.id == slot) {
            bail!("refused a join on an address with no open invite");
        }
        let mut session = Session::join(&self.identity, welcome)?;
        let group_id = session.group_id();

        let matched = match session
            .decrypt(&self.identity, hello)
            .and_then(|pt| decode::<Payload>(&pt))
        {
            Ok(Payload::Hello {
                reply_to,
                invite_tag,
            }) if valid_address(&reply_to) => self
                .state
                .invites
                .iter()
                .position(|i| i.slot.id == slot && i.tag == invite_tag)
                .map(|idx| (idx, reply_to)),
            _ => None,
        };
        let Some((idx, reply_to)) = matched else {
            session.delete(&self.identity)?;
            self.save()?;
            bail!("refused a join that does not match any open invite");
        };

        let invite = self.state.invites.remove(idx);
        let name = invite.name.clone();
        self.add_contact(&name, session, reply_to, invite.slot);
        let mut events = vec![Event::Joined {
            contact: name.clone(),
        }];

        // Messages that overtook this Join in the mixnet.
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.state.pending)
            .into_iter()
            .partition(|p| {
                p.slot == slot && message_group_id(&p.ciphertext).is_ok_and(|g| g == group_id)
            });
        self.state.pending = waiting;
        for p in ready {
            match self.receive_mls(&group_id, slot, &p.ciphertext) {
                Ok((event, _)) => events.extend(event),
                Err(e) => tracing::warn!("dropping early message from {name}: {e:#}"),
            }
        }
        self.save()?;
        Ok(events)
    }

    async fn handle_mls<N: Network>(
        &mut self,
        mux: &mut Mux<N>,
        slot: &str,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<Event>> {
        let group_id = message_group_id(&ciphertext)?;
        if !self.sessions.contains_key(&group_id) {
            // Only an invite in progress can have messages ahead of its Join.
            if !self.state.invites.iter().any(|i| i.slot.id == slot) {
                bail!("message for an unknown conversation");
            }
            if self.state.pending.len() >= PENDING_LIMIT {
                self.state.pending.remove(0);
            }
            self.state.pending.push(PendingMessage {
                slot: slot.to_string(),
                ciphertext,
            });
            self.save()?;
            return Ok(vec![]);
        }
        let received = self.receive_mls(&group_id, slot, &ciphertext);
        // The ratchet may have moved even if the message was then refused.
        self.save()?;
        let (event, ack) = received?;
        if let Some(Event::Timer { .. }) = event {
            self.expire()?;
        }
        if ack {
            if let Err(e) = self.send_payload(mux, &group_id, &Payload::RotateAck).await {
                tracing::warn!("could not confirm an address change: {e:#}");
            }
        }
        Ok(event.into_iter().collect())
    }

    /// Decrypt and apply one message of the conversation `group_id` that
    /// arrived on `slot`. Returns the event, if any, and whether the contact
    /// asked us to confirm an address change.
    fn receive_mls(
        &mut self,
        group_id: &[u8],
        slot: &str,
        ciphertext: &[u8],
    ) -> Result<(Option<Event>, bool)> {
        let idx = self
            .state
            .contacts
            .iter()
            .position(|c| c.group_id == group_id)
            .ok_or_else(|| anyhow!("unknown conversation"))?;
        let contact = &self.state.contacts[idx];
        let on_current = contact.slot.id == slot;
        if !on_current && !contact.old_slots.iter().any(|o| o.slot.id == slot) {
            bail!("message arrived on an address that is not this conversation's");
        }
        let session = self
            .sessions
            .get_mut(group_id)
            .ok_or_else(|| anyhow!("conversation state is missing"))?;
        let plaintext = session.decrypt(&self.identity, ciphertext)?;
        let payload = decode::<Payload>(&plaintext)?;

        let contact = &mut self.state.contacts[idx];
        if on_current {
            // They wrote to our newest address, so they have switched.
            let retire_at = unix_now() + RETIRE_GRACE;
            for old in contact
                .old_slots
                .iter_mut()
                .filter(|o| o.retire_at.is_none())
            {
                old.retire_at = Some(retire_at);
            }
        }
        match payload {
            Payload::Text(text) if text.len() > MAX_TEXT => {
                bail!("dropped a {}-byte message (limit {MAX_TEXT})", text.len())
            }
            Payload::Text(text) => {
                contact.unread = contact.unread.saturating_add(1);
                let contact = self.record(group_id, false, &text);
                Ok((Some(Event::Message { contact, text }), false))
            }
            Payload::Rotate { reply_to } if valid_address(&reply_to) => {
                contact.address = reply_to;
                Ok((None, true))
            }
            Payload::Rotate { .. } => bail!("refused an address change to an invalid address"),
            Payload::Timer { after } if after.is_none_or(|s| TIMER_RANGE.contains(&s)) => {
                contact.disappear_after = after;
                let contact = contact.name.clone();
                Ok((Some(Event::Timer { contact, after }), false))
            }
            Payload::Timer { .. } => bail!("refused an out-of-range disappearing timer"),
            // A repeated Hello carries nothing new; an ack did its work above.
            Payload::Hello { .. } | Payload::RotateAck => Ok((None, false)),
        }
    }

    /// Encrypt `payload` for the conversation `group_id` and send it to the
    /// contact. Saves either way: the ratchet advanced.
    async fn send_payload<N: Network>(
        &mut self,
        mux: &mut Mux<N>,
        group_id: &[u8],
        payload: &Payload,
    ) -> Result<()> {
        let contact = self
            .state
            .contacts
            .iter()
            .find(|c| c.group_id == group_id)
            .ok_or_else(|| anyhow!("unknown conversation"))?;
        let to = MixAddress(contact.address.clone());
        let session = self
            .sessions
            .get_mut(group_id)
            .ok_or_else(|| anyhow!("conversation state is missing"))?;
        let ciphertext = session.encrypt(&self.identity, &encode(payload)?)?;
        let sent = mux.send(&to, &encode(&Envelope::Mls(ciphertext))?).await;
        self.save()?;
        sent
    }

    /// Open a brand-new address.
    async fn new_slot<N: Network>(&mut self, mux: &mut Mux<N>) -> Result<Slot> {
        let id = hex(&random::<16>());
        let address = match mux.open(std::slice::from_ref(&id)).await {
            Ok(mut addresses) => addresses.remove(0),
            Err(e) => {
                mux.forget(&id).await.ok();
                return Err(e);
            }
        };
        self.opened.insert(id.clone(), Instant::now());
        Ok(Slot {
            id,
            address: address.0,
        })
    }

    /// Destroy a slot's keys, unless something still uses it (a migrated
    /// version 1 profile shares one slot between many conversations).
    async fn release_slot<N: Network>(&mut self, mux: &mut Mux<N>, id: &str) -> Result<()> {
        if !self.slots().any(|s| s.id == id) {
            mux.forget(id).await?;
            self.opened.remove(id);
        }
        Ok(())
    }

    /// Every slot in the profile.
    fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.state
            .contacts
            .iter()
            .flat_map(|c| std::iter::once(&c.slot).chain(c.old_slots.iter().map(|o| &o.slot)))
            .chain(self.state.invites.iter().map(|i| &i.slot))
    }

    fn slots_mut(&mut self) -> impl Iterator<Item = &mut Slot> {
        self.state
            .contacts
            .iter_mut()
            .flat_map(|c| {
                std::iter::once(&mut c.slot).chain(c.old_slots.iter_mut().map(|o| &mut o.slot))
            })
            .chain(self.state.invites.iter_mut().map(|i| &mut i.slot))
    }

    fn index(&self, name: &str) -> Result<usize> {
        self.state
            .contacts
            .iter()
            .position(|c| c.name == name)
            .ok_or_else(|| anyhow!("no contact named {name:?} (see `privmsg contacts`)"))
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

    fn add_contact(&mut self, name: &str, session: Session, address: String, slot: Slot) {
        let group_id = session.group_id();
        self.state.contacts.push(Contact {
            name: name.to_string(),
            group_id: group_id.clone(),
            address,
            slot,
            old_slots: Vec::new(),
            rotated_at: unix_now(),
            history: Vec::new(),
            unread: 0,
            disappear_after: None,
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
            at: unix_now(),
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
    use privmsg_transport::memory::MemoryNetwork;
    use tempfile::TempDir;

    const PW: &str = "test passphrase";

    struct Peer {
        _dir: TempDir,
        path: PathBuf,
        node: Node,
        mux: Mux<MemoryNetwork>,
    }

    impl Peer {
        fn new(network: &MemoryNetwork) -> Result<Self> {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("profile");
            Ok(Self {
                node: Node::create(&path, PW)?,
                mux: Mux::new(network.clone()),
                path,
                _dir: dir,
            })
        }

        /// The next frame, as it arrived.
        async fn frame(&mut self) -> Result<(String, Vec<u8>)> {
            let (slot, msg) = self.mux.recv().await?;
            Ok((slot, msg.payload))
        }

        async fn deliver(&mut self, (slot, frame): &(String, Vec<u8>)) -> Result<Vec<Event>> {
            self.node.handle_incoming(&mut self.mux, slot, frame).await
        }

        async fn recv(&mut self) -> Result<Vec<Event>> {
            let frame = self.frame().await?;
            self.deliver(&frame).await
        }

        async fn send(&mut self, to: &str, text: &str) -> Result<()> {
            self.node.send_text(&mut self.mux, to, text).await
        }

        /// Simulate quitting and restarting: the old node (and its profile
        /// lock) is dropped before the profile is reopened from disk. The
        /// network keeps whatever was sent meanwhile.
        fn reopen(self) -> Result<Self> {
            let Peer {
                _dir,
                path,
                node,
                mux,
            } = self;
            drop(node);
            Ok(Peer {
                node: Node::open(&path, PW)?,
                _dir,
                path,
                mux,
            })
        }

        fn current_slot(&self, name: &str) -> Slot {
            self.node.contact(name).unwrap().slot.clone()
        }
    }

    fn joined(name: &str) -> Vec<Event> {
        vec![Event::Joined {
            contact: name.into(),
        }]
    }

    fn message(from: &str, text: &str) -> Vec<Event> {
        vec![Event::Message {
            contact: from.into(),
            text: text.into(),
        }]
    }

    /// `inviter` invites `joiner`; the joiner accepts; the inviter processes
    /// the Join.
    async fn connect(
        inviter: &mut Peer,
        joiner_name: &str,
        joiner: &mut Peer,
        inviter_name: &str,
    ) -> Result<()> {
        let code = inviter
            .node
            .create_invite(&mut inviter.mux, joiner_name)
            .await?;
        joiner
            .node
            .accept_invite(&mut joiner.mux, &code, inviter_name)
            .await?;
        assert_eq!(inviter.recv().await?, joined(joiner_name));
        Ok(())
    }

    /// Bob invites Alice; Alice joins; Bob processes the Join.
    async fn connected(net: &MemoryNetwork) -> Result<(Peer, Peer)> {
        let mut alice = Peer::new(net)?;
        let mut bob = Peer::new(net)?;
        connect(&mut bob, "alice", &mut alice, "bob").await?;
        Ok((alice, bob))
    }

    #[tokio::test]
    async fn invite_join_and_chat_both_ways() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        assert!(bob.node.invites().is_empty(), "invite is used up");

        alice.send("bob", "hi bob").await?;
        assert_eq!(bob.recv().await?, message("alice", "hi bob"));
        bob.send("alice", "hi alice").await?;
        assert_eq!(alice.recv().await?, message("bob", "hi alice"));

        let history = &alice.node.contact("bob")?.history;
        assert_eq!(history.len(), 2);
        assert!(history[0].outgoing && !history[1].outgoing);

        assert_eq!(bob.node.contact("alice")?.unread, 1);
        bob.node.mark_read("alice")?;
        assert_eq!(bob.reopen()?.node.contact("alice")?.unread, 0);
        Ok(())
    }

    /// Pretend every message with `name` was sent `secs` ago.
    fn age(peer: &mut Peer, name: &str, secs: u64) {
        let idx = peer.node.index(name).unwrap();
        for entry in &mut peer.node.state.contacts[idx].history {
            entry.at -= secs;
        }
    }

    #[tokio::test]
    async fn disappearing_timer_applies_on_both_sides() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        alice.send("bob", "old news").await?;
        bob.recv().await?;
        age(&mut alice, "bob", 2 * 3600);
        age(&mut bob, "alice", 2 * 3600);
        alice.send("bob", "fresh").await?;
        bob.recv().await?;

        alice
            .node
            .set_timer(&mut alice.mux, "bob", Some(3600))
            .await?;
        let kept = |p: &Peer, name: &str| -> Vec<String> {
            let history = &p.node.contact(name).unwrap().history;
            history.iter().map(|e| e.text.clone()).collect()
        };
        assert_eq!(kept(&alice, "bob"), ["fresh"]);
        assert_eq!(
            bob.recv().await?,
            vec![Event::Timer {
                contact: "alice".into(),
                after: Some(3600)
            }]
        );
        assert_eq!(kept(&bob, "alice"), ["fresh"]);
        assert_eq!(bob.node.contact("alice")?.unread, 1, "only what is left");

        // Expired messages also go while the app is closed.
        age(&mut bob, "alice", 2 * 3600);
        bob.node.save()?;
        let mut bob = bob.reopen()?;
        assert!(kept(&bob, "alice").is_empty());
        assert_eq!(bob.node.contact("alice")?.unread, 0);

        bob.node.set_timer(&mut bob.mux, "alice", None).await?;
        alice.recv().await?;
        assert_eq!(alice.node.contact("bob")?.disappear_after, None);
        Ok(())
    }

    #[tokio::test]
    async fn out_of_range_timers_are_refused() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        let group_id = alice.node.contact("bob")?.group_id.clone();
        alice
            .node
            .send_payload(
                &mut alice.mux,
                &group_id,
                &Payload::Timer { after: Some(1) },
            )
            .await?;
        assert!(bob.recv().await.is_err());
        assert_eq!(bob.node.contact("alice")?.disappear_after, None);
        Ok(())
    }

    #[test]
    fn timer_words() -> Result<()> {
        assert_eq!(parse_timer("1h")?, Some(3600));
        assert_eq!(parse_timer("off")?, None);
        assert!(parse_timer("2h").is_err());
        assert_eq!(describe_timer(Some(3600)), "1 hour");
        assert_eq!(describe_timer(Some(14 * 24 * 3600)), "2 weeks");
        assert_eq!(describe_timer(Some(90)), "2 minutes");
        // Ctrl-D cycles off → 5m → 1h → 1d → 1w → off.
        let mut t = None;
        let mut seen = vec![];
        for _ in 0..5 {
            t = next_timer(t);
            seen.push(describe_timer(t));
        }
        assert_eq!(seen, ["5 minutes", "1 hour", "1 day", "1 week", "off"]);
        Ok(())
    }

    #[tokio::test]
    async fn every_invite_and_conversation_has_its_own_address() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut bob = Peer::new(&net)?;
        let first = bob.node.create_invite(&mut bob.mux, "alice").await?;
        let second = bob.node.create_invite(&mut bob.mux, "carol").await?;
        let (first, second) = (Invite::from_code(&first)?, Invite::from_code(&second)?);
        assert_ne!(first.address, second.address);

        let mut alice = Peer::new(&net)?;
        let mut carol = Peer::new(&net)?;
        alice
            .node
            .accept_invite(&mut alice.mux, &first.to_code()?, "bob")
            .await?;
        carol
            .node
            .accept_invite(&mut carol.mux, &second.to_code()?, "bob")
            .await?;
        bob.recv().await?;
        bob.recv().await?;
        let (a, c) = (bob.current_slot("alice"), bob.current_slot("carol"));
        assert_ne!(a.address, c.address);
        assert_eq!(a.address, first.address, "the invite's address carries on");

        let mut addresses = bob.node.all_slots();
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn message_on_another_conversations_address_is_refused() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        let mut carol = Peer::new(&net)?;
        connect(&mut bob, "carol", &mut carol, "bob").await?;

        alice.send("bob", "probe").await?;
        let (_, frame) = bob.frame().await?;
        let carols = bob.current_slot("carol").id;
        let err = bob.deliver(&(carols, frame.clone())).await.err().unwrap();
        assert!(err.to_string().contains("not this conversation's"));
        let alices = bob.current_slot("alice").id;
        assert_eq!(
            bob.deliver(&(alices, frame)).await?,
            message("alice", "probe")
        );
        Ok(())
    }

    #[tokio::test]
    async fn conversation_survives_restart() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        alice.send("bob", "one").await?;
        bob.recv().await?;

        let mut alice = alice.reopen()?;
        let mut bob = bob.reopen()?;
        assert_eq!(bob.node.contact("alice")?.history[0].text, "one");

        alice.send("bob", "two").await?;
        assert_eq!(bob.recv().await?, message("alice", "two"));
        bob.send("alice", "three").await?;
        assert_eq!(alice.recv().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn invite_works_after_inviter_restarts() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut alice = Peer::new(&net)?;
        let mut bob = Peer::new(&net)?;
        let code = bob.node.create_invite(&mut bob.mux, "alice").await?;
        let mut bob = bob.reopen()?;
        alice
            .node
            .accept_invite(&mut alice.mux, &code, "bob")
            .await?;
        assert_eq!(bob.recv().await?, joined("alice"));
        Ok(())
    }

    #[tokio::test]
    async fn invite_is_single_use() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut alice = Peer::new(&net)?;
        let mut carol = Peer::new(&net)?;
        let mut bob = Peer::new(&net)?;
        let code = bob.node.create_invite(&mut bob.mux, "alice").await?;

        alice
            .node
            .accept_invite(&mut alice.mux, &code, "bob")
            .await?;
        bob.recv().await?;
        carol
            .node
            .accept_invite(&mut carol.mux, &code, "bob")
            .await?;
        assert!(bob.recv().await.is_err(), "second use is refused");
        assert_eq!(bob.node.contacts().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn message_that_overtakes_its_join_is_delivered() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut alice = Peer::new(&net)?;
        let mut bob = Peer::new(&net)?;
        let code = bob.node.create_invite(&mut bob.mux, "alice").await?;
        alice
            .node
            .accept_invite(&mut alice.mux, &code, "bob")
            .await?;
        alice.send("bob", "early").await?;

        // Deliver in the wrong order, as the mixnet may.
        let join = bob.frame().await?;
        let text = bob.frame().await?;
        assert!(bob.deliver(&text).await?.is_empty(), "buffered");
        let mut expected = joined("alice");
        expected.extend(message("alice", "early"));
        assert_eq!(bob.deliver(&join).await?, expected);
        Ok(())
    }

    #[tokio::test]
    async fn strays_garbage_and_replays_are_rejected_without_breaking_the_node() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        let slot = bob.current_slot("alice").id;
        assert!(bob
            .deliver(&(slot.clone(), b"garbage".to_vec()))
            .await
            .is_err());

        alice.send("bob", "once").await?;
        let frame = bob.frame().await?;
        assert_eq!(bob.deliver(&frame).await?.len(), 1);
        assert!(bob.deliver(&frame).await.is_err(), "replay refused");

        // A Join on a conversation's address (not an invite's) is refused
        // before any MLS work.
        let join = encode(&Envelope::Join {
            welcome: vec![1, 2, 3],
            hello: vec![],
        })?;
        let err = bob.deliver(&(slot, join)).await.err().unwrap();
        assert!(err.to_string().contains("no open invite"));

        alice.send("bob", "still fine").await?;
        assert_eq!(bob.recv().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn names_must_be_unique_and_own_invite_is_refused() -> Result<()> {
        let net = MemoryNetwork::default();
        let mut bob = Peer::new(&net)?;
        let code = bob.node.create_invite(&mut bob.mux, "alice").await?;
        assert!(bob.node.create_invite(&mut bob.mux, "alice").await.is_err());
        assert!(bob.node.create_invite(&mut bob.mux, "  ").await.is_err());
        let err = bob
            .node
            .accept_invite(&mut bob.mux, &code, "me")
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("your own"));
        assert!(bob.send("nobody", "x").await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn long_messages_are_refused_with_a_clear_error() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        let err = alice
            .send("bob", &"x".repeat(MAX_TEXT + 1))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("limit"), "{err}");
        alice.send("bob", &"x".repeat(MAX_TEXT)).await?;
        assert_eq!(bob.recv().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn rotation_moves_the_conversation_to_a_new_address() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        let old = alice.current_slot("bob");

        alice.node.rotate(&mut alice.mux, "bob").await?;
        let new = alice.current_slot("bob");
        assert_ne!(old.address, new.address);
        assert!(
            alice.node.rotate(&mut alice.mux, "bob").await.is_err(),
            "unconfirmed"
        );

        // Bob learns the new address and confirms there.
        assert!(bob.recv().await?.is_empty());
        assert_eq!(bob.node.contact("alice")?.address, new.address);
        let ack = alice.frame().await?;
        assert_eq!(ack.0, new.id);
        alice.deliver(&ack).await?;
        let retiring = &alice.node.contact("bob")?.old_slots[0];
        assert!(retiring.retire_at.is_some(), "confirmed");

        // Bob now writes to the new address.
        bob.send("alice", "at the new place").await?;
        let frame = alice.frame().await?;
        assert_eq!(frame.0, new.id);
        assert_eq!(
            alice.deliver(&frame).await?,
            message("bob", "at the new place")
        );

        // Once the grace period is over and the old slot has drained, it is
        // retired for good.
        alice.node.state.contacts[0].old_slots[0].retire_at = Some(0);
        alice
            .node
            .opened
            .insert(old.id.clone(), Instant::now() - DRAIN_TIME * 2);
        alice.node.maintain(&mut alice.mux).await?;
        assert!(alice.node.contact("bob")?.old_slots.is_empty());
        assert!(!alice.mux.is_open(&old.id));
        assert_eq!(alice.node.slots_for("bob")?, vec![new.id]);
        Ok(())
    }

    #[tokio::test]
    async fn old_address_still_works_until_retired() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        let old = alice.current_slot("bob");
        // Bob sends before he learns about the rotation.
        bob.send("alice", "in flight").await?;
        alice.node.rotate(&mut alice.mux, "bob").await?;
        let frame = alice.frame().await?;
        assert_eq!(frame.0, old.id);
        assert_eq!(alice.deliver(&frame).await?, message("bob", "in flight"));
        Ok(())
    }

    #[tokio::test]
    async fn a_lost_rotation_is_sent_again_next_session() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        alice.node.rotate(&mut alice.mux, "bob").await?;
        bob.frame().await?; // lost in transit

        alice.node.maintain(&mut alice.mux).await?;
        let mut alice = alice.reopen()?;
        alice.node.maintain(&mut alice.mux).await?;
        assert!(bob.recv().await?.is_empty());
        assert_eq!(
            bob.node.contact("alice")?.address,
            alice.current_slot("bob").address
        );
        alice.recv().await?;
        assert!(alice.node.contact("bob")?.old_slots[0].retire_at.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn addresses_rotate_automatically_when_due() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        let old = alice.current_slot("bob");
        alice.node.maintain(&mut alice.mux).await?;
        assert_eq!(alice.current_slot("bob"), old, "not due yet");

        alice.node.state.contacts[0].rotated_at = 0;
        alice.node.maintain(&mut alice.mux).await?;
        assert_ne!(alice.current_slot("bob"), old);
        bob.recv().await?;
        assert_eq!(
            bob.node.contact("alice")?.address,
            alice.current_slot("bob").address
        );
        Ok(())
    }

    #[tokio::test]
    async fn decoys_are_discarded() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        alice.node.send_decoy(&mut alice.mux, "bob").await?;
        assert!(bob.recv().await?.is_empty());
        assert!(bob.node.contact("alice")?.history.is_empty());
        alice.send("bob", "real").await?;
        assert_eq!(bob.recv().await?, message("alice", "real"));
        Ok(())
    }

    #[tokio::test]
    async fn removed_contact_is_gone_with_its_addresses() -> Result<()> {
        let net = MemoryNetwork::default();
        let (mut alice, mut bob) = connected(&net).await?;
        let slot = bob.current_slot("alice").id;
        bob.node.remove(&mut bob.mux, "alice").await?;
        assert!(bob.node.contacts().is_empty());
        assert!(!bob.mux.is_open(&slot));

        let code = bob.node.create_invite(&mut bob.mux, "dave").await?;
        assert!(code.starts_with("privmsg1:"));
        bob.node.remove(&mut bob.mux, "dave").await?;
        assert!(bob.node.invites().is_empty());
        assert!(bob.node.remove(&mut bob.mux, "nobody").await.is_err());

        alice.send("bob", "anyone there?").await?;
        Ok(())
    }
}
