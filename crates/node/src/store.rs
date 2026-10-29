//! Encrypted on-disk profile, and erasing it for good.
//!
//! Everything privmsg must remember — the MLS identity and group state,
//! contacts, open invites, message history, and the Nym clients' keys —
//! lives in one file, `state.enc`:
//!
//! ```text
//! "PRIVMSG8" | KDF cost (12) | salt (16) | nonce (24) | XChaCha20-Poly1305(state)
//! ```
//!
//! sealed with a key made from two halves:
//!
//! ```text
//! passphrase key = Argon2id(passphrase, salt)       cost in the header
//! device key     = 32 random bytes, in device.key   sealed by a Vault
//! file key       = HKDF-SHA256(salt, device key ‖ passphrase key)
//! ```
//!
//! The device key is what makes erasing final. Every save writes a new
//! file, and on flash storage the old ones can linger where no tool that
//! deletes files can reach; with the passphrase alone, someone who later
//! learned it could read those leftovers. Erasing destroys the device key
//! first, so every copy of the file ever written, anywhere, is noise: the
//! passphrase no longer opens it, and guessing the device key means trying
//! 2^256 values. On the iPhone the device key is sealed by a key in the
//! Secure Enclave ([`Vault`]), which never leaves that chip; erasing deletes
//! it there. On computers it is stored as it is ([`FileVault`]) and erasing
//! destroys `device.key` itself.
//!
//! The cost in the header (memory in KiB, passes, lanes; each a
//! little-endian u32) can be raised later without a new format. The header
//! is bound as AEAD associated data, so it can't be swapped without
//! detection. Writes go to a temp file and are renamed into place, so a
//! crash never leaves a torn file.
//!
//! Version 1 profiles (`"PRIVMSG1"`, one mix address for everything) are
//! upgraded on open: their single Nym client moves to the slot
//! [`LEGACY_SLOT`], and every contact is due for an address rotation.
//! Version 2 profiles (`"PRIVMSG2"`) only lack the network settings and get
//! the defaults. Version 3 profiles (`"PRIVMSG3"`) lack disappearing
//! messages and auto-sleep, which start off. Versions 4 and 5
//! (`"PRIVMSG4"`, `"PRIVMSG5"`) have no message IDs: their messages get
//! local ones, so they can be deleted here but not for both sides. Version 6
//! (`"PRIVMSG6"`) lacks the replay list, which starts empty. Versions 1–4 used the Argon2
//! crate's default cost and no cost field; they are re-keyed at [`KDF`] when
//! opened. Versions 1–7 had no device key (the file key was the passphrase
//! key) and kept the Nym clients' keys in files under `slots/`, written by
//! the Nym SDK unencrypted; opening one makes its device key, and the node
//! moves those keys into the state (`Node::adopt_nym_files`). Copies of a
//! version 7 file written before that stay openable with the passphrase
//! alone wherever they linger.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use privmsg_transport::DataMode;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::secure::Secret;
use crate::wire::MessageId;

const MAGIC: &[u8; 8] = b"PRIVMSG8";
const MAGIC_V7: &[u8; 8] = b"PRIVMSG7";
const MAGIC_V6: &[u8; 8] = b"PRIVMSG6";
const MAGIC_V5: &[u8; 8] = b"PRIVMSG5";
const MAGIC_V4: &[u8; 8] = b"PRIVMSG4";
const MAGIC_V3: &[u8; 8] = b"PRIVMSG3";
const MAGIC_V2: &[u8; 8] = b"PRIVMSG2";
const MAGIC_V1: &[u8; 8] = b"PRIVMSG1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KDF_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + KDF_LEN + SALT_LEN;
/// Header length of versions 1–4, which had no cost field.
const OLD_HEADER_LEN: usize = MAGIC.len() + SALT_LEN;
const STATE_FILE: &str = "state.enc";
const LOCK_FILE: &str = "lock";
/// The sealed device key.
const DEVICE_FILE: &str = "device.key";
const DEVICE_MAGIC: &[u8; 8] = b"PRIVDEV1";
/// Present while an erase is under way, so one cut short (a crash, the
/// battery) is finished the next time the profile is looked at.
const ERASING_FILE: &str = "erasing";
/// What the desktop app logs to when asked to (`RUST_LOG`).
const LOG_FILE: &str = "privmsg.log";
/// Separates the file key from anything else made with the same inputs.
const FILE_KEY_INFO: &[u8] = b"privmsg profile file key v8";
const SLOTS_DIR: &str = "slots";
const TOR_DIR: &str = "tor";
/// Where a version 1 profile kept its one Nym client.
const NYM_DIR_V1: &str = "nym";

/// Argon2id cost for new and re-keyed profiles: 64 MiB, 3 passes, 1 lane
/// (RFC 9106's second recommended setting, about 0.2 s on a laptop). Tests
/// use a cheap cost so the suite stays fast.
#[cfg(not(any(test, fuzzing)))]
const KDF: Kdf = Kdf {
    memory_kib: 64 * 1024,
    passes: 3,
    lanes: 1,
};
#[cfg(any(test, fuzzing))]
const KDF: Kdf = Kdf {
    memory_kib: 64,
    passes: 1,
    lanes: 1,
};

/// Messages kept per contact; older ones are dropped.
pub const HISTORY_LIMIT: usize = 500;

/// Deletions remembered per contact for messages that have not arrived yet.
pub const GONE_LIMIT: usize = 64;

/// Messages remembered per contact to refuse replays (see `Contact::seen`).
pub const SEEN_LIMIT: usize = 1000;

/// The slot a version 1 profile's single address was moved to.
pub const LEGACY_SLOT: &str = "legacy";

/// Everything the node persists. Serialized, then encrypted as a whole.
#[derive(Serialize, Deserialize, Default)]
pub struct State {
    /// `privmsg_crypto::Identity::snapshot` — keys plus every MLS group.
    pub identity: Vec<u8>,
    pub contacts: Vec<Contact>,
    pub invites: Vec<PendingInvite>,
    /// MLS messages for groups we have not joined yet. The mixnet can
    /// deliver a message before the Join that creates its group.
    pub pending: Vec<PendingMessage>,
    pub settings: Settings,
    /// Each Nym client's keys and gateway registration, by slot name (and
    /// `"sender"`), as `privmsg_transport::NymKeys` holds them.
    pub nym: BTreeMap<String, Vec<u8>>,
}

impl State {
    /// Overwrite what is secret in memory, before it is dropped.
    pub fn wipe(&mut self) {
        self.identity.zeroize();
        for contact in &mut self.contacts {
            contact.name.zeroize();
            contact.group_id.zeroize();
            contact.address.zeroize();
            contact.slot.address.zeroize();
            for entry in &mut contact.history {
                entry.text.zeroize();
            }
        }
        for invite in &mut self.invites {
            invite.name.zeroize();
            invite.tag.zeroize();
        }
        for pending in &mut self.pending {
            pending.ciphertext.zeroize();
        }
        self.nym.values_mut().for_each(Zeroize::zeroize);
        self.contacts.clear();
        self.invites.clear();
        self.pending.clear();
        self.nym.clear();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Settings {
    /// Mean seconds between decoy-or-real sends per conversation while
    /// connected. `None` = decoys off, messages go out immediately.
    pub decoy_interval: Option<u32>,
    /// How much cover traffic is sent.
    pub data_mode: DataMode,
    /// Reach the Nym gateways through Tor, so they never see our IP.
    pub tor: bool,
    /// Minutes without typing after which the app stops the sender and its
    /// cover traffic. `None` = always on, which hides when you are active.
    pub auto_sleep: Option<u32>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            decoy_interval: None,
            data_mode: DataMode::default(),
            tor: true,
            auto_sleep: None,
        }
    }
}

/// One of our own mix addresses. Each conversation (and each open invite)
/// has its own, so no two of them can be linked by address.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Slot {
    /// Names the Nym client's key directory under `slots/`.
    pub id: String,
    /// The mix address, once known. Empty for a migrated version 1 slot
    /// until it is next opened.
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Contact {
    /// Local nickname. Never sent anywhere.
    pub name: String,
    pub group_id: Vec<u8>,
    /// The contact's mix address, where our messages go.
    pub address: String,
    /// Our address for this contact: they send here.
    pub slot: Slot,
    /// Addresses we rotated away from, still listened on until retired.
    pub old_slots: Vec<OldSlot>,
    /// When `slot` came into use (Unix seconds).
    pub rotated_at: u64,
    pub history: Vec<HistoryEntry>,
    /// Incoming messages not yet shown in `chat`, `ui` or `history`.
    pub unread: u32,
    /// Messages older than this many seconds are deleted, on both sides.
    pub disappear_after: Option<u64>,
    /// Messages the contact deleted for both of us before they arrived
    /// here (the mixnet can reorder): dropped when they do.
    pub gone: Vec<MessageId>,
    /// When the contact last emptied the chat for both of us, if they did
    /// since we last emptied it ourselves (Unix seconds).
    pub cleared_by_them: Option<u64>,
    /// IDs of the messages received since we last sent one, to refuse a
    /// replay of any of them. OpenMLS 0.6 saves its record of used keys
    /// when we encrypt, not when we decrypt, so after a restart those
    /// messages would decrypt again.
    pub seen: Vec<MessageId>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OldSlot {
    pub slot: Slot,
    /// Set once the contact has written to our new address (so has stopped
    /// using this one). `None` while we wait for that.
    pub retire_at: Option<u64>,
}

/// An early MLS message, with the slot it arrived on.
#[derive(Serialize, Deserialize, Clone)]
pub struct PendingMessage {
    pub slot: String,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HistoryEntry {
    pub outgoing: bool,
    pub text: String,
    /// Unix seconds.
    pub at: u64,
    pub id: MessageId,
    /// Whether the contact knows the message by `id` too
    /// (`wire::message_id`). Messages from before version 6 have a random
    /// local one, so they can only be deleted on this side.
    pub shared: bool,
}

/// The state layout of version 7: the Nym clients' keys were in files.
mod v7 {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct State {
        pub identity: Vec<u8>,
        pub contacts: Vec<super::Contact>,
        pub invites: Vec<super::PendingInvite>,
        pub pending: Vec<super::PendingMessage>,
        pub settings: super::Settings,
    }
}

impl From<v7::State> for State {
    fn from(old: v7::State) -> Self {
        State {
            identity: old.identity,
            contacts: old.contacts,
            invites: old.invites,
            pending: old.pending,
            settings: old.settings,
            nym: BTreeMap::new(),
        }
    }
}

/// The state layout of version 6: no replay list.
mod v6 {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct State {
        pub identity: Vec<u8>,
        pub contacts: Vec<Contact>,
        pub invites: Vec<super::PendingInvite>,
        pub pending: Vec<super::PendingMessage>,
        pub settings: super::Settings,
    }

    #[derive(Deserialize)]
    pub struct Contact {
        pub name: String,
        pub group_id: Vec<u8>,
        pub address: String,
        pub slot: super::Slot,
        pub old_slots: Vec<super::OldSlot>,
        pub rotated_at: u64,
        pub history: Vec<super::HistoryEntry>,
        pub unread: u32,
        pub disappear_after: Option<u64>,
        pub gone: Vec<super::MessageId>,
        pub cleared_by_them: Option<u64>,
    }
}

impl From<v6::State> for State {
    fn from(old: v6::State) -> Self {
        State {
            identity: old.identity,
            contacts: old
                .contacts
                .into_iter()
                .map(|c| Contact {
                    name: c.name,
                    group_id: c.group_id,
                    address: c.address,
                    slot: c.slot,
                    old_slots: c.old_slots,
                    rotated_at: c.rotated_at,
                    history: c.history,
                    unread: c.unread,
                    disappear_after: c.disappear_after,
                    gone: c.gone,
                    cleared_by_them: c.cleared_by_them,
                    seen: Vec::new(),
                })
                .collect(),
            invites: old.invites,
            pending: old.pending,
            settings: old.settings,
            nym: BTreeMap::new(),
        }
    }
}

/// The state layout of versions 4 and 5: no message IDs.
mod v5 {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct State {
        pub identity: Vec<u8>,
        pub contacts: Vec<Contact>,
        pub invites: Vec<super::PendingInvite>,
        pub pending: Vec<super::PendingMessage>,
        pub settings: super::Settings,
    }

    #[derive(Deserialize)]
    pub struct Contact {
        pub name: String,
        pub group_id: Vec<u8>,
        pub address: String,
        pub slot: super::Slot,
        pub old_slots: Vec<super::OldSlot>,
        pub rotated_at: u64,
        pub history: Vec<HistoryEntry>,
        pub unread: u32,
        pub disappear_after: Option<u64>,
    }

    #[derive(Deserialize)]
    pub struct HistoryEntry {
        pub outgoing: bool,
        pub text: String,
        pub at: u64,
    }
}

/// Older messages with fresh local IDs.
fn upgrade_history(history: Vec<v5::HistoryEntry>) -> Vec<HistoryEntry> {
    history
        .into_iter()
        .map(|e| {
            let mut id = MessageId::default();
            OsRng.fill_bytes(&mut id);
            HistoryEntry {
                outgoing: e.outgoing,
                text: e.text,
                at: e.at,
                id,
                shared: false,
            }
        })
        .collect()
}

impl From<v5::State> for State {
    fn from(old: v5::State) -> Self {
        State {
            identity: old.identity,
            contacts: old
                .contacts
                .into_iter()
                .map(|c| Contact {
                    name: c.name,
                    group_id: c.group_id,
                    address: c.address,
                    slot: c.slot,
                    old_slots: c.old_slots,
                    rotated_at: c.rotated_at,
                    history: upgrade_history(c.history),
                    unread: c.unread,
                    disappear_after: c.disappear_after,
                    gone: Vec::new(),
                    cleared_by_them: None,
                    seen: Vec::new(),
                })
                .collect(),
            invites: old.invites,
            pending: old.pending,
            settings: old.settings,
            nym: BTreeMap::new(),
        }
    }
}

/// An invite we handed out and nobody has used yet.
#[derive(Serialize, Deserialize, Clone)]
pub struct PendingInvite {
    pub tag: [u8; 16],
    /// The nickname the contact gets once they join.
    pub name: String,
    /// The fresh address in this invite; the Join must arrive here, and it
    /// becomes our address for the new contact.
    pub slot: Slot,
}

/// The version 3 state layout: no disappearing messages, no auto-sleep.
mod v3 {
    use privmsg_transport::DataMode;
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct State {
        pub identity: Vec<u8>,
        pub contacts: Vec<Contact>,
        pub invites: Vec<super::PendingInvite>,
        pub pending: Vec<super::PendingMessage>,
        pub settings: Settings,
    }

    #[derive(Deserialize)]
    pub struct Settings {
        pub decoy_interval: Option<u32>,
        pub data_mode: DataMode,
        pub tor: bool,
    }

    #[derive(Deserialize)]
    pub struct Contact {
        pub name: String,
        pub group_id: Vec<u8>,
        pub address: String,
        pub slot: super::Slot,
        pub old_slots: Vec<super::OldSlot>,
        pub rotated_at: u64,
        pub history: Vec<super::v5::HistoryEntry>,
        pub unread: u32,
    }
}

impl From<v3::Contact> for Contact {
    fn from(c: v3::Contact) -> Self {
        Contact {
            name: c.name,
            group_id: c.group_id,
            address: c.address,
            slot: c.slot,
            old_slots: c.old_slots,
            rotated_at: c.rotated_at,
            history: upgrade_history(c.history),
            unread: c.unread,
            disappear_after: None,
            gone: Vec::new(),
            cleared_by_them: None,
            seen: Vec::new(),
        }
    }
}

impl From<v3::State> for State {
    fn from(old: v3::State) -> Self {
        State {
            identity: old.identity,
            contacts: old.contacts.into_iter().map(Contact::from).collect(),
            invites: old.invites,
            pending: old.pending,
            settings: Settings {
                decoy_interval: old.settings.decoy_interval,
                data_mode: old.settings.data_mode,
                tor: old.settings.tor,
                ..Settings::default()
            },
            nym: BTreeMap::new(),
        }
    }
}

/// The version 2 state layout: version 3's, with only decoys in the settings.
mod v2 {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct State {
        pub identity: Vec<u8>,
        pub contacts: Vec<super::v3::Contact>,
        pub invites: Vec<super::PendingInvite>,
        pub pending: Vec<super::PendingMessage>,
        pub decoy_interval: Option<u32>,
    }
}

impl From<v2::State> for State {
    fn from(old: v2::State) -> Self {
        State {
            identity: old.identity,
            contacts: old.contacts.into_iter().map(Contact::from).collect(),
            invites: old.invites,
            pending: old.pending,
            settings: Settings {
                decoy_interval: old.decoy_interval,
                ..Settings::default()
            },
            nym: BTreeMap::new(),
        }
    }
}

/// The version 1 state layout, kept only to upgrade old profiles.
mod v1 {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct State {
        pub identity: Vec<u8>,
        pub contacts: Vec<Contact>,
        pub invites: Vec<PendingInvite>,
        pub pending: Vec<Vec<u8>>,
    }

    #[derive(Deserialize)]
    pub struct Contact {
        pub name: String,
        pub group_id: Vec<u8>,
        pub address: String,
        pub history: Vec<super::v5::HistoryEntry>,
    }

    #[derive(Deserialize)]
    pub struct PendingInvite {
        pub tag: [u8; 16],
        pub name: String,
    }
}

impl From<v1::State> for State {
    fn from(old: v1::State) -> Self {
        let legacy = || Slot {
            id: LEGACY_SLOT.into(),
            address: String::new(),
        };
        State {
            identity: old.identity,
            contacts: old
                .contacts
                .into_iter()
                .map(|c| Contact {
                    name: c.name,
                    group_id: c.group_id,
                    address: c.address,
                    slot: legacy(),
                    old_slots: Vec::new(),
                    // Due at once: move off the shared address.
                    rotated_at: 0,
                    history: upgrade_history(c.history),
                    unread: 0,
                    disappear_after: None,
                    gone: Vec::new(),
                    cleared_by_them: None,
                    seen: Vec::new(),
                })
                .collect(),
            invites: old
                .invites
                .into_iter()
                .map(|i| PendingInvite {
                    tag: i.tag,
                    name: i.name,
                    slot: legacy(),
                })
                .collect(),
            pending: old
                .pending
                .into_iter()
                .map(|ciphertext| PendingMessage {
                    slot: LEGACY_SLOT.into(),
                    ciphertext,
                })
                .collect(),
            settings: Settings::default(),
            nym: BTreeMap::new(),
        }
    }
}

/// Shortest passphrase accepted for a new profile. Existing profiles keep
/// whatever they were created with.
pub const MIN_PASSPHRASE: usize = 12;

/// Guards the device key. Whatever it seals is written to `device.key`;
/// once [`destroy`](Vault::destroy) has run, no sealed copy may ever be
/// opened again.
pub trait Vault: Send + Sync {
    fn seal(&self, key: &[u8]) -> Result<Vec<u8>>;
    fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    /// Make every sealed copy useless, for good.
    fn destroy(&self) -> Result<()>;
}

/// The computers' vault: there is no chip to lean on, so the device key is
/// kept as it is in `device.key`, and erasing destroys that file. It still
/// means a leftover copy of `state.enc` can't be opened with the
/// passphrase alone, but the file's own leftovers on flash storage are
/// only as gone as the drive makes them (full-disk encryption covers that).
pub struct FileVault;

impl Vault for FileVault {
    fn seal(&self, key: &[u8]) -> Result<Vec<u8>> {
        Ok(key.to_vec())
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(sealed.to_vec()))
    }

    fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

/// An open, unlocked profile directory. Holds an exclusive lock for as long
/// as it lives, so two privmsg processes can't overwrite each other.
pub struct Profile {
    dir: PathBuf,
    kdf: Kdf,
    salt: [u8; SALT_LEN],
    /// The file key.
    key: Secret,
    device: Secret,
    vault: Arc<dyn Vault>,
    /// `None` once erased.
    lock: Option<File>,
}

impl Profile {
    /// Whether `dir` holds a profile (and not one being erased).
    pub fn exists(dir: &Path) -> bool {
        dir.join(STATE_FILE).exists() && !Self::erase_pending(dir)
    }

    /// Whether an erase of the profile in `dir` was cut short.
    pub fn erase_pending(dir: &Path) -> bool {
        dir.join(ERASING_FILE).exists()
    }

    /// Finish an erase that was cut short, if there is one.
    pub fn finish_erase(dir: &Path, vault: &dyn Vault) -> Result<()> {
        if !Self::erase_pending(dir) {
            return Ok(());
        }
        let lock = lock(dir)?;
        wipe(dir, vault, Some(lock))
    }

    /// Create a new profile in `dir`, with its device key kept as a file
    /// (see [`FileVault`]). Fails if one already exists there.
    pub fn create(dir: &Path, passphrase: &str) -> Result<Self> {
        Self::create_with(dir, passphrase, Arc::new(FileVault))
    }

    /// Create a new profile in `dir` whose device key `vault` guards.
    pub fn create_with(dir: &Path, passphrase: &str, vault: Arc<dyn Vault>) -> Result<Self> {
        create_private_dir(dir)?;
        let lock = lock(dir)?;
        if dir.join(STATE_FILE).exists() {
            bail!("a profile already exists in {}", dir.display());
        }
        // A device key without a profile is left from a setup cut short.
        shred(&dir.join(DEVICE_FILE))?;
        let device = new_device_key(dir, vault.as_ref())?;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Ok(Self {
            dir: dir.to_path_buf(),
            key: file_key(&device, &*derive_key(KDF, passphrase, &salt)?, &salt)?,
            device,
            kdf: KDF,
            salt,
            vault,
            lock: Some(lock),
        })
    }

    /// Whether `passphrase` is the one this profile is locked with. Takes
    /// as long as unlocking does.
    pub fn check_passphrase(&self, passphrase: &str) -> bool {
        derive_key(self.kdf, passphrase, &self.salt)
            .and_then(|key| file_key(&self.device, &key, &self.salt))
            .is_ok_and(|key| key.matches(&self.key))
    }

    /// Unlock the profile in `dir` (device key kept as a file) and read its
    /// state.
    pub fn open(dir: &Path, passphrase: &str) -> Result<(Self, State)> {
        Self::open_with(dir, passphrase, Arc::new(FileVault))
    }

    /// Unlock the profile in `dir`, whose device key `vault` guards, and
    /// read its state.
    pub fn open_with(dir: &Path, passphrase: &str, vault: Arc<dyn Vault>) -> Result<(Self, State)> {
        let path = dir.join(STATE_FILE);
        if Self::erase_pending(dir) {
            Self::finish_erase(dir, vault.as_ref())?;
            bail!("this profile was erased");
        }
        if !path.exists() {
            bail!("no profile in {} (run `privmsg init` first)", dir.display());
        }
        let lock = lock(dir)?;
        let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let current = data.starts_with(MAGIC);
        let version_7 = data.starts_with(MAGIC_V7);
        let version_6 = data.starts_with(MAGIC_V6);
        let version_5 = data.starts_with(MAGIC_V5);
        let version_1 = data.starts_with(MAGIC_V1);
        let version_2 = data.starts_with(MAGIC_V2);
        let version_3 = data.starts_with(MAGIC_V3);
        let version_4 = data.starts_with(MAGIC_V4);
        let has_cost = current || version_7 || version_6 || version_5;
        let header_len = if has_cost { HEADER_LEN } else { OLD_HEADER_LEN };
        if data.len() < header_len + NONCE_LEN
            || !(current
                || version_7
                || version_6
                || version_5
                || version_4
                || version_3
                || version_2
                || version_1)
        {
            bail!("{} is not a privmsg profile", path.display());
        }
        let (kdf, salt): (Kdf, [u8; SALT_LEN]) = if has_cost {
            let kdf = Kdf::decode(&data[MAGIC.len()..MAGIC.len() + KDF_LEN])
                .with_context(|| format!("{} has a damaged header", path.display()))?;
            (kdf, data[MAGIC.len() + KDF_LEN..HEADER_LEN].try_into()?)
        } else {
            (Kdf::LEGACY, data[MAGIC.len()..OLD_HEADER_LEN].try_into()?)
        };
        let mut passphrase_key = derive_key(kdf, passphrase, &salt)?;
        // Versions 1–7 have no device key: the passphrase key opened them.
        let (key, device) = if current {
            let device = read_device_key(dir, vault.as_ref())?;
            (file_key(&device, &passphrase_key, &salt)?, Some(device))
        } else {
            (Secret::new(&mut passphrase_key), None)
        };

        let nonce = XNonce::from_slice(&data[header_len..header_len + NONCE_LEN]);
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new(key.bytes().into())
                .decrypt(
                    nonce,
                    Payload {
                        msg: &data[header_len + NONCE_LEN..],
                        aad: &data[..header_len],
                    },
                )
                .map_err(|_| anyhow!("wrong passphrase, or the profile is corrupted"))?,
        );
        let device = match device {
            Some(device) => device,
            // The passphrase was right: give the profile its device key.
            None => upgrade_device_key(dir, vault.as_ref())?,
        };
        let mut profile = Self {
            dir: dir.to_path_buf(),
            kdf,
            salt,
            key,
            device,
            vault,
            lock: Some(lock),
        };
        let rekey = !current || kdf.weaker_than(KDF);
        if rekey {
            // Older format or an outdated cost: re-key with a fresh salt.
            // Nothing is written until the save below.
            OsRng.fill_bytes(&mut profile.salt);
            profile.key = file_key(
                &profile.device,
                &*derive_key(KDF, passphrase, &profile.salt)?,
                &profile.salt,
            )?;
            profile.kdf = KDF;
        }
        let state = if version_7 {
            State::from(
                bincode::deserialize::<v7::State>(&plaintext).context("decode profile state")?,
            )
        } else if version_6 {
            State::from(
                bincode::deserialize::<v6::State>(&plaintext).context("decode profile state")?,
            )
        } else if version_4 || version_5 {
            State::from(
                bincode::deserialize::<v5::State>(&plaintext).context("decode profile state")?,
            )
        } else if version_3 {
            State::from(
                bincode::deserialize::<v3::State>(&plaintext).context("decode profile state")?,
            )
        } else if version_2 {
            State::from(
                bincode::deserialize::<v2::State>(&plaintext).context("decode profile state")?,
            )
        } else if version_1 {
            let old: v1::State =
                bincode::deserialize(&plaintext).context("decode profile state")?;
            // Move the old Nym client into its slot before anything
            // connects. Safe to repeat if a crash interrupts the upgrade.
            let old_nym = dir.join(NYM_DIR_V1);
            let legacy = profile.slots_dir().join(LEGACY_SLOT);
            if old_nym.exists() && !legacy.exists() {
                create_private_dir(&profile.slots_dir())?;
                fs::rename(&old_nym, &legacy).context("move Nym keys into slots/")?;
            }
            State::from(old)
        } else {
            bincode::deserialize(&plaintext).context("decode profile state")?
        };
        if !current {
            profile.replace_old_file(&path, &state)?;
            tracing::info!("upgraded profile to version 8");
        } else if rekey {
            profile.save(&state)?;
            tracing::info!("re-keyed profile with the current passphrase cost");
        }
        Ok((profile, state))
    }

    /// Save `state` over a file in an older format, then overwrite what was
    /// there (best effort: on most file systems the old blocks are written
    /// over in place; on flash and copy-on-write ones they may survive).
    fn replace_old_file(&self, path: &Path, state: &State) -> Result<()> {
        // Still names the old file after the save renames the new one over it.
        #[cfg(unix)]
        let old = OpenOptions::new().write(true).open(path).ok();
        #[cfg(not(unix))]
        let _ = path;
        self.save(state)?;
        #[cfg(unix)]
        if let Some(mut old) = old {
            if let Err(e) = overwrite(&mut old) {
                tracing::warn!("could not overwrite the old profile file: {e:#}");
            }
        }
        Ok(())
    }

    /// Encrypt and atomically replace the state file.
    pub fn save(&self, state: &State) -> Result<()> {
        if self.lock.is_none() {
            bail!("this profile was erased");
        }
        let plaintext = Zeroizing::new(bincode::serialize(state).context("encode state")?);
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&self.kdf.encode());
        header.extend_from_slice(&self.salt);

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = XChaCha20Poly1305::new(self.key.bytes().into())
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| anyhow!("encrypt state"))?;

        let tmp = self.dir.join(format!("{STATE_FILE}.tmp"));
        let mut file = private_file()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.write_all(&header)?;
        file.write_all(&nonce)?;
        file.write_all(&ciphertext)?;
        // Fuzzing saves on every input; durability is irrelevant there.
        #[cfg(not(fuzzing))]
        file.sync_all()?;
        drop(file);
        replace(&tmp, &self.dir.join(STATE_FILE)).context("replace state file")?;
        Ok(())
    }

    /// Destroy the profile for good, starting with what makes it
    /// unrecoverable: the device key. Then every file of the profile is
    /// overwritten with random bytes and deleted. Ends with the profile
    /// gone even if some step fails (the first failure is returned); one
    /// cut short by a crash is finished by [`Profile::finish_erase`].
    pub fn erase(&mut self) -> Result<()> {
        let lock = self
            .lock
            .take()
            .ok_or_else(|| anyhow!("this profile was erased"))?;
        wipe(&self.dir, self.vault.as_ref(), Some(lock))
    }

    /// Where version 1–7 profiles kept each Nym client's files.
    pub fn slots_dir(&self) -> PathBuf {
        self.dir.join(SLOTS_DIR)
    }

    /// Tor's state: its directory cache and entry guards.
    pub fn tor_dir(&self) -> PathBuf {
        self.dir.join(TOR_DIR)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// The erase itself (see [`Profile::erase`]). `lock` is the profile's lock,
/// held until the end.
fn wipe(dir: &Path, vault: &dyn Vault, lock: Option<File>) -> Result<()> {
    let mut first_error: Option<anyhow::Error> = None;
    let mut note = |result: Result<()>| {
        if let Err(e) = result {
            tracing::warn!("erasing: {e:#}");
            first_error.get_or_insert(e);
        }
    };
    note(mark_erasing(dir));
    // The key first: from here on, nothing left behind can be opened.
    note(vault.destroy().context("destroy the device key"));
    note(shred(&dir.join(DEVICE_FILE)));
    note(shred(&dir.join(STATE_FILE)));
    note(shred(&dir.join(format!("{STATE_FILE}.tmp"))));
    note(shred(&dir.join(LOG_FILE)));
    for sub in [SLOTS_DIR, TOR_DIR, NYM_DIR_V1] {
        note(shred_dir(&dir.join(sub)));
    }
    // The lock file can only go once it is closed (on Windows).
    drop(lock);
    note(shred(&dir.join(LOCK_FILE)));
    note(shred(&dir.join(ERASING_FILE)));
    // Only if nothing else is left in it: it may be a folder the user
    // keeps other things in.
    let _ = fs::remove_dir(dir);
    first_error.map_or(Ok(()), Err)
}

fn mark_erasing(dir: &Path) -> Result<()> {
    let file = private_file()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dir.join(ERASING_FILE))
        .context("start erasing")?;
    file.sync_all()?;
    Ok(())
}

/// Overwrite `path` with random bytes, flush that to the disk, and delete
/// it. Nothing to do if it isn't there. A link is removed, not followed.
pub fn shred(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        meta => meta.with_context(|| format!("look at {}", path.display()))?,
    };
    if meta.is_file() {
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        overwrite(&mut file).with_context(|| format!("overwrite {}", path.display()))?;
    }
    fs::remove_file(path).with_context(|| format!("delete {}", path.display()))
}

/// [`shred`] everything in `dir`, then the folder itself.
pub fn shred_dir(dir: &Path) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        entries => entries.with_context(|| format!("list {}", dir.display()))?,
    };
    let mut first_error = None;
    for entry in entries {
        let path = entry?.path();
        let result = if fs::symlink_metadata(&path)?.is_dir() {
            shred_dir(&path)
        } else {
            shred(&path)
        };
        if let Err(e) = result {
            first_error.get_or_insert(e);
        }
    }
    if let Some(e) = first_error {
        return Err(e);
    }
    fs::remove_dir(dir).with_context(|| format!("delete {}", dir.display()))
}

/// Write random bytes over the whole of `file` and flush them to the disk.
fn overwrite(file: &mut File) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut left = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut chunk = vec![0u8; 64 * 1024];
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        OsRng.fill_bytes(&mut chunk[..n]);
        file.write_all(&chunk[..n])?;
        left -= n as u64;
    }
    file.sync_all()?;
    Ok(())
}

/// Make a device key, seal it with `vault` and write it to `device.key`.
/// The file is written once and never rewritten, so there is only ever one
/// copy of it on the disk.
fn new_device_key(dir: &Path, vault: &dyn Vault) -> Result<Secret> {
    let key = Secret::random();
    let sealed = vault.seal(key.bytes()).context("seal the device key")?;
    let mut file = private_file()
        .write(true)
        .create_new(true)
        .open(dir.join(DEVICE_FILE))
        .context("write the device key")?;
    file.write_all(DEVICE_MAGIC)?;
    file.write_all(&sealed)?;
    file.sync_all()?;
    Ok(key)
}

fn read_device_key(dir: &Path, vault: &dyn Vault) -> Result<Secret> {
    let path = dir.join(DEVICE_FILE);
    let data = match fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "this profile's device key ({}) is missing, so it can't be opened: it was \
             erased, or copied without that file",
            path.display()
        ),
        data => Zeroizing::new(data.with_context(|| format!("read {}", path.display()))?),
    };
    let sealed = data
        .strip_prefix(DEVICE_MAGIC)
        .ok_or_else(|| anyhow!("{} is damaged", path.display()))?;
    let key = vault
        .unseal(sealed)
        .context("this profile's device key can't be opened on this device")?;
    Secret::from_slice(&key)
}

/// The device key for a profile being upgraded from a version without one:
/// a key left by an upgrade that was cut short, or a new one.
fn upgrade_device_key(dir: &Path, vault: &dyn Vault) -> Result<Secret> {
    match read_device_key(dir, vault) {
        Ok(key) => Ok(key),
        Err(_) => {
            shred(&dir.join(DEVICE_FILE))?;
            new_device_key(dir, vault)
        }
    }
}

/// The file key: both halves are needed, and the salt ties it to this file.
fn file_key(device: &Secret, passphrase_key: &[u8; 32], salt: &[u8]) -> Result<Secret> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(device.bytes());
    ikm[32..].copy_from_slice(passphrase_key);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm.as_ref())
        .expand(FILE_KEY_INFO, &mut key)
        .map_err(|_| anyhow!("derive the file key"))?;
    Ok(Secret::new(&mut key))
}

fn create_private_dir(dir: &Path) -> Result<()> {
    privmsg_transport::create_private_dir(dir).with_context(|| format!("create {}", dir.display()))
}

/// Options for a file only its owner can open. On Windows the profile
/// folder's access list (see [`create_private_dir`]) already ensures that.
fn private_file() -> OpenOptions {
    #[allow(unused_mut)]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

/// Atomically move `from` over `to`.
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    // On Windows a virus scanner or search indexer that just opened the
    // fresh file can make the rename fail for a moment; try a few times.
    #[cfg(windows)]
    for _ in 0..10 {
        match fs::rename(from, to) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                std::thread::sleep(std::time::Duration::from_millis(50))
            }
            done => return done,
        }
    }
    fs::rename(from, to)
}

/// Argon2id cost, as stored in the profile header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Kdf {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

impl Kdf {
    /// What versions 1–4 used: the argon2 crate's defaults.
    const LEGACY: Kdf = Kdf {
        memory_kib: argon2::Params::DEFAULT_M_COST,
        passes: argon2::Params::DEFAULT_T_COST,
        lanes: argon2::Params::DEFAULT_P_COST,
    };

    /// Whether this cost is below `other` in memory or passes. A profile
    /// saved by a newer build with a higher cost keeps it.
    fn weaker_than(self, other: Kdf) -> bool {
        self.memory_kib < other.memory_kib || self.passes < other.passes
    }

    fn encode(self) -> [u8; KDF_LEN] {
        let mut out = [0u8; KDF_LEN];
        out[..4].copy_from_slice(&self.memory_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.passes.to_le_bytes());
        out[8..].copy_from_slice(&self.lanes.to_le_bytes());
        out
    }

    /// Read a cost from a header, refusing ones so large that a tampered
    /// file could make unlocking hang or run out of memory.
    fn decode(bytes: &[u8]) -> Result<Self> {
        let word = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let kdf = Kdf {
            memory_kib: word(0),
            passes: word(4),
            lanes: word(8),
        };
        if kdf.memory_kib > 1024 * 1024 || kdf.passes > 64 || kdf.lanes > 16 {
            bail!("passphrase cost out of range: {kdf:?}");
        }
        Ok(kdf)
    }
}

fn derive_key(kdf: Kdf, passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(32))
        .map_err(|e| anyhow!("passphrase cost: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("derive key: {e}"))?;
    Ok(key)
}

fn lock(dir: &Path) -> Result<File> {
    let file = private_file()
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(LOCK_FILE))
        .context("open profile lock")?;
    file.try_lock().map_err(|_| {
        anyhow!(
            "profile {} is in use by another privmsg process",
            dir.display()
        )
    })?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> State {
        State {
            identity: vec![1, 2, 3],
            contacts: vec![Contact {
                name: "bob".into(),
                group_id: vec![9; 16],
                address: "bob-address".into(),
                slot: Slot {
                    id: "ab".into(),
                    address: "my-address".into(),
                },
                old_slots: vec![],
                rotated_at: 5,
                history: vec![HistoryEntry {
                    outgoing: true,
                    text: "hi".into(),
                    at: 1,
                    id: [8; 16],
                    shared: true,
                }],
                unread: 0,
                disappear_after: Some(3600),
                gone: vec![],
                cleared_by_them: None,
                seen: vec![],
            }],
            invites: vec![],
            pending: vec![],
            settings: Settings::default(),
            nym: BTreeMap::from([("sender".to_string(), b"nym-secret-bytes".to_vec())]),
        }
    }

    /// A message as versions 1–5 stored it: no ID.
    #[derive(Serialize)]
    struct EntryV5 {
        outgoing: bool,
        text: String,
        at: u64,
    }

    fn v5_history(history: Vec<HistoryEntry>) -> Vec<EntryV5> {
        history
            .into_iter()
            .map(|e| EntryV5 {
                outgoing: e.outgoing,
                text: e.text,
                at: e.at,
            })
            .collect()
    }

    /// The version 3 encoding of a contact: no timer, no message IDs.
    #[derive(Serialize)]
    struct ContactV3 {
        name: String,
        group_id: Vec<u8>,
        address: String,
        slot: Slot,
        old_slots: Vec<OldSlot>,
        rotated_at: u64,
        history: Vec<EntryV5>,
        unread: u32,
    }

    fn v3_contacts(contacts: Vec<Contact>) -> Vec<ContactV3> {
        contacts
            .into_iter()
            .map(|c| ContactV3 {
                name: c.name,
                group_id: c.group_id,
                address: c.address,
                slot: c.slot,
                old_slots: c.old_slots,
                rotated_at: c.rotated_at,
                history: v5_history(c.history),
                unread: c.unread,
            })
            .collect()
    }

    /// The encoding of versions 4 and 5: the current one without message IDs.
    fn v5_state(state: State) -> Vec<u8> {
        let contacts: Vec<_> = state
            .contacts
            .into_iter()
            .map(|c| {
                (
                    c.name,
                    c.group_id,
                    c.address,
                    c.slot,
                    c.old_slots,
                    c.rotated_at,
                    v5_history(c.history),
                    c.unread,
                    c.disappear_after,
                )
            })
            .collect();
        bincode::serialize(&(
            state.identity,
            contacts,
            state.invites,
            state.pending,
            state.settings,
        ))
        .unwrap()
    }

    /// Write `state` the way version 1 did.
    fn write_v1(dir: &Path, passphrase: &str, state: &[u8]) -> Result<()> {
        write_old(MAGIC_V1, dir, passphrase, state)
    }

    /// Write `state` under an older format's `magic`.
    fn write_old(magic: &[u8; 8], dir: &Path, passphrase: &str, state: &[u8]) -> Result<()> {
        let salt = [3u8; SALT_LEN];
        let key = derive_key(Kdf::LEGACY, passphrase, &salt)?;
        let mut header = magic.to_vec();
        header.extend_from_slice(&salt);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = XChaCha20Poly1305::new(key.as_ref().into())
            .encrypt(
                &nonce,
                Payload {
                    msg: state,
                    aad: &header,
                },
            )
            .map_err(|_| anyhow!("encrypt"))?;
        fs::create_dir_all(dir)?;
        fs::write(dir.join(STATE_FILE), [header, nonce.to_vec(), ct].concat())?;
        Ok(())
    }

    #[test]
    fn version_1_profile_is_upgraded() -> Result<()> {
        #[derive(Serialize)]
        struct V1 {
            identity: Vec<u8>,
            contacts: Vec<(String, Vec<u8>, String, Vec<EntryV5>)>,
            invites: Vec<([u8; 16], String)>,
            pending: Vec<Vec<u8>>,
        }
        let old = V1 {
            identity: vec![1],
            contacts: vec![(
                "bob".into(),
                vec![9],
                "bob-address".into(),
                vec![EntryV5 {
                    outgoing: false,
                    text: "old".into(),
                    at: 2,
                }],
            )],
            invites: vec![([4; 16], "carol".into())],
            pending: vec![vec![7]],
        };
        let dir = tempfile::tempdir()?;
        write_v1(dir.path(), "pw", &bincode::serialize(&old)?)?;
        fs::create_dir(dir.path().join(NYM_DIR_V1))?;
        fs::write(dir.path().join(NYM_DIR_V1).join("keys"), b"k")?;

        let (profile, state) = Profile::open(dir.path(), "pw")?;
        let bob = &state.contacts[0];
        assert_eq!(
            (bob.name.as_str(), bob.address.as_str()),
            ("bob", "bob-address")
        );
        assert_eq!(bob.slot.id, LEGACY_SLOT);
        assert_eq!(bob.rotated_at, 0, "due for rotation");
        assert_eq!(bob.history[0].text, "old");
        assert_eq!(state.invites[0].slot.id, LEGACY_SLOT);
        assert_eq!(state.pending[0].slot, LEGACY_SLOT);
        assert!(profile.slots_dir().join(LEGACY_SLOT).join("keys").exists());
        assert!(!dir.path().join(NYM_DIR_V1).exists());
        drop(profile);

        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(raw.starts_with(MAGIC), "rewritten as the current version");
        assert_eq!(Profile::open(dir.path(), "pw")?.1.contacts[0].name, "bob");
        Ok(())
    }

    #[test]
    fn version_2_profile_gets_default_network_settings() -> Result<()> {
        #[derive(Serialize)]
        struct V2 {
            identity: Vec<u8>,
            contacts: Vec<ContactV3>,
            invites: Vec<PendingInvite>,
            pending: Vec<PendingMessage>,
            decoy_interval: Option<u32>,
        }
        let current = sample_state();
        let old = V2 {
            identity: current.identity,
            contacts: v3_contacts(current.contacts),
            invites: current.invites,
            pending: current.pending,
            decoy_interval: Some(30),
        };
        let dir = tempfile::tempdir()?;
        write_old(MAGIC_V2, dir.path(), "pw", &bincode::serialize(&old)?)?;

        let (profile, state) = Profile::open(dir.path(), "pw")?;
        assert_eq!(state.contacts[0].history[0].text, "hi");
        assert_eq!(
            state.settings,
            Settings {
                decoy_interval: Some(30),
                data_mode: DataMode::Saver,
                tor: true,
                auto_sleep: None,
            }
        );
        drop(profile);
        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(raw.starts_with(MAGIC), "rewritten as the current version");
        Ok(())
    }

    #[test]
    fn version_3_profile_keeps_settings_and_starts_without_timers() -> Result<()> {
        #[derive(Serialize)]
        struct V3 {
            identity: Vec<u8>,
            contacts: Vec<ContactV3>,
            invites: Vec<PendingInvite>,
            pending: Vec<PendingMessage>,
            settings: (Option<u32>, DataMode, bool),
        }
        let current = sample_state();
        let old = V3 {
            identity: current.identity,
            contacts: v3_contacts(current.contacts),
            invites: current.invites,
            pending: current.pending,
            settings: (Some(30), DataMode::Balanced, false),
        };
        let dir = tempfile::tempdir()?;
        write_old(MAGIC_V3, dir.path(), "pw", &bincode::serialize(&old)?)?;

        let (profile, state) = Profile::open(dir.path(), "pw")?;
        assert_eq!(state.contacts[0].history[0].text, "hi");
        assert_eq!(state.contacts[0].disappear_after, None);
        assert_eq!(
            state.settings,
            Settings {
                decoy_interval: Some(30),
                data_mode: DataMode::Balanced,
                tor: false,
                auto_sleep: None,
            }
        );
        drop(profile);
        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(raw.starts_with(MAGIC), "rewritten as the current version");
        assert_eq!(
            Profile::open(dir.path(), "pw")?.1.settings.data_mode,
            DataMode::Balanced
        );
        Ok(())
    }

    #[test]
    fn version_4_profile_is_rekeyed_at_the_current_cost() -> Result<()> {
        let dir = tempfile::tempdir()?;
        write_old(MAGIC_V4, dir.path(), "pw", &v5_state(sample_state()))?;
        let (_, state) = Profile::open(dir.path(), "pw")?;
        assert_eq!(state.contacts[0].history[0].text, "hi");

        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(raw.starts_with(MAGIC), "rewritten as the current version");
        assert_eq!(Kdf::decode(&raw[MAGIC.len()..][..KDF_LEN])?, KDF);
        assert_ne!(&raw[MAGIC.len() + KDF_LEN..HEADER_LEN], &[3u8; SALT_LEN]);
        let (_, again) = Profile::open(dir.path(), "pw")?;
        assert_eq!(again.contacts[0].history[0].text, "hi");
        Ok(())
    }

    #[test]
    fn version_6_profile_starts_with_an_empty_replay_list() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut old = sample_state();
        old.contacts[0].gone = vec![[4; 16]];
        let contacts: Vec<_> = old
            .contacts
            .into_iter()
            .map(|c| {
                (
                    c.name,
                    c.group_id,
                    c.address,
                    c.slot,
                    c.old_slots,
                    c.rotated_at,
                    c.history,
                    c.unread,
                    c.disappear_after,
                    c.gone,
                    c.cleared_by_them,
                )
            })
            .collect();
        let v6 = bincode::serialize(&(
            old.identity,
            contacts,
            old.invites,
            old.pending,
            old.settings,
        ))?;
        write_with_cost(MAGIC_V6, dir.path(), "pw", &v6)?;

        let (profile, state) = Profile::open(dir.path(), "pw")?;
        let bob = &state.contacts[0];
        assert_eq!(bob.history[0].id, [8; 16]);
        assert_eq!(bob.gone, [[4; 16]]);
        assert!(bob.seen.is_empty());
        drop(profile);
        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(raw.starts_with(MAGIC), "rewritten as the current version");
        Ok(())
    }

    /// Write `state` under `magic` with a cost field, as versions 5 and up do.
    fn write_with_cost(magic: &[u8; 8], dir: &Path, passphrase: &str, state: &[u8]) -> Result<()> {
        let (salt, kdf) = ([5u8; SALT_LEN], KDF);
        let key = derive_key(kdf, passphrase, &salt)?;
        let header = [magic.as_slice(), &kdf.encode(), &salt].concat();
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = XChaCha20Poly1305::new(key.as_ref().into())
            .encrypt(
                &nonce,
                Payload {
                    msg: state,
                    aad: &header,
                },
            )
            .map_err(|_| anyhow!("encrypt"))?;
        fs::create_dir_all(dir)?;
        fs::write(dir.join(STATE_FILE), [header, nonce.to_vec(), ct].concat())?;
        Ok(())
    }

    #[test]
    fn version_5_messages_get_local_ids() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut old = sample_state();
        let entry = old.contacts[0].history[0].clone();
        old.contacts[0].history.push(entry);
        write_with_cost(MAGIC_V5, dir.path(), "pw", &v5_state(old))?;

        let (profile, state) = Profile::open(dir.path(), "pw")?;
        let bob = &state.contacts[0];
        assert_eq!(bob.disappear_after, Some(3600));
        assert!(bob.history.iter().all(|e| !e.shared), "only deletable here");
        assert_ne!(bob.history[0].id, bob.history[1].id);
        drop(profile);
        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(raw.starts_with(MAGIC), "rewritten as the current version");
        let (_, again) = Profile::open(dir.path(), "pw")?;
        assert_eq!(again.contacts[0].history[0].id, bob.history[0].id, "kept");
        Ok(())
    }

    #[test]
    fn passphrase_cost_is_bound_and_bounded() -> Result<()> {
        let dir = tempfile::tempdir()?;
        Profile::create(dir.path(), "pw")?.save(&sample_state())?;
        let path = dir.path().join(STATE_FILE);
        let good = fs::read(&path)?;

        // A lowered cost changes the key and fails authentication.
        let mut lowered = good.clone();
        let half = KDF.memory_kib / 2;
        lowered[MAGIC.len()..][..4].copy_from_slice(&half.to_le_bytes());
        fs::write(&path, &lowered)?;
        assert!(Profile::open(dir.path(), "pw").is_err());

        // An absurd cost is refused before any work is done.
        let mut huge = good;
        huge[MAGIC.len()..][..4].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, &huge)?;
        let err = Profile::open(dir.path(), "pw").err().unwrap();
        assert!(format!("{err:#}").contains("out of range"));
        Ok(())
    }

    #[test]
    fn save_and_reopen() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let profile = Profile::create(dir.path(), "correct horse")?;
        profile.save(&sample_state())?;
        drop(profile);

        let (_, state) = Profile::open(dir.path(), "correct horse")?;
        assert_eq!(state.identity, vec![1, 2, 3]);
        assert_eq!(state.contacts[0].history[0].text, "hi");
        Ok(())
    }

    #[test]
    fn state_file_does_not_contain_plaintext() -> Result<()> {
        let dir = tempfile::tempdir()?;
        Profile::create(dir.path(), "pw")?.save(&sample_state())?;
        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(!raw.windows(11).any(|w| w == b"bob-address"));
        Ok(())
    }

    #[test]
    fn wrong_passphrase_is_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        Profile::create(dir.path(), "right")?.save(&sample_state())?;
        let err = Profile::open(dir.path(), "wrong").err().unwrap();
        assert!(err.to_string().contains("wrong passphrase"));
        Ok(())
    }

    #[test]
    fn passphrase_check_matches_only_the_right_one() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let profile = Profile::create(dir.path(), "right")?;
        assert!(profile.check_passphrase("right"));
        assert!(!profile.check_passphrase("wrong"));
        Ok(())
    }

    #[test]
    fn tampered_file_is_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        Profile::create(dir.path(), "pw")?.save(&sample_state())?;
        let path = dir.path().join(STATE_FILE);
        let mut raw = fs::read(&path)?;
        let last = raw.len() - 1;
        raw[last] ^= 1;
        fs::write(&path, raw)?;
        assert!(Profile::open(dir.path(), "pw").is_err());
        Ok(())
    }

    #[test]
    fn profile_is_locked_while_open() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let profile = Profile::create(dir.path(), "pw")?;
        profile.save(&State::default())?;
        assert!(Profile::open(dir.path(), "pw").is_err());
        drop(profile);
        assert!(Profile::open(dir.path(), "pw").is_ok());
        Ok(())
    }

    #[test]
    fn create_refuses_to_overwrite() -> Result<()> {
        let dir = tempfile::tempdir()?;
        Profile::create(dir.path(), "pw")?.save(&State::default())?;
        assert!(Profile::create(dir.path(), "pw").is_err());
        Ok(())
    }

    #[test]
    fn version_7_profile_gets_a_device_key() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let old = sample_state();
        let v7 = bincode::serialize(&(
            old.identity,
            old.contacts,
            old.invites,
            old.pending,
            old.settings,
        ))?;
        write_with_cost(MAGIC_V7, dir.path(), "pw", &v7)?;
        assert!(!dir.path().join(DEVICE_FILE).exists());

        let (profile, state) = Profile::open(dir.path(), "pw")?;
        assert_eq!(state.contacts[0].history[0].text, "hi");
        assert!(state.nym.is_empty(), "the node adopts the key files later");
        drop(profile);
        assert!(dir.path().join(DEVICE_FILE).exists());
        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(raw.starts_with(MAGIC), "rewritten as the current version");
        assert_eq!(Profile::open(dir.path(), "pw")?.1.contacts[0].name, "bob");

        // From now on the passphrase alone opens nothing.
        fs::remove_file(dir.path().join(DEVICE_FILE))?;
        let err = Profile::open(dir.path(), "pw").err().unwrap();
        assert!(format!("{err:#}").contains("device key"), "{err:#}");
        Ok(())
    }

    #[test]
    fn nym_keys_are_saved_encrypted() -> Result<()> {
        let dir = tempfile::tempdir()?;
        Profile::create(dir.path(), "pw")?.save(&sample_state())?;
        let raw = fs::read(dir.path().join(STATE_FILE))?;
        assert!(!raw.windows(16).any(|w| w == b"nym-secret-bytes"));
        let (_, state) = Profile::open(dir.path(), "pw")?;
        assert_eq!(state.nym["sender"], b"nym-secret-bytes");
        Ok(())
    }

    #[test]
    fn a_copy_without_its_device_key_cannot_be_opened() -> Result<()> {
        let dir = tempfile::tempdir()?;
        Profile::create(dir.path(), "pw")?.save(&sample_state())?;
        let copy = tempfile::tempdir()?;
        fs::copy(dir.path().join(STATE_FILE), copy.path().join(STATE_FILE))?;
        let err = Profile::open(copy.path(), "pw").err().unwrap();
        assert!(format!("{err:#}").contains("device key"), "{err:#}");
        Ok(())
    }

    /// Everything a profile writes, as one blob, to search for leftovers.
    fn every_byte(dir: &Path) -> Vec<u8> {
        let mut all = Vec::new();
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            if entry.path().is_dir() {
                all.extend(every_byte(&entry.path()));
            } else {
                all.extend(fs::read(entry.path()).unwrap_or_default());
            }
        }
        all
    }

    #[test]
    fn erasing_destroys_every_file_and_old_copies_stay_shut() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let dir = parent.path().join("profile");
        let mut profile = Profile::create(&dir, "pw")?;
        profile.save(&sample_state())?;
        // Leftovers of the kind flash storage keeps: an old copy of the
        // state file, and Nym and Tor files.
        let leftover = fs::read(dir.join(STATE_FILE))?;
        for sub in [SLOTS_DIR, TOR_DIR] {
            fs::create_dir_all(dir.join(sub).join("inner"))?;
            fs::write(dir.join(sub).join("inner").join("keys.pem"), b"secret")?;
        }
        fs::write(dir.join(LOG_FILE), b"log")?;

        profile.erase()?;
        assert!(!dir.exists(), "the profile folder is gone");
        assert!(!Profile::exists(&dir));
        assert!(profile.save(&sample_state()).is_err(), "unusable after");
        drop(profile);

        // The leftover copy, put back, with the right passphrase: no way in.
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(STATE_FILE), &leftover)?;
        let err = Profile::open(&dir, "pw").err().unwrap();
        assert!(format!("{err:#}").contains("device key"), "{err:#}");
        Ok(())
    }

    #[test]
    fn erasing_leaves_other_files_in_the_folder_alone() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("notes.txt"), b"mine")?;
        let mut profile = Profile::create(dir.path(), "pw")?;
        profile.save(&sample_state())?;
        profile.erase()?;
        let names: Vec<_> = fs::read_dir(dir.path())?
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["notes.txt"]);
        assert!(!every_byte(dir.path()).windows(2).any(|w| w == b"hi"));
        Ok(())
    }

    #[test]
    fn an_interrupted_erase_is_finished() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let dir = parent.path().join("profile");
        let profile = Profile::create(&dir, "pw")?;
        profile.save(&sample_state())?;
        drop(profile);
        // As if the battery died right after the erase began.
        mark_erasing(&dir)?;
        assert!(!Profile::exists(&dir), "not offered for opening");
        let err = Profile::open(&dir, "pw").err().unwrap();
        assert!(err.to_string().contains("erased"));
        assert!(!dir.exists(), "opening finished the erase");
        Ok(())
    }

    /// A vault like the phone's: the device key is sealed with a key held
    /// elsewhere, which `destroy` deletes.
    struct TestVault {
        key: std::sync::Mutex<Option<u8>>,
    }

    impl Vault for TestVault {
        fn seal(&self, key: &[u8]) -> Result<Vec<u8>> {
            let k = self
                .key
                .lock()
                .unwrap()
                .ok_or_else(|| anyhow!("destroyed"))?;
            Ok(key.iter().map(|b| b ^ k).collect())
        }

        fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let k = self
                .key
                .lock()
                .unwrap()
                .ok_or_else(|| anyhow!("destroyed"))?;
            Ok(Zeroizing::new(sealed.iter().map(|b| b ^ k).collect()))
        }

        fn destroy(&self) -> Result<()> {
            *self.key.lock().unwrap() = None;
            Ok(())
        }
    }

    #[test]
    fn a_vault_seals_the_device_key_and_erasing_destroys_it() -> Result<()> {
        let vault = Arc::new(TestVault {
            key: std::sync::Mutex::new(Some(0x5a)),
        });
        let parent = tempfile::tempdir()?;
        let dir = parent.path().join("profile");
        let profile = Profile::create_with(&dir, "pw", vault.clone())?;
        profile.save(&sample_state())?;
        drop(profile);
        let sealed = fs::read(dir.join(DEVICE_FILE))?;
        let (mut profile, state) = Profile::open_with(&dir, "pw", vault.clone())?;
        assert_eq!(state.contacts[0].name, "bob");
        assert!(Profile::open(&dir, "pw").is_err(), "in use");

        profile.erase()?;
        assert!(
            vault.key.lock().unwrap().is_none(),
            "the vault's key is gone"
        );
        // Even the sealed device key and the state file, recovered, are useless.
        drop(profile);
        assert!(vault.unseal(&sealed[DEVICE_MAGIC.len()..]).is_err());
        Ok(())
    }

    #[test]
    fn shredding_overwrites_before_deleting() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("f");
        fs::write(&path, b"plain secret text")?;
        let mut file = OpenOptions::new().write(true).open(&path)?;
        overwrite(&mut file)?;
        drop(file);
        let after = fs::read(&path)?;
        assert_eq!(after.len(), 17);
        assert_ne!(after, b"plain secret text");
        shred(&path)?;
        assert!(!path.exists());
        shred(&path)?; // nothing there: fine
        Ok(())
    }

    #[test]
    fn open_missing_profile_explains() {
        let dir = tempfile::tempdir().unwrap();
        let err = Profile::open(dir.path(), "pw").err().unwrap();
        assert!(err.to_string().contains("privmsg init"));
    }
}
