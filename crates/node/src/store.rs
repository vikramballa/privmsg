//! Encrypted on-disk profile.
//!
//! Everything privmsg must remember — the MLS identity and group state,
//! contacts, open invites, message history — lives in one file,
//! `state.enc`, sealed with a key derived from the user's passphrase:
//!
//! ```text
//! "PRIVMSG5" | KDF cost (12) | salt (16) | nonce (24) | XChaCha20-Poly1305(state)
//! ```
//!
//! The key is Argon2id(passphrase, salt) with the cost in the header
//! (memory in KiB, passes, lanes; each a little-endian u32), so it can be
//! raised later without a new format. The header is bound as AEAD
//! associated data, so it can't be swapped without detection. Writes go to a
//! temp file and are renamed into place, so a crash never leaves a torn file.
//!
//! Version 1 profiles (`"PRIVMSG1"`, one mix address for everything) are
//! upgraded on open: their single Nym client moves to the slot
//! [`LEGACY_SLOT`], and every contact is due for an address rotation.
//! Version 2 profiles (`"PRIVMSG2"`) only lack the network settings and get
//! the defaults. Version 3 profiles (`"PRIVMSG3"`) lack disappearing
//! messages and auto-sleep, which start off. Versions 1–4 used the Argon2
//! crate's default cost and no cost field; they are re-keyed at [`KDF`] when
//! opened.
//!
//! Not covered: the Nym clients' own files under `slots/` (their keys and
//! gateway registrations) are written by the Nym SDK and are not encrypted
//! by us.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use privmsg_transport::DataMode;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"PRIVMSG5";
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
        pub history: Vec<super::HistoryEntry>,
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
            history: c.history,
            unread: c.unread,
            disappear_after: None,
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
        pub history: Vec<super::HistoryEntry>,
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
                    history: c.history,
                    unread: 0,
                    disappear_after: None,
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
        }
    }
}

/// Shortest passphrase accepted for a new profile. Existing profiles keep
/// whatever they were created with.
pub const MIN_PASSPHRASE: usize = 12;

/// An open, unlocked profile directory. Holds an exclusive lock for as long
/// as it lives, so two privmsg processes can't overwrite each other.
pub struct Profile {
    dir: PathBuf,
    kdf: Kdf,
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,
    _lock: File,
}

impl Profile {
    /// Whether `dir` holds a profile.
    pub fn exists(dir: &Path) -> bool {
        dir.join(STATE_FILE).exists()
    }

    /// Create a new profile in `dir`. Fails if one already exists there.
    pub fn create(dir: &Path, passphrase: &str) -> Result<Self> {
        create_private_dir(dir)?;
        let lock = lock(dir)?;
        if dir.join(STATE_FILE).exists() {
            bail!("a profile already exists in {}", dir.display());
        }
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Ok(Self {
            dir: dir.to_path_buf(),
            key: derive_key(KDF, passphrase, &salt)?,
            kdf: KDF,
            salt,
            _lock: lock,
        })
    }

    /// Whether `passphrase` is the one this profile is locked with. Takes
    /// as long as unlocking does.
    pub fn check_passphrase(&self, passphrase: &str) -> bool {
        // Without early exit, though after Argon2 timing reveals nothing.
        derive_key(self.kdf, passphrase, &self.salt).is_ok_and(|key| {
            key.iter()
                .zip(self.key.iter())
                .fold(0, |acc, (a, b)| acc | (a ^ b))
                == 0
        })
    }

    /// Unlock the profile in `dir` and read its state.
    pub fn open(dir: &Path, passphrase: &str) -> Result<(Self, State)> {
        let path = dir.join(STATE_FILE);
        if !path.exists() {
            bail!("no profile in {} (run `privmsg init` first)", dir.display());
        }
        let lock = lock(dir)?;
        let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let current = data.starts_with(MAGIC);
        let version_1 = data.starts_with(MAGIC_V1);
        let version_2 = data.starts_with(MAGIC_V2);
        let version_3 = data.starts_with(MAGIC_V3);
        let version_4 = data.starts_with(MAGIC_V4);
        let header_len = if current { HEADER_LEN } else { OLD_HEADER_LEN };
        if data.len() < header_len + NONCE_LEN
            || !(current || version_4 || version_3 || version_2 || version_1)
        {
            bail!("{} is not a privmsg profile", path.display());
        }
        let (kdf, salt): (Kdf, [u8; SALT_LEN]) = if current {
            let kdf = Kdf::decode(&data[MAGIC.len()..MAGIC.len() + KDF_LEN])
                .with_context(|| format!("{} has a damaged header", path.display()))?;
            (kdf, data[MAGIC.len() + KDF_LEN..HEADER_LEN].try_into()?)
        } else {
            (Kdf::LEGACY, data[MAGIC.len()..OLD_HEADER_LEN].try_into()?)
        };
        let key = derive_key(kdf, passphrase, &salt)?;

        let nonce = XNonce::from_slice(&data[header_len..header_len + NONCE_LEN]);
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new(key.as_ref().into())
                .decrypt(
                    nonce,
                    Payload {
                        msg: &data[header_len + NONCE_LEN..],
                        aad: &data[..header_len],
                    },
                )
                .map_err(|_| anyhow!("wrong passphrase, or the profile is corrupted"))?,
        );
        let mut profile = Self {
            dir: dir.to_path_buf(),
            kdf,
            salt,
            key,
            _lock: lock,
        };
        let rekey = !current || kdf.weaker_than(KDF);
        if rekey {
            // Older format or an outdated cost: re-key with a fresh salt.
            // Nothing is written until the save below.
            OsRng.fill_bytes(&mut profile.salt);
            profile.key = derive_key(KDF, passphrase, &profile.salt)?;
            profile.kdf = KDF;
        }
        if version_2 || version_3 {
            let state = if version_3 {
                State::from(
                    bincode::deserialize::<v3::State>(&plaintext)
                        .context("decode profile state")?,
                )
            } else {
                State::from(
                    bincode::deserialize::<v2::State>(&plaintext)
                        .context("decode profile state")?,
                )
            };
            profile.save(&state)?;
            tracing::info!("upgraded profile to version 5");
            return Ok((profile, state));
        }
        if !version_1 {
            let state = bincode::deserialize(&plaintext).context("decode profile state")?;
            if rekey {
                profile.save(&state)?;
                tracing::info!("re-keyed profile with the current passphrase cost");
            }
            return Ok((profile, state));
        }

        let old: v1::State = bincode::deserialize(&plaintext).context("decode profile state")?;
        // Move the old Nym client into its slot before anything connects.
        // Safe to repeat if a crash interrupts the upgrade.
        let old_nym = dir.join(NYM_DIR_V1);
        let legacy = profile.slots_dir().join(LEGACY_SLOT);
        if old_nym.exists() && !legacy.exists() {
            create_private_dir(&profile.slots_dir())?;
            fs::rename(&old_nym, &legacy).context("move Nym keys into slots/")?;
        }
        let state = State::from(old);
        profile.save(&state)?;
        tracing::info!("upgraded profile to version 5");
        Ok((profile, state))
    }

    /// Encrypt and atomically replace the state file.
    pub fn save(&self, state: &State) -> Result<()> {
        let plaintext = Zeroizing::new(bincode::serialize(state).context("encode state")?);
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&self.kdf.encode());
        header.extend_from_slice(&self.salt);

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = XChaCha20Poly1305::new(self.key.as_ref().into())
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

    /// Where each slot's Nym client keeps its keys and gateway registration.
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
                }],
                unread: 0,
                disappear_after: Some(3600),
            }],
            invites: vec![],
            pending: vec![],
            settings: Settings::default(),
        }
    }

    /// The version 3 encoding of a contact: everything but the timer.
    #[derive(Serialize)]
    struct ContactV3 {
        name: String,
        group_id: Vec<u8>,
        address: String,
        slot: Slot,
        old_slots: Vec<OldSlot>,
        rotated_at: u64,
        history: Vec<HistoryEntry>,
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
                history: c.history,
                unread: c.unread,
            })
            .collect()
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
            contacts: Vec<(String, Vec<u8>, String, Vec<HistoryEntry>)>,
            invites: Vec<([u8; 16], String)>,
            pending: Vec<Vec<u8>>,
        }
        let old = V1 {
            identity: vec![1],
            contacts: vec![(
                "bob".into(),
                vec![9],
                "bob-address".into(),
                vec![HistoryEntry {
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
        write_old(
            MAGIC_V4,
            dir.path(),
            "pw",
            &bincode::serialize(&sample_state())?,
        )?;
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
    fn open_missing_profile_explains() {
        let dir = tempfile::tempdir().unwrap();
        let err = Profile::open(dir.path(), "pw").err().unwrap();
        assert!(err.to_string().contains("privmsg init"));
    }
}
