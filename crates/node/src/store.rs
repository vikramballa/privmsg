//! Encrypted on-disk profile.
//!
//! Everything privmsg must remember — the MLS identity and group state,
//! contacts, open invites, message history — lives in one file,
//! `state.enc`, sealed with a key derived from the user's passphrase:
//!
//! ```text
//! "PRIVMSG1" | salt (16) | nonce (24) | XChaCha20-Poly1305(state)
//! ```
//!
//! The key is Argon2id(passphrase, salt). The header is bound as AEAD
//! associated data, so it can't be swapped without detection. Writes go to a
//! temp file and are renamed into place, so a crash never leaves a torn file.
//!
//! Not covered: the Nym client's own files under `nym/` (its keys and gateway
//! registration) are written by the Nym SDK and are not encrypted by us.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"PRIVMSG1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN;
const STATE_FILE: &str = "state.enc";
const LOCK_FILE: &str = "lock";

/// Messages kept per contact; older ones are dropped.
pub const HISTORY_LIMIT: usize = 500;

/// Everything the node persists. Serialized, then encrypted as a whole.
#[derive(Serialize, Deserialize, Default)]
pub struct State {
    /// `privmsg_crypto::Identity::snapshot` — keys plus every MLS group.
    pub identity: Vec<u8>,
    pub contacts: Vec<Contact>,
    pub invites: Vec<PendingInvite>,
    /// MLS messages for groups we have not joined yet. The mixnet can
    /// deliver a message before the Join that creates its group.
    pub pending: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Contact {
    /// Local nickname. Never sent anywhere.
    pub name: String,
    pub group_id: Vec<u8>,
    /// The contact's mix address, where our messages go.
    pub address: String,
    pub history: Vec<HistoryEntry>,
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
}

/// An open, unlocked profile directory. Holds an exclusive lock for as long
/// as it lives, so two privmsg processes can't overwrite each other.
pub struct Profile {
    dir: PathBuf,
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,
    _lock: File,
}

impl Profile {
    /// Create a new profile in `dir`. Fails if one already exists there.
    pub fn create(dir: &Path, passphrase: &str) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
        let lock = lock(dir)?;
        if dir.join(STATE_FILE).exists() {
            bail!("a profile already exists in {}", dir.display());
        }
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Ok(Self {
            dir: dir.to_path_buf(),
            key: derive_key(passphrase, &salt)?,
            salt,
            _lock: lock,
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
        if data.len() < HEADER_LEN + NONCE_LEN || &data[..MAGIC.len()] != MAGIC {
            bail!("{} is not a privmsg profile", path.display());
        }
        let salt: [u8; SALT_LEN] = data[MAGIC.len()..HEADER_LEN].try_into()?;
        let key = derive_key(passphrase, &salt)?;

        let nonce = XNonce::from_slice(&data[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new(key.as_ref().into())
                .decrypt(
                    nonce,
                    Payload {
                        msg: &data[HEADER_LEN + NONCE_LEN..],
                        aad: &data[..HEADER_LEN],
                    },
                )
                .map_err(|_| anyhow!("wrong passphrase, or the profile is corrupted"))?,
        );
        let state = bincode::deserialize(&plaintext).context("decode profile state")?;

        let profile = Self {
            dir: dir.to_path_buf(),
            salt,
            key,
            _lock: lock,
        };
        Ok((profile, state))
    }

    /// Encrypt and atomically replace the state file.
    pub fn save(&self, state: &State) -> Result<()> {
        let plaintext = Zeroizing::new(bincode::serialize(state).context("encode state")?);
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
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
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.write_all(&header)?;
        file.write_all(&nonce)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
        fs::rename(&tmp, self.dir.join(STATE_FILE)).context("replace state file")?;
        Ok(())
    }

    /// Where the Nym client keeps its keys and gateway registration.
    pub fn nym_dir(&self) -> PathBuf {
        self.dir.join("nym")
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("derive key: {e}"))?;
    Ok(key)
}

fn lock(dir: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
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
                history: vec![HistoryEntry {
                    outgoing: true,
                    text: "hi".into(),
                    at: 1,
                }],
            }],
            invites: vec![],
            pending: vec![],
        }
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
