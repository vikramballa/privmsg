//! Keeping secrets out of places they could be read back from later: swap,
//! crash dumps, and memory that is freed without being wiped.
//!
//! All of this is best effort. Rust may leave stray copies of data behind
//! when buffers grow, and the MLS library keeps its own keys. What makes an
//! erased profile unreadable is destroying its device key (see `store`),
//! not this.

use anyhow::{bail, Result};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use zeroize::Zeroize;

/// A 32-byte key on the heap, kept out of swap where the system allows,
/// and wiped when dropped.
pub struct Secret(Box<[u8; 32]>);

impl Secret {
    /// Take `bytes`, wiping the caller's copy.
    pub fn new(bytes: &mut [u8; 32]) -> Self {
        let secret = Self(Box::new(*bytes));
        bytes.zeroize();
        lock_memory(secret.0.as_ptr(), 32);
        secret
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let Ok(mut array) = <[u8; 32]>::try_from(bytes) else {
            bail!("a key is {} bytes, not 32", bytes.len());
        };
        Ok(Self::new(&mut array))
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::new(&mut bytes)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compare without stopping at the first difference.
    pub fn matches(&self, other: &Secret) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
        // The page stays locked: another key may share it, and the system
        // doesn't count locks, so unlocking here could unlock that one too.
    }
}

/// Ask the system to keep `len` bytes at `ptr` in RAM, never in swap.
/// Refusal (a low memory-lock limit) is not an error: it only means the
/// bytes could reach swap.
fn lock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    // SAFETY: mlock only reads the address range; it is valid for `len`.
    unsafe {
        libc::mlock(ptr.cast(), len);
    }
    #[cfg(windows)]
    // SAFETY: as above.
    unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(ptr.cast(), len);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (ptr, len);
}

/// Make this process harder to read secrets from: no crash dump files
/// (they would hold messages and keys), and on Linux no attaching by other
/// programs of the same user.
pub fn harden_process() {
    #[cfg(unix)]
    // SAFETY: plain system calls with valid arguments.
    unsafe {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_takes_the_bytes_and_wipes_the_source() {
        let mut bytes = [7u8; 32];
        let secret = Secret::new(&mut bytes);
        assert_eq!(bytes, [0; 32]);
        assert_eq!(secret.bytes(), &[7; 32]);
        assert!(secret.matches(&Secret::from_slice(&[7; 32]).unwrap()));
        assert!(!secret.matches(&Secret::random()));
        assert!(Secret::from_slice(&[1; 31]).is_err());
    }
}
