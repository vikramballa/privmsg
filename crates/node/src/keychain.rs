//! Optional passphrase storage in the macOS login keychain, keyed by the
//! profile's directory. Elsewhere every call reports that it is unsupported
//! and privmsg keeps prompting.

use std::path::Path;

use anyhow::Result;
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
const SERVICE: &str = "privmsg";

/// One keychain entry per profile directory.
#[cfg(target_os = "macos")]
fn account(dir: &Path) -> String {
    std::fs::canonicalize(dir)
        .unwrap_or_else(|_| dir.to_path_buf())
        .display()
        .to_string()
}

#[cfg(target_os = "macos")]
pub fn get(dir: &Path) -> Option<Zeroizing<String>> {
    use security_framework::passwords::get_generic_password;
    let bytes = Zeroizing::new(get_generic_password(SERVICE, &account(dir)).ok()?);
    std::str::from_utf8(&bytes)
        .ok()
        .map(|s| Zeroizing::new(s.to_string()))
}

#[cfg(target_os = "macos")]
pub fn set(dir: &Path, passphrase: &str) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(SERVICE, &account(dir), passphrase.as_bytes())
        .map_err(|e| anyhow::anyhow!("save to keychain: {e}"))
}

/// Returns whether there was an entry to delete.
#[cfg(target_os = "macos")]
pub fn delete(dir: &Path) -> Result<bool> {
    use security_framework::passwords::delete_generic_password;
    // errSecItemNotFound
    const NOT_FOUND: i32 = -25300;
    match delete_generic_password(SERVICE, &account(dir)) {
        Ok(()) => Ok(true),
        Err(e) if e.code() == NOT_FOUND => Ok(false),
        Err(e) => Err(anyhow::anyhow!("remove from keychain: {e}")),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn get(_dir: &Path) -> Option<Zeroizing<String>> {
    None
}

#[cfg(not(target_os = "macos"))]
pub fn set(_dir: &Path, _passphrase: &str) -> Result<()> {
    anyhow::bail!("keychain storage is only supported on macOS")
}

#[cfg(not(target_os = "macos"))]
pub fn delete(_dir: &Path) -> Result<bool> {
    anyhow::bail!("keychain storage is only supported on macOS")
}
