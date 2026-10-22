//! Directories only the current user can open.
//!
//! The Nym clients' keys and gateway registrations are not encrypted by
//! privmsg, so the folders that hold them (and the profile folder around
//! them) must keep other local users out. On Unix that is mode 0700. On
//! Windows it is a protected access list with a single entry, full control
//! for the current user, inherited by every file and folder inside, so the
//! permissions of the parent folder don't leak in.
//!
//! Like `DirBuilder::mode`, only directories this call creates are
//! restricted: pointing privmsg at an existing folder never rewrites that
//! folder's permissions.

use std::io;
use std::path::Path;

#[cfg(unix)]
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(windows)]
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    windows::restrict_to_current_user(dir)
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE,
        SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Replace `dir`'s access list with one entry: full control for the
    /// current user, inherited by everything inside. Protected, so nothing
    /// is inherited from the parent folder.
    pub(super) fn restrict_to_current_user(dir: &Path) -> io::Result<()> {
        let user = CurrentUser::get()?;
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: user.sid().cast(),
            },
        };
        let mut acl: *mut ACL = null_mut();
        // SAFETY: `access` and the SID it points into live until the call
        // returns; on success `acl` is a LocalAlloc'd ACL we free below.
        let err = unsafe { SetEntriesInAclW(1, &access, null(), &mut acl) };
        if err != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let path: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: `path` is NUL-terminated UTF-16 and `acl` is a valid ACL.
        let err = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null(),
            )
        };
        // SAFETY: allocated by SetEntriesInAclW, not used after this.
        unsafe { LocalFree(acl.cast()) };
        if err != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        Ok(())
    }

    /// The `TOKEN_USER` of this process: who "the current user" is.
    pub(crate) struct CurrentUser {
        // u64s so the buffer is aligned for the pointer inside TOKEN_USER.
        buf: Vec<u64>,
    }

    impl CurrentUser {
        pub(crate) fn get() -> io::Result<Self> {
            let mut token: HANDLE = null_mut();
            // SAFETY: plain Win32 calls with valid out-pointers; the token
            // handle is closed on every path.
            unsafe {
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut len = 0u32;
                GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
                let mut buf = vec![0u64; (len as usize).div_ceil(8)];
                let ok =
                    GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
                let err = io::Error::last_os_error();
                CloseHandle(token);
                if ok == 0 {
                    return Err(err);
                }
                Ok(Self { buf })
            }
        }

        /// Valid for as long as `self` is.
        pub(crate) fn sid(&self) -> PSID {
            // SAFETY: GetTokenInformation(TokenUser) filled `buf` with a
            // TOKEN_USER whose SID points into the same buffer.
            unsafe { (*self.buf.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::windows::CurrentUser;
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACL,
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };

    /// (is the DACL protected, the SIDs it allows, in order).
    fn dacl(path: &Path, user: &CurrentUser) -> (bool, Vec<bool>) {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let mut acl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        unsafe {
            let err = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut sd,
            );
            assert_eq!(err, ERROR_SUCCESS);
            let (mut control, mut revision) = (0u16, 0u32);
            assert_ne!(
                GetSecurityDescriptorControl(sd, &mut control, &mut revision),
                0
            );
            let mut is_user = Vec::new();
            for i in 0..(*acl).AceCount as u32 {
                let mut ace = null_mut();
                assert_ne!(GetAce(acl, i, &mut ace), 0);
                let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
                is_user.push(EqualSid(sid, user.sid()) != 0);
            }
            LocalFree(sd.cast());
            (control & SE_DACL_PROTECTED != 0, is_user)
        }
    }

    #[test]
    fn only_the_current_user_can_open_a_private_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("profile").join("slots");
        create_private_dir(&dir).unwrap();
        std::fs::write(dir.join("key"), b"secret").unwrap();

        let user = CurrentUser::get().unwrap();
        assert_eq!(dacl(&dir, &user), (true, vec![true]));
        // Files created inside inherit the single entry.
        assert_eq!(dacl(&dir.join("key"), &user).1, vec![true]);
    }

    #[test]
    fn existing_dirs_keep_their_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let user = CurrentUser::get().unwrap();
        let before = dacl(tmp.path(), &user);
        create_private_dir(tmp.path()).unwrap();
        assert_eq!(dacl(tmp.path(), &user), before);
    }
}
