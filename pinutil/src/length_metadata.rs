//! Optional, length-only companion metadata. Never stores a PIN or auth value.
use nix::libc;
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
};

pub const DIRECTORY: &str = "/var/lib/pinpam/pin-lengths";
static NEXT: AtomicUsize = AtomicUsize::new(0);

pub struct LengthStore {
    directory: PathBuf,
    owner: u32,
}
impl LengthStore {
    pub fn system() -> Self {
        Self {
            directory: DIRECTORY.into(),
            owner: 0,
        }
    }
    fn check_directory(&self) -> io::Result<()> {
        let m = fs::symlink_metadata(&self.directory)?;
        if !m.is_dir() || m.uid() != self.owner || m.mode() & 0o1000 == 0 || m.mode() & 0o002 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe PIN-length directory",
            ));
        }
        Ok(())
    }
    pub fn read(&self, uid: u32) -> io::Result<Option<usize>> {
        if let Err(e) = self.check_directory() {
            return if e.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            };
        }
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.directory.join(uid.to_string()))
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != uid || m.mode() & 0o022 != 0 || m.nlink() != 1 || m.len() > 3
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsafe PIN-length record",
            ));
        }
        let mut text = String::new();
        file.take(4).read_to_string(&mut text)?;
        let length = text.trim_end_matches('\n').parse::<usize>().ok();
        match length {
            Some(n) if (1..=64).contains(&n) && text == format!("{n}\n") => Ok(Some(n)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PIN length",
            )),
        }
    }
    pub fn write(&self, uid: u32, length: usize) -> io::Result<()> {
        if !(1..=64).contains(&length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid PIN length",
            ));
        }
        self.check_directory()?;
        let temp = self.directory.join(format!(
            ".{}-{}-{}",
            uid,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // create_new never follows an existing link; rename replaces a link itself.
        let mut created = false;
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp)?;
            created = true;
            writeln!(file, "{length}")?;
            if unsafe { libc::geteuid() } == 0
                && unsafe { libc::fchown(file.as_raw_fd(), uid, !0) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            fs::rename(&temp, self.directory.join(uid.to_string()))?;
            File::open(&self.directory)?.sync_all()
        })();
        // Do not unlink a create_new collision belonging to somebody else.
        if result.is_err() && created {
            let _ = fs::remove_file(&temp);
        }
        result
    }
    pub fn remove(&self, uid: u32) -> io::Result<()> {
        if let Err(e) = self.check_directory() {
            return if e.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            };
        }
        match fs::remove_file(self.directory.join(uid.to_string())) {
            Ok(()) => File::open(&self.directory)?.sync_all(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}
use pinpam_core::{
    pin::Pin,
    pinerror::{DeleteResult, PinResult},
    pinmanager::PinManager,
};
pub struct LengthAwareManager {
    manager: PinManager,
    store: LengthStore,
}
impl LengthAwareManager {
    pub fn new(manager: PinManager) -> Self {
        Self {
            manager,
            store: LengthStore::system(),
        }
    }
    pub fn prepare_change(&self, uid: u32) -> PinResult<()> {
        // Abort before deleting the old TPM enrollment if stale metadata cannot
        // be invalidated. Missing optional storage is fine.
        self.store.remove(uid)?;
        Ok(())
    }
    pub fn setup_pin(&mut self, uid: u32, pin: &Pin) -> PinResult<()> {
        // Never discard metadata when an existing enrollment is rejected.
        if self.manager.get_pin_slot(uid)?.is_some() {
            return Err(pinpam_core::pinerror::PinError::AlreadyProvisioned(uid));
        }
        // Refuse to create a new PIN with stale metadata that cannot be removed.
        self.store.remove(uid)?;
        self.manager.setup_pin(uid, pin)?;
        if let Err(error) = self.store.write(uid, pin.as_bytes().len()) {
            eprintln!("PIN length metadata unavailable; use Enter for submission: {error}");
        }
        Ok(())
    }
    pub fn delete_pin_admin(&mut self, uid: u32) -> PinResult<()> {
        self.manager.delete_pin_admin(uid)?;
        self.remove_length(uid);
        Ok(())
    }
    pub fn delete_pin_with_auth(&mut self, uid: u32, pin: &Pin) -> PinResult<DeleteResult> {
        let result = self.manager.delete_pin_with_auth(uid, pin)?;
        if matches!(result, DeleteResult::Success) {
            self.remove_length(uid);
        }
        Ok(result)
    }
    pub fn length(&mut self, uid: u32) -> PinResult<Option<usize>> {
        // Owner-authorized status reads never authenticate using a PIN.
        if self.manager.get_pin_slot(uid)?.is_none() {
            return Ok(None);
        }
        Ok(self.store.read(uid).unwrap_or(None))
    }
    fn remove_length(&self, uid: u32) {
        if let Err(error) = self.store.remove(uid) {
            eprintln!("Could not remove PIN length metadata: {error}");
        }
    }
}
impl std::ops::Deref for LengthAwareManager {
    type Target = PinManager;
    fn deref(&self) -> &PinManager {
        &self.manager
    }
}
impl std::ops::DerefMut for LengthAwareManager {
    fn deref_mut(&mut self) -> &mut PinManager {
        &mut self.manager
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture {
        store: LengthStore,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "pin-length-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o1775)).unwrap();
            Self {
                store: LengthStore {
                    directory,
                    owner: unsafe { nix::libc::getuid() },
                },
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.store.directory).unwrap();
        }
    }
    #[test]
    fn length_round_trip_update_remove_and_uid_isolation() {
        let f = Fixture::new();
        let uid = unsafe { nix::libc::getuid() };
        assert_eq!(f.store.read(uid).unwrap(), None);
        f.store.write(uid, 4).unwrap();
        assert_eq!(f.store.read(uid).unwrap(), Some(4));
        assert_eq!(
            std::fs::read_to_string(f.store.directory.join(uid.to_string())).unwrap(),
            "4\n"
        );
        f.store.write(uid, 6).unwrap();
        assert_eq!(f.store.read(uid).unwrap(), Some(6));
        assert_eq!(f.store.read(uid + 1).unwrap(), None);
        f.store.remove(uid).unwrap();
        assert_eq!(f.store.read(uid).unwrap(), None);
        f.store.remove(uid).unwrap();
    }
    #[test]
    fn refuses_symlink_without_reading_or_modifying_target() {
        let f = Fixture::new();
        let uid = unsafe { nix::libc::getuid() };
        let target = f.store.directory.join("target");
        std::fs::write(&target, "4\n").unwrap();
        symlink(&target, f.store.directory.join(uid.to_string())).unwrap();
        assert!(f.store.read(uid).is_err());
        f.store.write(uid, 5).unwrap();
        assert_eq!(std::fs::read_to_string(target).unwrap(), "4\n");
        assert_eq!(f.store.read(uid).unwrap(), Some(5));
    }
    #[test]
    fn rejects_invalid_oversized_and_writable_records() {
        let f = Fixture::new();
        let uid = unsafe { nix::libc::getuid() };
        let path = f.store.directory.join(uid.to_string());
        for data in ["1234\n", "0\n", "-4\n", "4\n5\n", "٤\n", "", "4", "0004\n"] {
            std::fs::write(&path, data).unwrap();
            assert!(f.store.read(uid).is_err(), "accepted {data:?}");
        }
        std::fs::write(&path, "4\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(f.store.read(uid).is_err());
        for value in [0, 65] {
            assert!(f.store.write(uid, value).is_err());
        }
    }
    #[test]
    fn rejects_other_uid_hardlink_and_nonregular_records() {
        let f = Fixture::new();
        let uid = unsafe { libc::getuid() };
        f.store.write(uid, 4).unwrap();
        let path = f.store.directory.join(uid.to_string());
        let other = f.store.directory.join((uid + 1).to_string());
        fs::rename(&path, &other).unwrap();
        assert!(f.store.read(uid + 1).is_err());
        fs::rename(&other, &path).unwrap();
        fs::hard_link(&path, &other).unwrap();
        assert!(f.store.read(uid).is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(f.store.read(uid).is_err());
    }
    #[test]
    fn rejects_unsafe_parent_and_handles_missing_storage() {
        let f = Fixture::new();
        let uid = unsafe { nix::libc::getuid() };
        std::fs::set_permissions(&f.store.directory, std::fs::Permissions::from_mode(0o775))
            .unwrap();
        assert!(f.store.read(uid).is_err());
        assert!(f.store.write(uid, 4).is_err());
        let absent = LengthStore {
            directory: f.store.directory.join("missing"),
            owner: f.store.owner,
        };
        assert_eq!(absent.read(uid).unwrap(), None);
        absent.remove(uid).unwrap();
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../pinpam-core/tests/common/mod.rs"]
mod swtpm_common;
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use pinpam_core::{pinerror::VerificationResult, pinpolicy::PinPolicy};
    #[test]
    fn unsafe_change_metadata_preserves_the_current_pin() {
        let Some(swtpm) = swtpm_common::try_start_swtpm() else {
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o1775)).unwrap();
        let uid = unsafe { libc::getuid() };
        let policy = PinPolicy::default();
        let mut manager = LengthAwareManager {
            manager: PinManager::with_tcti(policy.clone(), swtpm.tcti_spec()).unwrap(),
            store: LengthStore {
                directory: directory.path().into(),
                owner: uid,
            },
        };
        let pin = Pin::new("0123", &policy).unwrap();
        manager.setup_pin(uid, &pin).unwrap();
        manager.restart_context().unwrap();
        // Simulate a damaged directory before either change path deletes the PIN.
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(manager.prepare_change(uid).is_err());
        assert!(matches!(
            manager.verify_pin(uid, &pin).unwrap(),
            VerificationResult::Success(_)
        ));
        manager.restart_context().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o1775)).unwrap();
        assert_eq!(manager.length(uid).unwrap(), Some(4));
        manager.prepare_change(uid).unwrap();
        assert_eq!(manager.store.read(uid).unwrap(), None);
        // Preflight invalidates only the old metadata, not the TPM enrollment.
        assert!(manager.get_pin_slot(uid).unwrap().is_some());
    }
    #[test]
    fn enrollment_change_delete_and_legacy_length_without_auth_attempts() {
        let Some(swtpm) = swtpm_common::try_start_swtpm() else {
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o1775)).unwrap();
        let store = LengthStore {
            directory: directory.path().into(),
            owner: unsafe { libc::getuid() },
        };
        let uid = unsafe { libc::getuid() };
        let policy = PinPolicy::default();
        let mut m = LengthAwareManager {
            manager: PinManager::with_tcti(policy.clone(), swtpm.tcti_spec()).unwrap(),
            store,
        };
        let pin = Pin::new("0123", &policy).unwrap();
        assert_eq!(m.length(uid).unwrap(), None);
        m.setup_pin(uid, &pin).unwrap();
        assert_eq!(m.length(uid).unwrap(), Some(4));
        for _ in 0..3 {
            assert_eq!(m.length(uid).unwrap(), Some(4));
        }
        assert_eq!(m.get_attempt_count(uid).unwrap(), Some(0));
        m.store.remove(uid).unwrap(); // Existing release enrollment, unknown length.
        assert_eq!(m.length(uid).unwrap(), None);
        assert!(matches!(
            m.verify_pin(uid, &pin).unwrap(),
            VerificationResult::Success(_)
        ));
        m.restart_context().unwrap();
        m.store.write(uid, 4).unwrap();
        // Failed enrollment must preserve the existing PIN and metadata.
        assert!(m
            .setup_pin(uid, &Pin::new("012345", &policy).unwrap())
            .is_err());
        assert_eq!(m.length(uid).unwrap(), Some(4));
        m.restart_context().unwrap();
        m.delete_pin_admin(uid).unwrap();
        assert_eq!(m.store.read(uid).unwrap(), None);
        m.restart_context().unwrap();
        m.setup_pin(uid, &Pin::new("012345", &policy).unwrap())
            .unwrap();
        assert_eq!(m.length(uid).unwrap(), Some(6));
        assert_eq!(m.get_attempt_count(uid).unwrap(), Some(0));
        m.restart_context().unwrap();
        assert!(matches!(
            m.delete_pin_with_auth(uid, &Pin::new("999999", &policy).unwrap())
                .unwrap(),
            DeleteResult::Invalid { .. }
        ));
        m.restart_context().unwrap();
        assert_eq!(m.length(uid).unwrap(), Some(6));
        m.restart_context().unwrap();
        assert!(matches!(
            m.delete_pin_with_auth(uid, &Pin::new("012345", &policy).unwrap())
                .unwrap(),
            DeleteResult::Success
        ));
        assert_eq!(m.length(uid).unwrap(), None);
        assert_eq!(m.store.read(uid).unwrap(), None);
    }
    #[test]
    fn unavailable_metadata_never_breaks_authentication() {
        let Some(swtpm) = swtpm_common::try_start_swtpm() else {
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        let policy = PinPolicy::default();
        let uid = unsafe { libc::getuid() };
        let mut m = LengthAwareManager {
            manager: PinManager::with_tcti(policy.clone(), swtpm.tcti_spec()).unwrap(),
            store: LengthStore {
                directory: directory.path().join("missing"),
                owner: unsafe { libc::getuid() },
            },
        };
        let pin = Pin::new("0123", &policy).unwrap();
        m.setup_pin(uid, &pin).unwrap();
        assert_eq!(m.length(uid).unwrap(), None);
        m.restart_context().unwrap();
        assert!(matches!(
            m.verify_pin(uid, &pin).unwrap(),
            VerificationResult::Success(_)
        ));
        m.restart_context().unwrap();
        m.delete_pin_admin(uid).unwrap();
    }
}
