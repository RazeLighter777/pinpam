use nix::unistd::Uid;

use crate::pinerror::{PinError, PinResult};

pub fn normalize_legacy_pin(pin: &str) -> String {
    let normalized = pin.trim_start_matches('0');
    if normalized.is_empty() {
        "0".to_owned()
    } else {
        normalized.to_owned()
    }
}

pub fn get_uid() -> u32 {
    Uid::current().as_raw()
}

/// Check if the current user can manage the target user's PIN.
/// Root (uid 0) can manage anyone's PIN, users can only manage their own.
pub fn can_manage_pin(target_uid: u32) -> bool {
    let current_uid = get_uid();
    current_uid == 0 || current_uid == target_uid
}

/// Get UID from username using nix crate.
pub fn get_uid_from_username(username: &str) -> PinResult<u32> {
    use nix::unistd::User;
    User::from_name(username)
        .map_err(|_| PinError::UserNotFound)?
        .map(|u| u.uid.as_raw())
        .ok_or(PinError::UserNotFound)
}

/// Get username from UID using nix crate.
pub fn get_username_from_uid(uid: u32) -> Option<String> {
    use nix::unistd::{Uid, User};
    User::from_uid(Uid::from_raw(uid)).ok()?.map(|u| u.name)
}

pub fn serialize_error_as_string<T, S>(err: &T, ser: S) -> ::core::result::Result<S::Ok, S::Error>
where
    T: std::fmt::Display,
    S: serde::Serializer,
{
    ser.serialize_str(&format!("{err}"))
}
