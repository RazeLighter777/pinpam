use crate::pindata::PinData;

pub type TssError = tss_esapi::Error;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum PinError {
    UserNotFound,
    PermissionDenied,
    PinAlreadySet,
    NoPinSet,
    PinsDontMatch,
    PinIsLocked,
    IncorrectPin { locked: bool },
    PinIsEmpty,
    PinContainsNonDigits,
    GetUsernameForUidFailed(u32),
    CannotDeletePin(DeleteResult),
    PinTooShort { length: usize, limit: usize },
    PinTooLong { length: usize, limit: usize },
    AlreadyProvisioned(u32),
    UidOverflow(u32),
    NotProvisioned(u32),
    TpmError(String),
    IoError(String),
    TermIoError(String),
    PinutilOutputDecodeError(String),
}

impl From<TssError> for PinError {
    fn from(err: TssError) -> Self {
        Self::TpmError(err.to_string())
    }
}

impl From<std::io::Error> for PinError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<nix::errno::Errno> for PinError {
    fn from(err: nix::errno::Errno) -> Self {
        Self::TermIoError(err.to_string())
    }
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::UserNotFound => t!("user_not_found"),
            Self::PermissionDenied => t!("permission_denied"),
            Self::PinAlreadySet => t!("pin_already_set"),
            Self::NoPinSet => t!("no_pin_set"),
            Self::PinsDontMatch => t!("pins_dont_match"),
            Self::PinIsLocked => t!("pin_is_locked"),
            Self::IncorrectPin { locked: false } => t!("incorrect_pin"),
            Self::IncorrectPin { locked: true } => t!("incorrect_pin_locked"),
            Self::PinIsEmpty => t!("pin_is_empty"),
            Self::PinContainsNonDigits => t!("pin_contains_non_digits"),
            Self::GetUsernameForUidFailed(uid) => t!("get_username_failed", "uid" => uid),
            Self::CannotDeletePin(e) => t!("cannot_delete_pin", "error" => e),
            Self::PinTooShort { length: _, limit } => t!("pin_too_short", "limit" => limit),
            Self::PinTooLong { length: _, limit } => t!("pin_too_long", "limit" => limit),
            Self::AlreadyProvisioned(uid) => t!("already_provisioned", "uid" => uid),
            Self::UidOverflow(uid) => t!("uid_overflow", "uid" => uid),
            Self::NotProvisioned(uid) => t!("not_provisioned", "uid" => uid),
            Self::TpmError(tss_error) => t!("tpm_error", "error" => tss_error),
            Self::IoError(e) => t!("io_error", "error" => e),
            Self::TermIoError(e) => t!("term_io_error", "error" => e),
            Self::PinutilOutputDecodeError(e) => t!("pinutil_decode_error", "error" => e),
        };
        write!(f, "{msg}")
    }
}

/// Result of PIN verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerificationResult {
    /// PIN verification succeeded. Contains the current PinData with attempt counters.
    Success(PinData),
    /// PIN verification failed - incorrect PIN provided. If `locked` is true, the PIN is now
    /// locked and future attempts with fail with [`VerificationResult::LockedOut`].
    Invalid { locked: bool },
    /// User is locked out due to too many failed attempts.
    LockedOut,
}

/// Result of authenticated PIN deletion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeleteResult {
    /// PIN deletion succeeded.
    Success,
    /// PIN deletion failed - incorrect PIN provided. If `locked` is true, the PIN is now locked
    /// and future attempts with fail with [`DeleteResult::LockedOut`].
    Invalid { locked: bool },
    /// User is locked out due to too many failed attempts.
    LockedOut,
}

impl std::fmt::Display for DeleteResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Success => t!("pin_del_success"),
            Self::Invalid { locked: false } => t!("pin_del_invalid"),
            Self::Invalid { locked: true } => t!("pin_del_invalid_locked"),
            Self::LockedOut => t!("pin_del_locked_out"),
        };
        write!(f, "{msg}")
    }
}

pub type PinResult<T> = std::result::Result<T, PinError>;
