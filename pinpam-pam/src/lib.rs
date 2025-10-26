//! TPM PIN Authentication PAM Module
//!
//! This library provides a PAM module for TPM-backed PIN authentication.

use libc::c_void;
use log::{debug, error, info, warn};
use pam_sys::{
    self, raw,
    types::{
        PamConversation, PamItemType, PamMessage, PamMessageStyle, PamResponse, PamReturnCode,
    },
};
use pinpam_core::{get_uid_from_username, PinError, PinManager, PinPolicy, VerificationResult};
use syslog::{BasicLogger, Facility, Formatter3164};
use std::{
    env,
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    process,
    ptr,
    sync::OnceLock,
};

type PamResult<T> = std::result::Result<T, PamReturnCode>;

/// Load PIN policy from configuration
fn load_pin_policy() -> PinPolicy {
    PinPolicy::load_from_standard_locations()
}

fn init_logging() {
    static LOGGER_INIT: OnceLock<()> = OnceLock::new();
    LOGGER_INIT.get_or_init(|| {
        // Route log crate output to syslog's authpriv facility; fall back to env_logger on failure.
        let rust_log = env::var("RUST_LOG").ok();

        let mut env_builder = env_logger::Builder::new();
        env_builder.filter_level(log::LevelFilter::Info);
        if let Some(ref value) = rust_log {
            env_builder.parse_filters(value);
        }

        let max_level = rust_log
            .as_deref()
            .map(|value| {
                if value.contains('=') || value.contains(',') {
                    log::LevelFilter::Trace
                } else {
                    value
                        .parse::<log::LevelFilter>()
                        .unwrap_or(log::LevelFilter::Trace)
                }
            })
            .unwrap_or(log::LevelFilter::Info);

        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTHPRIV,
            hostname: None,
            process: "pinpam".to_owned(),
            pid: process::id(),
        };

        if let Ok(writer) = syslog::unix(formatter) {
            if log::set_boxed_logger(Box::new(BasicLogger::new(writer))).is_ok() {
                log::set_max_level(max_level);
                return;
            }
        }

        let _ = env_builder.try_init();
    });
}

fn suppress_tss_logs() {
    static SUPPRESS_LOGS: OnceLock<()> = OnceLock::new();
    SUPPRESS_LOGS.get_or_init(|| {
        if env::var_os("RUST_LOG").is_none() {
            env::set_var("TSS2_LOG", "all+NONE");
        }
    });
}

struct PamIo {
    conv: *const PamConversation,
}

impl PamIo {
    unsafe fn new(pamh: *mut pam_sys::PamHandle) -> PamResult<Self> {
        let mut item_ptr: *const c_void = ptr::null();
        let status = PamReturnCode::from(raw::pam_get_item(
            pamh,
            PamItemType::CONV as c_int,
            &mut item_ptr,
        ));

        if status != PamReturnCode::SUCCESS {
            return Err(status);
        }

        if item_ptr.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }

        let conv = item_ptr as *const PamConversation;
        if conv.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }

        Ok(Self { conv })
    }

    unsafe fn prompt_hidden(&self, prompt: &str) -> PamResult<String> {
        let conv_struct = &*self.conv;
        let conv_fn = conv_struct.conv.ok_or(PamReturnCode::CONV_ERR)?;
        let prompt_cstr = CString::new(prompt).map_err(|_| PamReturnCode::SYSTEM_ERR)?;

        let mut message = PamMessage {
            msg_style: PamMessageStyle::PROMPT_ECHO_OFF as c_int,
            msg: prompt_cstr.as_ptr(),
        };

        let mut message_ptrs = [&mut message as *mut PamMessage];
        let mut response_ptr: *mut PamResponse = ptr::null_mut();

        let status = PamReturnCode::from(conv_fn(
            message_ptrs.len() as c_int,
            message_ptrs.as_mut_ptr(),
            &mut response_ptr,
            conv_struct.data_ptr,
        ));

        if status != PamReturnCode::SUCCESS {
            return Err(status);
        }

        if response_ptr.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }

        let response = *response_ptr;
        let result = if response.resp.is_null() {
            Err(PamReturnCode::CONV_ERR)
        } else {
            CStr::from_ptr(response.resp)
                .to_str()
                .map(|s| s.trim().to_owned())
                .map_err(|_| PamReturnCode::AUTH_ERR)
        };

        if !response.resp.is_null() {
            libc::free(response.resp as *mut c_void);
        }
        libc::free(response_ptr as *mut c_void);

        result
    }

    unsafe fn send_message(&self, style: PamMessageStyle, text: &str) -> PamResult<()> {
        let conv_struct = &*self.conv;
        let conv_fn = conv_struct.conv.ok_or(PamReturnCode::CONV_ERR)?;
        let text_cstr = CString::new(text).map_err(|_| PamReturnCode::SYSTEM_ERR)?;

        let mut message = PamMessage {
            msg_style: style as c_int,
            msg: text_cstr.as_ptr(),
        };

        let mut message_ptrs = [&mut message as *mut PamMessage];
        let mut response_ptr: *mut PamResponse = ptr::null_mut();

        let status = PamReturnCode::from(conv_fn(
            message_ptrs.len() as c_int,
            message_ptrs.as_mut_ptr(),
            &mut response_ptr,
            conv_struct.data_ptr,
        ));

        if status != PamReturnCode::SUCCESS {
            return Err(status);
        }

        if !response_ptr.is_null() {
            let response = *response_ptr;
            if !response.resp.is_null() {
                libc::free(response.resp as *mut c_void);
            }
            libc::free(response_ptr as *mut c_void);
        }

        Ok(())
    }

    unsafe fn info(&self, text: &str) -> PamResult<()> {
        self.send_message(PamMessageStyle::TEXT_INFO, text)
    }

    unsafe fn error(&self, text: &str) -> PamResult<()> {
        self.send_message(PamMessageStyle::ERROR_MSG, text)
    }
}

/// Get username from PAM handle
unsafe fn get_username(pamh: *mut pam_sys::PamHandle) -> PamResult<String> {
    extern "C" {
        fn pam_get_user(
            pamh: *const pam_sys::PamHandle,
            user: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
    }

    let mut user_ptr: *const c_char = ptr::null();
    let ret = pam_get_user(pamh, &mut user_ptr, ptr::null());
    let status = PamReturnCode::from(ret);

    if status != PamReturnCode::SUCCESS {
        return Err(status);
    }

    if user_ptr.is_null() {
        return Err(PamReturnCode::USER_UNKNOWN);
    }

    let username = CStr::from_ptr(user_ptr)
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| PamReturnCode::USER_UNKNOWN)?;

    Ok(username)
}

unsafe fn prompt_for_pin(io: &PamIo) -> PamResult<u32> {
    let pin_text = io.prompt_hidden("PIN: ")?;

    if pin_text.is_empty() {
        io.error("PIN cannot be empty.")?;
        return Err(PamReturnCode::AUTH_ERR);
    }

    match pin_text.parse::<u32>() {
        Ok(pin) => Ok(pin),
        Err(_) => {
            io.error("PIN must contain only digits.")?;
            Err(PamReturnCode::AUTH_ERR)
        }
    }
}

/// PAM authentication function
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    suppress_tss_logs();
    let pam_io = match PamIo::new(pamh) {
        Ok(io) => io,
        Err(code) => {
            error!("Failed to obtain PAM conversation: {:?}", code);
            return code as c_int;
        }
    };

    let username = match get_username(pamh) {
        Ok(user) => user,
        Err(code) => {
            error!("Failed to get username from PAM: {:?}", code);
            let _ = pam_io.error("Authentication failure.");
            return code as c_int;
        }
    };

    debug!("Authenticating user: {}", username);

    let uid = match get_uid_from_username(&username) {
        Some(uid) => uid,
        None => {
            warn!("User {} not found", username);
            let _ = pam_io.error("Authentication failure.");
            return PamReturnCode::USER_UNKNOWN as c_int;
        }
    };

    let policy = load_pin_policy();
    let mut manager = match PinManager::new(policy) {
        Ok(mgr) => mgr,
        Err(e) => {
            error!(
                "Failed to initialize TPM PIN manager for user {}: {} (TPM may be unavailable or not configured)",
                username, e
            );
            let _ = pam_io.error("PIN authentication is currently unavailable.");
            return PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
    };

    match manager.get_pin_slot(uid) {
        Ok(Some(_)) => {}
        Ok(None) | Err(PinError::NotProvisioned(_)) => {
            info!("No PIN set for user {} (uid: {})", username, uid);
            let _ = pam_io.info("PIN authentication is not configured for this account.");
            return PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
        Err(err) => {
            error!(
                "Failed to read PIN slot for user {} (uid: {}): {} (TPM communication or data access error)",
                username, uid, err
            );
            let _ = pam_io.error("PIN authentication is currently unavailable.");
            return PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
    }

    match manager.is_locked_out(uid) {
        Ok(true) => {
            warn!("User {} (uid: {}) is locked out due to previous failed attempts", username, uid);
            if let Err(code) = pam_io.error("Account locked due to too many PIN failures.") {
                return code as c_int;
            }
            return PamReturnCode::MAXTRIES as c_int;
        }
        Ok(false) => {}
        Err(PinError::NotProvisioned(_)) => {
            info!("No PIN set for user {} (uid: {}) during lockout check", username, uid);
            let _ = pam_io.info("PIN authentication is not configured for this account.");
            return PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
        Err(err) => {
            error!(
                "Failed to check lockout status for user {} (uid: {}): {} (TPM communication or data access error)",
                username, uid, err
            );
            let _ = pam_io.error("PIN authentication is currently unavailable.");
            return PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
    }

    let pin = match prompt_for_pin(&pam_io) {
        Ok(pin) => pin,
        Err(code) => return code as c_int,
    };

    match manager.verify_pin(uid, pin) {
        Ok(VerificationResult::Success(_)) => {
            info!("PIN authentication successful for user: {}", username);
            PamReturnCode::SUCCESS as c_int
        }
        Ok(VerificationResult::Invalid) => {
            warn!("PIN authentication failed for user: {}", username);
            if let Err(code) = pam_io.error("Authentication failure.") {
                return code as c_int;
            }
            PamReturnCode::AUTH_ERR as c_int
        }
        Ok(VerificationResult::LockedOut) => {
            warn!("User {} is now locked out after failed attempt", username);
            if let Err(code) = pam_io.error("Account locked due to too many PIN failures.") {
                return code as c_int;
            }
            PamReturnCode::MAXTRIES as c_int
        }
        Err(PinError::NotProvisioned(_)) => {
            info!("No PIN set for user {} (uid: {}) during verification", username, uid);
            if let Err(code) = pam_io.info("PIN authentication is not configured for this account.")
            {
                return code as c_int;
            }
            PamReturnCode::AUTHINFO_UNAVAIL as c_int
        }
        Err(PinError::LockedOut(_)) => {
            warn!("User {} (uid: {}) attempted to authenticate while locked out", username, uid);
            if let Err(code) = pam_io.error("Account locked due to too many PIN failures.") {
                return code as c_int;
            }
            PamReturnCode::MAXTRIES as c_int
        }
        Err(PinError::PinTooShort(_, min)) => {
            warn!("PIN entered too short for user {}", username);
            if let Err(code) = pam_io.error(&format!("PIN must be at least {} digits.", min)) {
                return code as c_int;
            }
            PamReturnCode::AUTH_ERR as c_int
        }
        Err(PinError::PinTooLong(_, max)) => {
            warn!("PIN entered too long for user {}", username);
            if let Err(code) = pam_io.error(&format!("PIN must be at most {} digits.", max)) {
                return code as c_int;
            }
            PamReturnCode::AUTH_ERR as c_int
        }
        Err(PinError::PinInvalidCharacter) => {
            warn!("PIN contained invalid characters for user {}", username);
            if let Err(code) = pam_io.error("PIN must contain only digits.") {
                return code as c_int;
            }
            PamReturnCode::AUTH_ERR as c_int
        }
        Err(PinError::PermissionDenied(_)) => {
            error!(
                "Permission denied while verifying PIN for user {} (uid: {}) - insufficient privileges to access TPM or PIN data",
                username, uid
            );
            if let Err(code) = pam_io.error("Authentication credentials are insufficient.") {
                return code as c_int;
            }
            PamReturnCode::CRED_INSUFFICIENT as c_int
        }
        Err(PinError::CorruptedRecord) => {
            error!(
                "Corrupted PIN record detected for user {} (uid: {}) - data integrity check failed, re-provisioning required",
                username, uid
            );
            if let Err(code) = pam_io.error("PIN authentication is currently unavailable.") {
                return code as c_int;
            }
            PamReturnCode::AUTHINFO_UNAVAIL as c_int
        }
        Err(PinError::UidMismatch(_)) | Err(PinError::AlreadyProvisioned(_)) => {
            error!(
                "Unexpected PIN state for user {} (uid: {}) - internal inconsistency detected, this should not occur during verification",
                username, uid
            );
            if let Err(code) = pam_io.error("PIN authentication is currently unavailable.") {
                return code as c_int;
            }
            PamReturnCode::AUTHINFO_UNAVAIL as c_int
        }
        Err(PinError::TpmError(e)) => {
            error!(
                "TPM error while verifying PIN for user {} (uid: {}): {} (TPM device error or communication failure)",
                username, uid, e
            );
            if let Err(code) = pam_io.error("PIN authentication is currently unavailable.") {
                return code as c_int;
            }
            PamReturnCode::AUTHINFO_UNAVAIL as c_int
        }
    }
}

/// PAM account management function
#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    // For PIN authentication, we typically just return success
    // Account management is handled by other PAM modules
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM session management function
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    // No special session handling needed for PIN authentication
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM session cleanup function
#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    // No special session cleanup needed
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM password change function
#[no_mangle]
pub unsafe extern "C" fn pam_sm_chauthtok(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    // PIN changes are handled by the pinutil utility
    // This PAM module doesn't support PIN changes directly
    pam_sys::PamReturnCode::AUTH_ERR as c_int
}

// PAM set credentials function
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    // No special credential setting needed for PIN authentication
    pam_sys::PamReturnCode::SUCCESS as c_int 
}