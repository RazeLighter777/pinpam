//! TPM PIN Authentication PAM Module
//!
//! This library provides a PAM module for TPM-backed PIN authentication.

use log::{debug, error, info, warn};
use pam_sys;
use pinpam_core::{PinPolicy, PinManager, VerificationResult, get_uid_from_username};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// Load PIN policy from configuration
fn load_pin_policy() -> PinPolicy {
    // TODO: Load from /etc/pinpam/policy or similar
    PinPolicy::default()
}

/// Get username from PAM handle
unsafe fn get_username(pamh: *mut pam_sys::PamHandle) -> Option<String> {
    // Using raw PAM C API since pam_sys doesn't expose wrapped versions we need
    extern "C" {
        fn pam_get_user(
            pamh: *const pam_sys::PamHandle,
            user: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
    }
    
    let mut user_ptr: *const c_char = std::ptr::null();
    let ret = pam_get_user(pamh, &mut user_ptr, std::ptr::null());
    
    if ret == pam_sys::PamReturnCode::SUCCESS as c_int && !user_ptr.is_null() {
        CStr::from_ptr(user_ptr)
            .to_str()
            .ok()
            .map(|s| s.to_string())
    } else {
        None
    }
}

/// Get PIN from user via PAM conversation
unsafe fn get_pin_from_user(_pamh: *mut pam_sys::PamHandle) -> Option<u32> {
    // TODO: Implement proper PAM conversation
    // For now, use environment variable for testing
    std::env::var("PIN").ok()?.parse().ok()
}

/// PAM authentication function
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // Get username
    let username = match get_username(pamh) {
        Some(user) => user,
        None => {
            error!("Failed to get username from PAM");
            return pam_sys::PamReturnCode::USER_UNKNOWN as c_int;
        }
    };

    debug!("Authenticating user: {}", username);

    // Get UID for username
    let uid = match get_uid_from_username(&username) {
        Some(uid) => uid,
        None => {
            error!("User {} not found", username);
            return pam_sys::PamReturnCode::USER_UNKNOWN as c_int;
        }
    };

    // Initialize TPM PIN manager
    let policy = load_pin_policy();
    let mut manager = match PinManager::new(policy) {
        Ok(mgr) => mgr,
        Err(e) => {
            error!("Failed to initialize TPM PIN manager: {}", e);
            return pam_sys::PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
    };

    // Check if PIN is provisioned BEFORE prompting for PIN
    if !manager.is_locked_out(uid).unwrap_or(false) {
        match manager.get_attempt_count(uid) {
            Ok(Some(_)) => {}
            Ok(None) => {
                info!("No PIN set for user {}", username);
                return pam_sys::PamReturnCode::AUTHINFO_UNAVAIL as c_int;
            }
            Err(pinpam_core::PinError::NotProvisioned(_)) => {
                info!("No PIN set for user {}", username);
                return pam_sys::PamReturnCode::AUTHINFO_UNAVAIL as c_int;
            }
            _ => {}
        }
    }

    // Check if user is locked out BEFORE prompting for PIN
    match manager.is_locked_out(uid) {
        Ok(true) => {
            warn!("User {} is locked out", username);
            return pam_sys::PamReturnCode::MAXTRIES as c_int;
        }
        Ok(false) => {}
        Err(pinpam_core::PinError::NotProvisioned(_)) => {
            info!("No PIN set for user {}", username);
            return pam_sys::PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
        Err(e) => {
            error!("Failed to check lockout status: {}", e);
            return pam_sys::PamReturnCode::AUTH_ERR as c_int;
        }
    }

    // Get PIN from user
    let pin = match get_pin_from_user(pamh) {
        Some(pin) => pin,
        None => {
            warn!("Failed to get PIN from user");
            return pam_sys::PamReturnCode::AUTH_ERR as c_int;
        }
    };

    // Verify PIN
    match manager.verify_pin(uid, pin) {
        Ok(VerificationResult::Success(_)) => {
            info!("PIN authentication successful for user: {}", username);
            pam_sys::PamReturnCode::SUCCESS as c_int
        }
        Ok(VerificationResult::Invalid) => {
            warn!("PIN authentication failed for user: {}", username);
            pam_sys::PamReturnCode::AUTH_ERR as c_int
        }
        Ok(VerificationResult::LockedOut) => {
            warn!("User {} is now locked out after failed attempt", username);
            pam_sys::PamReturnCode::MAXTRIES as c_int
        }
        Err(pinpam_core::PinError::NotProvisioned(_)) => {
            info!("No PIN set for user {}", username);
            pam_sys::PamReturnCode::AUTHINFO_UNAVAIL as c_int
        }
        Err(pinpam_core::PinError::LockedOut(_)) => {
            warn!("User {} is locked out", username);
            pam_sys::PamReturnCode::MAXTRIES as c_int
        }
        Err(e) => {
            error!("PIN verification error: {}", e);
            pam_sys::PamReturnCode::AUTH_ERR as c_int
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
    // PIN changes are handled by the pinutil utility
    // This PAM module doesn't support PIN changes directly
    pam_sys::PamReturnCode::AUTH_ERR as c_int
}
