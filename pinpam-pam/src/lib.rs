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
use pinpam_core::{AttemptInfo, PinError, PinPolicy};
use std::{
    env,
    ffi::{CStr, CString},
    io::{self, Write},
    os::raw::{c_char, c_int},
    path::Path,
    process::{self, Command, Stdio},
    ptr,
    sync::OnceLock,
};
use syslog::{BasicLogger, Facility, Formatter3164};

#[macro_use]
extern crate rust_i18n;
i18n!("locales", fallback = "en");

type PamResult<T> = std::result::Result<T, PamReturnCode>;

#[derive(Debug)]
enum PinStatus {
    Unavailable(PinError),
    LockedOut,
    NotProvisioned,
    Available { used: u32, limit: u32 },
}

impl From<Result<Option<AttemptInfo>, PinError>> for PinStatus {
    fn from(value: Result<Option<AttemptInfo>, PinError>) -> Self {
        match value {
            Err(PinError::PinIsLocked) => PinStatus::LockedOut,
            Err(e) => PinStatus::Unavailable(e),
            Ok(None) => PinStatus::NotProvisioned,
            Ok(Some(info)) => {
                if info.locked() {
                    PinStatus::LockedOut
                } else {
                    PinStatus::Available {
                        used: info.used,
                        limit: info.limit,
                    }
                }
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinutilTestOutcome {
    Success,
    InvalidPin,
    LockedOut,
    NewlyLockedOut,
    NotConfigured,
    Unavailable,
}

impl From<Result<(), PinError>> for PinutilTestOutcome {
    fn from(value: Result<(), PinError>) -> Self {
        let Err(e) = value else {
            return PinutilTestOutcome::Success;
        };
        match e {
            PinError::PinIsLocked => PinutilTestOutcome::LockedOut,
            PinError::IncorrectPin { locked: true } => PinutilTestOutcome::NewlyLockedOut,
            PinError::IncorrectPin { locked: false } => PinutilTestOutcome::InvalidPin,
            PinError::NotProvisioned(_) => PinutilTestOutcome::NotConfigured,
            _ => PinutilTestOutcome::Unavailable,
        }
    }
}

fn pin_policy() -> &'static PinPolicy {
    static POLICY: OnceLock<PinPolicy> = OnceLock::new();
    POLICY.get_or_init(PinPolicy::load_from_standard_locations)
}

fn pinutil_path() -> &'static Path {
    &pin_policy().pinutil_path
}

fn get_uid_from_username(username: &str) -> Option<u32> {
    let c_username = CString::new(username).ok()?;
    unsafe {
        let pwd = libc::getpwnam(c_username.as_ptr());
        if pwd.is_null() {
            None
        } else {
            Some((*pwd).pw_uid)
        }
    }
}

fn run_pinutil_status(username: &str) -> PinStatus {
    let pinutil = pinutil_path();
    let output = match Command::new(pinutil)
        .arg("-m")
        .arg("status")
        .arg(username)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            error!(
                "failed to execute pinutil status via {}: {}",
                pinutil.display(),
                e
            );
            return PinStatus::Unavailable(e.into());
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            "pinutil status exited with {}: {}",
            output.status,
            stderr.trim()
        );
        return PinStatus::Unavailable(PinError::IoError(format!(
            "output status: {}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!(
        "pinutil status output for {}: stdout='{}' stderr='{}'",
        username,
        stdout.trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    match serde_json::from_str::<Result<Option<AttemptInfo>, PinError>>(&stdout) {
        Ok(info) => PinStatus::from(info),
        Err(e) => {
            error!("pinutil output isn't valid JSON or is malformed: {e}");
            PinStatus::Unavailable(PinError::PinutilOutputDecodeError(e.to_string()))
        }
    }
}

fn run_pinutil_test(username: &str, pin: &str) -> Result<PinutilTestOutcome, String> {
    let pinutil = pinutil_path();
    let mut child = Command::new(pinutil)
        .arg("-m")
        .arg("test")
        .arg(username)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "failed to execute pinutil test via {}: {}",
                pinutil.display(),
                e
            )
        })?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to open stdin pipe to pinutil".to_string())?;

    if let Err(err) = writeln!(child_stdin, "{}", pin) {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return Err(format!("failed to send PIN to pinutil: {}", err));
        }
    }

    if let Err(err) = child_stdin.flush() {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return Err(format!("failed to flush PIN to pinutil: {}", err));
        }
    }
    drop(child_stdin);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to wait for pinutil test: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    debug!(
        "pinutil test output for {}: status={} stdout='{}' stderr='{}'",
        username,
        output.status,
        stdout.trim(),
        stderr.trim()
    );

    let result = serde_json::from_str::<Result<(), pinpam_core::PinError>>(&stdout)
        .map_err(|_| "pinutil output isn't valid JSON or is malformed")?;
    Ok(PinutilTestOutcome::from(result))
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

unsafe fn prompt_for_pin(io: &PamIo, used: u32, limit: u32) -> PamResult<String> {
    let prompt = match limit - used {
        // With at least 3 attempts remaining, just ask for the PIN with no extra warnings.
        3.. => t!("pin_prompt"),
        // With fewer than 3 attempts remaining, warn the user appropriately.
        2 => t!("pin_prompt_remaining", "remaining" => limit - used),
        1 => t!("pin_prompt_last"),
        // No more attempts remaining, bail.
        0 => return Err(PamReturnCode::AUTHINFO_UNAVAIL),
    };
    let pin_text = io.prompt_hidden(&prompt)?;

    if pin_text.is_empty() {
        io.error(&t!("pin_empty"))?;
        return Err(PamReturnCode::AUTH_ERR);
    }
    if pin_text.chars().all(|c| c.is_ascii_digit()) {
        Ok(pin_text)
    } else {
        io.error(&t!("pin_digits"))?;
        Err(PamReturnCode::AUTH_ERR)
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
    // Initialize locale for translations
    rust_i18n::set_locale(locale_config::Locale::current().as_ref());

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
            let _ = pam_io.error(&t!("auth_failure"));
            return code as c_int;
        }
    };

    debug!("Authenticating user: {}", username);

    let uid = match get_uid_from_username(&username) {
        Some(uid) => uid,
        None => {
            warn!("User {} not found", username);
            let _ = pam_io.error(&t!("auth_failure"));
            return PamReturnCode::USER_UNKNOWN as c_int;
        }
    };

    let (used, limit) = match run_pinutil_status(&username) {
        PinStatus::Unavailable(err) => {
            error!(
                "Failed to query PIN status for user {} (uid: {}): {}",
                username, uid, err
            );
            let _ = pam_io.error(&t!("pin_auth_unavail"));
            return PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
        PinStatus::NotProvisioned => {
            info!("No PIN set for user {} (uid: {})", username, uid);
            let _ = pam_io.info(&t!("pin_not_conf_for_user"));
            return PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
        PinStatus::LockedOut => {
            warn!(
                "User {} (uid: {}) is locked out due to previous failed attempts",
                username, uid
            );
            if let Err(code) = pam_io.error(&t!("account_locked")) {
                return code as c_int;
            }
            return PamReturnCode::MAXTRIES as c_int;
        }
        PinStatus::Available { used, limit } => (used, limit),
    };

    let pin = match prompt_for_pin(&pam_io, used, limit) {
        Ok(pin) => pin,
        Err(code) => return code as c_int,
    };

    let outcome = match run_pinutil_test(&username, &pin) {
        Ok(outcome) => outcome,
        Err(err) => {
            error!(
                "Failed to verify PIN via helper for user {} (uid: {}): {}",
                username, uid, err
            );
            if let Err(code) = pam_io.error(&t!("pin_auth_unavail")) {
                return code as c_int;
            }
            return PamReturnCode::AUTHINFO_UNAVAIL as c_int;
        }
    };

    match outcome {
        PinutilTestOutcome::Success => {
            info!("PIN authentication successful for user: {}", username);
            PamReturnCode::SUCCESS as c_int
        }
        PinutilTestOutcome::InvalidPin => {
            warn!("PIN authentication failed for user: {}", username);
            if let Err(code) = pam_io.error(&t!("auth_failure")) {
                return code as c_int;
            }
            PamReturnCode::AUTH_ERR as c_int
        }
        PinutilTestOutcome::NewlyLockedOut | PinutilTestOutcome::LockedOut => {
            warn!("User {} (uid: {}) is locked out", username, uid);
            if let Err(code) = pam_io.error(&t!("account_locked")) {
                return code as c_int;
            }
            PamReturnCode::MAXTRIES as c_int
        }
        PinutilTestOutcome::NotConfigured => {
            info!(
                "Helper reported no PIN set for user {} (uid: {}) during verification",
                username, uid
            );
            if let Err(code) = pam_io.info(&t!("pin_not_conf_for_user")) {
                return code as c_int;
            }
            PamReturnCode::AUTHINFO_UNAVAIL as c_int
        }
        PinutilTestOutcome::Unavailable => {
            error!(
                "Helper reported TPM unavailable during verification for user {} (uid: {})",
                username, uid
            );
            if let Err(code) = pam_io.error(&t!("pin_auth_unavail")) {
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
