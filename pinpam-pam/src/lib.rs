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
use pinpam_core::{
    pamlog::{init_syslog_logger, suppress_tss_logs},
    pin::Pin,
    pindata::AttemptInfo,
    pinerror::PinError,
    pinpolicy::PinPolicy,
    util::get_uid_from_username,
};
use std::{
    ffi::{CStr, CString},
    io::{self, Write},
    os::raw::{c_char, c_int},
    path::Path,
    process::{Command, Stdio},
    ptr,
};

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

fn pinutil_path() -> &'static Path {
    &PinPolicy::cached().pinutil_path
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

fn run_pinutil_test(username: &str, pin: &Pin) -> Result<PinutilTestOutcome, String> {
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

    if let Err(err) = writeln!(child_stdin, "{}", pin.as_str()) {
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

    let result = serde_json::from_str::<Result<(), PinError>>(&stdout)
        .map_err(|_| "pinutil output isn't valid JSON or is malformed")?;
    Ok(PinutilTestOutcome::from(result))
}

fn init_logging() {
    init_syslog_logger("pinpam");
}

/// Standard PAM module arguments parsed off the module's `argv`.
///
/// Only flags that affect this module's behaviour are recorded here; unknown
/// arguments are ignored to match the `pam_unix(8)` convention.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ModuleArgs {
    /// Try the previously-stacked module's password before prompting.
    pub try_first_pass: bool,
    /// Use the previously-stacked module's password exclusively; never prompt.
    pub use_first_pass: bool,
}

impl ModuleArgs {
    /// Parse module arguments from already-borrowed Rust strings.
    pub fn from_strs<'a, I>(args: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut out = Self::default();
        for arg in args {
            match arg {
                "try_first_pass" => out.try_first_pass = true,
                "use_first_pass" => out.use_first_pass = true,
                _ => {}
            }
        }
        out
    }

    /// True if either first-pass mode is requested.
    pub fn wants_first_pass(self) -> bool {
        self.try_first_pass || self.use_first_pass
    }
}

/// Decision about how to obtain the PIN before verifying it.
pub enum FirstPassDecision {
    /// Verify this PIN that came from a previously-stacked module.
    TryFirstPass(Pin),
    /// Prompt the user interactively for their PIN.
    PromptUser,
    /// Refuse without prompting: `use_first_pass` was set and no usable PIN
    /// was available on the PAM stack.
    Deny,
}

impl FirstPassDecision {
    /// True iff the decision is to verify a PIN supplied by a stacked module.
    pub fn is_try_first_pass(&self) -> bool {
        matches!(self, FirstPassDecision::TryFirstPass(_))
    }

    /// True iff the decision is to prompt the user interactively.
    pub fn is_prompt_user(&self) -> bool {
        matches!(self, FirstPassDecision::PromptUser)
    }

    /// True iff the decision is to deny without prompting.
    pub fn is_deny(&self) -> bool {
        matches!(self, FirstPassDecision::Deny)
    }

    /// Borrow the embedded PIN, if any. Useful for tests that want to assert
    /// on the value being forwarded.
    pub fn pin(&self) -> Option<&Pin> {
        match self {
            FirstPassDecision::TryFirstPass(pin) => Some(pin),
            _ => None,
        }
    }
}

/// Pure decision function: given parsed module args, the authtok that PAM
/// handed us, and the active PIN policy, decide how to source the PIN.
///
/// This is intentionally side-effect-free so it can be exhaustively tested.
pub fn decide_first_pass(
    args: ModuleArgs,
    authtok: Option<&str>,
    policy: &PinPolicy,
) -> FirstPassDecision {
    if !args.wants_first_pass() {
        return FirstPassDecision::PromptUser;
    }
    let candidate = authtok.and_then(|t| Pin::new(t, policy).ok());
    match (candidate, args.use_first_pass) {
        (Some(pin), _) => FirstPassDecision::TryFirstPass(pin),
        (None, true) => FirstPassDecision::Deny,
        (None, false) => FirstPassDecision::PromptUser,
    }
}

/// Convert a raw `argc`/`argv` pair from libpam into owned Rust strings.
///
/// Non-UTF-8 arguments are silently skipped — they cannot match either of the
/// flags we care about anyway.
///
/// # Safety
/// `argv` must point to `argc` valid, NUL-terminated C strings owned by libpam
/// for the duration of the call. The pointers may be null and are checked.
unsafe fn argv_to_strings(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    if argv.is_null() || argc <= 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(argc as usize);
    for i in 0..argc as usize {
        let ptr = unsafe { *argv.add(i) };
        if ptr.is_null() {
            continue;
        }
        let cstr = unsafe { CStr::from_ptr(ptr) };
        if let Ok(s) = cstr.to_str() {
            out.push(s.to_owned());
        }
    }
    out
}

/// Read `PAM_AUTHTOK` from the PAM handle, returning `Ok(None)` if no
/// previously-stacked module has cached one.
fn get_pam_authtok(pamh: *mut pam_sys::PamHandle) -> PamResult<Option<String>> {
    let mut item_ptr: *const c_void = ptr::null();
    // SAFETY: PAM contract: `pamh` is valid for the call; `item_ptr` is a
    // local out-parameter that PAM populates.
    let status = PamReturnCode::from(unsafe {
        raw::pam_get_item(pamh, PamItemType::AUTHTOK as c_int, &mut item_ptr)
    });
    if status != PamReturnCode::SUCCESS {
        return Err(status);
    }
    if item_ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: PAM returned a non-null pointer to a NUL-terminated string owned
    // by the PAM stack; copy it into an owned `String` so the borrow does not
    // outlive this call.
    let cstr = unsafe { CStr::from_ptr(item_ptr as *const c_char) };
    match cstr.to_str() {
        Ok(s) => Ok(Some(s.to_owned())),
        Err(_) => Ok(None),
    }
}

/// Safe wrapper around the PAM conversation function pointer.
///
/// The invariant that `conv` is non-null and points to a live `PamConversation`
/// owned by the PAM stack is established by [`PamIo::new`] (the only `unsafe`
/// constructor) and relied on by the safe methods below.
struct PamIo {
    conv: *const PamConversation,
}

impl PamIo {
    fn new(pamh: *mut pam_sys::PamHandle) -> PamResult<Self> {
        let mut item_ptr: *const c_void = ptr::null();
        // SAFETY: PAM contract: `pamh` is valid for the call; `item_ptr` is a
        // local out-parameter that PAM populates.
        let status = PamReturnCode::from(unsafe {
            raw::pam_get_item(pamh, PamItemType::CONV as c_int, &mut item_ptr)
        });

        if status != PamReturnCode::SUCCESS {
            return Err(status);
        }
        if item_ptr.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }
        Ok(Self {
            conv: item_ptr as *const PamConversation,
        })
    }

    /// Dispatch a single PAM message through the conversation function and
    /// return the response pointer for the caller to consume.
    fn converse(
        &self,
        style: PamMessageStyle,
        text: &str,
    ) -> PamResult<*mut PamResponse> {
        // SAFETY: `self.conv` is non-null and stable for the lifetime of `self`
        // (established in `PamIo::new`).
        let conv_struct = unsafe { &*self.conv };
        let conv_fn = conv_struct.conv.ok_or(PamReturnCode::CONV_ERR)?;
        let text_cstr = CString::new(text).map_err(|_| PamReturnCode::SYSTEM_ERR)?;

        let mut message = PamMessage {
            msg_style: style as c_int,
            msg: text_cstr.as_ptr(),
        };
        let mut message_ptrs = [&mut message as *mut PamMessage];
        let mut response_ptr: *mut PamResponse = ptr::null_mut();

        // `conv_fn` is `extern "C" fn` (not `unsafe extern "C" fn`), so the
        // call itself is safe. Its raw-pointer arguments are owned by us and
        // remain valid for the duration of the call.
        let status = PamReturnCode::from(conv_fn(
            message_ptrs.len() as c_int,
            message_ptrs.as_mut_ptr(),
            &mut response_ptr,
            conv_struct.data_ptr,
        ));

        if status != PamReturnCode::SUCCESS {
            return Err(status);
        }
        Ok(response_ptr)
    }

    fn prompt_hidden(&self, prompt: &str) -> PamResult<String> {
        let response_ptr = self.converse(PamMessageStyle::PROMPT_ECHO_OFF, prompt)?;
        if response_ptr.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }

        // SAFETY: PAM successfully filled `response_ptr` with a heap-allocated
        // `PamResponse`; we own it and must free it before returning.
        let response = unsafe { *response_ptr };

        let result = if response.resp.is_null() {
            Err(PamReturnCode::CONV_ERR)
        } else {
            // SAFETY: `response.resp` is non-null and points to a
            // NUL-terminated C string allocated by the conversation function.
            let cstr = unsafe { CStr::from_ptr(response.resp) };
            cstr.to_str()
                .map(|s| s.trim().to_owned())
                .map_err(|_| PamReturnCode::AUTH_ERR)
        };

        // SAFETY: The PAM ABI requires the caller to libc::free the response
        // payload and the array itself.
        unsafe {
            if !response.resp.is_null() {
                libc::free(response.resp as *mut c_void);
            }
            libc::free(response_ptr as *mut c_void);
        }

        result
    }

    fn send_message(&self, style: PamMessageStyle, text: &str) -> PamResult<()> {
        let response_ptr = self.converse(style, text)?;
        if response_ptr.is_null() {
            return Ok(());
        }

        // SAFETY: `response_ptr` is non-null; PAM owns the contents and we
        // must libc::free both the inner string and the response struct.
        unsafe {
            let response = *response_ptr;
            if !response.resp.is_null() {
                libc::free(response.resp as *mut c_void);
            }
            libc::free(response_ptr as *mut c_void);
        }

        Ok(())
    }

    fn info(&self, text: &str) -> PamResult<()> {
        self.send_message(PamMessageStyle::TEXT_INFO, text)
    }

    fn error(&self, text: &str) -> PamResult<()> {
        self.send_message(PamMessageStyle::ERROR_MSG, text)
    }
}

fn get_username(pamh: *mut pam_sys::PamHandle) -> PamResult<String> {
    extern "C" {
        fn pam_get_user(
            pamh: *const pam_sys::PamHandle,
            user: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
    }

    let mut user_ptr: *const c_char = ptr::null();
    // SAFETY: PAM contract: `pamh` is valid for the call; `user_ptr` is a
    // local out-parameter that PAM populates with a pointer it owns.
    let status = PamReturnCode::from(unsafe { pam_get_user(pamh, &mut user_ptr, ptr::null()) });

    if status != PamReturnCode::SUCCESS {
        return Err(status);
    }
    if user_ptr.is_null() {
        return Err(PamReturnCode::USER_UNKNOWN);
    }

    // SAFETY: PAM returned a non-null pointer to a NUL-terminated string owned
    // by the PAM stack; we copy it into an owned `String` here so the borrow
    // does not outlive the call.
    let cstr = unsafe { CStr::from_ptr(user_ptr) };
    cstr.to_str()
        .map(str::to_owned)
        .map_err(|_| PamReturnCode::USER_UNKNOWN)
}

fn prompt_for_pin(io: &PamIo, used: u32, limit: u32) -> PamResult<Pin> {
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

    match Pin::new(&pin_text, PinPolicy::cached()) {
        Ok(pin) => Ok(pin),
        Err(PinError::PinIsEmpty) => {
            io.error(&t!("pin_empty"))?;
            Err(PamReturnCode::AUTH_ERR)
        }
        Err(_) => {
            io.error(&t!("pin_digits"))?;
            Err(PamReturnCode::AUTH_ERR)
        }
    }
}

/// PAM authentication entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI. `pamh` must be a valid
/// `pam_handle_t` and `argv` must point to `argc` valid C strings.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    init_logging();
    suppress_tss_logs();
    rust_i18n::set_locale(locale_config::Locale::current().as_ref());

    // SAFETY: `argv` must be a valid pointer to `argc` C strings, per the PAM
    // ABI contract documented on this function.
    let raw_args = unsafe { argv_to_strings(argc, argv) };
    let args = ModuleArgs::from_strs(raw_args.iter().map(String::as_str));

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

    let authtok = if args.wants_first_pass() {
        match get_pam_authtok(pamh) {
            Ok(value) => value,
            Err(code) => {
                error!("Failed to read PAM_AUTHTOK: {:?}", code);
                return code as c_int;
            }
        }
    } else {
        None
    };

    authenticate_user(&pam_io, &username, args, authtok.as_deref()) as c_int
}

/// Safe implementation of the authentication flow. All FFI has already been
/// resolved into owned Rust values by the entry point.
fn authenticate_user(
    pam_io: &PamIo,
    username: &str,
    args: ModuleArgs,
    authtok: Option<&str>,
) -> PamReturnCode {
    debug!(
        "Authenticating user: {} (try_first_pass={}, use_first_pass={})",
        username, args.try_first_pass, args.use_first_pass
    );

    let uid = match get_uid_from_username(username) {
        Ok(uid) => uid,
        Err(_) => {
            warn!("User {} not found", username);
            let _ = pam_io.error(&t!("auth_failure"));
            return PamReturnCode::USER_UNKNOWN;
        }
    };

    let (mut used, limit) = match run_pinutil_status(username) {
        PinStatus::Unavailable(err) => {
            error!(
                "Failed to query PIN status for user {} (uid: {}): {}",
                username, uid, err
            );
            let _ = pam_io.error(&t!("pin_auth_unavail"));
            return PamReturnCode::AUTHINFO_UNAVAIL;
        }
        PinStatus::NotProvisioned => {
            info!("No PIN set for user {} (uid: {})", username, uid);
            let _ = pam_io.info(&t!("pin_not_conf_for_user"));
            return PamReturnCode::AUTHINFO_UNAVAIL;
        }
        PinStatus::LockedOut => {
            warn!(
                "User {} (uid: {}) is locked out due to previous failed attempts",
                username, uid
            );
            let _ = pam_io.error(&t!("account_locked"));
            return PamReturnCode::MAXTRIES;
        }
        PinStatus::Available { used, limit } => (used, limit),
    };

    // Phase 1: try the previously-stacked module's password, if any.
    let policy = PinPolicy::cached();
    match decide_first_pass(args, authtok, policy) {
        FirstPassDecision::Deny => {
            warn!(
                "use_first_pass set but no usable PIN available on the PAM stack for user {}",
                username
            );
            let _ = pam_io.error(&t!("auth_failure"));
            return PamReturnCode::AUTH_ERR;
        }
        FirstPassDecision::TryFirstPass(pin) => {
            let outcome = match run_pinutil_test(username, &pin) {
                Ok(outcome) => outcome,
                Err(err) => {
                    error!(
                        "Failed to verify first-pass PIN via helper for user {} (uid: {}): {}",
                        username, uid, err
                    );
                    let _ = pam_io.error(&t!("pin_auth_unavail"));
                    return PamReturnCode::AUTHINFO_UNAVAIL;
                }
            };
            match outcome {
                PinutilTestOutcome::Success => {
                    info!(
                        "PIN authentication successful for user {} via first-pass",
                        username
                    );
                    return PamReturnCode::SUCCESS;
                }
                _ if args.use_first_pass => {
                    return finalize_outcome(pam_io, outcome, username, uid);
                }
                // try_first_pass: fall through to prompting. The attempt we
                // just made consumed one slot — bump `used` so the prompt
                // warns appropriately.
                PinutilTestOutcome::InvalidPin => {
                    info!(
                        "First-pass PIN rejected for user {}; prompting interactively",
                        username
                    );
                    used = used.saturating_add(1);
                }
                PinutilTestOutcome::NewlyLockedOut | PinutilTestOutcome::LockedOut => {
                    return finalize_outcome(pam_io, outcome, username, uid);
                }
                PinutilTestOutcome::NotConfigured | PinutilTestOutcome::Unavailable => {
                    return finalize_outcome(pam_io, outcome, username, uid);
                }
            }
        }
        FirstPassDecision::PromptUser => {}
    }

    // Refresh after a consumed attempt so we don't over-prompt past the limit.
    if used >= limit {
        warn!(
            "User {} (uid: {}) ran out of attempts after first-pass",
            username, uid
        );
        let _ = pam_io.error(&t!("account_locked"));
        return PamReturnCode::MAXTRIES;
    }

    let pin = match prompt_for_pin(pam_io, used, limit) {
        Ok(pin) => pin,
        Err(code) => return code,
    };

    let outcome = match run_pinutil_test(username, &pin) {
        Ok(outcome) => outcome,
        Err(err) => {
            error!(
                "Failed to verify PIN via helper for user {} (uid: {}): {}",
                username, uid, err
            );
            let _ = pam_io.error(&t!("pin_auth_unavail"));
            return PamReturnCode::AUTHINFO_UNAVAIL;
        }
    };

    finalize_outcome(pam_io, outcome, username, uid)
}

fn finalize_outcome(
    pam_io: &PamIo,
    outcome: PinutilTestOutcome,
    username: &str,
    uid: u32,
) -> PamReturnCode {
    match outcome {
        PinutilTestOutcome::Success => {
            info!("PIN authentication successful for user: {}", username);
            PamReturnCode::SUCCESS
        }
        PinutilTestOutcome::InvalidPin => {
            warn!("PIN authentication failed for user: {}", username);
            let _ = pam_io.error(&t!("auth_failure"));
            PamReturnCode::AUTH_ERR
        }
        PinutilTestOutcome::NewlyLockedOut | PinutilTestOutcome::LockedOut => {
            warn!("User {} (uid: {}) is locked out", username, uid);
            let _ = pam_io.error(&t!("account_locked"));
            PamReturnCode::MAXTRIES
        }
        PinutilTestOutcome::NotConfigured => {
            info!(
                "Helper reported no PIN set for user {} (uid: {}) during verification",
                username, uid
            );
            let _ = pam_io.info(&t!("pin_not_conf_for_user"));
            PamReturnCode::AUTHINFO_UNAVAIL
        }
        PinutilTestOutcome::Unavailable => {
            error!(
                "Helper reported TPM unavailable during verification for user {} (uid: {})",
                username, uid
            );
            let _ = pam_io.error(&t!("pin_auth_unavail"));
            PamReturnCode::AUTHINFO_UNAVAIL
        }
    }
}

/// PAM account management entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM session open entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM session close entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::SUCCESS as c_int
}

/// PAM password change entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
/// PIN changes are handled out-of-band by `pinutil`, so this module returns
/// `AUTH_ERR` to indicate it cannot service chauthtok.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_chauthtok(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::AUTH_ERR as c_int
}

/// PAM set-credentials entry point.
///
/// # Safety
/// Called by libpam through a `dlsym` C ABI; see [`pam_sm_authenticate`].
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_sys::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    init_logging();
    pam_sys::PamReturnCode::SUCCESS as c_int
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_policy() -> PinPolicy {
        PinPolicy {
            min_length: 4,
            max_length: Some(8),
            allow_alphanumeric: false,
            max_attempts: 5,
            pinutil_path: PathBuf::from("/usr/bin/true"),
            tcti: None,
        }
    }

    #[test]
    fn module_args_default_to_disabled() {
        let args = ModuleArgs::from_strs(std::iter::empty());
        assert!(!args.try_first_pass);
        assert!(!args.use_first_pass);
        assert!(!args.wants_first_pass());
    }

    #[test]
    fn module_args_parse_known_flags_and_ignore_others() {
        let args = ModuleArgs::from_strs(
            ["try_first_pass", "debug", "use_first_pass", "garbage"].into_iter(),
        );
        assert!(args.try_first_pass);
        assert!(args.use_first_pass);
        assert!(args.wants_first_pass());
    }

    #[test]
    fn module_args_unrelated_flags_alone_do_nothing() {
        let args = ModuleArgs::from_strs(["expose_authtok", "no_warn"].into_iter());
        assert!(!args.try_first_pass);
        assert!(!args.use_first_pass);
    }

    #[test]
    fn no_first_pass_flag_always_prompts() {
        let policy = test_policy();
        let args = ModuleArgs::default();
        // Even with a perfectly good authtok present, no flag means we prompt.
        assert!(decide_first_pass(args, Some("1234"), &policy).is_prompt_user());
        assert!(decide_first_pass(args, None, &policy).is_prompt_user());
    }

    #[test]
    fn try_first_pass_uses_valid_pin() {
        let policy = test_policy();
        let args = ModuleArgs {
            try_first_pass: true,
            use_first_pass: false,
        };
        let decision = decide_first_pass(args, Some("4321"), &policy);
        assert!(decision.is_try_first_pass());
        assert_eq!(decision.pin().unwrap().as_str(), "4321");
    }

    #[test]
    fn try_first_pass_prompts_when_token_is_not_a_pin() {
        let policy = test_policy();
        let args = ModuleArgs {
            try_first_pass: true,
            use_first_pass: false,
        };
        // Letters: not a digit-only PIN; should fall through to prompting
        // without consuming a TPM attempt.
        assert!(decide_first_pass(args, Some("hunter2"), &policy).is_prompt_user());
        // Too short: also not a valid PIN under this policy.
        assert!(decide_first_pass(args, Some("12"), &policy).is_prompt_user());
        // Missing authtok entirely.
        assert!(decide_first_pass(args, None, &policy).is_prompt_user());
    }

    #[test]
    fn use_first_pass_denies_when_token_is_not_a_pin() {
        let policy = test_policy();
        let args = ModuleArgs {
            try_first_pass: false,
            use_first_pass: true,
        };
        assert!(decide_first_pass(args, Some("hunter2"), &policy).is_deny());
        assert!(decide_first_pass(args, Some(""), &policy).is_deny());
        assert!(decide_first_pass(args, None, &policy).is_deny());
    }

    #[test]
    fn use_first_pass_uses_valid_pin() {
        let policy = test_policy();
        let args = ModuleArgs {
            try_first_pass: false,
            use_first_pass: true,
        };
        let decision = decide_first_pass(args, Some("4242"), &policy);
        assert!(decision.is_try_first_pass());
        assert_eq!(decision.pin().unwrap().as_str(), "4242");
    }

    #[test]
    fn use_first_pass_overrides_try_first_pass_on_bad_token() {
        let policy = test_policy();
        // When both flags are set and the token is not usable, the stricter
        // use_first_pass wins and we deny rather than prompt.
        let args = ModuleArgs {
            try_first_pass: true,
            use_first_pass: true,
        };
        assert!(decide_first_pass(args, Some("not-a-pin"), &policy).is_deny());
    }

    #[test]
    fn first_pass_respects_policy_bounds() {
        let policy = PinPolicy {
            min_length: 6,
            max_length: Some(6),
            ..test_policy()
        };
        let args = ModuleArgs {
            try_first_pass: true,
            use_first_pass: false,
        };
        // Wrong length for this policy: token isn't a valid PIN here.
        assert!(decide_first_pass(args, Some("1234"), &policy).is_prompt_user());
        // Right length: valid.
        assert!(decide_first_pass(args, Some("123456"), &policy).is_try_first_pass());
    }
}
