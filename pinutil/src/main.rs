//! TPM PIN Utility - Command-line utility for managing TPM-backed PIN authentication.

use clap::{Parser, Subcommand};
use pinpam_core::{
    can_manage_pin, get_uid, get_uid_from_username, get_username_from_uid, DeleteResult, PinData,
    PinManager, PinPolicy, VerificationResult,
};
#[cfg(feature = "machine")]
use std::io::IsTerminal;
use std::io::{self, Write};

#[macro_use]
extern crate rust_i18n;
i18n!("locales", fallback = "en");

mod sandbox;

type Result<T> = ::core::result::Result<T, Error>;

#[derive(Parser)]
#[command(
    name = "pinutil",
    about = "TPM PIN authentication utility",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long)]
    verbose: bool,
    #[cfg(feature = "machine")]
    /// Forces machine-readable output in JSON format and disables displaying input prompts.
    /// If not provided, machine mode is automatically enabled if stdin is NOT a terminal.
    #[arg(short, long, default_value_t)]
    machine: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Set up a new PIN (root or user for self)
    Setup {
        /// Target username (defaults to the current user)
        #[arg(value_name = "USERNAME")]
        username: Option<String>,
    },
    /// Change PIN (requires current PIN, or root)
    Change {
        /// Target username (defaults to the current user)
        #[arg(value_name = "USERNAME")]
        username: Option<String>,
    },
    /// Delete PIN (requires PIN auth for non-root, root can delete any)
    Delete {
        /// Target username (defaults to the current user)
        #[arg(value_name = "USERNAME")]
        username: Option<String>,
    },
    /// Test PIN authentication
    Test {
        /// Target username (defaults to the current user)
        #[arg(value_name = "USERNAME")]
        username: Option<String>,
    },
    /// Show PIN status
    Status {
        /// Target username (defaults to the current user)
        #[arg(value_name = "USERNAME")]
        username: Option<String>,
    },
}

fn main() -> Result<()> {
    rust_i18n::set_locale(locale_config::Locale::current().as_ref());
    if let Err(e) = sandbox::pinutil_sandbox() {
        eprintln!("{}: {}", t!("sandbox_fail"), e);
    }
    let cli = Cli::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if cli.verbose { "debug" } else { "none" }),
    )
    .target(env_logger::Target::Stderr)
    .init();
    if !cli.verbose {
        unsafe {
            std::env::set_var("TSS2_LOG", "all+NONE");
        }
    }

    #[cfg(feature = "machine")]
    let machine = cli.machine || !std::io::stdin().is_terminal();
    #[cfg(not(feature = "machine"))]
    let machine = false;

    match cli.command {
        Commands::Setup { username } => {
            handle_result(setup_pin(&resolve_username(username)?, machine), machine)
        }
        Commands::Change { username } => {
            handle_result(change_pin(&resolve_username(username)?, machine), machine)
        }
        Commands::Delete { username } => {
            handle_result(delete_pin(&resolve_username(username)?, machine), machine)
        }
        Commands::Test { username } => {
            handle_result(test_pin(&resolve_username(username)?, machine), machine)
        }
        Commands::Status { username } => {
            handle_result(show_status(&resolve_username(username)?, machine), machine)
        }
    };
    Ok(())
}

#[cfg(feature = "machine")]
fn handle_result<T>(res: Result<T>, machine: bool)
where
    Result<T>: serde::Serialize,
{
    if !machine {
        // In human mode, stay quiet unless there's an error, which go to stderr.
        if let Err(e) = &res {
            eprintln!("{}", t!("error_result", "error" => e));
        }
    } else {
        // In machine mode, always output the result to stdout in JSON format.
        println!("{}", serde_json::to_string(&res).expect(&t!("ser_error")));
    }
    if res.is_err() {
        std::process::exit(1);
    }
}

#[cfg(not(feature = "machine"))]
fn handle_result<T>(res: Result<T>, _machine: bool) {
    if let Err(e) = &res {
        eprintln!("{}", t!("error_result", "error" => e));
    }
}

fn new_manager() -> Result<PinManager> {
    PinManager::new(PinPolicy::load_from_standard_locations()).map_err(Error::PinManagerNewError)
}

fn setup_pin(username: &str, machine: bool) -> Result<()> {
    let uid = get_uid_from_username(username).ok_or(Error::UserNotFound)?;

    if !can_manage_pin(uid) {
        return Err(Error::PermissionDenied);
    }

    let mut manager = new_manager()?;

    // Check if already provisioned - only error if it's NOT a NotProvisioned error
    match manager.get_attempt_count(uid) {
        Ok(None) => {
            // Good - no PIN set, we can proceed
        }
        Ok(Some(_)) => {
            return Err(Error::PinAlreadySet);
        }
        Err(pinpam_core::PinError::NotProvisioned(_)) => {
            // Good - no PIN set, we can proceed
        }
        Err(e) => {
            return Err(Error::CoreError(e));
        }
    }

    let pin = prompt_pin(&t!("enter_new_pin"), None, machine)?;
    // only prompt for confirmation when stdin is an interactive terminal
    if !machine {
        let confirm = prompt_pin(&t!("confirm_pin"), None, machine)?;
        if pin != confirm {
            return Err(Error::PinsDontMatch);
        }
    }

    manager.setup_pin(uid, pin).map_err(Error::PinSetupError)?;
    if !machine {
        println!("{}", t!("pin_set_for_user", "username" => username));
    }
    Ok(())
}

fn change_pin(username: &str, machine: bool) -> Result<()> {
    let uid = get_uid_from_username(username).ok_or(Error::UserNotFound)?;

    if !can_manage_pin(uid) {
        return Err(Error::PermissionDenied);
    }

    let mut manager = new_manager()?;
    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => return Err(Error::NoPinSet),
    };

    manager
        .restart_context()
        .map_err(Error::PinRestartContext)?;
    manager.clear_sessions();

    if get_uid() != 0 {
        if attempt_info.locked() {
            return Err(Error::PinIsLocked);
        }

        // User changing their own PIN - require current PIN
        let current = prompt_pin(&t!("pin"), Some(attempt_info.prompt_tuple()), machine)?;
        match manager
            .verify_pin(uid, current)
            .map_err(Error::PinVerifyFailed)?
        {
            VerificationResult::Success(_) => {}
            VerificationResult::Invalid => return Err(Error::IncorrectPin),
            VerificationResult::LockedOut => return Err(Error::PinIsLocked),
        }
        manager
            .restart_context()
            .map_err(Error::PinRestartContext)?;

        let new_pin = prompt_pin(&t!("new_pin"), None, machine)?;
        if !machine {
            let confirm = prompt_pin(&t!("confirm"), None, machine)?;
            if new_pin != confirm {
                return Err(Error::PinsDontMatch);
            }
        }

        match manager
            .delete_pin_with_auth(uid, current)
            .map_err(Error::PinDeleteFailed)?
        {
            DeleteResult::Success => {
                manager.clear_sessions();
                manager
                    .setup_pin(uid, new_pin)
                    .map_err(Error::PinSetupError)?;
                if !machine {
                    println!("{}", t!("pin_changed_for_user", "username" => username));
                }
            }
            result => return Err(Error::CannotDeletePin(result)),
        }
    } else {
        // Root changing PIN - no auth required
        let new_pin = prompt_pin(&t!("new_pin"), None, machine)?;
        if !machine {
            let confirm = prompt_pin(&t!("confirm"), None, machine)?;
            if new_pin != confirm {
                return Err(Error::PinsDontMatch);
            }
        }
        match manager.delete_pin_admin(uid) {
            Ok(_) => {}
            Err(pinpam_core::PinError::NotProvisioned(_)) => return Err(Error::NoPinSet),
            Err(e) => return Err(Error::PinDeleteFailed(e)),
        }
        manager.clear_sessions();
        manager
            .setup_pin(uid, new_pin)
            .map_err(Error::PinSetupError)?;
        if !machine {
            println!("{}", t!("pin_changed_for_user", "username" => username));
        }
    }
    Ok(())
}

fn delete_pin(username: &str, machine: bool) -> Result<()> {
    let uid = get_uid_from_username(username).ok_or(Error::UserNotFound)?;

    let current_uid = get_uid();
    let is_root = current_uid == 0;

    // Non-root users can only delete their own PIN
    if !is_root && current_uid != uid {
        return Err(Error::PermissionDenied);
    }

    let mut manager = new_manager()?;

    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => return Err(Error::NoPinSet),
    };

    if !is_root && attempt_info.locked() {
        return Err(Error::PinIsLocked);
    }

    if is_root {
        if !machine {
            // Root deletion - no PIN required, but confirm
            print!("Delete PIN for '{}'? (y/N): ", username);
            io::stdout().flush().map_err(Error::IoError)?;
            let mut input = String::new();
            io::stdin().read_line(&mut input).map_err(Error::IoError)?;

            if !input.trim().to_lowercase().starts_with('y') {
                println!("{}", t!("cancelled"));
                return Ok(());
            }
        }
        let result = manager.delete_pin_admin(uid);
        if !machine {
            match result {
                Ok(_) => println!("{}", t!("pin_deleted_for_user", "username" => username)),
                Err(e) => println!("{}", t!("pin_delete_failed", "error" => e)),
            }
            Ok(())
        } else {
            result.map_err(Error::PinDeleteFailed)
        }
    } else {
        // User deletion - requires PIN authentication
        let pin = prompt_pin("PIN", Some(attempt_info.prompt_tuple()), machine)?;
        let result = manager.delete_pin_with_auth(uid, pin);
        if !machine {
            match result {
                Ok(DeleteResult::Success) => {
                    println!("{}", t!("pin_deleted_for_user", "username" => username))
                }
                Ok(DeleteResult::Invalid) => println!("{}", t!("incorrect_pin")),
                Ok(DeleteResult::LockedOut) => println!("{}", t!("now_locked_out")),
                Err(e) => println!("{}", t!("pin_delete_failed", "error" => e)),
            }
            Ok(())
        } else {
            match result.map_err(Error::PinDeleteFailed)? {
                DeleteResult::Success => Ok(()),
                DeleteResult::Invalid => Err(Error::IncorrectPin),
                DeleteResult::LockedOut => Err(Error::PinIsLocked),
            }
        }
    }
}

fn test_pin(username: &str, machine: bool) -> Result<()> {
    let uid = get_uid_from_username(username).ok_or(Error::UserNotFound)?;

    let mut manager = new_manager()?;

    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => {
            if !machine {
                println!("{}", t!("no_pin_set_for_user"));
            }
            return Err(Error::NoPinSet);
        }
    };

    if attempt_info.locked() {
        if !machine {
            println!("{}", t!("user_is_locked_out"));
        }
        return Err(Error::PinIsLocked);
    }

    let pin = prompt_pin("PIN", Some(attempt_info.prompt_tuple()), machine)?;
    let result = manager
        .verify_pin(uid, pin)
        .map_err(Error::PinVerifyFailed)?;
    if !machine {
        match result {
            VerificationResult::Success(_) => {
                println!("{}", t!("pin_correct"));
            }
            VerificationResult::Invalid => {
                println!("{}", t!("pin_incorrect"));
            }
            VerificationResult::LockedOut => {
                println!("{}", t!("now_locked_out"));
            }
        }
        Ok(())
    } else {
        match result {
            VerificationResult::Success(_) => Ok(()),
            VerificationResult::Invalid => Err(Error::IncorrectPin),
            VerificationResult::LockedOut => Err(Error::PinIsLocked),
        }
    }
}

fn show_status(username: &str, machine: bool) -> Result<Option<AttemptInfo>> {
    let uid = get_uid_from_username(username).ok_or(Error::UserNotFound)?;

    let mut manager = new_manager()?;

    if !machine {
        println!(
            "{}",
            t!("status_for_user", "username" => username, "uid" => uid)
        );
    }
    let info = get_attempt_info(&mut manager, uid)?;
    if !machine {
        match &info {
            Some(info) => {
                println!("  {}", t!("pin_provisioned_yes"));
                let remaining = info.limit - info.used;
                println!(
                    "  {}",
                    t!("remaining_attempts", "remaining" => remaining, "limit" => info.limit),
                );
                println!(
                    "  {}",
                    t!("locked_out", "locked" => if info.locked() { t!("yes") } else { t!("no") }),
                );
            }
            None => {
                println!("  {}", t!("pin_provisioned_no"));
            }
        }
    }
    Ok(info)
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "machine", derive(serde::Serialize))]
struct AttemptInfo {
    used: u32,
    limit: u32,
}

impl AttemptInfo {
    fn from_pin_data(slot: PinData) -> Self {
        let used = if slot.pinCount < 0 {
            0
        } else {
            slot.pinCount as u32
        };
        let limit = if slot.pinLimit <= 0 {
            0
        } else {
            slot.pinLimit as u32
        };
        Self { used, limit }
    }

    fn locked(&self) -> bool {
        self.limit > 0 && self.used >= self.limit
    }

    fn prompt_tuple(&self) -> (u32, u32) {
        (self.used, self.limit)
    }
}

fn get_attempt_info(manager: &mut PinManager, uid: u32) -> Result<Option<AttemptInfo>> {
    Ok(manager
        .get_pin_slot(uid)
        .map_err(Error::GetPinSlotFailed)?
        .map(AttemptInfo::from_pin_data))
}

fn prompt_pin(prompt: &str, attempts: Option<(u32, u32)>, machine: bool) -> Result<u32> {
    use nix::sys::termios::{self, LocalFlags, SetArg};

    let stdin = std::io::stdin();
    // Only show prompts if input is an interactive terminal
    if !machine {
        let prompt_text = if let Some((used, limit)) = attempts {
            t!("pin_prompt", "remaining" => limit - used, "limit" => limit).to_string()
        } else {
            prompt.to_string()
        };

        eprint!("{}", prompt_text);
        io::stderr().flush().map_err(Error::IoError)?;
    }

    let mut input = String::new();

    if !machine {
        // Disable echo for interactive terminal entry
        let mut termios = termios::tcgetattr(&stdin).map_err(Error::TermIoError)?;
        let orig = termios.local_flags;
        termios.local_flags &= !LocalFlags::ECHO;
        termios::tcsetattr(&stdin, SetArg::TCSANOW, &termios).map_err(Error::TermIoError)?;

        let result = io::stdin().read_line(&mut input).map_err(Error::IoError);

        // Re-enable echo before checking for input error
        termios.local_flags = orig;
        termios::tcsetattr(&stdin, SetArg::TCSANOW, &termios).map_err(Error::TermIoError)?;
        eprintln!();
        result?;
    } else {
        io::stdin().read_line(&mut input).map_err(Error::IoError)?;
    };

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::PinIsEmpty);
    }

    trimmed.parse().map_err(|_| Error::PinContainsNonDigits)
}

fn resolve_username(username: Option<String>) -> Result<String> {
    if let Some(username) = username {
        return Ok(username);
    }

    let current_uid = get_uid();
    get_username_from_uid(current_uid).ok_or(Error::GetUsernameForUidFailed(current_uid))
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
#[cfg_attr(feature = "machine", derive(serde::Serialize))]
enum Error {
    UserNotFound,
    PermissionDenied,
    PinAlreadySet,
    NoPinSet,
    PinsDontMatch,
    PinIsLocked,
    IncorrectPin,
    PinIsEmpty,
    PinContainsNonDigits,
    GetUsernameForUidFailed(u32),
    CannotDeletePin(pinpam_core::DeleteResult),
    CoreError(pinpam_core::PinError),
    PinManagerNewError(pinpam_core::PinError),
    PinSetupError(pinpam_core::PinError),
    PinRestartContext(pinpam_core::PinError),
    PinVerifyFailed(pinpam_core::PinError),
    PinDeleteFailed(pinpam_core::PinError),
    GetPinSlotFailed(pinpam_core::PinError),
    IoError(
        #[cfg_attr(
            feature = "machine",
            serde(serialize_with = "pinpam_core::serialize_error_as_string")
        )]
        std::io::Error,
    ),
    TermIoError(
        #[cfg_attr(
            feature = "machine",
            serde(serialize_with = "pinpam_core::serialize_error_as_string")
        )]
        nix::errno::Errno,
    ),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::UserNotFound => t!("user_not_found"),
            Self::PermissionDenied => t!("permission_denied"),
            Self::PinAlreadySet => t!("pin_already_set"),
            Self::NoPinSet => t!("no_pin_set"),
            Self::PinsDontMatch => t!("pins_dont_match"),
            Self::PinIsLocked => t!("pin_is_locked"),
            Self::IncorrectPin => t!("incorrect_pin"),
            Self::PinIsEmpty => t!("pin_is_empty"),
            Self::PinContainsNonDigits => t!("pin_contains_non_digits"),
            Self::GetUsernameForUidFailed(uid) => t!("get_username_failed", "uid" => uid),
            Self::CannotDeletePin(e) => t!("cannot_delete_pin", "error" => e),
            Self::CoreError(e) => t!("core_error", "error" => e),
            Self::PinManagerNewError(e) => t!("pin_manager_new_error", "error" => e),
            Self::PinSetupError(e) => t!("pin_setup_error", "error" => e),
            Self::PinRestartContext(e) => t!("pin_restart_context", "error" => e),
            Self::PinVerifyFailed(e) => t!("pin_verify_failed", "error" => e),
            Self::PinDeleteFailed(e) => t!("pin_delete_failed", "error" => e),
            Self::GetPinSlotFailed(e) => t!("get_pin_slot_failed", "error" => e),
            Self::IoError(e) => t!("io_error", "error" => e),
            Self::TermIoError(e) => t!("term_io_error", "error" => e),
        };
        write!(f, "{msg}")
    }
}
