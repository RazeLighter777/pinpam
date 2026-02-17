//! TPM PIN Utility - Command-line utility for managing TPM-backed PIN authentication.

use clap::{Parser, Subcommand};
use pinpam_core::{
    can_manage_pin, get_uid, get_uid_from_username, get_username_from_uid, AttemptInfo,
    DeleteResult, PinError, PinManager, PinPolicy, VerificationResult,
};
use std::io::{self, IsTerminal, Write};

#[macro_use]
extern crate rust_i18n;
i18n!("locales", fallback = "en");

mod sandbox;

type Result<T> = ::core::result::Result<T, pinpam_core::PinError>;

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

    let machine = cli.machine || !std::io::stdin().is_terminal();
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

fn new_manager() -> Result<PinManager> {
    PinManager::new(PinPolicy::load_from_standard_locations())
}

fn setup_pin(username: &str, machine: bool) -> Result<()> {
    let uid = get_uid_from_username(username)?;

    if !can_manage_pin(uid) {
        return Err(PinError::PermissionDenied);
    }

    let mut manager = new_manager()?;

    // Check if already provisioned - only error if it's NOT a NotProvisioned error
    match manager.get_attempt_count(uid) {
        Ok(None) => {
            // Good - no PIN set, we can proceed
        }
        Ok(Some(_)) => {
            return Err(PinError::PinAlreadySet);
        }
        Err(pinpam_core::PinError::NotProvisioned(_)) => {
            // Good - no PIN set, we can proceed
        }
        Err(e) => {
            return Err(e);
        }
    }

    let pin = prompt_pin(&t!("enter_new_pin"), None, machine)?;
    // only prompt for confirmation when stdin is an interactive terminal
    if !machine {
        let confirm = prompt_pin(&t!("confirm_pin"), None, machine)?;
        if pin != confirm {
            return Err(PinError::PinsDontMatch);
        }
    }

    manager.setup_pin(uid, pin)?;
    if !machine {
        println!("{}", t!("pin_set_for_user", "username" => username));
    }
    Ok(())
}

fn change_pin(username: &str, machine: bool) -> Result<()> {
    let uid = get_uid_from_username(username)?;

    if !can_manage_pin(uid) {
        return Err(PinError::PermissionDenied);
    }

    let mut manager = new_manager()?;
    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => return Err(PinError::NoPinSet),
    };

    manager.restart_context()?;
    manager.clear_sessions();

    if get_uid() != 0 {
        if attempt_info.locked() {
            return Err(PinError::PinIsLocked);
        }

        // User changing their own PIN - require current PIN
        let current = prompt_pin(&t!("pin"), Some(attempt_info.prompt_tuple()), machine)?;
        match manager.verify_pin(uid, &current)? {
            VerificationResult::Success(_) => {}
            VerificationResult::Invalid { locked } => {
                return Err(PinError::IncorrectPin { locked })
            }
            VerificationResult::LockedOut => return Err(PinError::PinIsLocked),
        }
        manager.restart_context()?;

        let new_pin = prompt_pin(&t!("new_pin"), None, machine)?;
        if !machine {
            let confirm = prompt_pin(&t!("confirm"), None, machine)?;
            if new_pin != confirm {
                return Err(PinError::PinsDontMatch);
            }
        }

        match manager.delete_pin_with_auth(uid, &current)? {
            DeleteResult::Success => {
                manager.clear_sessions();
                manager.setup_pin(uid, new_pin)?;
                if !machine {
                    println!("{}", t!("pin_changed_for_user", "username" => username));
                }
            }
            result => return Err(PinError::CannotDeletePin(result)),
        }
    } else {
        // Root changing PIN - no auth required
        let new_pin = prompt_pin(&t!("new_pin"), None, machine)?;
        if !machine {
            let confirm = prompt_pin(&t!("confirm"), None, machine)?;
            if new_pin != confirm {
                return Err(PinError::PinsDontMatch);
            }
        }
        manager.delete_pin_admin(uid)?;
        manager.clear_sessions();
        manager.setup_pin(uid, new_pin)?;
        if !machine {
            println!("{}", t!("pin_changed_for_user", "username" => username));
        }
    }
    Ok(())
}

fn delete_pin(username: &str, machine: bool) -> Result<()> {
    let uid = get_uid_from_username(username)?;

    let current_uid = get_uid();
    let is_root = current_uid == 0;

    // Non-root users can only delete their own PIN
    if !is_root && current_uid != uid {
        return Err(PinError::PermissionDenied);
    }

    let mut manager = new_manager()?;

    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => return Err(PinError::NoPinSet),
    };

    if !is_root && attempt_info.locked() {
        return Err(PinError::PinIsLocked);
    }

    if is_root {
        if !machine {
            // Root deletion - no PIN required, but confirm
            print!("Delete PIN for '{}'? (y/N): ", username);
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if !input.trim().to_lowercase().starts_with('y') {
                println!("{}", t!("cancelled"));
                return Ok(());
            }
        }
        let result = manager.delete_pin_admin(uid);
        if !machine {
            match &result {
                Ok(_) => println!("{}", t!("pin_deleted_for_user", "username" => username)),
                Err(e) => println!("{}", t!("pin_delete_failed", "error" => e)),
            }
        }
        result
    } else {
        // User deletion - requires PIN authentication
        let pin = prompt_pin("PIN", Some(attempt_info.prompt_tuple()), machine)?;
        let result = manager.delete_pin_with_auth(uid, &pin)?;
        if !machine {
            match result {
                DeleteResult::Success => {
                    println!("{}", t!("pin_deleted_for_user", "username" => username))
                }
                DeleteResult::Invalid { locked: _ } => println!("{}", t!("incorrect_pin")),
                DeleteResult::LockedOut => println!("{}", t!("now_locked_out")),
            }
        }
        Ok(())
    }
}

fn test_pin(username: &str, machine: bool) -> Result<()> {
    let uid = get_uid_from_username(username)?;

    let mut manager = new_manager()?;

    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => {
            if !machine {
                println!("{}", t!("no_pin_set_for_user"));
            }
            return Err(PinError::NoPinSet);
        }
    };

    if attempt_info.locked() {
        if !machine {
            println!("{}", t!("user_is_locked_out"));
        }
        return Err(PinError::PinIsLocked);
    }

    let pin = prompt_pin("PIN", Some(attempt_info.prompt_tuple()), machine)?;
    let result = manager.verify_pin(uid, &pin)?;
    if !machine {
        match result {
            VerificationResult::Success(_) => {
                println!("{}", t!("pin_correct"));
            }
            VerificationResult::Invalid { locked: _ } => {
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
            VerificationResult::Invalid { locked } => Err(PinError::IncorrectPin { locked }),
            VerificationResult::LockedOut => Err(PinError::PinIsLocked),
        }
    }
}

fn show_status(username: &str, machine: bool) -> Result<Option<AttemptInfo>> {
    let uid = get_uid_from_username(username)?;

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

fn get_attempt_info(manager: &mut PinManager, uid: u32) -> Result<Option<AttemptInfo>> {
    Ok(manager.get_pin_slot(uid)?.map(AttemptInfo::from_pin_data))
}

fn prompt_pin(prompt: &str, attempts: Option<(u32, u32)>, machine: bool) -> Result<String> {
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
        io::stderr().flush()?;
    }

    let mut input = String::new();

    if !machine {
        // Disable echo for interactive terminal entry
        let mut termios = termios::tcgetattr(&stdin)?;
        let orig = termios.local_flags;
        termios.local_flags &= !LocalFlags::ECHO;
        termios::tcsetattr(&stdin, SetArg::TCSANOW, &termios)?;

        let result = io::stdin().read_line(&mut input);

        // Re-enable echo before checking for input error
        termios.local_flags = orig;
        termios::tcsetattr(&stdin, SetArg::TCSANOW, &termios)?;
        eprintln!();
        result?;
    } else {
        io::stdin().read_line(&mut input)?;
    };

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PinError::PinIsEmpty);
    }

    Ok(trimmed.to_string())
}

fn resolve_username(username: Option<String>) -> Result<String> {
    if let Some(username) = username {
        return Ok(username);
    }

    let current_uid = get_uid();
    get_username_from_uid(current_uid).ok_or(PinError::GetUsernameForUidFailed(current_uid))
}
