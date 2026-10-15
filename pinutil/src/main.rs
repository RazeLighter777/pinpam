//! TPM PIN Utility - Command-line utility for managing TPM-backed PIN authentication.

use clap::{Parser, Subcommand};
use pinpam_core::{
    master_key,
    pin::Pin,
    pinconstants::MASTER_KEY_SEALED_FILE,
    pindata::AttemptInfo,
    pinerror::{DeleteResult, PinError, PinResult, VerificationResult},
    pinmanager::PinManager,
    pinpolicy::PinPolicy,
    util::{can_attempt_pin, can_manage_pin, get_uid, get_uid_from_username, get_username_from_uid},
};
use std::io::{self, IsTerminal, Write};

#[macro_use]
extern crate rust_i18n;
i18n!("locales", fallback = "en");

mod length_metadata;
mod sandbox;
use length_metadata::LengthAwareManager;

#[derive(Parser)]
#[command(
    name = "pinutil",
    about = "TPM PIN authentication utility",
    version = "0.0.5"
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

    /// Read enrolled PIN length only (never authenticates or reads a PIN)
    Length {
        #[arg(value_name = "USERNAME")]
        username: Option<String>,
    },

    /// Manage the TPM-backed master AUTHTOK key
    #[command(subcommand)]
    MasterKey(MasterKeyCommands),
}

#[derive(Subcommand)]
enum MasterKeyCommands {
    /// Initialize a new TPM-backed master key and write recovery data to disk
    Init,
    /// Show master-key provisioning status
    Status,
    /// Import the master key into TPM using the recovery phrase
    ImportToTpm,
    /// Remove master-key persistent handles from TPM
    ClearFromTpm,
    /// Delete the sealed recovery blob from disk
    ClearFromDisk,
    /// Derive and print the per-user token for a username
    GetUserToken {
        #[arg(value_name = "USERNAME")]
        username: String,
    },
}

fn main() -> PinResult<()> {
    rust_i18n::set_locale(locale_config::Locale::current().as_ref());
    if let Err(e) = sandbox::pinutil_sandbox() {
        eprintln!("{}: {}", t!("sandbox_fail"), e);
    }
    let cli = Cli::parse();
    // Don't read RUST_LOG: this binary is setuid/setgid, so an attacker-controlled
    // environment must not be able to crank up logging. Verbosity is driven solely
    // by the `-v` flag.
    env_logger::Builder::new()
        .filter_level(if cli.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Off
        })
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
        Commands::Length { username } => {
            handle_result(show_length(username, machine), machine)
        }
        Commands::MasterKey(cmd) => {
            if let Err(e) = require_root() {
                handle_result::<()>(Err(e), machine);
            }
            match cmd {
                MasterKeyCommands::Init => handle_result(master_key_init(machine), machine),
                MasterKeyCommands::Status => handle_result(master_key_status(machine), machine),
                MasterKeyCommands::ImportToTpm => {
                    handle_result(master_key_import_to_tpm(machine), machine)
                }
                MasterKeyCommands::ClearFromTpm => {
                    handle_result(master_key_clear_from_tpm(machine), machine)
                }
                MasterKeyCommands::ClearFromDisk => {
                    handle_result(master_key_clear_from_disk(machine), machine)
                }
                MasterKeyCommands::GetUserToken { username } => {
                    if machine {
                        handle_result(master_key_get_user_token(&username), machine)
                    } else {
                        // Human mode must print the token.
                        match master_key_get_user_token(&username) {
                            Ok(token) => println!("{token}"),
                            Err(e) => {
                                eprintln!("{}", t!("error_result", "error" => e));
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(())
}

fn require_root() -> PinResult<()> {
    if get_uid() != 0 {
        return Err(PinError::PermissionDenied);
    }
    Ok(())
}

fn require_interactive(machine: bool, purpose: String) -> PinResult<()> {
    if machine {
        return Err(PinError::TermIoError(
            t!("requires_interactive_confirmation", "purpose" => purpose).to_string(),
        ));
    }
    Ok(())
}

fn prompt_line(prompt: &str) -> PinResult<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_yes_no(prompt: &str) -> PinResult<bool> {
    let input = prompt_line(prompt)?;
    Ok(input.trim().to_lowercase().starts_with('y'))
}

fn prompt_acknowledgement(expected: &str, prompt: &str) -> PinResult<()> {
    let got = prompt_line(prompt)?;
    if got.trim() != expected {
        return Err(PinError::TermIoError(t!("cancelled").to_string()));
    }
    Ok(())
}

fn master_key_status(machine: bool) -> PinResult<pinpam_core::master_key::MasterKeyStatus> {
    let st = master_key::status()?;
    if !machine {
        println!("sealed_file_present: {}", st.sealed_file_present);
        println!("rsa_parent_present: {}", st.rsa_parent_present);
        println!("hmac_key_present: {}", st.hmac_key_present);
        println!("sealed_file_path: {}", st.sealed_file_path);
        println!("rsa_handle: 0x{:08x}", st.rsa_handle);
        println!("hmac_handle: 0x{:08x}", st.hmac_handle);
    }
    Ok(st)
}

fn master_key_init(machine: bool) -> PinResult<pinpam_core::master_key::MasterKeyInitResult> {
    if !machine {
        eprintln!("{}", t!("mk_warn_init_new_key"));
        eprintln!("{}", t!("mk_warn_init_break_old_unlocks"));
        let proceed_prompt = t!("mk_proceed_prompt");
        if !prompt_yes_no(&proceed_prompt)? {
            return Err(PinError::TermIoError(t!("cancelled").to_string()));
        }
    }

    let res = master_key::init()?;
    if !machine {
        println!(
            "\n{}\n\n{}\n",
            t!("mk_recovery_phrase_header"),
            res.recovery_phrase
        );
        let confirm_prompt = t!("mk_recovery_confirm_prompt");
        let confirm = prompt_line(&confirm_prompt)?;
        if confirm.trim() != res.recovery_phrase.trim() {
            return Err(PinError::TermIoError(
                t!("mk_recovery_confirm_mismatch").to_string(),
            ));
        }
    }
    Ok(res)
}

fn master_key_import_to_tpm(machine: bool) -> PinResult<pinpam_core::master_key::MasterKeyStatus> {
    require_interactive(machine, t!("mk_purpose_import").to_string())?;
    let phrase_prompt = t!("mk_recovery_phrase_prompt");
    let phrase = prompt_line(&phrase_prompt)?;
    let st = master_key::import_to_tpm(&phrase)?;
    println!("{}", t!("mk_import_success"));
    Ok(st)
}

fn master_key_clear_from_tpm(machine: bool) -> PinResult<()> {
    require_interactive(machine, t!("mk_purpose_tpm_clear").to_string())?;
    eprintln!("{}", t!("mk_warn_clear_tpm"));
    let ack_prompt = t!("mk_ack_prompt");
    prompt_acknowledgement("yes", &ack_prompt)?;
    master_key::clear_from_tpm()?;
    println!("{}", t!("mk_clear_tpm_success"));
    Ok(())
}

fn master_key_clear_from_disk(machine: bool) -> PinResult<()> {
    require_interactive(machine, t!("mk_purpose_disk_clear").to_string())?;
    eprintln!(
        "{}",
        t!("mk_warn_clear_disk", "path" => MASTER_KEY_SEALED_FILE)
    );
    let ack_prompt = t!("mk_ack_prompt");
    prompt_acknowledgement("yes", &ack_prompt)?;
    master_key::clear_from_disk()?;
    println!("{}", t!("mk_clear_disk_success"));
    Ok(())
}

fn master_key_get_user_token(username: &str) -> PinResult<String> {
    master_key::derive_user_token(username)
}

fn handle_result<T>(res: PinResult<T>, machine: bool)
where
    PinResult<T>: serde::Serialize,
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

fn new_manager() -> PinResult<LengthAwareManager> {
    Ok(LengthAwareManager::new(PinManager::new(
        PinPolicy::cached().clone(),
    )?))
}

fn show_length(username: Option<String>, machine: bool) -> PinResult<Option<usize>> {
    let uid = get_uid_from_username(&resolve_username(username)?)?;
    if !can_manage_pin(uid) {
        return Err(PinError::PermissionDenied);
    }
    let length = new_manager()?.length(uid)?;
    if !machine {
        if let Some(length) = length {
            println!("{length}");
        }
    }
    Ok(length)
}

fn setup_pin(username: &str, machine: bool) -> PinResult<()> {
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
        Err(pinpam_core::pinerror::PinError::NotProvisioned(_)) => {
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
        if pin.as_str() != confirm.as_str() {
            return Err(PinError::PinsDontMatch);
        }
    }

    manager.setup_pin(uid, &pin)?;
    if !machine {
        println!("{}", t!("pin_set_for_user", "username" => username));
    }
    Ok(())
}

fn change_pin(username: &str, machine: bool) -> PinResult<()> {
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
            if new_pin.as_str() != confirm.as_str() {
                return Err(PinError::PinsDontMatch);
            }
        }

        manager.prepare_change(uid)?;
        match manager.delete_pin_with_auth(uid, &current)? {
            DeleteResult::Success => {
                manager.clear_sessions();
                manager.setup_pin(uid, &new_pin)?;
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
            if new_pin.as_str() != confirm.as_str() {
                return Err(PinError::PinsDontMatch);
            }
        }
        manager.prepare_change(uid)?;
        manager.delete_pin_admin(uid)?;
        manager.clear_sessions();
        manager.setup_pin(uid, &new_pin)?;
        if !machine {
            println!("{}", t!("pin_changed_for_user", "username" => username));
        }
    }
    Ok(())
}

fn delete_pin(username: &str, machine: bool) -> PinResult<()> {
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

fn test_pin(username: &str, machine: bool) -> PinResult<()> {
    let uid = get_uid_from_username(username)?;

    // Each wrong attempt permanently consumes a TPM lockout slot. Restrict
    // verification to the target user themselves or to a process running with
    // effective uid 0 (login/sudo/su/polkit drive PAM with euid 0). In the
    // setgid deployment this still blocks a direct unprivileged
    // `pinutil test <victim>` loop from locking out every account, while leaving
    // all PAM paths -- including `su` to another user -- working.
    if !can_attempt_pin(uid) {
        return Err(PinError::PermissionDenied);
    }

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

fn show_status(username: &str, machine: bool) -> PinResult<Option<AttemptInfo>> {
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

fn get_attempt_info(manager: &mut PinManager, uid: u32) -> PinResult<Option<AttemptInfo>> {
    Ok(manager.get_pin_slot(uid)?.map(AttemptInfo::from_pin_data))
}

fn prompt_pin(prompt: &str, attempts: Option<(u32, u32)>, machine: bool) -> PinResult<Pin> {
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

    Pin::new(&input, PinPolicy::cached())
}

fn resolve_username(username: Option<String>) -> PinResult<String> {
    if let Some(username) = username {
        return Ok(username);
    }

    let current_uid = get_uid();
    get_username_from_uid(current_uid).ok_or(PinError::GetUsernameForUidFailed(current_uid))
}
