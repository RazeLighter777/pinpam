//! TPM PIN Utility - Command-line utility for managing TPM-backed PIN authentication.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pinpam_core::{
    can_manage_pin, get_uid, get_uid_from_username, get_username_from_uid, DeleteResult, PinData,
    PinManager, PinPolicy, VerificationResult,
};
use std::io::{self, Write};

mod sandbox;

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
    if let Err(e) = sandbox::pinutil_sandbox() {
        eprintln!("Warning: Failed to enable sandboxing: {}", e);
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

    if let Err(e) = match cli.command {
        Commands::Setup { username } => {
            let username = resolve_username(username)?;
            setup_pin(&username)
        }
        Commands::Change { username } => {
            let username = resolve_username(username)?;
            change_pin(&username)
        }
        Commands::Delete { username } => {
            let username = resolve_username(username)?;
            delete_pin(&username)
        }
        Commands::Test { username } => {
            let username = resolve_username(username)?;
            test_pin(&username)
        }
        Commands::Status { username } => {
            let username = resolve_username(username)?;
            show_status(&username)
        }
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    Ok(())
}

fn new_manager() -> Result<PinManager> {
    Ok(PinManager::new(PinPolicy::load_from_standard_locations())?)
}

fn setup_pin(username: &str) -> Result<()> {
    let uid = get_uid_from_username(username)
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", username))?;

    if !can_manage_pin(uid) {
        return Err(anyhow::anyhow!("Permission denied"));
    }

    let mut manager = new_manager()?;

    // Check if already provisioned - only error if it's NOT a NotProvisioned error
    match manager.get_attempt_count(uid) {
        Ok(None) => {
            // Good - no PIN set, we can proceed
        }
        Ok(Some(_)) => {
            return Err(anyhow::anyhow!("PIN already set for user '{}'", username));
        }
        Err(pinpam_core::PinError::NotProvisioned(_)) => {
            // Good - no PIN set, we can proceed
        }
        Err(e) => {
            return Err(e.into());
        }
    }

    let pin = prompt_pin("Enter new PIN", None)?;
    let confirm = prompt_pin("Confirm PIN", None)?;
    if pin != confirm {
        return Err(anyhow::anyhow!("PINs do not match"));
    }

    manager.setup_pin(uid, pin)?;
    println!("✅ PIN set for user: {}", username);
    Ok(())
}

fn change_pin(username: &str) -> Result<()> {
    let uid = get_uid_from_username(username).ok_or_else(|| anyhow::anyhow!("User not found"))?;

    if !can_manage_pin(uid) {
        return Err(anyhow::anyhow!("Permission denied"));
    }

    let mut manager = new_manager()?;
    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => return Err(anyhow::anyhow!("No PIN set. Use 'setup' first")),
    };

    manager.restart_context()?;
    manager.clear_sessions()?;

    if get_uid() != 0 {
        if attempt_info.locked() {
            return Err(anyhow::anyhow!("User is locked out"));
        }

        // User changing their own PIN - require current PIN
        let current = prompt_pin("PIN", Some(attempt_info.prompt_tuple()))?;
        match manager.verify_pin(uid, current)? {
            VerificationResult::Success(_) => {}
            VerificationResult::Invalid => return Err(anyhow::anyhow!("Incorrect PIN")),
            VerificationResult::LockedOut => return Err(anyhow::anyhow!("Now locked out")),
        }
        manager.restart_context()?;

        let new_pin = prompt_pin("New PIN", None)?;
        let confirm = prompt_pin("Confirm", None)?;
        if new_pin != confirm {
            return Err(anyhow::anyhow!("PINs do not match"));
        }

        match manager.delete_pin_with_auth(uid, current)? {
            DeleteResult::Success => {
                manager.clear_sessions()?;
                manager.setup_pin(uid, new_pin)?;
                println!("✅ PIN changed for: {}", username);
            }
            _ => return Err(anyhow::anyhow!("Failed to delete old PIN")),
        }
    } else {
        // Root changing PIN - no auth required
        let new_pin = prompt_pin("New PIN", None)?;
        let confirm = prompt_pin("Confirm", None)?;
        if new_pin != confirm {
            return Err(anyhow::anyhow!("PINs do not match"));
        }

        match manager.delete_pin_admin(uid) {
            Ok(_) => {}
            Err(pinpam_core::PinError::NotProvisioned(_)) => {
                return Err(anyhow::anyhow!("No PIN set. Use 'setup' first"))
            }
            Err(e) => return Err(e.into()),
        }
        manager.clear_sessions()?;
        manager.setup_pin(uid, new_pin)?;
        println!("✅ PIN changed for: {}", username);
    }
    Ok(())
}

fn delete_pin(username: &str) -> Result<()> {
    let uid = get_uid_from_username(username).ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let current_uid = get_uid();
    let is_root = current_uid == 0;

    // Non-root users can only delete their own PIN
    if !is_root && current_uid != uid {
        return Err(anyhow::anyhow!(
            "Permission denied: can only delete your own PIN"
        ));
    }

    let mut manager = new_manager()?;

    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => return Err(anyhow::anyhow!("No PIN set")),
    };

    if !is_root && attempt_info.locked() {
        return Err(anyhow::anyhow!("User is locked out"));
    }

    if is_root {
        // Root deletion - no PIN required, but confirm
        print!("Delete PIN for '{}'? (y/N): ", username);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().to_lowercase().starts_with('y') {
            println!("Cancelled");
            return Ok(());
        }

        match manager.delete_pin_admin(uid) {
            Ok(_) => println!("✅ PIN deleted for: {}", username),
            Err(e) => println!("❌ PIN deletion failed or PIN not set: {}", e),
        }
    } else {
        // User deletion - requires PIN authentication
        let pin = prompt_pin("PIN", Some(attempt_info.prompt_tuple()))?;
        match manager.delete_pin_with_auth(uid, pin) {
            Ok(DeleteResult::Success) => println!("✅ PIN deleted for: {}", username),
            Ok(DeleteResult::Invalid) => println!("❌ Incorrect PIN"),
            Ok(DeleteResult::LockedOut) => println!("⚠️  Now locked out"),
            Err(e) => println!("❌ PIN deletion failed or PIN not set: {}", e),
        }
    }
    Ok(())
}

fn test_pin(username: &str) -> Result<()> {
    let uid = get_uid_from_username(username).ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let mut manager = new_manager()?;

    let attempt_info = match get_attempt_info(&mut manager, uid)? {
        Some(info) => info,
        None => {
            println!("No PIN set for user");
            return Ok(());
        }
    };

    if attempt_info.locked() {
        println!("⚠️  User is locked out");
        return Ok(());
    }

    let pin = prompt_pin("PIN", Some(attempt_info.prompt_tuple()))?;
    match manager.verify_pin(uid, pin) {
        Ok(VerificationResult::Success(_)) => {
            println!("✅ PIN is correct");
        }
        Ok(VerificationResult::Invalid) => {
            println!("❌ Incorrect PIN");
        }
        Ok(VerificationResult::LockedOut) => {
            println!("⚠️  Now locked out");
        }
        Err(e) => println!("❌ PIN verification failed or PIN not set: {}", e),
    }
    Ok(())
}

fn show_status(username: &str) -> Result<()> {
    let uid = get_uid_from_username(username).ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let mut manager = new_manager()?;

    println!("Status for: {} (uid: {})", username, uid);
    match get_attempt_info(&mut manager, uid)? {
        Some(info) => {
            println!("  PIN provisioned: Yes");
            println!("  Failed attempts: {}", info.used);
            println!("  Attempt limit: {}", info.limit);
            println!("  Locked out: {}", if info.locked() { "Yes" } else { "No" });
        }
        None => {
            println!("  PIN provisioned: No");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
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
    Ok(manager.get_pin_slot(uid)?.map(AttemptInfo::from_pin_data))
}

fn prompt_pin(prompt: &str, attempts: Option<(u32, u32)>) -> Result<u32> {
    use nix::sys::termios::{self, LocalFlags, SetArg};

    let prompt_text = if let Some((used, limit)) = attempts {
        format!("PIN ({}/{}): ", used, limit)
    } else {
        format!("{}: ", prompt)
    };

    eprint!("{}", prompt_text);
    io::stderr().flush()?;

    let stdin = std::io::stdin();

    let mut termios = termios::tcgetattr(&stdin)?;
    let orig = termios.local_flags;
    termios.local_flags &= !LocalFlags::ECHO;
    termios::tcsetattr(&stdin, SetArg::TCSANOW, &termios)?;

    let mut input = String::new();
    let result = io::stdin().read_line(&mut input);

    termios.local_flags = orig;
    termios::tcsetattr(&stdin, SetArg::TCSANOW, &termios)?;
    eprintln!();

    result?;

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("PIN cannot be empty"));
    }

    trimmed.parse().context("PIN must contain only digits")
}

fn resolve_username(username: Option<String>) -> Result<String> {
    if let Some(username) = username {
        return Ok(username);
    }

    let current_uid = get_uid();
    get_username_from_uid(current_uid).ok_or_else(|| {
        anyhow::anyhow!(
            "Unable to determine username for current uid {}",
            current_uid
        )
    })
}
