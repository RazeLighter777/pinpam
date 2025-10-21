//! TPM PIN Utility - Command-line utility for managing TPM-backed PIN authentication.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pinpam_core::{
    can_manage_pin, get_uid, get_uid_from_username, DeleteResult, PinManager, PinPolicy,
    VerificationResult,
};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "pinutil", about = "TPM PIN authentication utility", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Set up a new PIN (root or user for self)
    Setup { username: String },
    /// Change PIN (requires current PIN, or root)
    Change { username: String },
    /// Delete PIN (requires PIN auth for non-root, root can delete any)
    Delete { username: String },
    /// Test PIN authentication
    Test { username: String },
    /// Show PIN status
    Status { username: String },
}

fn main() -> Result<()> {
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
        Commands::Setup { username } => setup_pin(&username),
        Commands::Change { username } => change_pin(&username),
        Commands::Delete { username } => delete_pin(&username),
        Commands::Test { username } => test_pin(&username),
        Commands::Status { username } => show_status(&username),
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    Ok(())
}

fn setup_pin(username: &str) -> Result<()> {
    let uid = get_uid_from_username(username)
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", username))?;

    if !can_manage_pin(uid) {
        return Err(anyhow::anyhow!("Permission denied"));
    }

    let mut manager = PinManager::new(PinPolicy::default())?;

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

    let pin = prompt_pin("Enter new PIN: ")?;
    let confirm = prompt_pin("Confirm PIN: ")?;
    if pin != confirm {
        return Err(anyhow::anyhow!("PINs do not match"));
    }

    manager.setup_pin(uid, pin)?;
    println!("✅ PIN set for user: {}", username);
    Ok(())
}

fn change_pin(username: &str) -> Result<()> {
    let uid = get_uid_from_username(username)
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    if !can_manage_pin(uid) {
        return Err(anyhow::anyhow!("Permission denied"));
    }

    let mut manager = PinManager::new(PinPolicy::default())?;

    // Check status before prompting
    match manager.is_locked_out(uid) {
        Ok(true) => return Err(anyhow::anyhow!("User is locked out")),
        Err(pinpam_core::PinError::NotProvisioned(_)) => {
            return Err(anyhow::anyhow!("No PIN set. Use 'setup' first"))
        }
        _ => {}
    }
    manager.clear_sessions()?;

    if get_uid() != 0 {
        // User changing their own PIN - require current PIN
        let current = prompt_pin("Current PIN: ")?;
        match manager.verify_pin(uid, current)? {
            VerificationResult::Success(_) => {}
            VerificationResult::Invalid => return Err(anyhow::anyhow!("Incorrect PIN")),
            VerificationResult::LockedOut => return Err(anyhow::anyhow!("Now locked out")),
        }

        let new_pin = prompt_pin("New PIN: ")?;
        let confirm = prompt_pin("Confirm: ")?;
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
        let new_pin = prompt_pin("New PIN: ")?;
        let confirm = prompt_pin("Confirm: ")?;
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
    let uid = get_uid_from_username(username)
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let current_uid = get_uid();
    let is_root = current_uid == 0;

    // Non-root users can only delete their own PIN
    if !is_root && current_uid != uid {
        return Err(anyhow::anyhow!("Permission denied: can only delete your own PIN"));
    }

    let mut manager = PinManager::new(PinPolicy::default())?;

    // Check if PIN exists
    match manager.is_locked_out(uid) {
        Ok(true) => {
            if !is_root {
                return Err(anyhow::anyhow!("User is locked out"));
            }
            // Root can still delete even if locked out
        }
        Err(pinpam_core::PinError::NotProvisioned(_)) => {
            return Err(anyhow::anyhow!("No PIN set"))
        }
        _ => {}
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
        println!("✅ PIN deleted for: {}", username);
    } else {
        // User deletion - requires PIN authentication
        let pin = prompt_pin("Enter current PIN: ")?;
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
    let uid = get_uid_from_username(username)
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let mut manager = PinManager::new(PinPolicy::default())?;

    match manager.is_locked_out(uid) {
        Ok(true) => {
            println!("⚠️  User is locked out");
            return Ok(());
        }
        Err(pinpam_core::PinError::NotProvisioned(_)) => {
            println!("No PIN set for user");
            return Ok(());
        }
        _ => {}
    }

    let pin = prompt_pin("Enter PIN: ")?;
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
    let uid = get_uid_from_username(username)
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let mut manager = PinManager::new(PinPolicy::default())?;

    println!("Status for: {} (uid: {})", username, uid);
    match manager.get_attempt_count(uid) {
        Ok(Some(attempts)) => {
            let locked = manager.is_locked_out(uid)?;
            println!("  PIN provisioned: Yes");
            println!("  Failed attempts: {}", attempts);
            println!("  Locked out: {}", if locked { "Yes" } else { "No" });
        }
        Ok(None) | Err(pinpam_core::PinError::NotProvisioned(_)) => {
            println!("  PIN provisioned: No");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn prompt_pin(prompt: &str) -> Result<u32> {
    use nix::sys::termios::{self, LocalFlags, SetArg};

    eprint!("{}", prompt);
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
    
    trimmed.parse()
        .context("PIN must contain only digits")
}
