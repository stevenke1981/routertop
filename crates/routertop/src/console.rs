//! Physical-console gate. Authentication never falls back to an open shell.
use crate::web::{self, ConsoleAuth};
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Captures the actual TTY mode, disabling terminal-generated signals while a
/// password is being read. Ctrl-C/Ctrl-Z therefore cannot bypass restoration by
/// terminating/suspending this process in the hidden-input section.
struct HiddenInput(String);
impl HiddenInput {
    fn begin() -> Result<Self, String> {
        let original = Command::new("stty")
            .arg("-g")
            .stdin(Stdio::inherit())
            .output()
            .map_err(|_| "Cannot read terminal settings")?;
        if !original.status.success() {
            return Err("Cannot read terminal settings".into());
        }
        let original =
            String::from_utf8(original.stdout).map_err(|_| "Invalid terminal settings")?;
        let guard = Self(original.trim().into());
        let status = Command::new("stty")
            .args(["-echo", "-isig"])
            .status()
            .map_err(|_| "Cannot protect password input")?;
        if !status.success() {
            return Err("Cannot protect password input".into());
        }
        Ok(guard)
    }
}
impl Drop for HiddenInput {
    fn drop(&mut self) {
        let _ = Command::new("stty").arg(&self.0).status();
    }
}

fn prompt(label: &str, secret: bool) -> Result<Option<String>, String> {
    // Disable echo before publishing the prompt: serial automation may respond
    // immediately, and must never race terminal configuration with its secret.
    let hidden = if secret {
        Some(HiddenInput::begin()?)
    } else {
        None
    };
    print!("{label}");
    io::stdout().flush().map_err(|_| "Terminal output failed")?;
    let mut input = io::stdin().lock();
    let mut bytes = Vec::with_capacity(128);
    let mut invalid = false;
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => {
                bytes.fill(0);
                drop(hidden);
                println!();
                return Ok(None);
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if bytes.len() >= 128 || byte[0].is_ascii_control() {
                    invalid = true;
                } else {
                    bytes.push(byte[0]);
                }
            }
            Err(_) => {
                bytes.fill(0);
                return Err("Terminal input failed".into());
            }
        }
    }
    drop(hidden);
    if secret {
        println!();
    }
    let result = if invalid {
        None
    } else {
        String::from_utf8(bytes.clone()).ok()
    };
    bytes.fill(0);
    Ok(result)
}

fn prepare_runtime(runtime: &Path) -> Result<(), String> {
    fs::create_dir_all(runtime).map_err(|_| "Console runtime unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(runtime).map_err(|_| "Console runtime unavailable")?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.gid() != 0 {
            return Err("Console runtime must be a root-owned directory".into());
        }
        fs::set_permissions(runtime, fs::Permissions::from_mode(0o700))
            .map_err(|_| "Console runtime permissions unavailable")?;
    }
    Ok(())
}

/// CLI entry point. Only the real local TTY may authorize a root shell; CLI
/// argument/environment password injection and piped standard input are refused.
pub fn run(data: &Path, runtime: &Path) -> Result<(), String> {
    if !cfg!(target_os = "linux") || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("Console login requires a local Linux terminal".into());
    }
    let id = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|_| "Cannot verify console privilege")?;
    if !id.status.success() || id.stdout != b"0\n" {
        return Err("Console login requires root".into());
    }
    prepare_runtime(runtime)?;
    loop {
        let setup = match web::console_setup_required(data) {
            Ok(setup) => setup,
            Err(_) => {
                println!("Console locked: persistent administrator state unavailable.");
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        if setup {
            println!("RouterTop administrator setup (12-128 bytes).");
            match prompt("Setup choice [create/token]: ", false)?.as_deref() {
                Some("create") => {
                    let Some(password) = prompt("New password: ", true)? else {
                        continue;
                    };
                    let Some(confirmation) = prompt("Confirm password: ", true)? else {
                        continue;
                    };
                    match web::console_setup(data, &password, &confirmation) {
                        Ok(()) => println!("Administrator created. Log in to continue."),
                        Err(_) => println!("Setup failed; passwords must match (12-128 bytes) and state must be available."),
                    }
                }
                Some("token") => match web::bootstrap_token(data) {
                    Ok(token) => println!("Web enrollment token: {token}"),
                    Err(_) => println!(
                        "Enrollment token unavailable; account may already be initialized."
                    ),
                },
                _ => {
                    println!("Choose create or token; no shell is available before authentication.")
                }
            }
            continue;
        }
        println!("RouterTop console login (admin)");
        let Some(password) = prompt("Password: ", true)? else {
            continue;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "System clock unavailable")?
            .as_secs();
        match web::console_authenticate(data, runtime, &password, now) {
            Ok(ConsoleAuth::Accepted) => {
                drop(password);
                println!("Authenticated. Type exit to log out.");
                let result = Command::new("/bin/sh")
                    .arg("-l")
                    .env("HOME", "/root")
                    .env("USER", "root")
                    .env("LOGNAME", "root")
                    .current_dir("/root")
                    .status();
                if result.is_err() {
                    println!("Cannot start shell; returning to login.");
                }
                println!("Logged out.");
            }
            Ok(ConsoleAuth::Rejected) => {
                println!("Authentication failed.");
                thread::sleep(Duration::from_secs(2));
            }
            Ok(ConsoleAuth::Throttled) => {
                println!("Too many attempts. Try again after five minutes.");
                thread::sleep(Duration::from_secs(2));
            }
            Err(_) => {
                println!("Console locked: persistent administrator state unavailable.");
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}
