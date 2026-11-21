use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Password, PasswordDisplayMode};
use ombracrypt_core::{fs_guard, pipeline};
use std::io::{stdin, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(name = "ombracrypt")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), " (core ", env!("CARGO_PKG_VERSION"), " | format OMBV02)"))]
#[command(
    about = "Offline Post-Quantum Hybrid Cryptographic Vault for the Terminal",
    long_about = "Ombracrypt is a local-first, zero-escrow post-quantum cryptographic vault engineered\n\
                  to protect directories against contemporary interception and 'Harvest Now, Decrypt Later' (HNDL) attacks.\n\
                  It combines hybrid ML-KEM with classical X25519 and bounded in-memory AEAD streaming."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum CipherChoice {
    #[value(name = "xchacha20")]
    XChaCha20,
    #[value(name = "aes256gcm")]
    Aes256Gcm,
}

impl ToString for CipherChoice {
    fn to_string(&self) -> String {
        match self {
            CipherChoice::XChaCha20 => "xchacha20".to_string(),
            CipherChoice::Aes256Gcm => "aes256gcm".to_string(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum KemChoice {
    #[value(name = "xwing")]
    XWing,
    #[value(name = "cypherpunk")]
    Cypherpunk,
}

impl ToString for KemChoice {
    fn to_string(&self) -> String {
        match self {
            KemChoice::XWing => "xwing".to_string(),
            KemChoice::Cypherpunk => "cypherpunk".to_string(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum InspectMode {
    #[value(name = "encrypt")]
    Encrypt,
    #[value(name = "decrypt")]
    Decrypt,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a directory into a Quantum-Safe Vault (.obv)
    Encrypt {
        /// Path to the target directory to encrypt
        #[arg(short, long)]
        target: PathBuf,

        /// Output directory for the encrypted vault (.obv) [default: parent of target]
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// Destination folder for generated keypair (.obk/.obp) [default: same as output-dir]
        #[arg(short = 'k', long)]
        key_dir: Option<PathBuf>,

        /// Path to an existing Public Key (.obp) to seal against (omits .obk generation)
        #[arg(short = 'p', long)]
        public_key: Option<PathBuf>,

        /// Symmetric cipher: 'xchacha20' (default) or 'aes256gcm'
        #[arg(short, long, value_enum, default_value_t = CipherChoice::XChaCha20)]
        cipher: CipherChoice,

        /// Post-Quantum KEM Profile: 'xwing' (ML-KEM-768, default) or 'cypherpunk' (ML-KEM-1024)
        #[arg(short = 'm', long, value_enum, default_value_t = KemChoice::XWing)]
        kem: KemChoice,

        /// Path to a file containing the Master Password
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Name of the environment variable containing the Master Password
        #[arg(long)]
        password_env: Option<String>,

        /// Path to a file containing the Deception Passcode
        #[arg(long)]
        deception_passcode_file: Option<PathBuf>,

        /// Name of the environment variable containing the Deception Passcode
        #[arg(long)]
        deception_passcode_env: Option<String>,

        /// Suppress interactive banners and progress displays
        #[arg(short, long)]
        quiet: bool,
    },

    /// Decrypt a Quantum-Safe Vault (.obv) using your Private Key (.obk)
    Decrypt {
        /// Path to the encrypted vault (.obv)
        #[arg(short, long)]
        target: PathBuf,

        /// Path to the Private Key (.obk)
        #[arg(short, long)]
        key: PathBuf,

        /// Directory where extracted contents should be published [default: parent of vault]
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// Path to a file containing the Master Password
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Name of the environment variable containing the Master Password
        #[arg(long)]
        password_env: Option<String>,

        /// Suppress interactive banners and progress displays
        #[arg(short, long)]
        quiet: bool,
    },

    /// Generate a standalone reusable Keypair (.obp Public Key + .obk Private Key)
    Keygen {
        /// Base filename stem for the keypair files
        #[arg(short, long)]
        name: String,

        /// Directory where the keypair files should be saved [default: current directory]
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// KEM Profile: 'xwing' (ML-KEM-768, default) or 'cypherpunk' (ML-KEM-1024)
        #[arg(short = 'm', long, value_enum, default_value_t = KemChoice::XWing)]
        kem: KemChoice,

        /// Path to a file containing the Deception Passcode
        #[arg(long)]
        deception_passcode_file: Option<PathBuf>,

        /// Name of the environment variable containing the Deception Passcode
        #[arg(long)]
        deception_passcode_env: Option<String>,

        /// Suppress interactive banners
        #[arg(short, long)]
        quiet: bool,
    },

    /// Reclaim and purge orphaned Ombracrypt staging directories (.ombracrypt_stage_*)
    Clean {
        /// Target folder(s) to inspect and clean [default: current directory]
        #[arg(short = 'd', long = "target-dir", action = clap::ArgAction::Append)]
        target_dirs: Vec<PathBuf>,

        /// Suppress output unless errors occur
        #[arg(short, long)]
        quiet: bool,
    },

    /// Pre-flight disk space telemetry and path conflict assessment
    Inspect {
        /// Operation mode to inspect: 'encrypt' or 'decrypt'
        #[arg(short, long, value_enum)]
        mode: InspectMode,

        /// Path to the source target (directory to encrypt, or .obv vault to decrypt)
        #[arg(short, long)]
        target: PathBuf,

        /// Output destination directory [default: parent of target or current directory]
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// Key directory (for encrypt) or key file path (for decrypt / public key sealing)
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Output assessment results in JSON format
        #[arg(long)]
        json: bool,
    },
}

fn print_banner(operation: &str, target: &str, quiet: bool) {
    if quiet {
        return;
    }
    let header = format!("OMBRACRYPT QUANTUM VAULT [v{}]", env!("CARGO_PKG_VERSION"));
    println!("\n{} {}", "::".magenta(), header.bold().cyan());
    println!(
        "   {}",
        "Post-Quantum Hybrid Cryptographic Vault (CAL-1.0)".bright_black()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_black()
    );
    println!(
        "{} {}",
        "▶ Operation:".bright_black(),
        operation.bold().green()
    );
    println!("{} {}", "▶ Target:   ".bright_black(), target.bold());
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n".bright_black()
    );
}

fn resolve_smart_output_dir(target: &Path, explicit: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir;
    }
    target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn fetch_credential(
    prompt_label: &str,
    confirm_label: Option<&str>,
    file_path: Option<&Path>,
    custom_env: Option<&str>,
    default_env: &str,
    is_optional: bool,
) -> Result<Zeroizing<String>, String> {
    if let Some(path) = file_path {
        let mut raw_bytes = std::fs::read(path)
            .map_err(|e| format!("Failed to read credential file '{}': {}", path.display(), e))?;
        while let Some(&last) = raw_bytes.last() {
            if last == b'\r' || last == b'\n' {
                raw_bytes.pop();
            } else {
                break;
            }
        }
        let s = String::from_utf8(raw_bytes).map_err(|e| {
            let mut b = e.into_bytes();
            b.zeroize();
            "Credential file contains invalid UTF-8 bytes.".to_string()
        })?;
        return Ok(Zeroizing::new(s));
    }

    if let Some(var_name) = custom_env {
        if let Ok(val) = std::env::var(var_name) {
            return Ok(Zeroizing::new(val));
        }
    }

    if let Ok(val) = std::env::var(default_env) {
        if !val.is_empty() || is_optional {
            return Ok(Zeroizing::new(val));
        }
    }

    if !stdin().is_terminal() {
        let mut buffer = Zeroizing::new(String::new());
        if stdin().read_line(&mut *buffer).is_ok() {
            while buffer.ends_with('\n') || buffer.ends_with('\r') {
                buffer.pop();
            }
            if !buffer.is_empty() || is_optional {
                return Ok(buffer);
            }
        }
        if is_optional {
            return Ok(Zeroizing::new(String::new()));
        }
        return Err(
            "Required credential was not provided and standard input is not a terminal."
                .to_string(),
        );
    }

    loop {
        let pass = Password::new(prompt_label)
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()
            .map_err(|_| "Operation cancelled by user.".to_string())?;
        let pass = Zeroizing::new(pass);

        if pass.trim().is_empty() {
            if is_optional {
                return Ok(Zeroizing::new(String::new()));
            }
            eprintln!(
                "{}",
                "✖ ERROR: Master Password cannot be blank or whitespace only!\n".red()
            );
            continue;
        }

        if let Some(conf_msg) = confirm_label {
            let confirm = Password::new(conf_msg)
                .with_display_mode(PasswordDisplayMode::Masked)
                .without_confirmation()
                .prompt()
                .map_err(|_| "Operation cancelled by user.".to_string())?;
            let confirm = Zeroizing::new(confirm);

            if *pass != *confirm {
                eprintln!(
                    "{}",
                    "✖ ERROR: Passwords do not match. Please try again.\n".red()
                );
                continue;
            }
        }

        return Ok(pass);
    }
}

fn create_progress_reporter(
    quiet: bool,
) -> (
    Option<ProgressBar>,
    Box<dyn Fn(u8) -> Result<(), String> + Send + Sync>,
) {
    if quiet || !std::io::stdout().is_terminal() {
        let cb = Box::new(|_| Ok(()));
        return (None, cb);
    }

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:38.cyan/blue}] {pos}% {msg}")
            .expect("Valid progress template")
            .progress_chars("━╸ "),
    );
    pb.set_message("Processing cryptographic pipeline...");

    let pb_clone = pb.clone();
    let cb = Box::new(move |percent: u8| {
        pb_clone.set_position(percent as u64);
        if percent == 100 {
            pb_clone.finish_and_clear();
        }
        Ok(())
    });

    (Some(pb), cb)
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            target,
            output_dir,
            key_dir,
            public_key,
            cipher,
            kem,
            password_file,
            password_env,
            deception_passcode_file,
            deception_passcode_env,
            quiet,
        } => {
            let target_str = target.to_string_lossy().to_string();
            print_banner("ENCRYPT (Quantum Lock)", &target_str, quiet);

            let out_dir = resolve_smart_output_dir(&target, output_dir);
            let out_dir_str = out_dir.to_string_lossy().to_string();

            let use_existing_public_key = public_key.is_some();
            let key_location = if let Some(ref pub_key) = public_key {
                pub_key.to_string_lossy().to_string()
            } else {
                let k_dir = key_dir.unwrap_or_else(|| out_dir.clone());
                k_dir.to_string_lossy().to_string()
            };

            let main_pin = fetch_credential(
                "Enter Master Password:",
                Some("Confirm Master Password:"),
                password_file.as_deref(),
                password_env.as_deref(),
                "OMBRACRYPT_PASSWORD",
                false,
            )?;

            let deception_passcode = if use_existing_public_key {
                Zeroizing::new(String::new())
            } else {
                let p = fetch_credential(
                    "Enter Deception Passcode (Press ENTER to skip):",
                    Some("Confirm Deception Passcode:"),
                    deception_passcode_file.as_deref(),
                    deception_passcode_env.as_deref(),
                    "OMBRACRYPT_DECEPTION_PASSCODE",
                    true,
                )?;
                if !p.is_empty() && *p == *main_pin {
                    return Err("Deception Passcode CANNOT match Master Password!".to_string());
                }
                p
            };

            let cancel_flag = Arc::new(AtomicBool::new(false));
            let flag_clone = cancel_flag.clone();
            ctrlc::set_handler(move || {
                flag_clone.store(true, Ordering::Relaxed);
            })
            .map_err(|e| format!("Failed to register OS signal handler: {e}"))?;

            if !quiet {
                println!(
                    "{}",
                    "▶ Initializing Streaming Cryptographic Pipeline..."
                        .bold()
                        .yellow()
                );
            }

            let (_pb, progress_cb) = create_progress_reporter(quiet);

            match pipeline::encrypt_vault(
                Some(&*progress_cb),
                &target_str,
                &out_dir_str,
                &key_location,
                use_existing_public_key,
                &cipher.to_string(),
                &kem.to_string(),
                &main_pin,
                &deception_passcode,
                Some(cancel_flag.clone()),
            ) {
                Ok(msg) => {
                    println!("\n{} {}\n", "✔".green(), msg.bold().green());
                    Ok(())
                }
                Err(e) => {
                    if cancel_flag.load(Ordering::Relaxed)
                        || e.contains("aborted by user")
                        || e.contains("cancelled by user")
                    {
                        eprintln!(
                            "\n{} Operation aborted by user. Atomic staging rollback and artifact removal completed.\n",
                            "[!]".yellow().bold()
                        );
                        Err("Operation aborted by user.".to_string())
                    } else {
                        Err(e)
                    }
                }
            }
        }

        Commands::Decrypt {
            target,
            key,
            output_dir,
            password_file,
            password_env,
            quiet,
        } => {
            let target_str = target.to_string_lossy().to_string();
            let key_str = key.to_string_lossy().to_string();
            print_banner("DECRYPT (Quantum Unlock)", &target_str, quiet);

            let out_dir = resolve_smart_output_dir(&target, output_dir);
            let out_dir_str = out_dir.to_string_lossy().to_string();

            let main_pin = fetch_credential(
                "Enter Master Password:",
                None,
                password_file.as_deref(),
                password_env.as_deref(),
                "OMBRACRYPT_PASSWORD",
                false,
            )?;

            let cancel_flag = Arc::new(AtomicBool::new(false));
            let flag_clone = cancel_flag.clone();
            ctrlc::set_handler(move || {
                flag_clone.store(true, Ordering::Relaxed);
            })
            .map_err(|e| format!("Failed to register OS signal handler: {e}"))?;

            if !quiet {
                println!(
                    "{}",
                    "▶ Authenticating Header & Initializing Decryption Engine..."
                        .bold()
                        .yellow()
                );
            }

            let (_pb, progress_cb) = create_progress_reporter(quiet);

            match pipeline::decrypt_vault(
                Some(&*progress_cb),
                &target_str,
                Some(&key_str),
                &out_dir_str,
                &main_pin,
                Some(cancel_flag.clone()),
            ) {
                Ok(msg) => {
                    println!("\n{} {}\n", "✔".green(), msg.bold().green());
                    Ok(())
                }
                Err(e) => {
                    if cancel_flag.load(Ordering::Relaxed)
                        || e.contains("aborted by user")
                        || e.contains("cancelled by user")
                    {
                        eprintln!(
                            "\n{} Operation aborted by user. Atomic staging rollback and artifact removal completed.\n",
                            "[!]".yellow().bold()
                        );
                        Err("Operation aborted by user.".to_string())
                    } else {
                        Err(e)
                    }
                }
            }
        }

        Commands::Keygen {
            name,
            output_dir,
            kem,
            deception_passcode_file,
            deception_passcode_env,
            quiet,
        } => {
            print_banner("KEYGEN (Generate Reusable Keypair)", &name, quiet);

            let out_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
            let out_dir_str = out_dir.to_string_lossy().to_string();

            let deception_passcode = fetch_credential(
                "Enter Deception Passcode for Duress Trapdoor (Press ENTER to skip):",
                Some("Confirm Deception Passcode:"),
                deception_passcode_file.as_deref(),
                deception_passcode_env.as_deref(),
                "OMBRACRYPT_DECEPTION_PASSCODE",
                true,
            )?;

            let msg = pipeline::generate_standalone_keypair(
                &out_dir_str,
                &name,
                &kem.to_string(),
                &deception_passcode,
            )?;
            println!("\n{} {}\n", "✔".green(), msg.bold().green());
            Ok(())
        }

        Commands::Clean { target_dirs, quiet } => {
            let input_dirs = if target_dirs.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                target_dirs
            };

            let mut resolved_dirs: Vec<PathBuf> = Vec::new();
            for path in input_dirs {
                let dir = if path.is_file() {
                    path.parent()
                        .map(|p| {
                            if p.as_os_str().is_empty() {
                                Path::new(".")
                            } else {
                                p
                            }
                        })
                        .unwrap_or(Path::new("."))
                        .to_path_buf()
                } else {
                    path
                };

                let canon = dir.canonicalize().unwrap_or(dir);
                if !resolved_dirs.contains(&canon) {
                    resolved_dirs.push(canon);
                }
            }

            let mut total_count = 0usize;
            let mut total_freed = 0u64;

            for dir in &resolved_dirs {
                if !quiet {
                    println!(
                        "{} {}",
                        "▶ Scanning directory for orphaned staging artifacts:".cyan(),
                        dir.display()
                    );
                }
                let (count, freed) = fs_guard::clean_scoped_staging_dir(dir)?;
                total_count += count;
                total_freed = total_freed.saturating_add(freed);
            }

            if !quiet {
                if total_count == 0 {
                    println!(
                        "{} Clean sweep finished (0 staging remnants found).",
                        "✔".green()
                    );
                } else {
                    println!(
                        "{} Successfully cleaned {} staging artifact(s) ({:.2} MB reclaimed).",
                        "✔".green(),
                        total_count,
                        total_freed as f64 / 1_048_576.0
                    );
                }
            }
            Ok(())
        }

        Commands::Inspect {
            mode,
            target,
            output_dir,
            key,
            json,
        } => {
            let mode_str = match mode {
                InspectMode::Encrypt => "ENCRYPT",
                InspectMode::Decrypt => "DECRYPT",
            };

            let out_dir = resolve_smart_output_dir(&target, output_dir);
            let target_str = target.to_string_lossy().to_string();
            let out_dir_str = out_dir.to_string_lossy().to_string();
            let key_str = key.as_ref().map(|k| k.to_string_lossy().to_string());

            let assessment = fs_guard::assess_storage_and_paths(
                mode_str,
                &target_str,
                &out_dir_str,
                key_str.as_deref(),
            )?;

            if json {
                let json_str =
                    serde_json::to_string_pretty(&assessment).unwrap_or_else(|_| "{}".to_string());
                println!("{}", json_str);
            } else {
                println!(
                    "\n{} {}",
                    "::".magenta(),
                    "OMBRACRYPT PRE-FLIGHT STORAGE ASSESSMENT".bold().cyan()
                );
                println!(
                    "{}",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        .bright_black()
                );
                println!(
                    "{} {}",
                    "▶ Mode:              ".bright_black(),
                    mode_str.bold()
                );
                println!(
                    "{} {}",
                    "▶ Target:            ".bright_black(),
                    target.display()
                );
                println!(
                    "{} {}",
                    "▶ Destination:       ".bright_black(),
                    out_dir.display()
                );
                println!(
                    "{} {:.2} MB",
                    "▶ Required Free:     ".bright_black(),
                    assessment.required_bytes as f64 / 1_048_576.0
                );
                println!(
                    "{} {:.2} MB",
                    "▶ Available Free:    ".bright_black(),
                    assessment.available_bytes as f64 / 1_048_576.0
                );
                println!(
                    "{} {}",
                    "▶ Sufficient Space:  ".bright_black(),
                    if assessment.sufficient {
                        "YES".green().bold()
                    } else {
                        "NO".red().bold()
                    }
                );
                if let Some(ref conflict) = assessment.conflict_error {
                    println!(
                        "{} {}",
                        "▶ Conflict Detected: ".red().bold(),
                        conflict.red()
                    );
                } else {
                    println!(
                        "{} {}",
                        "▶ Path Conflicts:    ".bright_black(),
                        "None (Clear)".green()
                    );
                }
                println!(
                    "{} {}",
                    "▶ Summary:           ".bright_black(),
                    assessment.summary
                );
                println!(
                    "{}",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        .bright_black()
                );
            }
            Ok(())
        }
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[!] Error: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
