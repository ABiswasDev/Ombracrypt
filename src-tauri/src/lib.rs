pub mod crypto;
pub mod deception;
pub mod fs_guard;
pub mod pipeline;
pub mod stream;

#[cfg(test)]
mod tests;

use fs_guard::SpaceAssessment;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

pub struct AppState {
    pub cancel_flag: Arc<AtomicBool>,
}

#[tauri::command]
async fn inspect_path_space(
    mode: String,
    source_path: String,
    output_dir: String,
    key_dir_or_file: Option<String>,
) -> Result<SpaceAssessment, String> {
    fs_guard::assess_storage_and_paths(
        &mode,
        &source_path,
        &output_dir,
        key_dir_or_file.as_deref(),
    )
}

#[tauri::command]
async fn generate_keypair_files(
    output_dir: String,
    key_name: String,
    kem: String,
    deception_passcode: String,
) -> Result<String, String> {
    let deception_secure = Zeroizing::new(deception_passcode);
    pipeline::generate_standalone_keypair(&output_dir, &key_name, &kem, &deception_secure)
}

#[tauri::command]
async fn cancel_current_operation(state: State<'_, AppState>) -> Result<String, String> {
    state.cancel_flag.store(true, Ordering::Relaxed);
    Ok("Cancellation signal acknowledged.".to_string())
}

#[tauri::command]
async fn clean_staging_artifacts(paths: Vec<String>) -> Result<String, String> {
    let mut total_count = 0usize;
    let mut total_bytes = 0u64;
    let mut total_active_skipped = 0usize;
    let mut total_unowned_skipped = 0usize;
    let mut total_failed = 0usize;
    let mut failure_details: Vec<(std::path::PathBuf, String)> = Vec::new();

    for p in paths {
        let dir = Path::new(&p);
        match fs::symlink_metadata(dir) {
            Ok(meta) => {
                let target_dir = if meta.is_file() || meta.file_type().is_symlink() {
                    dir.parent().unwrap_or(dir)
                } else {
                    dir
                };
                match fs_guard::clean_scoped_staging_dir_report(target_dir) {
                    Ok(report) => {
                        total_count += report.removed_count;
                        total_bytes = total_bytes.saturating_add(report.freed_bytes);
                        total_active_skipped += report.active_skipped_count;
                        total_unowned_skipped += report.unowned_skipped_count;
                        total_failed += report.failed_count;
                        failure_details.extend(report.failed_artifacts);
                    }
                    Err(e) => {
                        return Err(format!("Failed to scan directory {}: {}", target_dir.display(), e));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!("Directory does not exist: {}", dir.display()));
            }
            Err(e) => {
                return Err(format!("Cannot inspect directory {}: {}", dir.display(), e));
            }
        }
    }

    if total_failed > 0 {
        let sample_failures: Vec<String> = failure_details
            .iter()
            .take(3)
            .map(|(path, err)| format!("{}: {}", path.display(), err))
            .collect();
        let detail_str = sample_failures.join("; ");
        let skip_note = if total_active_skipped > 0 || total_unowned_skipped > 0 {
            format!(" (also skipped {} active, {} unowned)", total_active_skipped, total_unowned_skipped)
        } else {
            String::new()
        };

        if total_count > 0 {
            Ok(format!(
                "Warning: Partially cleaned {} staging artifact(s) ({:.2} MB reclaimed), but {} artifact(s) could not be removed: {}{}",
                total_count,
                total_bytes as f64 / 1_048_576.0,
                total_failed,
                detail_str,
                skip_note
            ))
        } else {
            Err(format!(
                "Cleanup Incomplete: {} staging artifact(s) could not be removed due to permissions or locks: {}{}",
                total_failed,
                detail_str,
                skip_note
            ))
        }
    } else if total_count > 0 {
        let mut msg = format!(
            "Successfully cleaned {} staging artifact(s) ({:.2} MB reclaimed).",
            total_count,
            total_bytes as f64 / 1_048_576.0
        );
        if total_active_skipped > 0 || total_unowned_skipped > 0 {
            let mut skip_parts = Vec::new();
            if total_active_skipped > 0 {
                skip_parts.push(format!("{} active operation(s)", total_active_skipped));
            }
            if total_unowned_skipped > 0 {
                skip_parts.push(format!("{} unowned/markerless remnant(s)", total_unowned_skipped));
            }
            msg.push_str(&format!(" (Skipped: {})", skip_parts.join(", ")));
        }
        Ok(msg)
    } else if total_active_skipped > 0 || total_unowned_skipped > 0 {
        let mut skip_parts = Vec::new();
        if total_active_skipped > 0 {
            skip_parts.push(format!("{} active in-flight operation(s)", total_active_skipped));
        }
        if total_unowned_skipped > 0 {
            skip_parts.push(format!("{} unowned/markerless artifact(s) requiring manual review", total_unowned_skipped));
        }
        Ok(format!(
            "0 staging remnants removed (Skipped: {}).",
            skip_parts.join(", ")
        ))
    } else {
        Ok("Selected folders are clean (0 staging remnants found).".to_string())
    }
}

#[tauri::command]
async fn process_cryptography(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: String,
    target_path: String,
    output_dir: String,
    key_path: Option<String>,
    use_existing_public_key: bool,
    cipher: String,
    kem: String,
    main_pin: String,
    deception_passcode: String,
) -> Result<String, String> {
    state.cancel_flag.store(false, Ordering::Relaxed);
    let cancel_token = Some(state.cancel_flag.clone());

    let main_pin_secure = Zeroizing::new(main_pin);
    let deception_passcode_secure = Zeroizing::new(deception_passcode);

    if mode == "ENCRYPT" {
        let key_loc =
            key_path.ok_or("Please select a destination folder or Public Key (.obp) file.")?;
        pipeline::encrypt_vault(
            &app,
            &target_path,
            &output_dir,
            &key_loc,
            use_existing_public_key,
            &cipher,
            &kem,
            &main_pin_secure,
            &deception_passcode_secure,
            cancel_token,
        )
    } else if mode == "DECRYPT" {
        pipeline::decrypt_vault(
            &app,
            &target_path,
            key_path.as_deref(),
            &output_dir,
            &main_pin_secure,
            cancel_token,
        )
    } else {
        Err("Invalid operation mode selected.".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            cancel_flag: Arc::new(AtomicBool::new(false)),
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            process_cryptography,
            inspect_path_space,
            generate_keypair_files,
            cancel_current_operation,
            clean_staging_artifacts
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}