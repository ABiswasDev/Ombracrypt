pub mod crypto;
pub mod deception;
pub mod fs_guard;
pub mod pipeline;
pub mod stream;

#[cfg(test)]
mod tests;

use fs_guard::{CleanupReport, SpaceAssessment};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
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

/// Core synchronous aggregation engine for multi-folder staging cleanup.
/// Deduplicates folders lexically without following symlinks and continues
/// scanning subsequent directories even if one folder encounters inspection errors.
/// Returns both the structured CleanupReport and the formatted UI telemetry result.
pub fn clean_staging_artifacts_aggregated(paths: Vec<String>) -> (CleanupReport, Result<String, String>) {
    let mut aggregated_report = CleanupReport::default();
    let mut failure_details: Vec<(PathBuf, String)> = Vec::new();
    let mut seen_dirs: HashSet<PathBuf> = HashSet::new();

    for p in paths {
        let path_buf = PathBuf::from(&p);
        let target_dir = match fs::symlink_metadata(&path_buf) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    aggregated_report.failed_count = aggregated_report.failed_count.saturating_add(1);
                    if failure_details.len() < 10 {
                        failure_details.push((
                            path_buf,
                            "Refusing to scan symbolic-link directory root".to_string(),
                        ));
                    }
                    continue;
                } else if meta.is_file() {
                    path_buf.parent().unwrap_or(&path_buf).to_path_buf()
                } else {
                    path_buf
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                aggregated_report.failed_count = aggregated_report.failed_count.saturating_add(1);
                if failure_details.len() < 10 {
                    failure_details.push((
                        path_buf.clone(),
                        format!("Selected directory does not exist: {}", path_buf.display()),
                    ));
                }
                continue;
            }
            Err(e) => {
                aggregated_report.failed_count = aggregated_report.failed_count.saturating_add(1);
                if failure_details.len() < 10 {
                    failure_details.push((
                        path_buf,
                        format!("Cannot inspect directory: {}", e),
                    ));
                }
                continue;
            }
        };

        // Lexical deduplication without following symlinks
        if !seen_dirs.insert(target_dir.clone()) {
            continue;
        }

        match fs_guard::clean_scoped_staging_dir_report(&target_dir) {
            Ok(report) => {
                aggregated_report.removed_count = aggregated_report
                    .removed_count
                    .saturating_add(report.removed_count);
                aggregated_report.freed_bytes = aggregated_report
                    .freed_bytes
                    .saturating_add(report.freed_bytes);
                aggregated_report.active_skipped_count = aggregated_report
                    .active_skipped_count
                    .saturating_add(report.active_skipped_count);
                aggregated_report.unowned_skipped_count = aggregated_report
                    .unowned_skipped_count
                    .saturating_add(report.unowned_skipped_count);
                aggregated_report.failed_count = aggregated_report
                    .failed_count
                    .saturating_add(report.failed_count);
                for item in report.failed_artifacts {
                    if failure_details.len() < 10 {
                        failure_details.push(item);
                    }
                }
            }
            Err(e) => {
                aggregated_report.failed_count = aggregated_report
                    .failed_count
                    .saturating_add(1);
                if failure_details.len() < 10 {
                    failure_details.push((target_dir, e));
                }
            }
        }
    }

    aggregated_report.failed_artifacts = failure_details;

    let ui_result = if aggregated_report.failed_count > 0 {
        let sample_failures: Vec<String> = aggregated_report
            .failed_artifacts
            .iter()
            .take(3)
            .map(|(path, err)| format!("{}: {}", path.display(), err))
            .collect();
        let detail_str = sample_failures.join("; ");
        let skip_note = if aggregated_report.active_skipped_count > 0 || aggregated_report.unowned_skipped_count > 0 {
            format!(
                " (also skipped {} active, {} unowned)",
                aggregated_report.active_skipped_count, aggregated_report.unowned_skipped_count
            )
        } else {
            String::new()
        };

        if aggregated_report.removed_count > 0 {
            Ok(format!(
                "Warning: Partially cleaned {} staging artifact(s) ({:.2} MB reclaimed), but {} item(s) could not be removed or inspected: {}{}",
                aggregated_report.removed_count,
                aggregated_report.freed_bytes as f64 / 1_048_576.0,
                aggregated_report.failed_count,
                detail_str,
                skip_note
            ))
        } else {
            Err(format!(
                "Cleanup Incomplete: {} item(s) could not be removed or inspected due to permissions or errors: {}{}",
                aggregated_report.failed_count,
                detail_str,
                skip_note
            ))
        }
    } else if aggregated_report.removed_count > 0 {
        let mut msg = format!(
            "Successfully cleaned {} staging artifact(s) ({:.2} MB reclaimed).",
            aggregated_report.removed_count,
            aggregated_report.freed_bytes as f64 / 1_048_576.0
        );
        if aggregated_report.active_skipped_count > 0 || aggregated_report.unowned_skipped_count > 0 {
            let mut skip_parts = Vec::new();
            if aggregated_report.active_skipped_count > 0 {
                skip_parts.push(format!("{} active operation(s)", aggregated_report.active_skipped_count));
            }
            if aggregated_report.unowned_skipped_count > 0 {
                skip_parts.push(format!(
                    "{} unowned/markerless remnant(s)",
                    aggregated_report.unowned_skipped_count
                ));
            }
            msg.push_str(&format!(" (Skipped: {})", skip_parts.join(", ")));
        }
        Ok(msg)
    } else if aggregated_report.active_skipped_count > 0 || aggregated_report.unowned_skipped_count > 0 {
        let mut skip_parts = Vec::new();
        if aggregated_report.active_skipped_count > 0 {
            skip_parts.push(format!(
                "{} active in-flight operation(s)",
                aggregated_report.active_skipped_count
            ));
        }
        if aggregated_report.unowned_skipped_count > 0 {
            skip_parts.push(format!(
                "{} unowned/markerless artifact(s) requiring manual review",
                aggregated_report.unowned_skipped_count
            ));
        }
        Ok(format!(
            "0 staging remnants removed (Skipped: {}).",
            skip_parts.join(", ")
        ))
    } else {
        Ok("Selected folders are clean (0 staging remnants found).".to_string())
    };

    (aggregated_report, ui_result)
}

pub fn clean_staging_artifacts_report(paths: Vec<String>) -> Result<CleanupReport, String> {
    Ok(clean_staging_artifacts_aggregated(paths).0)
}

pub fn clean_staging_artifacts_core(paths: Vec<String>) -> Result<String, String> {
    clean_staging_artifacts_aggregated(paths).1
}

#[tauri::command]
async fn clean_staging_artifacts(paths: Vec<String>) -> Result<String, String> {
    clean_staging_artifacts_core(paths)
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