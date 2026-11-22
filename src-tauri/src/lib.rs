pub use ombracrypt_core::{
    clean_staging_artifacts_aggregated, clean_staging_artifacts_core,
    clean_staging_artifacts_report, crypto, deception, fs_guard, pipeline, stream,
};

use ombracrypt_core::fs_guard::SpaceAssessment;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroizing;

pub struct AppState {
    active_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            active_cancel: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

struct ActiveOperationGuard {
    slot: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

impl Drop for ActiveOperationGuard {
    fn drop(&mut self) {
        let mut guard = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }
}

fn acquire_operation_slot(
    state: &AppState,
) -> Result<(Arc<AtomicBool>, ActiveOperationGuard), String> {
    let mut guard = state
        .active_cancel
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return Err(
            "Another cryptographic operation is already in progress. Wait for it to finish or cancel it first."
                .to_string(),
        );
    }
    let cancel_flag = Arc::new(AtomicBool::new(false));
    *guard = Some(Arc::clone(&cancel_flag));
    Ok((
        cancel_flag,
        ActiveOperationGuard {
            slot: Arc::clone(&state.active_cancel),
        },
    ))
}

#[tauri::command]
async fn inspect_path_space(
    mode: String,
    source_path: String,
    output_dir: String,
    key_dir_or_file: Option<String>,
) -> Result<SpaceAssessment, String> {
    tauri::async_runtime::spawn_blocking(move || {
        fs_guard::assess_storage_and_paths(
            &mode,
            &source_path,
            &output_dir,
            key_dir_or_file.as_deref(),
        )
    })
    .await
    .map_err(|e| format!("Storage inspection task failed: {e}"))?
}

#[tauri::command]
async fn generate_keypair_files(
    state: State<'_, AppState>,
    output_dir: String,
    key_name: String,
    kem: String,
    deception_passcode: String,
) -> Result<String, String> {
    let deception_secure = Zeroizing::new(deception_passcode);
    let (_cancel_flag, op_guard) = acquire_operation_slot(&state)?;

    tauri::async_runtime::spawn_blocking(move || {
        let _guard = op_guard;
        pipeline::generate_standalone_keypair(&output_dir, &key_name, &kem, &deception_secure)
    })
    .await
    .map_err(|e| format!("Key generation task failed: {e}"))?
}

#[tauri::command]
async fn cancel_current_operation(state: State<'_, AppState>) -> Result<String, String> {
    let guard = state
        .active_cancel
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(flag) = guard.as_ref() {
        flag.store(true, Ordering::Relaxed);
        Ok("Cancellation signal acknowledged.".to_string())
    } else {
        Ok("No active operation to cancel.".to_string())
    }
}

#[tauri::command]
async fn clean_staging_artifacts(paths: Vec<String>) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || clean_staging_artifacts_core(paths))
        .await
        .map_err(|e| format!("Staging cleanup task failed: {e}"))?
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
    let main_pin_secure = Zeroizing::new(main_pin);
    let deception_passcode_secure = Zeroizing::new(deception_passcode);
    let (cancel_flag, op_guard) = acquire_operation_slot(&state)?;

    tauri::async_runtime::spawn_blocking(move || {
        let _guard = op_guard;
        let cancel_token = Some(cancel_flag);
        let progress_cb = |progress: u8| -> Result<(), String> {
            app.emit("crypto-progress", progress)
                .map_err(|e| e.to_string())
        };

        if mode == "ENCRYPT" {
            let key_loc =
                key_path.ok_or("Please select a destination folder or Public Key (.obp) file.")?;
            pipeline::encrypt_vault(
                Some(&progress_cb),
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
                Some(&progress_cb),
                &target_path,
                key_path.as_deref(),
                &output_dir,
                &main_pin_secure,
                cancel_token,
            )
        } else {
            Err("Invalid operation mode selected.".to_string())
        }
    })
    .await
    .map_err(|e| format!("Cryptographic worker task failed: {e}"))?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::new())
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