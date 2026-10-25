pub mod crypto;
pub mod deception;
pub mod pipeline;

use pipeline::SpaceAssessment;
use tauri::AppHandle;
use zeroize::Zeroizing;

#[tauri::command]
async fn inspect_path_space(
    mode: String,
    source_path: String,
    output_dir: String,
    key_dir_or_file: Option<String>,
) -> Result<SpaceAssessment, String> {
    pipeline::assess_storage_and_paths(
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
async fn process_cryptography(
    app: AppHandle,
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

    if mode == "ENCRYPT" {
        let key_loc = key_path.ok_or("Please select a destination folder or Public Key (.obp) file.")?;
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
        )
    } else if mode == "DECRYPT" {
        pipeline::decrypt_vault(
            &app,
            &target_path,
            key_path.as_deref(),
            &output_dir,
            &main_pin_secure,
        )
    } else {
        Err("Invalid operation mode selected.".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            process_cryptography,
            inspect_path_space,
            generate_keypair_files
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}