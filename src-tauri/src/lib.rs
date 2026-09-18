pub mod crypto;
pub mod deception;
pub mod pipeline;

use tauri::AppHandle;
use zeroize::Zeroizing;

#[tauri::command]
async fn process_cryptography(
    app: AppHandle,
    mode: String,
    target_path: String,
    key_path: Option<String>,
    cipher: String,
    kem: String,
    main_pin: String,
    deception_passcode: String,
) -> Result<String, String> {
    // Wrap sensitive user credentials into zeroizing memory structures immediately on command entry
    let main_pin_secure = Zeroizing::new(main_pin);
    let deception_passcode_secure = Zeroizing::new(deception_passcode);
    
    if mode == "ENCRYPT" {
        pipeline::encrypt_vault(
            &app,
            &target_path,
            &cipher,
            &kem,
            &main_pin_secure,
            &deception_passcode_secure, // Pass the deception passcode down to the encryption pipeline
        )
    } else if mode == "DECRYPT" {
        pipeline::decrypt_vault(
            &app,
            &target_path,
            key_path.as_deref(),
            &main_pin_secure,
            &deception_passcode_secure,
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
        .invoke_handler(tauri::generate_handler![process_cryptography])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}