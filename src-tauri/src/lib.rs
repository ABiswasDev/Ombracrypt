use tauri::{AppHandle, Emitter};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use tar::{Archive, Builder};

// Standard Cryptography Imports
use argon2::Argon2;
use chacha20poly1305::{aead::{Aead, KeyInit}, XChaCha20Poly1305, XNonce};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use rand::{rngs::OsRng, RngCore};

// Post-Quantum KEM Imports
use pqcrypto_kyber::{kyber1024, kyber768};
use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};

/// Derives a 256-bit Master Key and a 16-byte salt from a user password.
/// Utilizes Argon2id with default secure parameters to prevent brute-force attacks.
fn derive_key(pin: &str) -> Result<([u8; 32], [u8; 16]), String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(pin.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Argon2 hashing failed: {}", e))?;
    Ok((key, salt))
}

/// Generates a post-quantum keypair and encapsulates a shared secret.
/// Returns a tuple containing: (Secret Key, Ciphertext, Shared Secret, KEM ID flag).
fn generate_kem(kem_choice: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u8), String> {
    if kem_choice == "cypherpunk" {
        let (pk, sk) = kyber1024::keypair();
        let (ss, ct) = kyber1024::encapsulate(&pk);
        Ok((sk.as_bytes().to_vec(), ct.as_bytes().to_vec(), ss.as_bytes().to_vec(), 2))
    } else {
        let (pk, sk) = kyber768::keypair();
        let (ss, ct) = kyber768::encapsulate(&pk);
        Ok((sk.as_bytes().to_vec(), ct.as_bytes().to_vec(), ss.as_bytes().to_vec(), 1))
    }
}

/// Core cryptographic pipeline. Routes commands from the frontend IPC bridge,
/// handles file archiving, key synthesis, and payload encryption/decryption.
#[tauri::command]
async fn process_cryptography(
    app: AppHandle,
    mode: String,
    target_path: String,
    key_path: Option<String>,
    cipher: String,
    kem: String,
    main_pin: String,
    panic_pin: String,
) -> Result<String, String> {
    
    if mode == "ENCRYPT" {
        app.emit("crypto-progress", 10).map_err(|e| e.to_string())?;

        let target_path_obj = Path::new(&target_path);
        let parent_dir = target_path_obj.parent().ok_or("Failed to find parent directory")?;
        let folder_name = target_path_obj.file_name().ok_or("Failed to get folder name")?.to_str().unwrap();
        
        let temp_tar_path = parent_dir.join(format!("{}.tmp.tar", folder_name));
        
        let tar_file = File::create(&temp_tar_path).map_err(|e| format!("Failed to create temp file: {}", e))?;
        let mut archive = Builder::new(tar_file);
        archive.append_dir_all(".", &target_path).map_err(|e| format!("Failed to bundle folder: {}", e))?;
        archive.finish().map_err(|e| format!("Failed to finish archive: {}", e))?;

        app.emit("crypto-progress", 30).map_err(|e| e.to_string())?;

        let (argon_key, salt) = derive_key(&main_pin)?;
        let (sk_bytes, ct_bytes, ss_bytes, kem_id) = generate_kem(&kem)?;
        
        let mut final_master_key = [0u8; 32];
        for i in 0..32 {
            final_master_key[i] = argon_key[i] ^ ss_bytes[i];
        }

        app.emit("crypto-progress", 50).map_err(|e| e.to_string())?;

        let mut tar_data = Vec::new();
        File::open(&temp_tar_path).map_err(|e| format!("Failed to open tar: {}", e))?
            .read_to_end(&mut tar_data).map_err(|e| format!("Failed to read tar: {}", e))?;

        let mut nonce_bytes = Vec::new();
        let encrypted_data;
        let cipher_id: u8;

        if cipher == "aes256gcm" {
            cipher_id = 2;
            let mut n = [0u8; 12];
            OsRng.fill_bytes(&mut n);
            nonce_bytes.extend_from_slice(&n);
            
            let cipher_engine = Aes256Gcm::new(&final_master_key.into());
            let nonce_obj = AesNonce::from_slice(&n);
            encrypted_data = cipher_engine.encrypt(nonce_obj, tar_data.as_ref())
                .map_err(|e| format!("AES Encryption failed: {}", e))?;
        } else {
            cipher_id = 1;
            let mut n = [0u8; 24];
            OsRng.fill_bytes(&mut n);
            nonce_bytes.extend_from_slice(&n);
            
            let cipher_engine = XChaCha20Poly1305::new(&final_master_key.into());
            let nonce_obj = XNonce::from_slice(&n);
            encrypted_data = cipher_engine.encrypt(nonce_obj, tar_data.as_ref())
                .map_err(|e| format!("XChaCha20 Encryption failed: {}", e))?;
        }

        app.emit("crypto-progress", 80).map_err(|e| e.to_string())?;

        let obk_path = parent_dir.join(format!("{}.obk", folder_name));
        let mut key_file = File::create(&obk_path).map_err(|e| format!("Failed to create key file: {}", e))?;
        key_file.write_all(&sk_bytes).map_err(|e| e.to_string())?;

        let obv_path = parent_dir.join(format!("{}.obv", folder_name));
        let mut vault_file = File::create(&obv_path).map_err(|e| format!("Failed to create vault: {}", e))?;
        
        vault_file.write_all(&[cipher_id, kem_id]).map_err(|e| e.to_string())?;
        vault_file.write_all(&salt).map_err(|e| e.to_string())?;
        
        let nonce_len = nonce_bytes.len() as u8;
        vault_file.write_all(&[nonce_len]).map_err(|e| e.to_string())?;
        vault_file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;
        
        let ct_len = ct_bytes.len() as u16;
        vault_file.write_all(&ct_len.to_le_bytes()).map_err(|e| e.to_string())?;
        vault_file.write_all(&ct_bytes).map_err(|e| e.to_string())?;
        vault_file.write_all(&encrypted_data).map_err(|e| e.to_string())?;

        fs::remove_file(&temp_tar_path).map_err(|e| format!("Failed to delete temp file: {}", e))?;

        app.emit("crypto-progress", 100).map_err(|e| e.to_string())?;
        return Ok("Operation Successful: Vault securely locked (.obv) and Quantum Key (.obk) generated.".to_string());

    } else if mode == "DECRYPT" {
        app.emit("crypto-progress", 10).map_err(|e| e.to_string())?;

        let key_path_str = key_path.ok_or("No key file (.obk) selected for decryption!")?;

        // --- PANIC PROTOCOL ---
        if !panic_pin.is_empty() && main_pin == panic_pin {
            let _ = fs::remove_file(&key_path_str);
            return Err("Security Protocol Executed: Vault key permanently deleted.".to_string());
        }
        
        // --- PHASE 1: Header Extraction ---
        let mut sk_bytes = Vec::new();
        File::open(&key_path_str).map_err(|_| "Authentication Error: Target key file (.obk) could not be located or accessed.".to_string())?
            .read_to_end(&mut sk_bytes).map_err(|_| "Integrity Error: Failed to read key file stream.".to_string())?;

        let mut vault_file = File::open(&target_path).map_err(|e| format!("Failed to open .obv: {}", e))?;
        
        let mut header_2 = [0u8; 2];
        vault_file.read_exact(&mut header_2).map_err(|e| format!("Invalid vault format: {}", e))?;
        let cipher_id = header_2[0];
        let kem_id = header_2[1];

        let mut salt = [0u8; 16];
        vault_file.read_exact(&mut salt).map_err(|e| format!("Failed to read salt: {}", e))?;
        
        let mut nonce_len_buf = [0u8; 1];
        vault_file.read_exact(&mut nonce_len_buf).map_err(|e| format!("Failed to read nonce length: {}", e))?;
        let nonce_len = nonce_len_buf[0] as usize;
        
        let mut nonce_bytes = vec![0u8; nonce_len];
        vault_file.read_exact(&mut nonce_bytes).map_err(|e| format!("Failed to read nonce: {}", e))?;
        
        let mut ct_len_buf = [0u8; 2];
        vault_file.read_exact(&mut ct_len_buf).map_err(|e| format!("Failed to read KEM length: {}", e))?;
        let ct_len = u16::from_le_bytes(ct_len_buf) as usize;
        
        let mut ct_bytes = vec![0u8; ct_len];
        vault_file.read_exact(&mut ct_bytes).map_err(|e| format!("Failed to read KEM ciphertext: {}", e))?;

        let mut encrypted_payload = Vec::new();
        vault_file.read_to_end(&mut encrypted_payload).map_err(|e| format!("Failed to read vault payload: {}", e))?;

        app.emit("crypto-progress", 30).map_err(|e| e.to_string())?;

        // --- PHASE 2: Reconstruct Master Key ---
        let mut argon_key = [0u8; 32];
        Argon2::default()
            .hash_password_into(main_pin.as_bytes(), &salt, &mut argon_key)
            .map_err(|e| format!("Argon2 hashing failed: {}", e))?;

       let ss_bytes = if kem_id == 2 {
            let sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(&sk_bytes)
                .map_err(|_| "Integrity Error: The provided key file is invalid or structurally compromised.".to_string())?;
            let ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(&ct_bytes)
                .map_err(|_| "Integrity Error: Vault header is structurally compromised.".to_string())?;
            pqcrypto_kyber::kyber1024::decapsulate(&ct, &sk).as_bytes().to_vec()
        } else {
            let sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(&sk_bytes)
                .map_err(|_| "Integrity Error: The provided key file is invalid or structurally compromised.".to_string())?;
            let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(&ct_bytes)
                .map_err(|_| "Integrity Error: Vault header is structurally compromised.".to_string())?;
            pqcrypto_kyber::kyber768::decapsulate(&ct, &sk).as_bytes().to_vec()
        };

        let mut final_master_key = [0u8; 32];
        for i in 0..32 {
            final_master_key[i] = argon_key[i] ^ ss_bytes[i];
        }

        app.emit("crypto-progress", 60).map_err(|e| e.to_string())?;

        // --- PHASE 3: Decrypt Payload ---
        let decrypted_data = if cipher_id == 2 {
            let cipher_engine = Aes256Gcm::new(&final_master_key.into());
            let nonce_obj = AesNonce::from_slice(&nonce_bytes);
            cipher_engine.decrypt(nonce_obj, encrypted_payload.as_ref())
                .map_err(|_| "Decryption Failed! Invalid password or mismatched cryptographic key.".to_string())?
        } else {
            let cipher_engine = XChaCha20Poly1305::new(&final_master_key.into());
            let nonce_obj = XNonce::from_slice(&nonce_bytes);
            cipher_engine.decrypt(nonce_obj, encrypted_payload.as_ref())
                .map_err(|_| "Decryption Failed! Invalid password or mismatched cryptographic key.".to_string())?
        };

        app.emit("crypto-progress", 80).map_err(|e| e.to_string())?;

        // --- PHASE 4: Unpack Archive ---
        let target_path_obj = Path::new(&target_path);
        let parent_dir = target_path_obj.parent().unwrap();
        let file_stem = target_path_obj.file_stem().unwrap().to_str().unwrap();
        
        let temp_tar_path = parent_dir.join(format!("{}.decrypted.tmp.tar", file_stem));
        
        let mut tar_file = File::create(&temp_tar_path).map_err(|e| format!("Failed to write decrypted data: {}", e))?;
        tar_file.write_all(&decrypted_data).map_err(|e| e.to_string())?;
        tar_file.flush().unwrap();

        let tar_file_read = File::open(&temp_tar_path).unwrap();
        let mut archive = Archive::new(tar_file_read);
        
        let out_dir = parent_dir.join(file_stem);
        fs::create_dir_all(&out_dir).unwrap();
        archive.unpack(&out_dir).map_err(|e| format!("Failed to extract vault contents: {}", e))?;

        fs::remove_file(&temp_tar_path).unwrap();

        app.emit("crypto-progress", 100).map_err(|e| e.to_string())?;
        return Ok("Operation Successful: Vault decrypted and contents securely extracted.".to_string());
    }

    Ok(String::new())
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