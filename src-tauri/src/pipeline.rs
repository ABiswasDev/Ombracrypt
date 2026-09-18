use tauri::{AppHandle, Emitter};
use std::fs::{self, File};
use std::io::{Read, Write, Seek};
use std::path::Path;
use tar::{Archive, Builder};
use zeroize::Zeroizing;

use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use rand::{rngs::OsRng, RngCore};

use crate::crypto;
use crate::deception;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB Memory Ceiling

pub fn encrypt_vault(
    app: &AppHandle,
    target_path: &str,
    cipher: &str,
    kem: &str,
    main_pin: &str,
    deception_passcode: &str, 
) -> Result<String, String> {
    app.emit("crypto-progress", 10).map_err(|e| e.to_string())?;

    let target_path_obj = Path::new(target_path);
    let parent_dir = target_path_obj.parent().ok_or("Failed to find parent directory")?;
    let folder_name = target_path_obj.file_name().ok_or("Failed to get folder name")?.to_str().ok_or("Invalid UTF-8 in folder name")?;
    
    let temp_tar_path = parent_dir.join(format!("{}.tmp.tar", folder_name));
    let tar_file = File::create(&temp_tar_path).map_err(|e| format!("Failed to create temp file: {}", e))?;
    let mut archive = Builder::new(tar_file);
    
    if let Err(e) = archive.append_dir_all(".", target_path) {
        let _ = fs::remove_file(&temp_tar_path);
        return Err(format!("Failed to bundle folder: {}", e));
    }
    if let Err(e) = archive.finish() {
        let _ = fs::remove_file(&temp_tar_path);
        return Err(format!("Failed to finish archive: {}", e));
    }

    app.emit("crypto-progress", 30).map_err(|e| e.to_string())?;

    // Derive hybrid key components (X25519 + Kyber combined via SHA-256)
    let (argon_key, salt) = crypto::derive_key(main_pin)?;
    let (sk_bytes, ct_bytes, ss_bytes, kem_id) = crypto::generate_hybrid_kem(kem)?;
    let final_master_key = crypto::compute_master_key(&argon_key, &ss_bytes);
    
    // Generate the 32-byte Phantom Block for the key file ===>Plausibly Deniable Duress Trapdoor
    let phantom_block = crypto::generate_phantom_block(deception_passcode, &salt)?;

    app.emit("crypto-progress", 50).map_err(|e| e.to_string())?;

    let mut nonce_bytes = Vec::new();
    let cipher_id: u8;

    if cipher == "aes256gcm" {
        cipher_id = 2;
        let mut n = [0u8; 12];
        OsRng.fill_bytes(&mut n);
        nonce_bytes.extend_from_slice(&n);
    } else {
        cipher_id = 1;
        let mut n = [0u8; 24];
        OsRng.fill_bytes(&mut n);
        nonce_bytes.extend_from_slice(&n);
    }

    // Write the Key File (.obk)
    let obk_path = parent_dir.join(format!("{}.obk", folder_name));
    let mut key_file = File::create(&obk_path).map_err(|e| format!("Failed to create key file: {}", e))?;
    key_file.write_all(&sk_bytes).map_err(|e| e.to_string())?;
    
    // Append the Phantom Block to the very end of the file ===> Plausibly Deniable Duress Trapdoor
    key_file.write_all(&phantom_block).map_err(|e| e.to_string())?;

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

    let mut tar_file_read = File::open(&temp_tar_path).map_err(|e| format!("Failed to open tar: {}", e))?;
    let total_size = tar_file_read.metadata().map_err(|e| e.to_string())?.len();
    
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_index = 0u64;
    let mut processed = 0u64;
    let mut last_percent = 0;

    loop {
        let bytes_read = tar_file_read.read(&mut buffer).map_err(|e| e.to_string())?;
        let is_final = if processed + (bytes_read as u64) >= total_size { 1u8 } else { 0u8 };
        
        if bytes_read == 0 && is_final == 1 && chunk_index > 0 { break; }

        let chunk_data = &buffer[..bytes_read];
        
        let mut aad = Vec::new();
        aad.extend_from_slice(&chunk_index.to_le_bytes());
        aad.push(is_final);
        
        let current_nonce = crypto::increment_nonce(&nonce_bytes, chunk_index);
        
        let encrypted_chunk = if cipher_id == 2 {
            let cipher_engine = Aes256Gcm::new(&(*final_master_key).into());
            let nonce_obj = AesNonce::from_slice(&current_nonce);
            cipher_engine.encrypt(nonce_obj, Payload { msg: chunk_data, aad: &aad })
                .map_err(|e| format!("AES Encryption failed: {}", e))?
        } else {
            let cipher_engine = XChaCha20Poly1305::new(&(*final_master_key).into());
            let nonce_obj = XNonce::from_slice(&current_nonce);
            cipher_engine.encrypt(nonce_obj, Payload { msg: chunk_data, aad: &aad })
                .map_err(|e| format!("XChaCha20 Encryption failed: {}", e))?
        };
        
        let chunk_len = encrypted_chunk.len() as u32;
        vault_file.write_all(&chunk_len.to_le_bytes()).map_err(|e| e.to_string())?;
        vault_file.write_all(&encrypted_chunk).map_err(|e| e.to_string())?;
        
        processed += bytes_read as u64;
        chunk_index += 1;
        
        let progress = 50 + ((processed as f64 / total_size.max(1) as f64) * 30.0) as u8;
        if progress > last_percent {
            let _ = app.emit("crypto-progress", progress);
            last_percent = progress;
        }
        
        if is_final == 1 { break; }
    }

    vault_file.sync_all().map_err(|e| e.to_string())?;
    fs::remove_file(&temp_tar_path).map_err(|e| format!("Failed to delete temp file: {}", e))?;

    app.emit("crypto-progress", 100).map_err(|e| e.to_string())?;
    Ok("Operation Successful: Vault securely locked (.obv) and Quantum Key (.obk) generated.".to_string())
}

pub fn decrypt_vault(
    app: &AppHandle,
    target_path: &str,
    key_path: Option<&str>,
    main_pin: &str,
    _deception_passcode: &str, 
) -> Result<String, String> {
    app.emit("crypto-progress", 10).map_err(|e| e.to_string())?;

    let key_path_str = key_path.ok_or("No key file (.obk) selected for decryption!")?;

    let mut full_obk_bytes = Vec::new();
    File::open(key_path_str)
        .map_err(|_| "Authentication Error: Target key file (.obk) could not be located or accessed.".to_string())?
        .read_to_end(&mut full_obk_bytes)
        .map_err(|_| "Integrity Error: Failed to read key file stream.".to_string())?;

    if full_obk_bytes.len() < 32 {
        return Err("Integrity Error: Key file is corrupted or structurally compromised.".to_string());
    }

    let split_index = full_obk_bytes.len() - 32;
    let sk_bytes_raw = &full_obk_bytes[..split_index];
    let phantom_block = &full_obk_bytes[split_index..];
    
    let sk_bytes = Zeroizing::new(sk_bytes_raw.to_vec());

    let mut vault_file = File::open(target_path).map_err(|e| format!("Failed to open .obv: {}", e))?;
    
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

    app.emit("crypto-progress", 30).map_err(|e| e.to_string())?;

    let argon_key = crypto::derive_key_with_salt(main_pin, &salt)?;

    // --- PHANTOM HASH VERIFICATION (THE TRAPDOOR) --- ===>Plausibly Deniable Duress Trapdoor
    if argon_key.as_slice() == phantom_block {
        return deception::trigger_dummy_scramble(key_path_str);
    }

    // Hybrid Decapsulation (Extracts both X25519 and Kyber layers)
    let ss_bytes = crypto::decapsulate_hybrid_kem(kem_id, &sk_bytes, &ct_bytes)?;
    let final_master_key = crypto::compute_master_key(&argon_key, &ss_bytes);

    app.emit("crypto-progress", 60).map_err(|e| e.to_string())?;

    let target_path_obj = Path::new(target_path);
    let parent_dir = target_path_obj.parent().ok_or("Failed to find parent directory")?;
    let file_stem = target_path_obj.file_stem().ok_or("Failed to get file stem")?.to_str().ok_or("Invalid UTF-8 in file stem")?;
    
    let temp_tar_path = parent_dir.join(format!("{}.decrypted.tmp.tar", file_stem));
    let mut tar_file_write = File::create(&temp_tar_path).map_err(|e| format!("Failed to prepare decryption temp file: {}", e))?;

    let obv_total_size = vault_file.metadata().map_err(|e| e.to_string())?.len();
    let mut obv_processed = vault_file.stream_position().map_err(|e| e.to_string())?;
    
    let mut chunk_index = 0u64;
    let mut last_percent = 0;

    loop {
        let mut len_buf = [0u8; 4];
        if vault_file.read_exact(&mut len_buf).is_err() { break; }
        
        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        let mut encrypted_chunk = vec![0u8; chunk_len];
        
        if vault_file.read_exact(&mut encrypted_chunk).is_err() {
            let _ = fs::remove_file(&temp_tar_path);
            return Err("Integrity Error: Vault was truncated or tampered with!".to_string());
        }

        obv_processed += 4 + chunk_len as u64;
        let is_final = if obv_processed >= obv_total_size { 1u8 } else { 0u8 };

        let mut aad = Vec::new();
        aad.extend_from_slice(&chunk_index.to_le_bytes());
        aad.push(is_final);
        
        let current_nonce = crypto::increment_nonce(&nonce_bytes, chunk_index);
        
        let decrypted_chunk = if cipher_id == 2 {
            let cipher_engine = Aes256Gcm::new(&(*final_master_key).into());
            let nonce_obj = AesNonce::from_slice(&current_nonce);
            match cipher_engine.decrypt(nonce_obj, Payload { msg: encrypted_chunk.as_ref(), aad: &aad }) {
                Ok(data) => data,
                Err(_) => {
                    let _ = fs::remove_file(&temp_tar_path);
                    return Err("Decryption Failed! Data corruption or mismatched cryptographic key.".to_string());
                }
            }
        } else {
            let cipher_engine = XChaCha20Poly1305::new(&(*final_master_key).into());
            let nonce_obj = XNonce::from_slice(&current_nonce);
            match cipher_engine.decrypt(nonce_obj, Payload { msg: encrypted_chunk.as_ref(), aad: &aad }) {
                Ok(data) => data,
                Err(_) => {
                    let _ = fs::remove_file(&temp_tar_path);
                    return Err("Decryption Failed! Data corruption or mismatched cryptographic key.".to_string());
                }
            }
        };
        
        tar_file_write.write_all(&decrypted_chunk).map_err(|e| e.to_string())?;
        chunk_index += 1;
        
        let progress = 60 + ((obv_processed as f64 / obv_total_size.max(1) as f64) * 20.0) as u8;
        if progress > last_percent {
            let _ = app.emit("crypto-progress", progress);
            last_percent = progress;
        }
        
        if is_final == 1 { break; }
    }

    tar_file_write.flush().map_err(|e| e.to_string())?;
    app.emit("crypto-progress", 80).map_err(|e| e.to_string())?;

    let tar_file_read = File::open(&temp_tar_path).map_err(|e| format!("Failed to read decrypted archive: {}", e))?;
    let mut archive = Archive::new(tar_file_read);
    
    let out_dir = parent_dir.join(file_stem);
    fs::create_dir_all(&out_dir).map_err(|e| format!("Failed to create output directory: {}", e))?;
    archive.unpack(&out_dir).map_err(|e| format!("Failed to extract vault contents: {}", e))?;

    fs::remove_file(&temp_tar_path).map_err(|e| format!("Failed to delete temp archive: {}", e))?;

    app.emit("crypto-progress", 100).map_err(|e| e.to_string())?;
    Ok("Operation Successful: Vault decrypted and contents securely extracted.".to_string())
}