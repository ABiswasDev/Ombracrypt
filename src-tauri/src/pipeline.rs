use rand::{rngs::OsRng, RngCore};
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tar::{Archive, Builder};
use tauri::AppHandle;
use zeroize::Zeroizing;

use crate::crypto;
use crate::deception;
use crate::fs_guard::{
    assess_storage_and_paths, create_private_staging_file, create_public_staging_file,
    create_secure_staging_dir, read_bounded_key_file, sync_parent_directory, unique_staging_path,
    verify_no_source_overlap, CommitRollbackGuard, TempDirGuard, TempFileGuard,
};
use crate::stream::{
    build_and_hash_header, emit_progress, extract_tar_archive_safely, parse_and_validate_header,
    ChunkedDecryptReader, ChunkedEncryptWriter, CHUNK_SIZE,
};

/// Standalone helper to generate a reusable Group/Individual Keypair (.obp Public + .obk Private)
pub fn generate_standalone_keypair(
    output_dir: &str,
    key_name: &str,
    kem: &str,
    deception_passcode: &str,
) -> Result<String, String> {
    let out_dir_path = Path::new(output_dir);
    if !out_dir_path.exists() || !out_dir_path.is_dir() {
        return Err("Selected key output directory does not exist.".to_string());
    }

    let safe_stem = Path::new(key_name.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid keypair name.")?;

    let obp_final = out_dir_path.join(format!("{}.obp", safe_stem));
    let obk_final = out_dir_path.join(format!("{}.obk", safe_stem));

    if obp_final.exists() || obk_final.exists() {
        return Err(format!(
            "Key files for '{}' already exist in the selected directory.",
            safe_stem
        ));
    }

    let obp_part = unique_staging_path(out_dir_path, &format!("{}.obp", safe_stem));
    let obk_part = unique_staging_path(out_dir_path, &format!("{}.obk", safe_stem));

    let mut stage_guard = TempFileGuard::new(vec![obp_part.clone(), obk_part.clone()]);

    let (obp_bytes, obk_bytes, _) = crypto::generate_keypair_blobs(kem, deception_passcode)?;
    let key_fp = crypto::compute_obp_fingerprint(&obp_bytes)?;

    let mut obp_file = create_public_staging_file(&obp_part)?;
    obp_file.write_all(&obp_bytes).map_err(|e| e.to_string())?;
    obp_file.sync_all().map_err(|e| e.to_string())?;
    drop(obp_file);

    let mut obk_file = create_private_staging_file(&obk_part)?;
    obk_file.write_all(&obk_bytes).map_err(|e| e.to_string())?;
    obk_file.sync_all().map_err(|e| e.to_string())?;
    drop(obk_file);

    let mut commit_guard = CommitRollbackGuard::new();
    commit_guard.commit_file(&obk_part, &obk_final)?;
    commit_guard.commit_file(&obp_part, &obp_final)?;
    commit_guard.disarm();
    stage_guard.disarm();
    sync_parent_directory(out_dir_path);

    Ok(format!(
        "Generated Keypair ({}.obp + {}.obk) | Key ID: {}",
        safe_stem, safe_stem, key_fp
    ))
}

/// Tauri wrapper for encryption
pub fn encrypt_vault(
    app: &AppHandle,
    target_path: &str,
    vault_output_dir: &str,
    key_location: &str,
    use_existing_public_key: bool,
    cipher: &str,
    kem: &str,
    main_pin: &str,
    deception_passcode: &str,
    cancellation_token: Option<Arc<AtomicBool>>,
) -> Result<String, String> {
    encrypt_vault_core(
        Some(app),
        target_path,
        vault_output_dir,
        key_location,
        use_existing_public_key,
        cipher,
        kem,
        main_pin,
        deception_passcode,
        cancellation_token,
    )
}

/// Core On-the-Fly Streaming Encryption Pipeline
pub fn encrypt_vault_core(
    app: Option<&AppHandle>,
    target_path: &str,
    vault_output_dir: &str,
    key_location: &str,
    use_existing_public_key: bool,
    cipher: &str,
    kem: &str,
    main_pin: &str,
    deception_passcode: &str,
    cancellation_token: Option<Arc<AtomicBool>>,
) -> Result<String, String> {
    if main_pin.trim().is_empty() {
        return Err("Security Error: Master Password cannot be empty or whitespace only.".to_string());
    }
    if !deception_passcode.trim().is_empty() && main_pin == deception_passcode {
        return Err("Security Error: Deception passcode cannot match Master Password.".to_string());
    }

    emit_progress(app, 5)?;

    let (cipher_id, nonce_len) = match cipher {
        "xchacha20" => (1u8, 24usize),
        "aes256gcm" => (2u8, 12usize),
        _ => return Err(format!("Security Error: Unsupported cipher algorithm '{}'.", cipher)),
    };
    if !use_existing_public_key && kem != "xwing" && kem != "cypherpunk" {
        return Err(format!("Security Error: Unsupported KEM algorithm '{}'.", kem));
    }

    let target_path_obj = Path::new(target_path);
    let vault_out_obj = Path::new(vault_output_dir);

    let check =
        assess_storage_and_paths("ENCRYPT", target_path, vault_output_dir, Some(key_location))?;
    if !check.sufficient {
        return Err(format!("Insufficient Disk Space! {}", check.summary));
    }
    if let Some(conflict) = check.conflict_error {
        return Err(conflict);
    }

    verify_no_source_overlap(target_path_obj, vault_out_obj, "Vault Output")?;
    if !use_existing_public_key {
        verify_no_source_overlap(target_path_obj, Path::new(key_location), "Key Output")?;
    }

    let folder_name = target_path_obj
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Failed to resolve source folder name.")?;

    let uncompressed_bytes = check.raw_bytes;
    let estimated_tar_size = uncompressed_bytes
        .saturating_add(check.item_count.saturating_mul(512))
        .max(1024);

    emit_progress(app, 15)?;

    let (argon_key, salt) = crypto::derive_key(main_pin)?;

    let (ct_bytes, ss_bytes, kem_id, key_fp, generated_keys) = if use_existing_public_key {
        let obp_raw = read_bounded_key_file(key_location, "Public Key (.obp)")?;
        let fp = crypto::compute_obp_fingerprint(&obp_raw)?;
        let (ct, ss, kid) = crypto::encapsulate_with_obp(&obp_raw)?;
        (ct, ss, kid, fp, None)
    } else {
        let (obp_bytes, obk_bytes, kid) =
            crypto::generate_keypair_blobs(kem, deception_passcode)?;
        let fp = crypto::compute_obp_fingerprint(&obp_bytes)?;
        let (ct, ss, _) = crypto::encapsulate_with_obp(&obp_bytes)?;
        (ct, ss, kid, fp, Some((obp_bytes, obk_bytes)))
    };

    let final_master_key = crypto::compute_master_key(&argon_key, &ss_bytes, &salt)?;

    let mut nonce_bytes = vec![0u8; nonce_len];
    OsRng.fill_bytes(&mut nonce_bytes);

    let obv_final = vault_out_obj.join(format!("{}.obv", folder_name));
    let obv_part = unique_staging_path(vault_out_obj, &format!("{}.obv", folder_name));

    let mut staged_paths = vec![obv_part.clone()];
    let mut key_targets: Option<(PathBuf, PathBuf, PathBuf, PathBuf)> = None;

    if generated_keys.is_some() {
        let key_dir = Path::new(key_location);
        if !key_dir.exists() || !key_dir.is_dir() {
            return Err("Selected key destination directory does not exist.".to_string());
        }
        let obk_final = key_dir.join(format!("{}.obk", folder_name));
        let obp_final = key_dir.join(format!("{}.obp", folder_name));
        let obk_part = unique_staging_path(key_dir, &format!("{}.obk", folder_name));
        let obp_part = unique_staging_path(key_dir, &format!("{}.obp", folder_name));

        staged_paths.push(obk_part.clone());
        staged_paths.push(obp_part.clone());
        key_targets = Some((obk_part, obk_final, obp_part, obp_final));
    }

    let mut stage_guard = TempFileGuard::new(staged_paths);

    if let (Some((obp_bytes, obk_bytes)), Some((ref obk_part, _, ref obp_part, _))) =
        (generated_keys, &key_targets)
    {
        let mut obk_file = create_private_staging_file(obk_part)?;
        obk_file.write_all(&obk_bytes).map_err(|e| e.to_string())?;
        obk_file.sync_all().map_err(|e| e.to_string())?;

        let mut obp_file = create_public_staging_file(obp_part)?;
        obp_file.write_all(&obp_bytes).map_err(|e| e.to_string())?;
        obp_file.sync_all().map_err(|e| e.to_string())?;
    }

    let (header_bytes, header_hash) = build_and_hash_header(
        cipher_id,
        kem_id,
        uncompressed_bytes,
        &salt,
        &nonce_bytes,
        &ct_bytes,
    );

    let mut vault_file = create_public_staging_file(&obv_part)?;
    vault_file
        .write_all(&header_bytes)
        .map_err(|e| e.to_string())?;

    emit_progress(app, 30)?;

    let encrypt_writer = ChunkedEncryptWriter {
        inner: vault_file,
        cipher_id,
        master_key: final_master_key,
        base_nonce: nonce_bytes,
        header_hash,
        buffer: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE)),
        chunk_index: 0,
        processed_bytes: 0,
        total_expected: estimated_tar_size,
        app,
        last_percent: 30,
        cancellation_token: cancellation_token.clone(),
    };

    let mut tar_builder = Builder::new(encrypt_writer);
    tar_builder.follow_symlinks(false);

    if let Err(e) = tar_builder.append_dir_all(".", target_path_obj) {
        if let Some(ref token) = cancellation_token {
            if token.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("Operation aborted by user.".to_string());
            }
        }
        let s = e.to_string();
        if s.contains("Operation aborted by user") {
            return Err("Operation aborted by user.".to_string());
        }
        return Err(format!("Failed to stream folder into encrypted archive: {}", s));
    }

    let encrypt_writer = match tar_builder.into_inner() {
        Ok(w) => w,
        Err(e) => {
            if let Some(ref token) = cancellation_token {
                if token.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err("Operation aborted by user.".to_string());
                }
            }
            let s = e.to_string();
            if s.contains("Operation aborted by user") {
                return Err("Operation aborted by user.".to_string());
            }
            return Err(format!("Failed to finalize TAR stream: {}", s));
        }
    };

    let vault_file = match encrypt_writer.finalize() {
        Ok(f) => f,
        Err(e) => {
            if let Some(ref token) = cancellation_token {
                if token.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err("Operation aborted by user.".to_string());
                }
            }
            let s = e.to_string();
            if s.contains("Operation aborted by user") {
                return Err("Operation aborted by user.".to_string());
            }
            return Err(format!("Failed to finalize encrypted stream: {}", s));
        }
    };

    vault_file.sync_all().map_err(|e| e.to_string())?;
    drop(vault_file);

    let mut commit_guard = CommitRollbackGuard::new();
    if let Some((obk_part, obk_final, obp_part, obp_final)) = key_targets {
        commit_guard.commit_file(&obk_part, &obk_final)?;
        commit_guard.commit_file(&obp_part, &obp_final)?;
        sync_parent_directory(Path::new(key_location));
    }
    commit_guard.commit_file(&obv_part, &obv_final)?;
    sync_parent_directory(vault_out_obj);

    commit_guard.disarm();
    stage_guard.disarm();

    let _ = emit_progress(app, 100);
    if use_existing_public_key {
        Ok(format!(
            "Operation Successful: Vault sealed (.obv) with Public Key [Key ID: {}].",
            key_fp
        ))
    } else {
        Ok(format!(
            "Operation Successful: Vault locked (.obv) & Keypair generated [Key ID: {}].",
            key_fp
        ))
    }
}

/// Tauri wrapper for decryption
pub fn decrypt_vault(
    app: &AppHandle,
    vault_path: &str,
    key_path: Option<&str>,
    output_dir: &str,
    main_pin: &str,
    cancellation_token: Option<Arc<AtomicBool>>,
) -> Result<String, String> {
    decrypt_vault_core(
        Some(app),
        vault_path,
        key_path,
        output_dir,
        main_pin,
        cancellation_token,
    )
}

/// Core On-the-Fly Streaming Decryption Pipeline
pub fn decrypt_vault_core(
    app: Option<&AppHandle>,
    vault_path: &str,
    key_path: Option<&str>,
    output_dir: &str,
    main_pin: &str,
    cancellation_token: Option<Arc<AtomicBool>>,
) -> Result<String, String> {
    emit_progress(app, 10)?;

    let key_path_str = key_path.ok_or("No Private Key (.obk) selected for decryption!")?;

    let full_obk_bytes = read_bounded_key_file(key_path_str, "Private Key (.obk)")?;

    let mut vault_file =
        File::open(vault_path).map_err(|e| format!("Failed to open .obv: {}", e))?;
    let total_vault_len = vault_file.metadata().map_err(|e| e.to_string())?.len();

    let header = parse_and_validate_header(&mut vault_file)?;

    let check = assess_storage_and_paths("DECRYPT", vault_path, output_dir, Some(key_path_str))?;
    if !check.sufficient {
        return Err(format!(
            "Insufficient Disk Space to extract vault! {}",
            check.summary
        ));
    }
    if let Some(conflict) = check.conflict_error {
        return Err(conflict);
    }

    emit_progress(app, 25)?;

    let (duress_triggered, ss_opt) = crypto::decapsulate_with_obk(
        header.kem_id,
        &full_obk_bytes,
        &header.ct_bytes,
        main_pin,
    )?;

    if duress_triggered {
        return deception::trigger_dummy_scramble(key_path_str);
    }

    let ss_bytes = ss_opt.ok_or("Decapsulation failed.")?;
    let argon_key = crypto::derive_key_with_params(
        main_pin,
        &header.salt,
        header.m_cost,
        header.t_cost,
        header.p_cost,
    )?;
    let final_master_key = crypto::compute_master_key(&argon_key, &ss_bytes, &header.salt)?;

    emit_progress(app, 40)?;

    let vault_path_obj = Path::new(vault_path);
    let out_dir_obj = Path::new(output_dir);
    let file_stem = vault_path_obj
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("Invalid vault filename.")?;

    let final_extract_dir = out_dir_obj.join(file_stem);
    let stage_dir = create_secure_staging_dir(out_dir_obj, file_stem)?;
    let mut dir_guard = TempDirGuard::new(stage_dir.clone());

    let header_end_pos = vault_file.stream_position().map_err(|e| e.to_string())?;
    let vault_body_size = total_vault_len.saturating_sub(header_end_pos);

    let decrypt_reader = ChunkedDecryptReader {
        inner: vault_file,
        cipher_id: header.cipher_id,
        master_key: final_master_key,
        base_nonce: header.nonce_bytes,
        header_hash: header.header_hash,
        buffer: Zeroizing::new(Vec::new()),
        read_pos: 0,
        chunk_index: 0,
        bytes_read_from_vault: 0,
        vault_body_size,
        reached_final_chunk: false,
        app,
        last_percent: 40,
        cancellation_token: cancellation_token.clone(),
    };

    let mut archive = Archive::new(decrypt_reader);
    let max_permitted_bytes = header.uncompressed_bytes.saturating_add(1024 * 1024);

    if let Err(e) = extract_tar_archive_safely(&mut archive, &stage_dir, max_permitted_bytes) {
        if let Some(ref token) = cancellation_token {
            if token.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("Operation aborted by user.".to_string());
            }
        }
        if e.contains("Operation aborted by user") {
            return Err("Operation aborted by user.".to_string());
        }
        return Err(e);
    }

    let mut reader = archive.into_inner();
    let mut drain = [0u8; 1024];
    while match reader.read(&mut drain) {
        Ok(n) => n > 0,
        Err(e) => {
            if let Some(ref token) = cancellation_token {
                if token.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err("Operation aborted by user.".to_string());
                }
            }
            let s = e.to_string();
            if s.contains("Operation aborted by user") {
                return Err("Operation aborted by user.".to_string());
            }
            return Err(s);
        }
    } {}

    if let Some(ref token) = cancellation_token {
        if token.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("Operation aborted by user.".to_string());
        }
    }

    if !reader.reached_final_chunk {
        return Err(
            "Integrity Error: Vault stream ended without a verified final chunk tag.".to_string(),
        );
    }

    if final_extract_dir.exists() {
        return Err(format!(
            "Refusing to overwrite existing destination directory: {}",
            final_extract_dir.display()
        ));
    }
    fs::rename(&stage_dir, &final_extract_dir)
        .map_err(|e| format!("Failed to finalize extracted output directory: {}", e))?;
    sync_parent_directory(&final_extract_dir);
    sync_parent_directory(out_dir_obj);
    dir_guard.disarm();

    let _ = emit_progress(app, 100);
    Ok("Operation Successful: Vault authenticated and extracted directly in memory.".to_string())
}