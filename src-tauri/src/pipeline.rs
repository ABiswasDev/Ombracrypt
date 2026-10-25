use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use fs2::available_space;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use tar::{Archive, Builder, EntryType};
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

use crate::crypto;
use crate::deception;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB Streaming Ceiling
const VAULT_MAGIC: &[u8; 5] = b"OMBV\x02";

#[derive(Serialize)]
pub struct SpaceAssessment {
    pub required_bytes: u64,
    pub available_bytes: u64,
    pub sufficient: bool,
    pub conflict_error: Option<String>,
    pub summary: String,
}

fn emit_progress(app: Option<&AppHandle>, progress: u8) -> Result<(), String> {
    if let Some(handle) = app {
        handle
            .emit("crypto-progress", progress)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Flushes directory metadata to disk/USB so newly renamed files/folders appear immediately
fn sync_parent_directory(dir: &Path) {
    if let Ok(dir_handle) = File::open(dir) {
        let _ = dir_handle.sync_all();
    }
}

/// RAII Guard that automatically removes partial files on error or early return
struct TempFileGuard {
    paths: Vec<PathBuf>,
    armed: bool,
}

impl TempFileGuard {
    fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            for p in &self.paths {
                let _ = fs::remove_file(p);
            }
        }
    }
}

/// RAII Guard that automatically wipes the temporary extraction staging folder on decryption failure
struct TempDirGuard {
    path: PathBuf,
    armed: bool,
}

impl TempDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if self.armed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Recursively calculates total payload bytes and file count while rejecting symlinks
pub fn calculate_dir_metrics(path: &Path) -> Result<(u64, u64), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("Cannot access path: {}", e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("Symlinks are restricted for security: {:?}", path));
    }
    if meta.is_file() {
        return Ok((meta.len(), 1));
    }
    let mut total_bytes = 0u64;
    let mut count = 1u64;
    for entry in fs::read_dir(path).map_err(|e| format!("Failed to read directory: {}", e))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let (b, c) = calculate_dir_metrics(&entry.path())?;
        total_bytes = total_bytes.saturating_add(b);
        count = count.saturating_add(c);
    }
    Ok((total_bytes, count))
}

/// Reads the uncompressed payload size stored inside an OMBV v2 vault header
pub fn read_vault_uncompressed_size(vault_path: &Path) -> Result<u64, String> {
    let mut file = File::open(vault_path).map_err(|e| format!("Failed to open vault: {}", e))?;
    let mut magic = [0u8; 5];
    file.read_exact(&mut magic)
        .map_err(|_| "Invalid or truncated vault header.".to_string())?;
    if &magic != VAULT_MAGIC {
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        return Ok(len);
    }
    // Skip cipher_id (1) + kem_id (1) + m_cost (4) + t_cost (4) + p_cost (4) = 14 bytes
    file.seek(SeekFrom::Current(14))
        .map_err(|e| e.to_string())?;
    let mut size_buf = [0u8; 8];
    file.read_exact(&mut size_buf).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(size_buf))
}

/// Pre-flight capacity & path collision check for both Encryption and Decryption modes
pub fn assess_storage_and_paths(
    mode: &str,
    source_path: &str,
    output_dir: &str,
    key_dir_or_file: Option<&str>,
) -> Result<SpaceAssessment, String> {
    let src = Path::new(source_path);
    let out = Path::new(output_dir);

    if !src.exists() {
        return Err("Selected source path does not exist.".to_string());
    }
    if !out.exists() || !out.is_dir() {
        return Err("Selected output destination must be an existing directory.".to_string());
    }

    let avail = available_space(out)
        .map_err(|e| format!("Failed to query destination free space: {}", e))?;

    if mode == "ENCRYPT" {
        let (raw_bytes, item_count) = calculate_dir_metrics(src)?;
        let tar_overhead = item_count.saturating_mul(1024).saturating_add(2048);
        let estimated_stream = raw_bytes.saturating_add(tar_overhead);
        let chunks = (estimated_stream / (CHUNK_SIZE as u64)) + 1;
        let required = estimated_stream
            .saturating_add(chunks * 28)
            .saturating_add(65_536);

        let folder_name = src
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid source folder name.")?;

        let target_obv = out.join(format!("{}.obv", folder_name));
        let mut conflict = None;
        if target_obv.exists() {
            conflict = Some(format!(
                "Vault '{}' already exists in the output directory.",
                target_obv.display()
            ));
        }

        if conflict.is_none() {
            if let Some(k_path) = key_dir_or_file {
                let kp = Path::new(k_path);
                if kp.is_dir() {
                    let obk = kp.join(format!("{}.obk", folder_name));
                    let obp = kp.join(format!("{}.obp", folder_name));
                    if obk.exists() || obp.exists() {
                        conflict = Some(format!(
                            "Key file (.obk/.obp) for '{}' already exists in the selected key directory.",
                            folder_name
                        ));
                    }
                }
            }
        }

        let sufficient = avail >= required;
        let summary = format!(
            "Required: {:.2} MB | Available: {:.2} MB",
            required as f64 / 1_048_576.0,
            avail as f64 / 1_048_576.0
        );

        Ok(SpaceAssessment {
            required_bytes: required,
            available_bytes: avail,
            sufficient,
            conflict_error: conflict,
            summary,
        })
    } else {
        let uncompressed = read_vault_uncompressed_size(src)?;
        let required = uncompressed.saturating_add(65_536);

        let stem = src
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("Invalid vault filename.")?;
        let final_extract_dir = out.join(stem);
        let conflict = if final_extract_dir.exists() {
            Some(format!(
                "Destination '{}' already exists in the output folder.",
                final_extract_dir.display()
            ))
        } else {
            None
        };

        let sufficient = avail >= required;
        let summary = format!(
            "Required: {:.2} MB | Available: {:.2} MB",
            required as f64 / 1_048_576.0,
            avail as f64 / 1_048_576.0
        );

        Ok(SpaceAssessment {
            required_bytes: required,
            available_bytes: avail,
            sufficient,
            conflict_error: conflict,
            summary,
        })
    }
}

/// Custom In-Memory Streaming AEAD Writer (Zero .tmp.tar written to disk)
struct ChunkedEncryptWriter<'a, W: Write> {
    inner: W,
    cipher_id: u8,
    master_key: Zeroizing<[u8; 32]>,
    base_nonce: Vec<u8>,
    header_hash: [u8; 32],
    buffer: Zeroizing<Vec<u8>>,
    chunk_index: u64,
    processed_bytes: u64,
    total_expected: u64,
    app: Option<&'a AppHandle>,
    last_percent: u8,
}

impl<'a, W: Write> ChunkedEncryptWriter<'a, W> {
    fn encrypt_and_flush_chunk(&mut self, is_final: u8) -> std::io::Result<()> {
        let mut aad = Vec::with_capacity(32 + 8 + 1);
        aad.extend_from_slice(&self.header_hash);
        aad.extend_from_slice(&self.chunk_index.to_le_bytes());
        aad.push(is_final);

        let current_nonce = crypto::increment_nonce(&self.base_nonce, self.chunk_index);

        let encrypted_chunk = if self.cipher_id == 2 {
            let engine = Aes256Gcm::new(&(*self.master_key).into());
            let nonce_obj = AesNonce::from_slice(&current_nonce);
            engine
                .encrypt(
                    nonce_obj,
                    Payload {
                        msg: &self.buffer,
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::Other, "AES-256-GCM encryption failed")
                })?
        } else {
            let engine = XChaCha20Poly1305::new(&(*self.master_key).into());
            let nonce_obj = XNonce::from_slice(&current_nonce);
            engine
                .encrypt(
                    nonce_obj,
                    Payload {
                        msg: &self.buffer,
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "XChaCha20-Poly1305 encryption failed",
                    )
                })?
        };

        let chunk_len = encrypted_chunk.len() as u32;
        self.inner.write_all(&chunk_len.to_le_bytes())?;
        self.inner.write_all(&encrypted_chunk)?;

        self.processed_bytes = self
            .processed_bytes
            .saturating_add(self.buffer.len() as u64);
        self.buffer.clear();
        self.chunk_index += 1;

        let ratio = (self.processed_bytes as f64 / self.total_expected.max(1) as f64).min(1.0);
        let progress = 30 + (ratio * 65.0) as u8;
        if progress > self.last_percent {
            let _ = emit_progress(self.app, progress);
            self.last_percent = progress;
        }

        Ok(())
    }

    fn finalize(mut self) -> std::io::Result<W> {
        self.encrypt_and_flush_chunk(1u8)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<'a, W: Write> Write for ChunkedEncryptWriter<'a, W> {
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let total_incoming = buf.len();
        while !buf.is_empty() {
            if self.buffer.len() == CHUNK_SIZE {
                self.encrypt_and_flush_chunk(0u8)?;
            }
            let space = CHUNK_SIZE - self.buffer.len();
            let to_copy = space.min(buf.len());
            self.buffer.extend_from_slice(&buf[..to_copy]);
            buf = &buf[to_copy..];
        }
        Ok(total_incoming)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Custom In-Memory Streaming AEAD Reader (Streams decrypted TAR chunks directly in RAM)
struct ChunkedDecryptReader<'a, R: Read> {
    inner: R,
    cipher_id: u8,
    master_key: Zeroizing<[u8; 32]>,
    base_nonce: Vec<u8>,
    header_hash: [u8; 32],
    buffer: Zeroizing<Vec<u8>>,
    read_pos: usize,
    chunk_index: u64,
    bytes_read_from_vault: u64,
    vault_body_size: u64,
    reached_final_chunk: bool,
    app: Option<&'a AppHandle>,
    last_percent: u8,
}

impl<'a, R: Read> ChunkedDecryptReader<'a, R> {
    fn load_next_chunk(&mut self) -> std::io::Result<bool> {
        if self.reached_final_chunk {
            return Ok(false);
        }

        let mut len_buf = [0u8; 4];
        match self.inner.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Integrity Error: Vault stream ended prematurely before final authentication tag.",
                ));
            }
            Err(e) => return Err(e),
        }

        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        if chunk_len == 0 || chunk_len > CHUNK_SIZE + 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Integrity Error: Malformed encrypted chunk size in vault.",
            ));
        }

        let mut encrypted_chunk = vec![0u8; chunk_len];
        self.inner.read_exact(&mut encrypted_chunk).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Integrity Error: Vault was truncated mid-chunk.",
            )
        })?;

        self.bytes_read_from_vault += 4 + chunk_len as u64;
        let is_final = if self.bytes_read_from_vault >= self.vault_body_size {
            1u8
        } else {
            0u8
        };

        let mut aad = Vec::with_capacity(32 + 8 + 1);
        aad.extend_from_slice(&self.header_hash);
        aad.extend_from_slice(&self.chunk_index.to_le_bytes());
        aad.push(is_final);

        let current_nonce = crypto::increment_nonce(&self.base_nonce, self.chunk_index);

        let decrypted = if self.cipher_id == 2 {
            let engine = Aes256Gcm::new(&(*self.master_key).into());
            let nonce_obj = AesNonce::from_slice(&current_nonce);
            engine
                .decrypt(
                    nonce_obj,
                    Payload {
                        msg: &encrypted_chunk,
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Decryption Failed! Data corruption or mismatched cryptographic key.",
                    )
                })?
        } else {
            let engine = XChaCha20Poly1305::new(&(*self.master_key).into());
            let nonce_obj = XNonce::from_slice(&current_nonce);
            engine
                .decrypt(
                    nonce_obj,
                    Payload {
                        msg: &encrypted_chunk,
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Decryption Failed! Data corruption or mismatched cryptographic key.",
                    )
                })?
        };

        self.buffer = Zeroizing::new(decrypted);
        self.read_pos = 0;
        self.chunk_index += 1;

        if is_final == 1 {
            self.reached_final_chunk = true;
        }

        let ratio =
            (self.bytes_read_from_vault as f64 / self.vault_body_size.max(1) as f64).min(1.0);
        let progress = 40 + (ratio * 55.0) as u8;
        if progress > self.last_percent {
            let _ = emit_progress(self.app, progress);
            self.last_percent = progress;
        }

        Ok(true)
    }
}

impl<'a, R: Read> Read for ChunkedDecryptReader<'a, R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.read_pos >= self.buffer.len() {
            let has_more = self.load_next_chunk()?;
            if !has_more {
                return Ok(0);
            }
        }
        let available = self.buffer.len() - self.read_pos;
        let to_copy = available.min(out.len());
        out[..to_copy].copy_from_slice(&self.buffer[self.read_pos..self.read_pos + to_copy]);
        self.read_pos += to_copy;
        Ok(to_copy)
    }
}

/// Validates TAR entry paths to prevent Zip-Slip / Directory Traversal (`..`) attacks
pub fn sanitize_tar_path(entry_path: &Path) -> Result<PathBuf, String> {
    let mut clean = PathBuf::new();
    for comp in entry_path.components() {
        match comp {
            Component::Normal(c) => clean.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "Security Alert: Blocked unsafe path traversal inside archive ({:?})",
                    entry_path
                ));
            }
        }
    }
    Ok(clean)
}

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

    // Use dot-prefixed hidden staging files (.part)
    let obp_part = out_dir_path.join(format!(".{}.obp.part", safe_stem));
    let obk_part = out_dir_path.join(format!(".{}.obk.part", safe_stem));
    let _ = fs::remove_file(&obp_part);
    let _ = fs::remove_file(&obk_part);

    let mut guard = TempFileGuard::new(vec![obp_part.clone(), obk_part.clone()]);

    let (obp_bytes, obk_bytes, _) = crypto::generate_keypair_blobs(kem, deception_passcode)?;

    let mut obp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&obp_part)
        .map_err(|e| format!("Failed to create .obp file: {}", e))?;
    obp_file.write_all(&obp_bytes).map_err(|e| e.to_string())?;
    obp_file.sync_all().map_err(|e| e.to_string())?;
    drop(obp_file);

    let mut obk_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&obk_part)
        .map_err(|e| format!("Failed to create .obk file: {}", e))?;
    obk_file.write_all(&obk_bytes).map_err(|e| e.to_string())?;
    obk_file.sync_all().map_err(|e| e.to_string())?;
    drop(obk_file);

    fs::rename(&obp_part, &obp_final).map_err(|e| e.to_string())?;
    fs::rename(&obk_part, &obk_final).map_err(|e| e.to_string())?;
    sync_parent_directory(out_dir_path);
    guard.disarm();

    Ok(format!(
        "Generated Public Sealing Key ({}.obp) and Private Key ({}.obk).",
        safe_stem, safe_stem
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
) -> Result<String, String> {
    emit_progress(app, 5)?;

    // 1. Pre-flight space & collision enforcement
    let check =
        assess_storage_and_paths("ENCRYPT", target_path, vault_output_dir, Some(key_location))?;
    if !check.sufficient {
        return Err(format!("Insufficient Disk Space! {}", check.summary));
    }
    if let Some(conflict) = check.conflict_error {
        return Err(conflict);
    }

    let target_path_obj = Path::new(target_path);
    let vault_out_obj = Path::new(vault_output_dir);
    let folder_name = target_path_obj
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Failed to resolve source folder name.")?;

    let (uncompressed_bytes, item_count) = calculate_dir_metrics(target_path_obj)?;
    let estimated_tar_size = uncompressed_bytes
        .saturating_add(item_count.saturating_mul(512))
        .max(1024);

    emit_progress(app, 15)?;

    // 2. Derive Argon2id Key & Encapsulate Hybrid KEM
    let (argon_key, salt) = crypto::derive_key(main_pin)?;

    let (ct_bytes, ss_bytes, kem_id, generated_keys) = if use_existing_public_key {
        let mut obp_raw = Vec::new();
        File::open(key_location)
            .map_err(|_| "Failed to open selected Public Key (.obp) file.".to_string())?
            .read_to_end(&mut obp_raw)
            .map_err(|e| e.to_string())?;
        let (ct, ss, kid) = crypto::encapsulate_with_obp(&obp_raw)?;
        (ct, ss, kid, None)
    } else {
        let (obp_bytes, obk_bytes, kid) =
            crypto::generate_keypair_blobs(kem, deception_passcode)?;
        let (ct, ss, _) = crypto::encapsulate_with_obp(&obp_bytes)?;
        (ct, ss, kid, Some((obp_bytes, obk_bytes)))
    };

    let final_master_key = crypto::compute_master_key(&argon_key, &ss_bytes, &salt)?;

    let (cipher_id, nonce_bytes) = if cipher == "aes256gcm" {
        let mut n = vec![0u8; 12];
        OsRng.fill_bytes(&mut n);
        (2u8, n)
    } else {
        let mut n = vec![0u8; 24];
        OsRng.fill_bytes(&mut n);
        (1u8, n)
    };

    // 3. Prepare Hidden Atomic Staging Paths (.{name}.obv.part)
    let obv_final = vault_out_obj.join(format!("{}.obv", folder_name));
    let obv_part = vault_out_obj.join(format!(".{}.obv.part", folder_name));
    let _ = fs::remove_file(&obv_part); // Clean up any stale interrupted .part file

    let mut staged_paths = vec![obv_part.clone()];
    let mut key_targets: Option<(PathBuf, PathBuf, PathBuf, PathBuf)> = None;

    if generated_keys.is_some() {
        let key_dir = Path::new(key_location);
        if !key_dir.exists() || !key_dir.is_dir() {
            return Err("Selected key destination directory does not exist.".to_string());
        }
        let obk_final = key_dir.join(format!("{}.obk", folder_name));
        let obp_final = key_dir.join(format!("{}.obp", folder_name));
        let obk_part = key_dir.join(format!(".{}.obk.part", folder_name));
        let obp_part = key_dir.join(format!(".{}.obp.part", folder_name));
        let _ = fs::remove_file(&obk_part);
        let _ = fs::remove_file(&obp_part);

        staged_paths.push(obk_part.clone());
        staged_paths.push(obp_part.clone());
        key_targets = Some((obk_part, obk_final, obp_part, obp_final));
    }

    let mut guard = TempFileGuard::new(staged_paths);

    // 4. Write Key Files to Hidden Staging (.part) if generating new keys
    if let (Some((obp_bytes, obk_bytes)), Some((ref obk_part, _, ref obp_part, _))) =
        (generated_keys, &key_targets)
    {
        let mut obk_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(obk_part)
            .map_err(|e| format!("Failed to stage private key (.obk): {}", e))?;
        obk_file.write_all(&obk_bytes).map_err(|e| e.to_string())?;
        obk_file.sync_all().map_err(|e| e.to_string())?;

        let mut obp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(obp_part)
            .map_err(|e| format!("Failed to stage public key (.obp): {}", e))?;
        obp_file.write_all(&obp_bytes).map_err(|e| e.to_string())?;
        obp_file.sync_all().map_err(|e| e.to_string())?;
    }

    // 5. Build & Authenticate Versioned Header (OMBV\x02)
    let mut header_bytes = Vec::with_capacity(64 + ct_bytes.len());
    header_bytes.extend_from_slice(VAULT_MAGIC);
    header_bytes.push(cipher_id);
    header_bytes.push(kem_id);
    header_bytes.extend_from_slice(&crypto::ARGON2_M_COST.to_le_bytes());
    header_bytes.extend_from_slice(&crypto::ARGON2_T_COST.to_le_bytes());
    header_bytes.extend_from_slice(&crypto::ARGON2_P_COST.to_le_bytes());
    header_bytes.extend_from_slice(&uncompressed_bytes.to_le_bytes());
    header_bytes.extend_from_slice(&salt);
    header_bytes.push(nonce_bytes.len() as u8);
    header_bytes.extend_from_slice(&nonce_bytes);
    header_bytes.extend_from_slice(&(ct_bytes.len() as u16).to_le_bytes());
    header_bytes.extend_from_slice(&ct_bytes);

    let header_hash: [u8; 32] = Sha256::digest(&header_bytes).into();

    let mut vault_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&obv_part)
        .map_err(|e| format!("Failed to create staged vault file: {}", e))?;
    vault_file
        .write_all(&header_bytes)
        .map_err(|e| e.to_string())?;

    emit_progress(app, 30)?;

    // 6. Stream Directory -> In-Memory TAR Builder -> ChunkedEncryptWriter -> .{name}.obv.part
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
    };

    let mut tar_builder = Builder::new(encrypt_writer);
    tar_builder.follow_symlinks(false);
    tar_builder
        .append_dir_all(".", target_path_obj)
        .map_err(|e| format!("Failed to stream folder into encrypted archive: {}", e))?;

    let encrypt_writer = tar_builder
        .into_inner()
        .map_err(|e| format!("Failed to finalize TAR stream: {}", e))?;
    let vault_file = encrypt_writer
        .finalize()
        .map_err(|e| format!("Failed to finalize encrypted stream: {}", e))?;
    vault_file.sync_all().map_err(|e| e.to_string())?;
    drop(vault_file);

    // 7. Atomic Commit (.part -> final filenames) & Flush Directory Entries
    fs::rename(&obv_part, &obv_final).map_err(|e| format!("Failed to commit vault file: {}", e))?;
    sync_parent_directory(vault_out_obj);

    if let Some((obk_part, obk_final, obp_part, obp_final)) = key_targets {
        fs::rename(&obk_part, &obk_final)
            .map_err(|e| format!("Failed to commit .obk file: {}", e))?;
        fs::rename(&obp_part, &obp_final)
            .map_err(|e| format!("Failed to commit .obp file: {}", e))?;
        sync_parent_directory(Path::new(key_location));
    }
    guard.disarm();

    emit_progress(app, 100)?;
    if use_existing_public_key {
        Ok("Operation Successful: Vault sealed (.obv) using Public Key (.obp).".to_string())
    } else {
        Ok("Operation Successful: Vault locked (.obv) and Keypair (.obk + .obp) generated.".to_string())
    }
}

/// Tauri wrapper for decryption
pub fn decrypt_vault(
    app: &AppHandle,
    vault_path: &str,
    key_path: Option<&str>,
    output_dir: &str,
    main_pin: &str,
) -> Result<String, String> {
    decrypt_vault_core(Some(app), vault_path, key_path, output_dir, main_pin)
}

/// Core On-the-Fly Streaming Decryption Pipeline
pub fn decrypt_vault_core(
    app: Option<&AppHandle>,
    vault_path: &str,
    key_path: Option<&str>,
    output_dir: &str,
    main_pin: &str,
) -> Result<String, String> {
    emit_progress(app, 10)?;

    let key_path_str = key_path.ok_or("No Private Key (.obk) selected for decryption!")?;

    // 1. Pre-flight space & collision enforcement
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

    let mut full_obk_bytes = Zeroizing::new(Vec::new());
    File::open(key_path_str)
        .map_err(|_| "Authentication Error: Target key file (.obk) could not be accessed.".to_string())?
        .read_to_end(&mut full_obk_bytes)
        .map_err(|_| "Integrity Error: Failed to read key file stream.".to_string())?;

    let mut vault_file =
        File::open(vault_path).map_err(|e| format!("Failed to open .obv: {}", e))?;
    let total_vault_len = vault_file.metadata().map_err(|e| e.to_string())?.len();

    // 2. Parse & Hash OMBV\x02 Header for AAD Verification
    let mut fixed_prefix = [0u8; 44];
    vault_file
        .read_exact(&mut fixed_prefix)
        .map_err(|_| "Integrity Error: Vault header is truncated or invalid.".to_string())?;

    if &fixed_prefix[..5] != VAULT_MAGIC {
        return Err("Unsupported or corrupted vault format (Expected OMBV v2 header).".to_string());
    }

    let cipher_id = fixed_prefix[5];
    let kem_id = fixed_prefix[6];
    let m_cost = u32::from_le_bytes(fixed_prefix[7..11].try_into().unwrap());
    let t_cost = u32::from_le_bytes(fixed_prefix[11..15].try_into().unwrap());
    let p_cost = u32::from_le_bytes(fixed_prefix[15..19].try_into().unwrap());
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&fixed_prefix[27..43]);
    let nonce_len = fixed_prefix[43] as usize;

    if nonce_len != 12 && nonce_len != 24 {
        return Err("Integrity Error: Invalid cipher nonce length in header.".to_string());
    }

    let mut nonce_bytes = vec![0u8; nonce_len];
    vault_file
        .read_exact(&mut nonce_bytes)
        .map_err(|_| "Integrity Error: Failed to read nonce.".to_string())?;

    let mut ct_len_buf = [0u8; 2];
    vault_file
        .read_exact(&mut ct_len_buf)
        .map_err(|_| "Integrity Error: Failed to read KEM length.".to_string())?;
    let ct_len = u16::from_le_bytes(ct_len_buf) as usize;

    let mut ct_bytes = vec![0u8; ct_len];
    vault_file
        .read_exact(&mut ct_bytes)
        .map_err(|_| "Integrity Error: Failed to read KEM ciphertext.".to_string())?;

    let mut header_bytes = Vec::with_capacity(44 + nonce_len + 2 + ct_len);
    header_bytes.extend_from_slice(&fixed_prefix);
    header_bytes.extend_from_slice(&nonce_bytes);
    header_bytes.extend_from_slice(&ct_len_buf);
    header_bytes.extend_from_slice(&ct_bytes);
    let header_hash: [u8; 32] = Sha256::digest(&header_bytes).into();

    emit_progress(app, 25)?;

    // 3. Check Duress Trapdoor & Decapsulate Hybrid KEM
    let (duress_triggered, ss_opt) =
        crypto::decapsulate_with_obk(kem_id, &full_obk_bytes, &ct_bytes, main_pin)?;

    if duress_triggered {
        return deception::trigger_dummy_scramble(key_path_str);
    }

    let ss_bytes = ss_opt.ok_or("Decapsulation failed.")?;
    let argon_key = crypto::derive_key_with_params(main_pin, &salt, m_cost, t_cost, p_cost)?;
    let final_master_key = crypto::compute_master_key(&argon_key, &ss_bytes, &salt)?;

    emit_progress(app, 40)?;

    // 4. Prepare Hidden Atomic Staging Directory for Safe Extraction
    let vault_path_obj = Path::new(vault_path);
    let out_dir_obj = Path::new(output_dir);
    let file_stem = vault_path_obj
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("Invalid vault filename.")?;

    let final_extract_dir = out_dir_obj.join(file_stem);
    let mut rnd = [0u8; 4];
    OsRng.fill_bytes(&mut rnd);
    let stage_dir = out_dir_obj.join(format!(
        ".ombracrypt_stage_{}_{:02x}{:02x}{:02x}{:02x}",
        file_stem, rnd[0], rnd[1], rnd[2], rnd[3]
    ));

    fs::create_dir_all(&stage_dir)
        .map_err(|e| format!("Failed to create staging directory: {}", e))?;
    let mut dir_guard = TempDirGuard::new(stage_dir.clone());

    let header_end_pos = vault_file.stream_position().map_err(|e| e.to_string())?;
    let vault_body_size = total_vault_len.saturating_sub(header_end_pos);

    let decrypt_reader = ChunkedDecryptReader {
        inner: vault_file,
        cipher_id,
        master_key: final_master_key,
        base_nonce: nonce_bytes,
        header_hash,
        buffer: Zeroizing::new(Vec::new()),
        read_pos: 0,
        chunk_index: 0,
        bytes_read_from_vault: 0,
        vault_body_size,
        reached_final_chunk: false,
        app,
        last_percent: 40,
    };

    let mut archive = Archive::new(decrypt_reader);
    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read encrypted archive stream: {}", e))?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| e.to_string())?;
        let entry_type = entry.header().entry_type();
        if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
            return Err(
                "Security Error: Archive contains restricted symbolic or hard links.".to_string(),
            );
        }
        let raw_path = entry.path().map_err(|e| e.to_string())?.into_owned();
        let clean_rel = sanitize_tar_path(&raw_path)?;
        if clean_rel.as_os_str().is_empty() {
            continue;
        }
        let dest_path = stage_dir.join(clean_rel);
        if entry_type.is_dir() {
            fs::create_dir_all(&dest_path).map_err(|e| e.to_string())?;
        } else {
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            entry
                .unpack(&dest_path)
                .map_err(|e| format!("Failed to unpack file: {}", e))?;
        }
    }

    // Drain any trailing TAR padding blocks to ensure the final AEAD chunk tag is verified
    let mut reader = archive.into_inner();
    let mut drain = [0u8; 1024];
    while reader.read(&mut drain).map_err(|e| e.to_string())? > 0 {}

    if !reader.reached_final_chunk {
        return Err(
            "Integrity Error: Vault stream ended without a verified final chunk tag.".to_string(),
        );
    }

    // 5. Commit Staging Folder to Final Output Directory & Flush USB Directory Cache
    fs::rename(&stage_dir, &final_extract_dir)
        .map_err(|e| format!("Failed to finalize extracted output directory: {}", e))?;
    sync_parent_directory(&final_extract_dir);
    sync_parent_directory(out_dir_obj);
    dir_guard.disarm();

    emit_progress(app, 100)?;
    Ok("Operation Successful: Vault authenticated and extracted directly in memory.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_workspace(name: &str) -> (PathBuf, TempDirGuard) {
        let mut rnd = [0u8; 6];
        OsRng.fill_bytes(&mut rnd);
        let dir = std::env::temp_dir().join(format!(
            "ombracrypt_test_{}_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            name, rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5]
        ));
        fs::create_dir_all(&dir).unwrap();
        let guard = TempDirGuard::new(dir.clone());
        (dir, guard)
    }

    #[test]
    fn test_roundtrip_xwing_xchacha20_and_zero_temp_files() {
        let (ws, _guard) = create_test_workspace("xwing_xchacha");
        let src_dir = ws.join("sample_payload");
        let vault_dir = ws.join("vault_out");
        let key_dir = ws.join("keys_out");
        let extract_dir = ws.join("extract_out");

        fs::create_dir_all(src_dir.join("nested")).unwrap();
        fs::create_dir_all(&vault_dir).unwrap();
        fs::create_dir_all(&key_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        let secret_data = b"Post-Quantum FIPS 203 ML-KEM-768 + X25519 Test Payload";
        fs::write(src_dir.join("nested/secret.txt"), secret_data).unwrap();

        encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
            key_dir.to_str().unwrap(),
            false,
            "xchacha20",
            "xwing",
            "CorrectHorseBatteryStaple!",
            "DuressCode999",
        )
        .expect("Encryption should succeed");

        let obv_path = vault_dir.join("sample_payload.obv");
        let obk_path = key_dir.join("sample_payload.obk");
        let obp_path = key_dir.join("sample_payload.obp");
        assert!(obv_path.exists() && obk_path.exists() && obp_path.exists());

        // Verify zero .tmp.tar or .part files exist anywhere
        assert!(!ws.join("sample_payload.tmp.tar").exists());
        assert!(!vault_dir.join(".sample_payload.obv.part").exists());

        decrypt_vault_core(
            None,
            obv_path.to_str().unwrap(),
            Some(obk_path.to_str().unwrap()),
            extract_dir.to_str().unwrap(),
            "CorrectHorseBatteryStaple!",
        )
        .expect("Decryption should succeed");

        let recovered =
            fs::read(extract_dir.join("sample_payload/nested/secret.txt")).unwrap();
        assert_eq!(recovered, secret_data);
    }

    #[test]
    fn test_roundtrip_cypherpunk_aes256gcm() {
        let (ws, _guard) = create_test_workspace("cypherpunk_aes");
        let src_dir = ws.join("alpha");
        let vault_dir = ws.join("vault");
        let key_dir = ws.join("keys");
        let extract_dir = ws.join("out");

        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&vault_dir).unwrap();
        fs::create_dir_all(&key_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        let payload = vec![0xABu8; CHUNK_SIZE + 25_000]; // Multi-chunk (>1 MiB) test
        fs::write(src_dir.join("large.bin"), &payload).unwrap();

        encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
            key_dir.to_str().unwrap(),
            false,
            "aes256gcm",
            "cypherpunk",
            "MasterPass#2026",
            "",
        )
        .expect("Multi-chunk encryption should succeed");

        let obv_path = vault_dir.join("alpha.obv");
        let obk_path = key_dir.join("alpha.obk");

        decrypt_vault_core(
            None,
            obv_path.to_str().unwrap(),
            Some(obk_path.to_str().unwrap()),
            extract_dir.to_str().unwrap(),
            "MasterPass#2026",
        )
        .expect("Multi-chunk decryption should succeed");

        let restored = fs::read(extract_dir.join("alpha/large.bin")).unwrap();
        assert_eq!(restored, payload);
    }

    #[test]
    fn test_public_key_obp_sealing_workflow() {
        let (ws, _guard) = create_test_workspace("obp_seal");
        let src_dir = ws.join("docs");
        let key_dir = ws.join("keys");
        let vault_dir_1 = ws.join("v1");
        let vault_dir_2 = ws.join("v2");
        let out_1 = ws.join("out1");
        let out_2 = ws.join("out2");

        for d in [&src_dir, &key_dir, &vault_dir_1, &vault_dir_2, &out_1, &out_2] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(src_dir.join("note.txt"), b"Group Seal Verified").unwrap();

        // Vault 1: Generate keypair (.obk + .obp) with password "1234"
        encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            vault_dir_1.to_str().unwrap(),
            key_dir.to_str().unwrap(),
            false,
            "xchacha20",
            "xwing",
            "1234",
            "5555",
        )
        .unwrap();

        let obp_path = key_dir.join("docs.obp");
        let obk_path = key_dir.join("docs.obk");

        // Vault 2: Seal using existing .obp ONLY with password "2345"
        encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            vault_dir_2.to_str().unwrap(),
            obp_path.to_str().unwrap(),
            true,
            "xchacha20",
            "xwing",
            "2345",
            "",
        )
        .unwrap();

        // Decrypt Vault 1 with "1234" and Vault 2 with "2345" using the same .obk
        decrypt_vault_core(
            None,
            vault_dir_1.join("docs.obv").to_str().unwrap(),
            Some(obk_path.to_str().unwrap()),
            out_1.to_str().unwrap(),
            "1234",
        )
        .expect("Vault 1 must unlock with 1234");

        decrypt_vault_core(
            None,
            vault_dir_2.join("docs.obv").to_str().unwrap(),
            Some(obk_path.to_str().unwrap()),
            out_2.to_str().unwrap(),
            "2345",
        )
        .expect("Vault 2 must unlock with 2345");
    }

    #[test]
    fn test_audit_p0_collision_preserves_existing_obk_and_obv() {
        let (ws, _guard) = create_test_workspace("collision_safety");
        let src_dir = ws.join("sample");
        let out_dir = ws.join("out");

        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&out_dir).unwrap();
        fs::write(src_dir.join("secret.txt"), b"top secret").unwrap();

        // Pre-create an existing sample.obk and a directory colliding at sample.obv
        let existing_obk = out_dir.join("sample.obk");
        let original_key_bytes = b"ORIGINAL_PROTECTED_KEY_MATERIAL";
        fs::write(&existing_obk, original_key_bytes).unwrap();
        fs::create_dir_all(out_dir.join("sample.obv")).unwrap();

        let res = encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            out_dir.to_str().unwrap(),
            out_dir.to_str().unwrap(),
            false,
            "aes256gcm",
            "xwing",
            "pass123",
            "",
        );

        assert!(res.is_err(), "Collision must be rejected");
        assert_eq!(
            fs::read(&existing_obk).unwrap(),
            original_key_bytes,
            "Existing .obk must never be clobbered on error"
        );
    }

    #[test]
    fn test_wrong_password_rejected_and_staging_cleaned() {
        let (ws, _guard) = create_test_workspace("wrong_pass");
        let src_dir = ws.join("data");
        let vault_dir = ws.join("vault");
        let out_dir = ws.join("out");

        for d in [&src_dir, &vault_dir, &out_dir] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(src_dir.join("file.txt"), b"sensitive").unwrap();

        encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
            false,
            "xchacha20",
            "xwing",
            "RightPassword",
            "DuressPassword",
        )
        .unwrap();

        let obv = vault_dir.join("data.obv");
        let obk = vault_dir.join("data.obk");
        let obk_before = fs::read(&obk).unwrap();

        let err = decrypt_vault_core(
            None,
            obv.to_str().unwrap(),
            Some(obk.to_str().unwrap()),
            out_dir.to_str().unwrap(),
            "WrongPasswordTypo",
        );

        assert!(err.is_err());
        assert_eq!(fs::read(&obk).unwrap(), obk_before, "Typo must not scramble .obk");
        assert!(
            fs::read_dir(&out_dir).unwrap().next().is_none(),
            "Staging directory must be completely removed on failure"
        );
    }

    #[test]
    fn test_header_tampering_aad_rejection() {
        let (ws, _guard) = create_test_workspace("header_tamper");
        let src_dir = ws.join("data");
        let vault_dir = ws.join("vault");
        let out_dir = ws.join("out");

        for d in [&src_dir, &vault_dir, &out_dir] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(src_dir.join("file.txt"), b"immutable header test").unwrap();

        encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
            false,
            "aes256gcm",
            "xwing",
            "Pass1234",
            "",
        )
        .unwrap();

        let obv = vault_dir.join("data.obv");
        let obk = vault_dir.join("data.obk");

        // Flip 1 bit inside the uncompressed_size metadata field in the header (byte offset 20)
        let mut vault_bytes = fs::read(&obv).unwrap();
        vault_bytes[20] ^= 0x01;
        fs::write(&obv, &vault_bytes).unwrap();

        let res = decrypt_vault_core(
            None,
            obv.to_str().unwrap(),
            Some(obk.to_str().unwrap()),
            out_dir.to_str().unwrap(),
            "Pass1234",
        );
        assert!(res.is_err(), "Tampered header must fail AEAD AAD verification");
    }

    #[test]
    fn test_duress_trapdoor_scrambles_obk() {
        let (ws, _guard) = create_test_workspace("duress");
        let src_dir = ws.join("data");
        let vault_dir = ws.join("vault");
        let out_dir = ws.join("out");

        for d in [&src_dir, &vault_dir, &out_dir] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(src_dir.join("file.txt"), b"destroy key on duress").unwrap();

        encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
            false,
            "xchacha20",
            "xwing",
            "RealSecret123",
            "PanicDuress999",
        )
        .unwrap();

        let obv = vault_dir.join("data.obv");
        let obk = vault_dir.join("data.obk");
        let original_obk = fs::read(&obk).unwrap();

        let res = decrypt_vault_core(
            None,
            obv.to_str().unwrap(),
            Some(obk.to_str().unwrap()),
            out_dir.to_str().unwrap(),
            "PanicDuress999",
        );
        assert!(res.is_err());

        let scrambled_obk = fs::read(&obk).unwrap();
        assert_ne!(scrambled_obk, original_obk, ".obk must be overwritten with random noise");
    }

    #[test]
    fn test_zip_slip_path_traversal_sanitization() {
        assert!(sanitize_tar_path(Path::new("../../etc/passwd")).is_err());
        assert!(sanitize_tar_path(Path::new("/etc/shadow")).is_err());
        assert!(sanitize_tar_path(Path::new("safe/subdir/file.txt")).is_ok());
    }
}