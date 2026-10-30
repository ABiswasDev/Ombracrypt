use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tar::{Archive, EntryType};
use tauri::{AppHandle, Emitter};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto;

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB Streaming Ceiling
pub const VAULT_MAGIC: &[u8; 5] = b"OMBV\x02";

// Exact expected hybrid ciphertext lengths: ML-KEM CT + 32-byte X25519 Ephemeral PK
const XWING_CT_LEN: usize = 1088 + 32; // 1120 bytes
const CYPHERPUNK_CT_LEN: usize = 1568 + 32; // 1600 bytes

pub struct ValidatedHeader {
    pub cipher_id: u8,
    pub kem_id: u8,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub uncompressed_bytes: u64,
    pub salt: [u8; 16],
    pub nonce_bytes: Vec<u8>,
    pub ct_bytes: Vec<u8>,
    pub header_hash: [u8; 32],
}

pub fn emit_progress(app: Option<&AppHandle>, progress: u8) -> Result<(), String> {
    if let Some(handle) = app {
        handle
            .emit("crypto-progress", progress)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Overwrites all active plaintext bytes in the vector with zeroes before resetting length to 0
pub fn clear_and_zeroize_buffer(buf: &mut Zeroizing<Vec<u8>>) {
    buf.as_mut_slice().zeroize();
    buf.clear();
}

/// Serializes the OMBV\x02 header and computes its SHA-256 digest for AEAD AAD binding
pub fn build_and_hash_header(
    cipher_id: u8,
    kem_id: u8,
    uncompressed_bytes: u64,
    salt: &[u8; 16],
    nonce_bytes: &[u8],
    ct_bytes: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let mut header_bytes = Vec::with_capacity(64 + ct_bytes.len());
    header_bytes.extend_from_slice(VAULT_MAGIC);
    header_bytes.push(cipher_id);
    header_bytes.push(kem_id);
    header_bytes.extend_from_slice(&crypto::ARGON2_M_COST.to_le_bytes());
    header_bytes.extend_from_slice(&crypto::ARGON2_T_COST.to_le_bytes());
    header_bytes.extend_from_slice(&crypto::ARGON2_P_COST.to_le_bytes());
    header_bytes.extend_from_slice(&uncompressed_bytes.to_le_bytes());
    header_bytes.extend_from_slice(salt);
    header_bytes.push(nonce_bytes.len() as u8);
    header_bytes.extend_from_slice(nonce_bytes);
    header_bytes.extend_from_slice(&(ct_bytes.len() as u16).to_le_bytes());
    header_bytes.extend_from_slice(ct_bytes);

    let header_hash: [u8; 32] = Sha256::digest(&header_bytes).into();
    (header_bytes, header_hash)
}

/// Strictly validates untrusted OMBV\x02 header fields before any KDF, KEM, or disk allocation
pub fn parse_and_validate_header(vault_file: &mut File) -> Result<ValidatedHeader, String> {
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
    let uncompressed_bytes = u64::from_le_bytes(fixed_prefix[19..27].try_into().unwrap());

    if m_cost != crypto::ARGON2_M_COST
        || t_cost != crypto::ARGON2_T_COST
        || p_cost != crypto::ARGON2_P_COST
    {
        return Err(
            "Security Error: Untrusted or unsupported Argon2id parameters in vault header."
                .to_string(),
        );
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&fixed_prefix[27..43]);
    let nonce_len = fixed_prefix[43] as usize;

    let valid_cipher_nonce =
        (cipher_id == 1 && nonce_len == 24) || (cipher_id == 2 && nonce_len == 12);
    if !valid_cipher_nonce {
        return Err(
            "Security Error: Invalid cipher ID or mismatched nonce length in vault header."
                .to_string(),
        );
    }

    let expected_ct_len = match kem_id {
        1 => XWING_CT_LEN,
        2 => CYPHERPUNK_CT_LEN,
        _ => {
            return Err("Security Error: Unsupported KEM profile ID in vault header.".to_string())
        }
    };

    let mut nonce_bytes = vec![0u8; nonce_len];
    vault_file
        .read_exact(&mut nonce_bytes)
        .map_err(|_| "Integrity Error: Failed to read cipher nonce.".to_string())?;

    let mut ct_len_buf = [0u8; 2];
    vault_file
        .read_exact(&mut ct_len_buf)
        .map_err(|_| "Integrity Error: Failed to read KEM length.".to_string())?;
    let ct_len = u16::from_le_bytes(ct_len_buf) as usize;

    if ct_len != expected_ct_len {
        return Err(
            "Security Error: KEM ciphertext length does not match the declared KEM profile."
                .to_string(),
        );
    }

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

    Ok(ValidatedHeader {
        cipher_id,
        kem_id,
        m_cost,
        t_cost,
        p_cost,
        uncompressed_bytes,
        salt,
        nonce_bytes,
        ct_bytes,
        header_hash,
    })
}

/// Reads the uncompressed payload size stored inside an OMBV v2 vault header
pub fn read_vault_uncompressed_size(vault_path: &Path) -> Result<u64, String> {
    let mut file = File::open(vault_path).map_err(|e| format!("Failed to open vault: {}", e))?;
    let mut magic = [0u8; 5];
    file.read_exact(&mut magic)
        .map_err(|_| "Invalid or truncated vault header.".to_string())?;
    if &magic != VAULT_MAGIC {
        return Err("Unsupported vault format (Expected OMBV v2 header).".to_string());
    }
    file.seek(SeekFrom::Current(14))
        .map_err(|e| e.to_string())?;
    let mut size_buf = [0u8; 8];
    file.read_exact(&mut size_buf).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(size_buf))
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
    // Reserve .active.lock sentinel name to prevent malicious archives from interfering with directory locking
    if clean == Path::new(".active.lock") || clean.starts_with(".active.lock") {
        return Err("Security Error: Archive contains reserved staging path '.active.lock'.".to_string());
    }
    Ok(clean)
}

/// Strict allowlist for TAR entry types (Regular Files and Directories only)
pub fn validate_tar_entry_type(entry_type: EntryType) -> Result<(), String> {
    match entry_type {
        EntryType::Regular | EntryType::Directory => Ok(()),
        _ => Err(format!(
            "Security Error: Archive contains disallowed entry type ({:?}). Only regular files and directories are permitted.",
            entry_type
        )),
    }
}

/// Safely extracts a TAR stream while enforcing depth, path length, entry count, duplicate-path, and suid limits
pub fn extract_tar_archive_safely<R: Read>(
    archive: &mut Archive<R>,
    stage_dir: &Path,
    max_permitted_bytes: u64,
) -> Result<(), String> {
    let entries = archive.entries().map_err(|e| {
        let s = e.to_string();
        if s.contains("Operation aborted by user") {
            "Operation aborted by user.".to_string()
        } else {
            format!("Failed to read encrypted archive stream: {}", s)
        }
    })?;

    let mut extracted_bytes = 0u64;
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    const MAX_ARCHIVE_ENTRIES: usize = 50_000;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| {
            let s = e.to_string();
            if s.contains("Operation aborted by user") {
                "Operation aborted by user.".to_string()
            } else {
                e.to_string()
            }
        })?;
        let entry_type = entry.header().entry_type();

        validate_tar_entry_type(entry_type)?;

        // Strict TAR header size validation (no silent 0-byte fallback)
        let entry_size = entry
            .header()
            .size()
            .map_err(|e| format!("Security Error: Corrupted TAR header size field: {}", e))?;

        extracted_bytes = extracted_bytes.saturating_add(entry_size);
        if extracted_bytes > max_permitted_bytes {
            return Err(
                "Security Error: Archive payload exceeds authenticated header size limit."
                    .to_string(),
            );
        }

        let raw_path = entry.path().map_err(|e| e.to_string())?.into_owned();
        let clean_rel = sanitize_tar_path(&raw_path)?;
        if clean_rel.as_os_str().is_empty() {
            continue;
        }

        // Anti-bomb invariant: Maximum directory recursion depth <= 64
        let depth = clean_rel.components().count();
        if depth > 64 {
            return Err(format!(
                "Security Error: Archive path depth exceeds maximum safety limit ({} > 64).",
                depth
            ));
        }

        // Anti-bomb invariant: Relative path length <= 512, component length <= 255
        if clean_rel.as_os_str().len() > 512 {
            return Err("Security Error: Archive path length exceeds 512 characters.".to_string());
        }
        for comp in clean_rel.components() {
            if comp.as_os_str().len() > 255 {
                return Err("Security Error: Path component exceeds 255 characters.".to_string());
            }
        }

        // Anti-bomb invariant: Total entry count ceiling
        if seen_paths.len() >= MAX_ARCHIVE_ENTRIES {
            return Err(
                "Security Error: Archive entry count exceeds safe maximum (50,000 entries)."
                    .to_string(),
            );
        }

        if !seen_paths.insert(clean_rel.clone()) {
            return Err(format!(
                "Security Error: Archive contains duplicate or conflicting entry path ({:?}).",
                clean_rel
            ));
        }

        let dest_path = stage_dir.join(&clean_rel);
        if entry_type.is_dir() {
            if dest_path.exists() && !dest_path.is_dir() {
                return Err(format!(
                    "Security Error: Directory entry conflicts with existing file ({:?}).",
                    clean_rel
                ));
            }
            fs::create_dir_all(&dest_path).map_err(|e| e.to_string())?;
        } else {
            if dest_path.exists() {
                return Err(format!(
                    "Security Error: File entry conflicts with existing path ({:?}).",
                    clean_rel
                ));
            }
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }

            entry.set_preserve_permissions(false);
            entry.set_unpack_xattrs(false);

            // Intercept mid-stream unpack cancellation errors cleanly
            if let Err(e) = entry.unpack(&dest_path) {
                let s = e.to_string();
                if s.contains("Operation aborted by user") {
                    return Err("Operation aborted by user.".to_string());
                }
                return Err(format!("Failed to unpack file: {}", s));
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::symlink_metadata(&dest_path) {
                    let safe_mode = meta.permissions().mode() & 0o0777;
                    let _ = fs::set_permissions(&dest_path, fs::Permissions::from_mode(safe_mode));
                }
            }
        }
    }

    Ok(())
}

/// Custom In-Memory Streaming AEAD Writer (Zero .tmp.tar written to disk) with mid-stream cancellation
pub struct ChunkedEncryptWriter<'a, W: Write> {
    pub inner: W,
    pub cipher_id: u8,
    pub master_key: Zeroizing<[u8; 32]>,
    pub base_nonce: Vec<u8>,
    pub header_hash: [u8; 32],
    pub buffer: Zeroizing<Vec<u8>>,
    pub chunk_index: u64,
    pub processed_bytes: u64,
    pub total_expected: u64,
    pub app: Option<&'a AppHandle>,
    pub last_percent: u8,
    pub cancellation_token: Option<Arc<AtomicBool>>,
}

impl<'a, W: Write> ChunkedEncryptWriter<'a, W> {
    fn encrypt_and_flush_chunk(&mut self, is_final: u8) -> std::io::Result<()> {
        if let Some(ref token) = self.cancellation_token {
            if token.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Operation aborted by user.",
                ));
            }
        }

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
        clear_and_zeroize_buffer(&mut self.buffer);
        self.chunk_index += 1;

        let ratio = (self.processed_bytes as f64 / self.total_expected.max(1) as f64).min(1.0);
        let progress = 30 + (ratio * 65.0) as u8;
        if progress > self.last_percent {
            let _ = emit_progress(self.app, progress);
            self.last_percent = progress;
        }

        Ok(())
    }

    pub fn finalize(mut self) -> std::io::Result<W> {
        self.encrypt_and_flush_chunk(1u8)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<'a, W: Write> Write for ChunkedEncryptWriter<'a, W> {
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        if let Some(ref token) = self.cancellation_token {
            if token.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Operation aborted by user.",
                ));
            }
        }

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

/// Custom In-Memory Streaming AEAD Reader (Streams decrypted TAR chunks directly in RAM) with mid-stream cancellation
pub struct ChunkedDecryptReader<'a, R: Read> {
    pub inner: R,
    pub cipher_id: u8,
    pub master_key: Zeroizing<[u8; 32]>,
    pub base_nonce: Vec<u8>,
    pub header_hash: [u8; 32],
    pub buffer: Zeroizing<Vec<u8>>,
    pub read_pos: usize,
    pub chunk_index: u64,
    pub bytes_read_from_vault: u64,
    pub vault_body_size: u64,
    pub reached_final_chunk: bool,
    pub app: Option<&'a AppHandle>,
    pub last_percent: u8,
    pub cancellation_token: Option<Arc<AtomicBool>>,
}

impl<'a, R: Read> ChunkedDecryptReader<'a, R> {
    fn load_next_chunk(&mut self) -> std::io::Result<bool> {
        clear_and_zeroize_buffer(&mut self.buffer);

        if let Some(ref token) = self.cancellation_token {
            if token.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Operation aborted by user.",
                ));
            }
        }

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
        if out.is_empty() {
            return Ok(0);
        }

        if let Some(ref token) = self.cancellation_token {
            if token.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Operation aborted by user.",
                ));
            }
        }

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