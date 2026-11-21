use rand::{rngs::OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use zeroize::Zeroizing;

use crate::fs_guard::{MAX_KEY_FILE_BYTES, MIN_KEY_FILE_BYTES};

/// Verifies target key file identity, enforces size/symlink guards, and overwrites it with CSPRNG noise
pub fn scramble_key_file_verified(key_path: &str) -> Result<(), String> {
    let lstat = fs::symlink_metadata(key_path)
        .map_err(|_| "Integrity Error: Target key file could not be accessed.".to_string())?;

    if lstat.file_type().is_symlink() || !lstat.is_file() {
        return Err(
            "Security Error: Refusing to scramble symlink or non-regular key file.".to_string(),
        );
    }

    let size = lstat.len();
    if !(MIN_KEY_FILE_BYTES..=MAX_KEY_FILE_BYTES).contains(&size) {
        return Err("Security Error: Key file size is outside valid bounds.".to_string());
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(key_path)
        .map_err(|_| "Integrity Error: Failed to open key file for write operation.".to_string())?;

    let fstat = file
        .metadata()
        .map_err(|_| "Integrity Error: Failed to verify open key file metadata.".to_string())?;

    // Prevent TOCTOU path substitution between symlink_metadata() and open() on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if lstat.dev() != fstat.dev() || lstat.ino() != fstat.ino() || fstat.nlink() > 1 {
            return Err(
                "Security Error: Key file inode changed or has multiple hard links.".to_string(),
            );
        }
    }

    if !fstat.is_file() || fstat.len() != size {
        return Err("Security Error: Key file state changed during access.".to_string());
    }

    let mut noise = Zeroizing::new(vec![0u8; size as usize]);
    OsRng.fill_bytes(&mut noise);

    file.seek(SeekFrom::Start(0))
        .map_err(|_| "Integrity Error: Key file seek failed.".to_string())?;
    file.write_all(&noise)
        .map_err(|_| "Integrity Error: Key file overwrite failed.".to_string())?;
    file.sync_all()
        .map_err(|_| "Integrity Error: Key file disk sync failed.".to_string())?;

    Ok(())
}

/// Silently overwrites the target key file (.obk) with cryptographically secure random noise
pub fn trigger_dummy_scramble(key_path: &str) -> Result<String, String> {
    scramble_key_file_verified(key_path)?;

    // Plausible deniability: string strictly matches standard AEAD authentication tag failure
    Err("Decryption Failed! Data corruption or mismatched cryptographic key.".to_string())
}