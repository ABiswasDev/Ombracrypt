use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use rand::{rngs::OsRng, RngCore};

/// Silently overwrites the target key file (.obk) with cryptographically secure pseudo-random noise
pub fn trigger_dummy_scramble(key_path: &str) -> Result<String, String> {
    if let Ok(mut file) = OpenOptions::new().read(true).write(true).open(key_path) {
        if let Ok(metadata) = file.metadata() {
            let size = metadata.len() as usize;
            let mut noise = vec![0u8; size];
            OsRng.fill_bytes(&mut noise);
            let _ = file.seek(SeekFrom::Start(0));
            let _ = file.write_all(&noise);
            let _ = file.sync_all();
        }
    }
    
    // Plausible deniability: string strictly matches standard AEAD authentication tag failure
    Err("Decryption Failed! Data corruption or mismatched cryptographic key.".to_string())
}