use fs2::{available_space, FileExt};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::crypto::{compute_obk_public_fingerprint, compute_obp_fingerprint};
use crate::stream::{read_vault_uncompressed_size, CHUNK_SIZE};

/// Maximum permissible size for an .obk or .obp file (8 KiB ceiling prevents OOM DoS)
pub const MAX_KEY_FILE_BYTES: u64 = 8192;
pub const MIN_KEY_FILE_BYTES: u64 = 64;

// Global registry tracking in-flight staging artifacts across threads to prevent cleaner collision
static ACTIVE_STAGING_PATHS: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);

fn register_active_staging_path(path: PathBuf) {
    if let Ok(mut lock) = ACTIVE_STAGING_PATHS.lock() {
        lock.get_or_insert_with(HashSet::new).insert(path);
    }
}

fn unregister_active_staging_path(path: &Path) {
    if let Ok(mut lock) = ACTIVE_STAGING_PATHS.lock() {
        if let Some(ref mut set) = *lock {
            set.remove(path);
        }
    }
}

pub fn is_staging_path_active(path: &Path) -> bool {
    if let Ok(lock) = ACTIVE_STAGING_PATHS.lock() {
        if let Some(ref set) = *lock {
            return set.contains(path);
        }
    }
    false
}

#[derive(Serialize)]
pub struct SpaceAssessment {
    pub required_bytes: u64,
    pub available_bytes: u64,
    pub raw_bytes: u64,
    pub item_count: u64,
    pub sufficient: bool,
    pub conflict_error: Option<String>,
    pub key_fingerprint: Option<String>,
    pub summary: String,
}

/// Flushes directory metadata to disk/USB so newly committed files/folders appear immediately
pub fn sync_parent_directory(dir: &Path) {
    if let Ok(dir_handle) = File::open(dir) {
        let _ = dir_handle.sync_all();
    }
}

/// Generates a hidden, CSPRNG-unique staging path so concurrent operations never collide
pub fn unique_staging_path(dir: &Path, base_filename: &str) -> PathBuf {
    let mut rnd = [0u8; 6];
    OsRng.fill_bytes(&mut rnd);
    dir.join(format!(
        ".{}.{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.part",
        base_filename, rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5]
    ))
}

/// Creates a staging file for private keys (.obk) with strict 0600 (owner-only) permissions on Unix
pub fn create_private_staging_file(path: &Path) -> Result<File, String> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts
        .open(path)
        .map_err(|e| format!("Failed to create private key staging file: {}", e))?;
    let _ = file.try_lock_exclusive();
    Ok(file)
}

/// Creates a standard exclusive staging file for public keys (.obp) and encrypted vaults (.obv)
pub fn create_public_staging_file(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Failed to create staging file: {}", e))?;
    let _ = file.try_lock_exclusive();
    Ok(file)
}

/// Creates a CSPRNG-unique extraction staging directory with restrictive 0700 permissions on Unix
pub fn create_secure_staging_dir(out_dir: &Path, file_stem: &str) -> Result<PathBuf, String> {
    let mut rnd = [0u8; 6];
    OsRng.fill_bytes(&mut rnd);
    let stage_dir = out_dir.join(format!(
        ".ombracrypt_stage_{}_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        file_stem, rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5]
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&stage_dir)
            .map_err(|e| format!("Failed to create secure staging directory: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(&stage_dir)
            .map_err(|e| format!("Failed to create secure staging directory: {}", e))?;
    }

    Ok(stage_dir)
}

/// Scans only the designated target folder for stale Ombracrypt staging remnants and purges them safely
pub fn clean_scoped_staging_dir(dir: &Path) -> Result<(usize, u64), String> {
    if !dir.exists() || !dir.is_dir() {
        return Ok((0, 0));
    }

    let mut count = 0usize;
    let mut freed_bytes = 0u64;

    let entries = fs::read_dir(dir).map_err(|e| format!("Failed to inspect directory: {}", e))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if path.is_dir() && name_str.starts_with(".ombracrypt_stage_") {
            // Never purge directories currently active in any running pipeline thread
            if is_staging_path_active(&path) {
                continue;
            }
            if let Ok((b, _)) = calculate_dir_metrics(&path) {
                freed_bytes = freed_bytes.saturating_add(b);
            }
            if fs::remove_dir_all(&path).is_ok() {
                count += 1;
            }
        } else if path.is_file() && name_str.starts_with('.') && name_str.ends_with(".part") {
            // Never purge files actively registered or locked by an ongoing write operation
            if is_staging_path_active(&path) {
                continue;
            }
            if let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) {
                if file.try_lock_exclusive().is_err() {
                    continue;
                }
            }
            if let Ok(meta) = path.metadata() {
                freed_bytes = freed_bytes.saturating_add(meta.len());
            }
            if fs::remove_file(&path).is_ok() {
                count += 1;
            }
        }
    }

    sync_parent_directory(dir);
    Ok((count, freed_bytes))
}

/// Reads an .obk or .obp key file only after enforcing strict minimum and maximum byte bounds
pub fn read_bounded_key_file(path_str: &str, label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = File::open(path_str)
        .map_err(|_| format!("Authentication Error: {} could not be accessed.", label))?;
    let meta = file
        .metadata()
        .map_err(|_| format!("Integrity Error: Failed to read {} metadata.", label))?;

    if !meta.is_file() {
        return Err(format!(
            "Security Error: Selected {} is not a regular file.",
            label
        ));
    }
    let len = meta.len();
    if !(MIN_KEY_FILE_BYTES..=MAX_KEY_FILE_BYTES).contains(&len) {
        return Err(format!(
            "Security Error: {} size ({} bytes) is outside valid key bounds.",
            label, len
        ));
    }

    let mut buf = Zeroizing::new(Vec::with_capacity(len as usize));
    file.take(MAX_KEY_FILE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|_| format!("Integrity Error: Failed to read {} stream.", label))?;
    Ok(buf)
}

/// RAII Guard that automatically tracks and removes partial staging files on error or early return
pub struct TempFileGuard {
    paths: Vec<PathBuf>,
    armed: bool,
}

impl TempFileGuard {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        for p in &paths {
            register_active_staging_path(p.clone());
        }
        Self { paths, armed: true }
    }
    pub fn disarm(&mut self) {
        self.armed = false;
        for p in &self.paths {
            unregister_active_staging_path(p);
        }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        for p in &self.paths {
            unregister_active_staging_path(p);
        }
        if self.armed {
            for p in &self.paths {
                let _ = fs::remove_file(p);
            }
        }
    }
}

/// RAII Guard that automatically tracks and wipes the temporary extraction staging folder on decryption failure
pub struct TempDirGuard {
    path: PathBuf,
    armed: bool,
}

impl TempDirGuard {
    pub fn new(path: PathBuf) -> Self {
        register_active_staging_path(path.clone());
        Self { path, armed: true }
    }
    pub fn disarm(&mut self) {
        self.armed = false;
        unregister_active_staging_path(&self.path);
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        unregister_active_staging_path(&self.path);
        if self.armed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Publishes a staged file to its final destination atomically without replacing an existing file.
/// Fails closed if the destination exists or if the filesystem does not support no-replace publication.
pub fn atomic_publish_noreplace(src: &Path, dst: &Path) -> Result<(), String> {
    atomic_publish_noreplace_internal(src, dst, false)
}

/// Internal implementation supporting simulated failure testing on CI environments.
pub fn atomic_publish_noreplace_internal(
    src: &Path,
    dst: &Path,
    simulate_unsupported: bool,
) -> Result<(), String> {
    if simulate_unsupported {
        return Err(format!(
            "Target filesystem does not support atomic no-replace publication: {}",
            dst.display()
        ));
    }

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_src = CString::new(src.as_os_str().as_bytes())
            .map_err(|e| format!("Invalid path encoding for source: {}", e))?;
        let c_dst = CString::new(dst.as_os_str().as_bytes())
            .map_err(|e| format!("Invalid path encoding for destination: {}", e))?;

        let ret = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                c_src.as_ptr(),
                libc::AT_FDCWD,
                c_dst.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EEXIST) => {
                    Err(format!("Refusing to overwrite existing file: {}", dst.display()))
                }
                Some(libc::ENOSYS) | Some(libc::ENOTSUP) => {
                    Err(format!(
                        "Target filesystem does not support atomic no-replace publication: {}",
                        dst.display()
                    ))
                }
                Some(libc::EINVAL) => {
                    Err(format!(
                        "Target filesystem returned EINVAL (unsupported flag or invalid arguments) during atomic publication: {}",
                        err
                    ))
                }
                _ => Err(format!(
                    "Failed to commit artifact {} via atomic rename: {}",
                    dst.display(),
                    err
                )),
            };
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_src = CString::new(src.as_os_str().as_bytes())
            .map_err(|e| format!("Invalid path encoding for source: {}", e))?;
        let c_dst = CString::new(dst.as_os_str().as_bytes())
            .map_err(|e| format!("Invalid path encoding for destination: {}", e))?;

        let ret = unsafe {
            libc::renamex_np(c_src.as_ptr(), c_dst.as_ptr(), libc::RENAME_EXCL)
        };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EEXIST) => {
                    Err(format!("Refusing to overwrite existing file: {}", dst.display()))
                }
                Some(libc::ENOTSUP) | Some(libc::ENOSYS) => {
                    Err(format!(
                        "Target filesystem does not support atomic no-replace publication: {}",
                        dst.display()
                    ))
                }
                _ => Err(format!(
                    "Failed to commit artifact {} via atomic rename: {}",
                    dst.display(),
                    err
                )),
            };
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        let wide_src: Vec<u16> = src.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let wide_dst: Vec<u16> = dst.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

        let success = unsafe {
            windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                wide_src.as_ptr(),
                wide_dst.as_ptr(),
                0, // Deliberately omit MOVEFILE_REPLACE_EXISTING
            )
        };

        if success == 0 {
            let err_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            const ERROR_FILE_EXISTS: u32 = 80;
            const ERROR_ALREADY_EXISTS: u32 = 183;
            return match err_code {
                ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => {
                    Err(format!("Refusing to overwrite existing file: {}", dst.display()))
                }
                _ => Err(format!(
                    "Failed to commit artifact {} via MoveFileExW (error code {}): {}",
                    dst.display(),
                    err_code,
                    std::io::Error::from_raw_os_error(err_code as i32)
                )),
            };
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(format!(
            "Target platform does not support atomic no-replace publication: {}",
            dst.display()
        ))
    }
}

/// Transactional Publication Guard: Atomically commits staged files without overwriting existing files,
/// and rolls back all newly committed artifacts if any step in a multi-file commit fails.
pub struct CommitRollbackGuard {
    committed: Vec<PathBuf>,
    armed: bool,
}

impl CommitRollbackGuard {
    pub fn new() -> Self {
        Self {
            committed: Vec::new(),
            armed: true,
        }
    }

    pub fn commit_file(&mut self, part_path: &Path, final_path: &Path) -> Result<(), String> {
        // Anti-collision check against regular files, directories, and broken symlinks
        if fs::symlink_metadata(final_path).is_ok() {
            return Err(format!(
                "Refusing to overwrite existing file: {}",
                final_path.display()
            ));
        }

        // Primary: Atomic hard-link promotion (NTFS, APFS, ext4, Btrfs, ZFS, XFS)
        match fs::hard_link(part_path, final_path) {
            Ok(()) => {
                let _ = fs::remove_file(part_path);
                self.committed.push(final_path.to_path_buf());
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
                "Refusing to overwrite existing file: {}",
                final_path.display()
            )),
            Err(_) => {
                // Fallback for filesystems without hard-link support (e.g. FAT32, exFAT).
                // Both part_path and final_path reside in the exact same directory.
                if fs::symlink_metadata(final_path).is_ok() {
                    return Err(format!(
                        "Refusing to overwrite existing file: {}",
                        final_path.display()
                    ));
                }

                // Platform-native atomic no-replace publication (never falls back to clobbering renames)
                atomic_publish_noreplace(part_path, final_path)?;

                self.committed.push(final_path.to_path_buf());
                Ok(())
            }
        }
    }

    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CommitRollbackGuard {
    fn drop(&mut self) {
        if self.armed {
            for p in &self.committed {
                let _ = fs::remove_file(p);
            }
        }
    }
}

/// Canonicalizes source and destination paths to ensure output/key folders are never inside the input folder
pub fn verify_no_source_overlap(
    source_dir: &Path,
    dest_dir: &Path,
    role_label: &str,
) -> Result<(), String> {
    let src_canon = fs::canonicalize(source_dir)
        .map_err(|e| format!("Failed to resolve source path: {}", e))?;
    let dst_canon = fs::canonicalize(dest_dir)
        .map_err(|e| format!("Failed to resolve {} path: {}", role_label, e))?;

    if src_canon.is_dir() && (dst_canon == src_canon || dst_canon.starts_with(&src_canon)) {
        return Err(format!(
            "{} folder cannot be the Input Folder itself or placed inside the Input Folder.",
            role_label
        ));
    }
    Ok(())
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

/// Pre-flight capacity, canonical overlap, path collision, and Key ID fingerprint check
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

        let mut conflict = None;
        let mut key_fingerprint = None;

        if let Err(overlap_err) = verify_no_source_overlap(src, out, "Vault Output") {
            conflict = Some(overlap_err);
        }

        if conflict.is_none() {
            if let Some(k_path) = key_dir_or_file {
                let kp = Path::new(k_path);
                if kp.exists() && kp.is_dir() {
                    if let Err(overlap_err) = verify_no_source_overlap(src, kp, "Key Output") {
                        conflict = Some(overlap_err);
                    }
                } else if kp.exists() && kp.is_file() {
                    match read_bounded_key_file(k_path, "Public Key (.obp)")
                        .and_then(|bytes| compute_obp_fingerprint(&bytes))
                    {
                        Ok(fp) => key_fingerprint = Some(fp),
                        Err(e) => conflict = Some(e),
                    }
                }
            }
        }

        let target_obv = out.join(format!("{}.obv", folder_name));
        if conflict.is_none() && target_obv.exists() {
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
            raw_bytes,
            item_count,
            sufficient,
            conflict_error: conflict,
            key_fingerprint,
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
        let mut conflict = if final_extract_dir.exists() {
            Some(format!(
                "Destination '{}' already exists in the output folder.",
                final_extract_dir.display()
            ))
        } else {
            None
        };

        let mut key_fingerprint = None;
        if conflict.is_none() {
            if let Some(k_path) = key_dir_or_file {
                let kp = Path::new(k_path);
                if kp.exists() && kp.is_file() {
                    match read_bounded_key_file(k_path, "Private Key (.obk)")
                        .and_then(|bytes| compute_obk_public_fingerprint(&bytes))
                    {
                        Ok(fp) => key_fingerprint = Some(fp),
                        Err(e) => conflict = Some(e),
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
            raw_bytes: uncompressed,
            item_count: 0,
            sufficient,
            conflict_error: conflict,
            key_fingerprint,
            summary,
        })
    }
}