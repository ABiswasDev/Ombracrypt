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

/// Validates that a filename strictly matches the Ombracrypt staging file specification:
/// .ombracrypt_part_<32-hex-characters>.part (exactly 54 bytes)
pub fn is_valid_staging_file_name(name: &str) -> bool {
    name.len() == 54
        && name.starts_with(".ombracrypt_part_")
        && name.ends_with(".part")
        && name[17..49].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validates that a directory name strictly matches the Ombracrypt extraction staging directory specification:
/// .ombracrypt_stage_<32-hex-characters> (exactly 50 bytes)
pub fn is_valid_staging_dir_name(name: &str) -> bool {
    name.len() == 50
        && name.starts_with(".ombracrypt_stage_")
        && name[18..50].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validates that an open, locked sentinel file descriptor still corresponds to an active,
/// non-unlinked file at sentinel_path. Detects and prevents the stale-open file descriptor race
/// across Unix (st_dev, st_ino, st_nlink) and Windows (dwVolumeSerialNumber, nFileIndex, nNumberOfLinks).
pub fn verify_locked_sentinel(sentinel_file: &File, sentinel_path: &Path) -> bool {
    let Ok(locked_meta) = sentinel_file.metadata() else {
        return false;
    };

    if !locked_meta.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // If nlink == 0, the file was unlinked before lock acquisition (stale FD race)
        if locked_meta.nlink() == 0 {
            return false;
        }

        // Verify the directory path entry still points to the exact same inode we locked
        let Ok(recheck_meta) = fs::symlink_metadata(sentinel_path) else {
            return false;
        };
        if recheck_meta.dev() != locked_meta.dev() || recheck_meta.ino() != locked_meta.ino() {
            return false;
        }
    }

    #[cfg(windows)]
    {
        use std::mem::MaybeUninit;
        use std::os::windows::io::AsRawHandle;

        let locked_h = sentinel_file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let mut locked_info = MaybeUninit::<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION>::uninit();
        let success = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
                locked_h,
                locked_info.as_mut_ptr(),
            )
        };
        if success == 0 {
            return false;
        }
        let locked_info = unsafe { locked_info.assume_init() };

        // If number of links is 0, the file is in delete-pending state on NTFS
        if locked_info.nNumberOfLinks == 0 {
            return false;
        }

        let Ok(recheck_file) = OpenOptions::new().read(true).open(sentinel_path) else {
            return false;
        };

        let recheck_h = recheck_file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let mut recheck_info = MaybeUninit::<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION>::uninit();
        let success = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
                recheck_h,
                recheck_info.as_mut_ptr(),
            )
        };
        if success == 0 {
            return false;
        }
        let recheck_info = unsafe { recheck_info.assume_init() };

        if locked_info.dwVolumeSerialNumber != recheck_info.dwVolumeSerialNumber
            || locked_info.nFileIndexHigh != recheck_info.nFileIndexHigh
            || locked_info.nFileIndexLow != recheck_info.nFileIndexLow
        {
            return false;
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        if fs::symlink_metadata(sentinel_path).is_err() {
            return false;
        }
    }

    true
}

/// Generates a hidden, CSPRNG-unique staging path with strict .ombracrypt_part_ namespace
pub fn unique_staging_path(dir: &Path, _base_filename: &str) -> PathBuf {
    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);
    dir.join(format!(".ombracrypt_part_{:032x}.part", u128::from_be_bytes(rnd)))
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
    if let Err(e) = file.try_lock_exclusive() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Failed to acquire exclusive lock on staging file: {}", e));
    }
    Ok(file)
}

/// Creates a standard exclusive staging file for public keys (.obp) and encrypted vaults (.obv)
pub fn create_public_staging_file(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Failed to create staging file: {}", e))?;
    if let Err(e) = file.try_lock_exclusive() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Failed to acquire exclusive lock on staging file: {}", e));
    }
    Ok(file)
}

/// Creates a CSPRNG-unique extraction staging directory with restrictive 0700 permissions on Unix
/// and initializes an exclusively locked .active.lock sentinel inside it.
pub fn create_secure_staging_dir(out_dir: &Path, _file_stem: &str) -> Result<(PathBuf, File), String> {
    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);
    let stage_dir = out_dir.join(format!(
        ".ombracrypt_stage_{:032x}",
        u128::from_be_bytes(rnd)
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

    let sentinel_path = stage_dir.join(".active.lock");
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let sentinel_file = opts.open(&sentinel_path).map_err(|e| {
        let _ = fs::remove_dir_all(&stage_dir);
        format!("Failed to create staging directory sentinel lock: {}", e)
    })?;

    if let Err(e) = sentinel_file.try_lock_exclusive() {
        drop(sentinel_file);
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(format!("Failed to acquire exclusive lock on staging directory sentinel: {}", e));
    }

    Ok((stage_dir, sentinel_file))
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

        // Reject symlinks without traversing them
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }

        if meta.is_dir() && is_valid_staging_dir_name(&name_str) {
            // Never purge directories currently active in any running pipeline thread in this process
            if is_staging_path_active(&path) {
                continue;
            }

            let sentinel_path = path.join(".active.lock");

            // Look for .active.lock; reject missing, symlink, or non-regular file
            let Ok(sentinel_meta) = fs::symlink_metadata(&sentinel_path) else {
                continue;
            };
            if !sentinel_meta.is_file() || sentinel_meta.file_type().is_symlink() {
                continue;
            }

            // Attempt to open the sentinel file
            let Ok(sentinel_file) = OpenOptions::new().read(true).write(true).open(&sentinel_path) else {
                continue;
            };

            // If an active extractor is holding the lock, try_lock_exclusive will fail
            if sentinel_file.try_lock_exclusive().is_err() {
                continue;
            }

            // Post-lock validation: Verify sentinel was not unlinked or substituted before lock acquisition
            if !verify_locked_sentinel(&sentinel_file, &sentinel_path) {
                drop(sentinel_file);
                continue;
            }

            let dir_bytes = calculate_dir_metrics(&path).map(|(b, _)| b).unwrap_or(0);

            #[cfg(unix)]
            {
                if fs::remove_dir_all(&path).is_ok() {
                    count += 1;
                    freed_bytes = freed_bytes.saturating_add(dir_bytes);
                }
                drop(sentinel_file);
            }
            #[cfg(windows)]
            {
                // On Windows: Delete inner files, then delete sentinel, drop lock handle, and remove parent dir.
                // Strict invariant: Never remove .active.lock if any child deletion or enumeration fails.
                let mut all_children_removed = true;
                match fs::read_dir(&path) {
                    Ok(sub_entries) => {
                        for sub_res in sub_entries {
                            match sub_res {
                                Ok(sub_entry) => {
                                    let sub_path = sub_entry.path();
                                    if sub_path.file_name().and_then(|s| s.to_str()) != Some(".active.lock") {
                                        let del_res = if sub_path.is_dir() {
                                            fs::remove_dir_all(&sub_path)
                                        } else {
                                            fs::remove_file(&sub_path)
                                        };
                                        if del_res.is_err() {
                                            all_children_removed = false;
                                            break;
                                        }
                                    }
                                }
                                Err(_) => {
                                    all_children_removed = false;
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        all_children_removed = false;
                    }
                }

                if all_children_removed {
                    if fs::remove_file(&sentinel_path).is_ok() {
                        drop(sentinel_file);
                        if fs::remove_dir(&path).is_ok() {
                            count += 1;
                            freed_bytes = freed_bytes.saturating_add(dir_bytes);
                        } else {
                            // Parent dir removal failed: atomically recreate sentinel under exclusive lock
                            // so subsequent passes can safely retry cleanup
                            if let Ok(recovered_sentinel) = OpenOptions::new()
                                .read(true)
                                .write(true)
                                .create_new(true)
                                .open(&sentinel_path)
                            {
                                let _ = recovered_sentinel.try_lock_exclusive();
                                drop(recovered_sentinel);
                            }
                        }
                    } else {
                        drop(sentinel_file);
                    }
                } else {
                    drop(sentinel_file);
                }
            }
            #[cfg(not(any(unix, windows)))]
            {
                if fs::remove_dir_all(&path).is_ok() {
                    count += 1;
                    freed_bytes = freed_bytes.saturating_add(dir_bytes);
                }
                drop(sentinel_file);
            }
        } else if meta.is_file() && is_valid_staging_file_name(&name_str) {
            // Never purge files actively registered in memory by an ongoing write operation
            if is_staging_path_active(&path) {
                continue;
            }

            // Attempt to open the candidate file
            let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
                continue;
            };

            // Skip files held by an active writer
            if file.try_lock_exclusive().is_err() {
                continue;
            }

            let file_len = meta.len();

            // Unlink while the exclusive lock handle remains active in scope
            if fs::remove_file(&path).is_ok() {
                freed_bytes = freed_bytes.saturating_add(file_len);
                count += 1;
            }
            drop(file);
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

/// RAII Guard that automatically tracks, locks, and wipes the temporary extraction staging folder on failure
pub struct TempDirGuard {
    path: PathBuf,
    sentinel_lock: Option<File>,
    armed: bool,
}

impl TempDirGuard {
    pub fn new(path: PathBuf) -> Self {
        register_active_staging_path(path.clone());
        Self {
            path,
            sentinel_lock: None,
            armed: true,
        }
    }

    pub fn with_sentinel(path: PathBuf, sentinel_lock: File) -> Self {
        register_active_staging_path(path.clone());
        Self {
            path,
            sentinel_lock: Some(sentinel_lock),
            armed: true,
        }
    }

    /// Releases and unlinks the sentinel file cleanly before publication so the target output remains clean.
    /// Retains ownership of the lock descriptor if unlinking fails to guarantee fail-closed teardown.
    pub fn release_sentinel(&mut self) -> Result<(), String> {
        if self.sentinel_lock.is_some() {
            let sentinel_path = self.path.join(".active.lock");
            fs::remove_file(&sentinel_path)
                .map_err(|e| format!("Security Error: Failed to remove staging sentinel: {}", e))?;
            self.sentinel_lock = None;
        }
        Ok(())
    }

    pub fn disarm(&mut self) {
        self.armed = false;
        self.sentinel_lock = None;
        unregister_active_staging_path(&self.path);
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        unregister_active_staging_path(&self.path);
        if self.armed && self.path.exists() {
            self.sentinel_lock = None;
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Publishes an extraction staging directory to its final destination atomically without replacing an existing directory or file.
/// Fails closed if the destination exists (including dangling symlinks) or if the filesystem does not support no-replace publication.
pub fn atomic_publish_dir_noreplace(src: &Path, dst: &Path) -> Result<(), String> {
    // Detect existing destination before rename to catch dangling symlinks and collisions upfront
    if fs::symlink_metadata(dst).is_ok() {
        return Err(format!(
            "Refusing to overwrite existing destination: {}",
            dst.display()
        ));
    }

    // Use platform-native atomic no-replace publication
    atomic_publish_noreplace_internal(src, dst, false).map_err(|e| {
        if e.contains("Refusing to overwrite existing") {
            format!("Refusing to overwrite existing destination: {}", dst.display())
        } else {
            e
        }
    })
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