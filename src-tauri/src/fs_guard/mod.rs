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

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub mod fallback;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
use fallback as platform;

pub const MAX_KEY_FILE_BYTES: u64 = 8192;
pub const MIN_KEY_FILE_BYTES: u64 = 64;

static ACTIVE_STAGING_PATHS: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);

pub fn register_active_staging_path(path: PathBuf) {
    if let Ok(mut lock) = ACTIVE_STAGING_PATHS.lock() {
        lock.get_or_insert_with(HashSet::new).insert(path);
    }
}

pub fn unregister_active_staging_path(path: &Path) {
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

/// Identifies whether a lock error is due to active lock contention rather than I/O or permissions failure
fn is_lock_contention(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        // ERROR_LOCK_VIOLATION = 33
        if err.raw_os_error() == Some(33) {
            return true;
        }
    }
    #[cfg(unix)]
    {
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN) {
            return true;
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

/// Structured report returned by staging cleanup operations.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct CleanupReport {
    pub removed_count: usize,
    pub freed_bytes: u64,
    pub active_skipped_count: usize,
    pub unowned_skipped_count: usize,
    pub failed_count: usize,
    pub failed_artifacts: Vec<(PathBuf, String)>,
}

pub fn sync_parent_directory(dir: &Path) {
    if let Ok(dir_handle) = File::open(dir) {
        let _ = dir_handle.sync_all();
    }
}

pub fn is_valid_staging_file_name(name: &str) -> bool {
    name.len() == 54
        && name.starts_with(".ombracrypt_part_")
        && name.ends_with(".part")
        && name[17..49].bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_valid_staging_dir_name(name: &str) -> bool {
    name.len() == 50
        && name.starts_with(".ombracrypt_stage_")
        && name[18..50].bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn verify_locked_sentinel(sentinel_file: &File, sentinel_path: &Path) -> bool {
    platform::verify_locked_sentinel(sentinel_file, sentinel_path)
}

pub fn unique_staging_path(dir: &Path, _base_filename: &str) -> PathBuf {
    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);
    dir.join(format!(".ombracrypt_part_{:032x}.part", u128::from_be_bytes(rnd)))
}

pub fn create_private_staging_file(path: &Path) -> Result<File, String> {
    platform::create_private_staging_file(path)
}

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

pub fn create_secure_staging_dir(
    out_dir: &Path,
    _file_stem: &str,
) -> Result<(PathBuf, PathBuf, File), String> {
    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);
    let wrapper_dir = out_dir.join(format!(
        ".ombracrypt_stage_{:032x}",
        u128::from_be_bytes(rnd)
    ));
    let payload_dir = wrapper_dir.join("payload");
    let sentinel_path = wrapper_dir.join(".active.lock");

    let sentinel_file = platform::create_secure_staging_dir(&wrapper_dir, &payload_dir, &sentinel_path)?;
    Ok((wrapper_dir, payload_dir, sentinel_file))
}

pub fn clean_scoped_staging_dir_report(dir: &Path) -> Result<CleanupReport, String> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!(
                "Security policy violation: Refusing to scan symbolic-link root: {}",
                dir.display()
            ));
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(format!(
                "Invalid path: Selected path is not a directory: {}",
                dir.display()
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "Directory not found: Selected path does not exist: {}",
                dir.display()
            ));
        }
        Err(e) => {
            return Err(format!(
                "Access error: Cannot inspect directory metadata for {}: {}",
                dir.display(),
                e
            ));
        }
    }

    let mut report = CleanupReport::default();
    let entries = fs::read_dir(dir).map_err(|e| format!("Failed to inspect directory: {}", e))?;

    for entry_res in entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(e) => {
                report.failed_count += 1;
                if report.failed_artifacts.len() < 10 {
                    report.failed_artifacts.push((
                        dir.to_path_buf(),
                        format!("Failed to read directory entry: {}", e),
                    ));
                }
                continue;
            }
        };

        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                report.failed_count += 1;
                if report.failed_artifacts.len() < 10 {
                    report.failed_artifacts.push((
                        path,
                        format!("Failed to read artifact metadata: {}", e),
                    ));
                }
                continue;
            }
        };

        // Conservative deletion policy: never traverse or delete symlinks.
        // Surface staging-named symlinks in failed_artifacts for auditability.
        if meta.file_type().is_symlink() {
            if is_valid_staging_dir_name(&name_str) || is_valid_staging_file_name(&name_str) {
                report.failed_count += 1;
                if report.failed_artifacts.len() < 10 {
                    report.failed_artifacts.push((
                        path,
                        "Skipped for safety: untrusted symbolic-link staging artifact".to_string(),
                    ));
                }
            }
            continue;
        }

        if meta.is_dir() && is_valid_staging_dir_name(&name_str) {
            if is_staging_path_active(&path) {
                report.active_skipped_count += 1;
                continue;
            }

            let sentinel_path = path.join(".active.lock");
            match fs::symlink_metadata(&sentinel_path) {
                Ok(sm) if sm.is_file() && !sm.file_type().is_symlink() => {}
                Ok(_) => {
                    report.unowned_skipped_count += 1;
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Safe reclamation: if sentinel is absent, check whether the wrapper is strictly empty.
                    let is_empty = match fs::read_dir(&path) {
                        Ok(mut it) => it.next().is_none(),
                        Err(_) => false,
                    };

                    if is_empty {
                        // Non-recursive remove_dir fails at kernel boundary if any child exists.
                        match fs::remove_dir(&path) {
                            Ok(()) => {
                                report.removed_count += 1;
                            }
                            Err(err) => {
                                report.failed_count += 1;
                                if report.failed_artifacts.len() < 10 {
                                    report.failed_artifacts.push((
                                        path.clone(),
                                        format!("Failed to remove empty residual staging wrapper: {}", err),
                                    ));
                                }
                            }
                        }
                    } else {
                        report.unowned_skipped_count += 1;
                    }
                    continue;
                }
                Err(e) => {
                    report.failed_count += 1;
                    if report.failed_artifacts.len() < 10 {
                        report.failed_artifacts.push((
                            sentinel_path,
                            format!("Inaccessible sentinel: {}", e),
                        ));
                    }
                    continue;
                }
            }

            let sentinel_file = match OpenOptions::new().read(true).write(true).open(&sentinel_path) {
                Ok(f) => f,
                Err(e) => {
                    report.failed_count += 1;
                    if report.failed_artifacts.len() < 10 {
                        report.failed_artifacts.push((
                            sentinel_path,
                            format!("Failed to open sentinel file: {}", e),
                        ));
                    }
                    continue;
                }
            };

            match sentinel_file.try_lock_exclusive() {
                Ok(()) => {}
                Err(e) if is_lock_contention(&e) => {
                    report.active_skipped_count += 1;
                    continue;
                }
                Err(e) => {
                    report.failed_count += 1;
                    if report.failed_artifacts.len() < 10 {
                        report.failed_artifacts.push((
                            sentinel_path,
                            format!("Failed to lock sentinel file: {}", e),
                        ));
                    }
                    continue;
                }
            }

            if !verify_locked_sentinel(&sentinel_file, &sentinel_path) {
                drop(sentinel_file);
                report.unowned_skipped_count += 1;
                continue;
            }

            let dir_bytes = calculate_dir_metrics(&path).map(|(b, _)| b).unwrap_or(0);
            platform::clean_staged_dir(&path, &sentinel_path, sentinel_file, dir_bytes, &mut report);
        } else if meta.is_file() && is_valid_staging_file_name(&name_str) {
            if is_staging_path_active(&path) {
                report.active_skipped_count += 1;
                continue;
            }

            let file = match OpenOptions::new().read(true).write(true).open(&path) {
                Ok(f) => f,
                Err(e) => {
                    report.failed_count += 1;
                    if report.failed_artifacts.len() < 10 {
                        report.failed_artifacts.push((
                            path,
                            format!("Failed to open staging file: {}", e),
                        ));
                    }
                    continue;
                }
            };

            match file.try_lock_exclusive() {
                Ok(()) => {}
                Err(e) if is_lock_contention(&e) => {
                    report.active_skipped_count += 1;
                    continue;
                }
                Err(e) => {
                    report.failed_count += 1;
                    if report.failed_artifacts.len() < 10 {
                        report.failed_artifacts.push((
                            path,
                            format!("Failed to lock staging file: {}", e),
                        ));
                    }
                    continue;
                }
            }

            let file_len = meta.len();
            platform::clean_staged_file(&path, file, file_len, &mut report);
        }
    }

    sync_parent_directory(dir);
    Ok(report)
}

pub fn clean_scoped_staging_dir(dir: &Path) -> Result<(usize, u64), String> {
    let report = clean_scoped_staging_dir_report(dir)?;
    if report.failed_count > 0 {
        return Err(format!(
            "Incomplete cleanup: {} staging artifact(s) could not be removed: {:?}",
            report.failed_count, report.failed_artifacts
        ));
    }
    Ok((report.removed_count, report.freed_bytes))
}

pub fn read_bounded_key_file(path_str: &str, label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = File::open(path_str)
        .map_err(|_| format!("Authentication Error: {} could not be accessed.", label))?;
    let meta = file
        .metadata()
        .map_err(|_| format!("Integrity Error: Failed to read {} metadata.", label))?;

    if !meta.is_file() {
        return Err(format!("Security Error: Selected {} is not a regular file.", label));
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

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Standard platform cleanup invoking OS-specific teardown.
    pub fn cleanup_fallible(&mut self) -> Result<(), (PathBuf, std::io::Error)> {
        self.cleanup_fallible_with(platform::teardown_staging_dir)
    }

    /// Teardown with dependency-injected teardown function for deterministic failure testing.
    pub fn cleanup_fallible_with<F>(&mut self, teardown_fn: F) -> Result<(), (PathBuf, std::io::Error)>
    where
        F: FnOnce(&Path, &Path, Option<File>) -> Result<(), (PathBuf, std::io::Error)>,
    {
        self.armed = false;
        unregister_active_staging_path(&self.path);

        match self.path.symlink_metadata() {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(e) => return Err((self.path.clone(), e)),
        }

        let payload = self.path.join("payload");
        match payload.symlink_metadata() {
            Ok(_) => {
                if let Err(e) = fs::remove_dir_all(&payload) {
                    return Err((payload, e));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err((payload, e)),
        }

        let sentinel_path = self.path.join(".active.lock");
        teardown_fn(&self.path, &sentinel_path, self.sentinel_lock.take())
    }

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
        if self.armed {
            let _ = self.cleanup_fallible();
        }
    }
}

pub fn atomic_publish_dir_noreplace(src: &Path, dst: &Path) -> Result<(), String> {
    if fs::symlink_metadata(dst).is_ok() {
        return Err(format!(
            "Refusing to overwrite existing destination: {}",
            dst.display()
        ));
    }
    atomic_publish_noreplace_internal(src, dst, false).map_err(|e| {
        if e.contains("Refusing to overwrite existing") {
            format!("Refusing to overwrite existing destination: {}", dst.display())
        } else {
            e
        }
    })
}

pub fn atomic_publish_noreplace(src: &Path, dst: &Path) -> Result<(), String> {
    atomic_publish_noreplace_internal(src, dst, false)
}

pub fn atomic_publish_noreplace_internal(
    src: &Path,
    dst: &Path,
    simulate_unsupported: bool,
) -> Result<(), String> {
    platform::rename_noreplace(src, dst, simulate_unsupported)
}

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
        if fs::symlink_metadata(final_path).is_ok() {
            return Err(format!(
                "Refusing to overwrite existing file: {}",
                final_path.display()
            ));
        }

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
                if fs::symlink_metadata(final_path).is_ok() {
                    return Err(format!(
                        "Refusing to overwrite existing file: {}",
                        final_path.display()
                    ));
                }
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