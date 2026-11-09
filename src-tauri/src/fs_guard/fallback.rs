use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use super::CleanupReport;

pub fn create_private_staging_file(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Failed to create private key staging file: {}", e))
}

pub fn create_secure_staging_dir(
    wrapper_dir: &Path,
    payload_dir: &Path,
    sentinel_path: &Path,
) -> Result<File, String> {
    fs::create_dir(wrapper_dir).map_err(|e| e.to_string())?;
    let sentinel = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(sentinel_path)
        .map_err(|e| e.to_string())?;
    fs::create_dir(payload_dir).map_err(|e| e.to_string())?;
    Ok(sentinel)
}

pub fn verify_locked_sentinel(_sentinel_file: &File, sentinel_path: &Path) -> bool {
    fs::symlink_metadata(sentinel_path).is_ok()
}

pub fn rename_noreplace(_src: &Path, dst: &Path, _simulate_unsupported: bool) -> Result<(), String> {
    Err(format!(
        "Target platform does not support atomic no-replace publication: {}",
        dst.display()
    ))
}

pub fn teardown_staging_dir(
    wrapper_dir: &Path,
    _sentinel_path: &Path,
    sentinel_lock: Option<File>,
) -> Result<(), (PathBuf, std::io::Error)> {
    drop(sentinel_lock);
    fs::remove_dir_all(wrapper_dir).map_err(|e| (wrapper_dir.to_path_buf(), e))
}

pub fn clean_staged_dir(
    path: &Path,
    _sentinel_path: &Path,
    sentinel_file: File,
    dir_bytes: u64,
    report: &mut CleanupReport,
) {
    drop(sentinel_file);
    if fs::remove_dir_all(path).is_ok() {
        report.removed_count += 1;
        report.freed_bytes = report.freed_bytes.saturating_add(dir_bytes);
    } else {
        report.failed_count += 1;
    }
}

pub fn clean_staged_file(
    path: &Path,
    file: File,
    file_len: u64,
    report: &mut CleanupReport,
) {
    drop(file);
    if fs::remove_file(path).is_ok() {
        report.removed_count += 1;
        report.freed_bytes = report.freed_bytes.saturating_add(file_len);
    } else {
        report.failed_count += 1;
    }
}