use std::fs::File;
use std::path::{Path, PathBuf};

use super::CleanupReport;

/// Refuses to stage private files on unsupported platforms lacking verified 0600 file modes.
pub fn create_private_staging_file(_path: &Path) -> Result<File, String> {
    Err("Target platform does not support secure private staging file creation with mandatory 0600 permissions and exclusive locking".to_string())
}

/// Fails closed: refuses to construct staging directories on unsupported platforms lacking kernel-enforced locking and atomic isolation.
pub fn create_secure_staging_dir(
    _wrapper_dir: &Path,
    _payload_dir: &Path,
    _sentinel_path: &Path,
) -> Result<File, String> {
    Err("Target platform does not support secure staging directory isolation and atomic lock guarantees".to_string())
}

/// Always returns false on unsupported platforms to prevent unauthorized operations on unvalidated handles.
pub fn verify_locked_sentinel(_sentinel_file: &File, _sentinel_path: &Path) -> bool {
    false
}

/// Fails closed: unsupported platforms do not guarantee atomic non-overwriting publication.
pub fn rename_noreplace(_src: &Path, dst: &Path, _simulate_unsupported: bool) -> Result<(), String> {
    Err(format!(
        "Target platform does not support atomic no-replace publication: {}",
        dst.display()
    ))
}

/// Rejects out-of-band teardown on unsupported platforms without verified file ownership.
pub fn teardown_staging_dir(
    wrapper_dir: &Path,
    _sentinel_path: &Path,
    sentinel_lock: Option<File>,
) -> Result<(), (PathBuf, std::io::Error)> {
    drop(sentinel_lock);
    Err((
        wrapper_dir.to_path_buf(),
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "Staging directory teardown is unsupported on this platform",
        ),
    ))
}

/// Records a failed cleanup artifact rather than silently attempting unvalidated directory sweeps.
pub fn clean_staged_dir(
    path: &Path,
    _sentinel_path: &Path,
    sentinel_file: File,
    _dir_bytes: u64,
    report: &mut CleanupReport,
) {
    drop(sentinel_file);
    report.failed_count += 1;
    if report.failed_artifacts.len() < 10 {
        report.failed_artifacts.push((
            path.to_path_buf(),
            "Staging directory cleanup is unsupported on this platform".to_string(),
        ));
    }
}

/// Records a failed cleanup artifact rather than silently attempting unvalidated file deletion.
pub fn clean_staged_file(
    path: &Path,
    file: File,
    _file_len: u64,
    report: &mut CleanupReport,
) {
    drop(file);
    report.failed_count += 1;
    if report.failed_artifacts.len() < 10 {
        report.failed_artifacts.push((
            path.to_path_buf(),
            "Staging file cleanup is unsupported on this platform".to_string(),
        ));
    }
}