use fs2::FileExt;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::CleanupReport;

/// Opens a private key file enforcing strict 0600 (owner read/write) permissions.
pub fn create_private_staging_file(path: &Path) -> Result<File, String> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
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

/// Creates the outer extraction wrapper with 0700 permissions and an inner payload directory.
pub fn create_secure_staging_dir(
    wrapper_dir: &Path,
    payload_dir: &Path,
    sentinel_path: &Path,
) -> Result<File, String> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(wrapper_dir)
        .map_err(|e| format!("Failed to create secure staging directory: {}", e))?;

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true).mode(0o600);
    let sentinel_file = opts.open(sentinel_path).map_err(|e| {
        let _ = fs::remove_dir_all(wrapper_dir);
        format!("Failed to create staging directory sentinel lock: {}", e)
    })?;

    if let Err(e) = sentinel_file.try_lock_exclusive() {
        drop(sentinel_file);
        let _ = fs::remove_dir_all(wrapper_dir);
        return Err(format!(
            "Failed to acquire exclusive lock on staging directory sentinel: {}",
            e
        ));
    }

    if let Err(e) = fs::DirBuilder::new().mode(0o700).create(payload_dir) {
        drop(sentinel_file);
        let _ = fs::remove_dir_all(wrapper_dir);
        return Err(format!("Failed to create staging payload directory: {}", e));
    }

    Ok(sentinel_file)
}

/// Validates that an open sentinel descriptor still links to the target inode on disk.
pub fn verify_locked_sentinel(sentinel_file: &File, sentinel_path: &Path) -> bool {
    let Ok(locked_meta) = sentinel_file.metadata() else {
        return false;
    };
    if !locked_meta.is_file() || locked_meta.nlink() == 0 {
        return false;
    }

    let Ok(recheck_meta) = fs::symlink_metadata(sentinel_path) else {
        return false;
    };
    recheck_meta.dev() == locked_meta.dev() && recheck_meta.ino() == locked_meta.ino()
}

/// Linux atomic no-replace publication via libc::renameat2.
pub fn rename_noreplace(src: &Path, dst: &Path, simulate_unsupported: bool) -> Result<(), String> {
    if simulate_unsupported {
        return Err(format!(
            "Target filesystem does not support atomic no-replace publication: {}",
            dst.display()
        ));
    }

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
                    "Atomic publication failed: Target filesystem returned EINVAL (os error 22). \
                    The underlying filesystem or mount configuration does not support RENAME_NOREPLACE flags, \
                    or the kernel rejected the requested operation. \
                    This frequently occurs on FUSE mounts (such as ntfs-3g) or eCryptfs encrypted directories. \
                    Please choose an extraction destination on a native Linux filesystem (e.g., ext4, btrfs) \
                    or remount NTFS volumes using the in-kernel 'ntfs3' driver. Existing files were not overwritten."
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

/// POSIX teardown: Unlinks the sentinel with explicit error classification, deletes wrapper, then drops lock.
pub fn teardown_staging_dir(
    wrapper_dir: &Path,
    sentinel_path: &Path,
    sentinel_lock: Option<File>,
) -> Result<(), (PathBuf, std::io::Error)> {
    match fs::symlink_metadata(sentinel_path) {
        Ok(_) => {
            if let Err(e) = fs::remove_file(sentinel_path) {
                return Err((sentinel_path.to_path_buf(), e));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err((sentinel_path.to_path_buf(), e)),
    }
    drop(sentinel_lock);

    if let Err(e) = fs::remove_dir(wrapper_dir) {
        return Err((wrapper_dir.to_path_buf(), e));
    }
    Ok(())
}

/// Cleans a stale staging directory on Linux by purging the tree and dropping the lock descriptor.
pub fn clean_staged_dir(
    path: &Path,
    _sentinel_path: &Path,
    sentinel_file: File,
    dir_bytes: u64,
    report: &mut CleanupReport,
) {
    match fs::remove_dir_all(path) {
        Ok(()) => {
            report.removed_count += 1;
            report.freed_bytes = report.freed_bytes.saturating_add(dir_bytes);
        }
        Err(e) => {
            report.failed_count += 1;
            if report.failed_artifacts.len() < 10 {
                report.failed_artifacts.push((
                    path.to_path_buf(),
                    format!("Failed to remove staging directory: {}", e),
                ));
            }
        }
    }
    drop(sentinel_file);
}

/// Cleans an unowned staging file while the descriptor lock is held.
pub fn clean_staged_file(
    path: &Path,
    file: File,
    file_len: u64,
    report: &mut CleanupReport,
) {
    match fs::remove_file(path) {
        Ok(()) => {
            report.removed_count += 1;
            report.freed_bytes = report.freed_bytes.saturating_add(file_len);
        }
        Err(e) => {
            report.failed_count += 1;
            if report.failed_artifacts.len() < 10 {
                report.failed_artifacts.push((
                    path.to_path_buf(),
                    format!("Failed to remove staging file: {}", e),
                ));
            }
        }
    }
    drop(file);
}