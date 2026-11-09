use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use super::CleanupReport;

pub fn create_private_staging_file(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Failed to create private key staging file: {}", e))?;
    if let Err(e) = file.try_lock_exclusive() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Failed to acquire exclusive lock on staging file: {}", e));
    }
    Ok(file)
}

pub fn create_secure_staging_dir(
    wrapper_dir: &Path,
    payload_dir: &Path,
    sentinel_path: &Path,
) -> Result<File, String> {
    fs::create_dir(wrapper_dir)
        .map_err(|e| format!("Failed to create secure staging directory: {}", e))?;

    let sentinel_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(sentinel_path)
        .map_err(|e| {
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

    if let Err(e) = fs::create_dir(payload_dir) {
        drop(sentinel_file);
        let _ = fs::remove_dir_all(wrapper_dir);
        return Err(format!("Failed to create staging payload directory: {}", e));
    }

    Ok(sentinel_file)
}

/// Windows sentinel validation using Win32 GetFileInformationByHandle.
pub fn verify_locked_sentinel(sentinel_file: &File, sentinel_path: &Path) -> bool {
    let Ok(locked_meta) = sentinel_file.metadata() else {
        return false;
    };
    if !locked_meta.is_file() {
        return false;
    }

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

    locked_info.dwVolumeSerialNumber == recheck_info.dwVolumeSerialNumber
        && locked_info.nFileIndexHigh == recheck_info.nFileIndexHigh
        && locked_info.nFileIndexLow == recheck_info.nFileIndexLow
}

/// Windows atomic no-replace publication via MoveFileExW.
pub fn rename_noreplace(src: &Path, dst: &Path, simulate_unsupported: bool) -> Result<(), String> {
    if simulate_unsupported {
        return Err(format!(
            "Target filesystem does not support atomic no-replace publication: {}",
            dst.display()
        ));
    }

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

/// Windows teardown: Closes lock handle immediately before unlinking sentinel, then unlinks directory.
pub fn teardown_staging_dir(
    wrapper_dir: &Path,
    sentinel_path: &Path,
    sentinel_lock: Option<File>,
) -> Result<(), (PathBuf, std::io::Error)> {
    drop(sentinel_lock);

    if sentinel_path.symlink_metadata().is_ok() {
        if let Err(e) = fs::remove_file(sentinel_path) {
            return Err((sentinel_path.to_path_buf(), e));
        }
    }

    if let Err(e) = fs::remove_dir(wrapper_dir) {
        return Err((wrapper_dir.to_path_buf(), e));
    }
    Ok(())
}

/// Windows staged directory cleanup handling NTFS file-sharing semantics.
pub fn clean_staged_dir(
    path: &Path,
    sentinel_path: &Path,
    sentinel_file: File,
    dir_bytes: u64,
    report: &mut CleanupReport,
) {
    let mut all_children_removed = true;
    match fs::read_dir(path) {
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
                            if let Err(e) = del_res {
                                all_children_removed = false;
                                report.failed_count += 1;
                                if report.failed_artifacts.len() < 10 {
                                    report.failed_artifacts.push((
                                        sub_path,
                                        format!("Failed to remove staging child: {}", e),
                                    ));
                                }
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        all_children_removed = false;
                        report.failed_count += 1;
                        if report.failed_artifacts.len() < 10 {
                            report.failed_artifacts.push((
                                path.to_path_buf(),
                                format!("Failed to read child metadata: {}", e),
                            ));
                        }
                        break;
                    }
                }
            }
        }
        Err(e) => {
            all_children_removed = false;
            report.failed_count += 1;
            if report.failed_artifacts.len() < 10 {
                report.failed_artifacts.push((
                    path.to_path_buf(),
                    format!("Failed to inspect staging directory: {}", e),
                ));
            }
        }
    }

    if all_children_removed {
        drop(sentinel_file);
        if fs::remove_file(sentinel_path).is_ok() {
            if fs::remove_dir(path).is_ok() {
                report.removed_count += 1;
                report.freed_bytes = report.freed_bytes.saturating_add(dir_bytes);
            } else {
                report.failed_count += 1;
                if report.failed_artifacts.len() < 10 {
                    report.failed_artifacts.push((
                        path.to_path_buf(),
                        "Failed to remove parent staging directory after children were deleted".to_string(),
                    ));
                }
            }
        } else {
            report.failed_count += 1;
            if report.failed_artifacts.len() < 10 {
                report.failed_artifacts.push((
                    sentinel_path.to_path_buf(),
                    "Failed to remove .active.lock sentinel".to_string(),
                ));
            }
        }
    } else {
        drop(sentinel_file);
    }
}

pub fn clean_staged_file(
    path: &Path,
    file: File,
    file_len: u64,
    report: &mut CleanupReport,
) {
    drop(file);
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
}