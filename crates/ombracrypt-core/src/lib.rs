pub mod crypto;
pub mod deception;
pub mod fs_guard;
pub mod pipeline;
pub mod stream;

#[cfg(test)]
mod tests;

use fs_guard::CleanupReport;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

/// Generic progress callback decoupled from UI frameworks (Tauri WebView or CLI terminal).
pub type ProgressCallback<'a> = Option<&'a (dyn Fn(u8) -> Result<(), String> + Send + Sync)>;

/// Core synchronous aggregation engine for multi-folder staging cleanup.
/// Deduplicates folders lexically without following symlinks and continues
/// scanning subsequent directories even if one folder encounters inspection errors.
/// Returns both the structured CleanupReport and the formatted UI telemetry result.
pub fn clean_staging_artifacts_aggregated(
    paths: Vec<String>,
) -> (CleanupReport, Result<String, String>) {
    let mut aggregated_report = CleanupReport::default();
    let mut failure_details: Vec<(PathBuf, String)> = Vec::new();
    let mut seen_dirs: HashSet<PathBuf> = HashSet::new();

    for p in paths {
        let path_buf = PathBuf::from(&p);
        let target_dir = match fs::symlink_metadata(&path_buf) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    aggregated_report.failed_count = aggregated_report.failed_count.saturating_add(1);
                    if failure_details.len() < 10 {
                        failure_details.push((
                            path_buf,
                            "Refusing to scan symbolic-link directory root".to_string(),
                        ));
                    }
                    continue;
                } else if meta.is_file() {
                    path_buf.parent().unwrap_or(&path_buf).to_path_buf()
                } else {
                    path_buf
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                aggregated_report.failed_count = aggregated_report.failed_count.saturating_add(1);
                if failure_details.len() < 10 {
                    failure_details.push((
                        path_buf.clone(),
                        format!("Selected directory does not exist: {}", path_buf.display()),
                    ));
                }
                continue;
            }
            Err(e) => {
                aggregated_report.failed_count = aggregated_report.failed_count.saturating_add(1);
                if failure_details.len() < 10 {
                    failure_details.push((
                        path_buf,
                        format!("Cannot inspect directory: {}", e),
                    ));
                }
                continue;
            }
        };

        // Lexical deduplication without following symlinks
        if !seen_dirs.insert(target_dir.clone()) {
            continue;
        }

        match fs_guard::clean_scoped_staging_dir_report(&target_dir) {
            Ok(report) => {
                aggregated_report.removed_count = aggregated_report
                    .removed_count
                    .saturating_add(report.removed_count);
                aggregated_report.freed_bytes = aggregated_report
                    .freed_bytes
                    .saturating_add(report.freed_bytes);
                aggregated_report.active_skipped_count = aggregated_report
                    .active_skipped_count
                    .saturating_add(report.active_skipped_count);
                aggregated_report.unowned_skipped_count = aggregated_report
                    .unowned_skipped_count
                    .saturating_add(report.unowned_skipped_count);
                aggregated_report.failed_count = aggregated_report
                    .failed_count
                    .saturating_add(report.failed_count);
                for item in report.failed_artifacts {
                    if failure_details.len() < 10 {
                        failure_details.push(item);
                    }
                }
            }
            Err(e) => {
                aggregated_report.failed_count = aggregated_report
                    .failed_count
                    .saturating_add(1);
                if failure_details.len() < 10 {
                    failure_details.push((target_dir, e));
                }
            }
        }
    }

    aggregated_report.failed_artifacts = failure_details;

    let ui_result = if aggregated_report.failed_count > 0 {
        let sample_failures: Vec<String> = aggregated_report
            .failed_artifacts
            .iter()
            .take(3)
            .map(|(path, err)| format!("{}: {}", path.display(), err))
            .collect();
        let detail_str = sample_failures.join("; ");
        let skip_note = if aggregated_report.active_skipped_count > 0
            || aggregated_report.unowned_skipped_count > 0
        {
            format!(
                " (also skipped {} active, {} unowned)",
                aggregated_report.active_skipped_count, aggregated_report.unowned_skipped_count
            )
        } else {
            String::new()
        };

        if aggregated_report.removed_count > 0 {
            Ok(format!(
                "Warning: Partially cleaned {} staging artifact(s) ({:.2} MB reclaimed), but {} item(s) could not be removed or inspected: {}{}",
                aggregated_report.removed_count,
                aggregated_report.freed_bytes as f64 / 1_048_576.0,
                aggregated_report.failed_count,
                detail_str,
                skip_note
            ))
        } else {
            Err(format!(
                "Cleanup Incomplete: {} item(s) could not be removed or inspected due to permissions or errors: {}{}",
                aggregated_report.failed_count,
                detail_str,
                skip_note
            ))
        }
    } else if aggregated_report.removed_count > 0 {
        let mut msg = format!(
            "Successfully cleaned {} staging artifact(s) ({:.2} MB reclaimed).",
            aggregated_report.removed_count,
            aggregated_report.freed_bytes as f64 / 1_048_576.0
        );
        if aggregated_report.active_skipped_count > 0
            || aggregated_report.unowned_skipped_count > 0
        {
            let mut skip_parts = Vec::new();
            if aggregated_report.active_skipped_count > 0 {
                skip_parts.push(format!(
                    "{} active operation(s)",
                    aggregated_report.active_skipped_count
                ));
            }
            if aggregated_report.unowned_skipped_count > 0 {
                skip_parts.push(format!(
                    "{} unowned/markerless remnant(s)",
                    aggregated_report.unowned_skipped_count
                ));
            }
            msg.push_str(&format!(" (Skipped: {})", skip_parts.join(", ")));
        }
        Ok(msg)
    } else if aggregated_report.active_skipped_count > 0
        || aggregated_report.unowned_skipped_count > 0
    {
        let mut skip_parts = Vec::new();
        if aggregated_report.active_skipped_count > 0 {
            skip_parts.push(format!(
                "{} active in-flight operation(s)",
                aggregated_report.active_skipped_count
            ));
        }
        if aggregated_report.unowned_skipped_count > 0 {
            skip_parts.push(format!(
                "{} unowned/markerless artifact(s) requiring manual review",
                aggregated_report.unowned_skipped_count
            ));
        }
        Ok(format!(
            "0 staging remnants removed (Skipped: {}).",
            skip_parts.join(", ")
        ))
    } else {
        Ok("Selected folders are clean (0 staging remnants found).".to_string())
    };

    (aggregated_report, ui_result)
}

pub fn clean_staging_artifacts_report(paths: Vec<String>) -> Result<CleanupReport, String> {
    Ok(clean_staging_artifacts_aggregated(paths).0)
}

pub fn clean_staging_artifacts_core(paths: Vec<String>) -> Result<String, String> {
    clean_staging_artifacts_aggregated(paths).1
}