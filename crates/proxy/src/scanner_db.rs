use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use tracing::warn;

use crate::time_utils::{format_system_time, system_time_age_seconds};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ScannerDbSummary {
	pub(crate) env_var: String,
	pub(crate) cache_dir: Option<String>,
	pub(crate) status: ScannerDbStatus,
	pub(crate) db_file: Option<String>,
	pub(crate) modified_at: Option<String>,
	pub(crate) age_seconds: Option<u64>,
	pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScannerDbStatus {
	NotConfigured,
	Missing,
	NotDirectory,
	NotFound,
	Unreadable,
	Found,
}
pub(crate) fn scanner_db_summaries_from_env() -> Vec<ScannerDbSummary> {
	[scanner_db_summary_from_env("TRIVY_CACHE_DIR")]
		.into_iter()
		.collect()
}

pub(crate) fn scanner_db_summary_from_env(
	env_var: &'static str,
) -> ScannerDbSummary {
	match env::var(env_var)
		.ok()
		.map(|value| value.trim().to_owned())
		.filter(|value| !value.is_empty())
	{
		Some(cache_dir) => {
			scanner_db_summary_for_dir(env_var, Path::new(&cache_dir))
		}
		None => ScannerDbSummary {
			env_var: env_var.to_owned(),
			cache_dir: None,
			status: ScannerDbStatus::NotConfigured,
			db_file: None,
			modified_at: None,
			age_seconds: None,
			error: None,
		},
	}
}

pub(crate) fn scanner_db_summary_for_dir(
	env_var: &'static str,
	cache_dir: &Path,
) -> ScannerDbSummary {
	let cache_dir_display = cache_dir.display().to_string();
	let metadata = match fs::metadata(cache_dir) {
		Ok(metadata) => metadata,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			return ScannerDbSummary {
				env_var: env_var.to_owned(),
				cache_dir: Some(cache_dir_display),
				status: ScannerDbStatus::Missing,
				db_file: None,
				modified_at: None,
				age_seconds: None,
				error: None,
			};
		}
		Err(error) => {
			warn!(
				%error,
				env_var,
				cache_dir = %cache_dir_display,
				"failed to read scanner DB cache metadata"
			);
			return ScannerDbSummary {
				env_var: env_var.to_owned(),
				cache_dir: Some(cache_dir_display),
				status: ScannerDbStatus::Unreadable,
				db_file: None,
				modified_at: None,
				age_seconds: None,
				error: Some(error.to_string()),
			};
		}
	};

	if !metadata.is_dir() {
		return ScannerDbSummary {
			env_var: env_var.to_owned(),
			cache_dir: Some(cache_dir_display),
			status: ScannerDbStatus::NotDirectory,
			db_file: None,
			modified_at: None,
			age_seconds: None,
			error: None,
		};
	}

	match newest_scanner_db_file(cache_dir) {
		Ok(Some((path, modified))) => ScannerDbSummary {
			env_var: env_var.to_owned(),
			cache_dir: Some(cache_dir_display),
			status: ScannerDbStatus::Found,
			db_file: Some(path.display().to_string()),
			modified_at: Some(format_system_time(modified)),
			age_seconds: Some(system_time_age_seconds(modified)),
			error: None,
		},
		Ok(None) => ScannerDbSummary {
			env_var: env_var.to_owned(),
			cache_dir: Some(cache_dir_display),
			status: ScannerDbStatus::NotFound,
			db_file: None,
			modified_at: None,
			age_seconds: None,
			error: None,
		},
		Err(error) => {
			warn!(
				%error,
				env_var,
				cache_dir = %cache_dir_display,
				"failed to inspect scanner DB cache"
			);
			ScannerDbSummary {
				env_var: env_var.to_owned(),
				cache_dir: Some(cache_dir_display),
				status: ScannerDbStatus::Unreadable,
				db_file: None,
				modified_at: None,
				age_seconds: None,
				error: Some(error),
			}
		}
	}
}

fn newest_scanner_db_file(
	cache_dir: &Path,
) -> Result<Option<(PathBuf, SystemTime)>, String> {
	let mut newest = None;
	visit_scanner_db_files(cache_dir, 0, &mut newest)?;

	Ok(newest)
}

fn visit_scanner_db_files(
	dir: &Path,
	depth: usize,
	newest: &mut Option<(PathBuf, SystemTime)>,
) -> Result<(), String> {
	if depth > 4 {
		return Ok(());
	}

	let entries = fs::read_dir(dir).map_err(|error| {
		format!("failed to read {}: {error}", dir.display())
	})?;

	for entry in entries {
		let entry = match entry {
			Ok(entry) => entry,
			Err(error) => {
				warn!(%error, dir = %dir.display(), "failed to read cache directory entry");
				continue;
			}
		};
		let path = entry.path();
		let metadata = match entry.metadata() {
			Ok(metadata) => metadata,
			Err(error) => {
				warn!(
					%error,
					path = %path.display(),
					"failed to read cache file metadata"
				);
				continue;
			}
		};

		if metadata.is_dir() {
			visit_scanner_db_files(&path, depth + 1, newest)?;
		} else if metadata.is_file() && is_scanner_db_file(&path) {
			let modified = match metadata.modified() {
				Ok(modified) => modified,
				Err(error) => {
					warn!(
						%error,
						path = %path.display(),
						"failed to read scanner DB file modified time"
					);
					continue;
				}
			};

			let should_replace = newest
				.as_ref()
				.is_none_or(|(_, current)| modified > *current);
			if should_replace {
				*newest = Some((path, modified));
			}
		}
	}

	Ok(())
}

fn is_scanner_db_file(path: &Path) -> bool {
	let Some(file_name) = path.file_name().and_then(|name| name.to_str())
	else {
		return false;
	};
	let file_name = file_name.to_ascii_lowercase();

	file_name == "metadata.json" || file_name.ends_with(".db")
}
