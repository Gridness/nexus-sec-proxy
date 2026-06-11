use std::env;
use std::net::SocketAddr;
use std::str::FromStr;

use nexus_sec_proxy_security::{
	SecurityPolicy, Severity, SeverityParseError, VulnerabilityLimits,
	default_osv_ecosystem_for_format,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_OSV_API_URL: &str = "https://api.osv.dev/v1/query";
const DEFAULT_REPOSITORY_FORMAT: &str = "generic";
const DEFAULT_CACHE_ALLOWED_TTL_SECS: u64 = 24 * 60 * 60;
const DEFAULT_CACHE_BLOCKED_TTL_SECS: u64 = 60 * 60;
const DEFAULT_CACHE_MAX_CAPACITY: u64 = 100_000;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_ARTIFACT_SCANNER_TIMEOUT_SECS: u64 = 5 * 60;
const DEFAULT_ARTIFACT_SCAN_MAX_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_ARTIFACT_SCANNER_CONCURRENCY: u64 = 2;

#[derive(Debug, Error)]
pub enum ConfigError {
	#[error("invalid socket address in {name}: {value}")]
	InvalidSocketAddr {
		name: &'static str,
		value: String,
		#[source]
		source: std::net::AddrParseError,
	},
	#[error("invalid boolean in {name}: {value}")]
	InvalidBool {
		name: &'static str,
		value: String,
		#[source]
		source: std::str::ParseBoolError,
	},
	#[error("invalid severity in {name}: {value}")]
	InvalidSeverity {
		name: &'static str,
		value: String,
		#[source]
		source: SeverityParseError,
	},
	#[error("invalid unsigned integer in {name}: {value}")]
	InvalidUnsignedInt {
		name: &'static str,
		value: String,
		#[source]
		source: std::num::ParseIntError,
	},
	#[error("invalid unsupported target policy in {name}: {value}")]
	InvalidUnsupportedTargetPolicy { name: &'static str, value: String },
	#[error("invalid artifact scanner in {name}: {value}")]
	InvalidArtifactScanner { name: &'static str, value: String },
	#[error("missing required environment variable: {name}")]
	MissingRequired { name: &'static str },
}

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedTargetPolicy {
	#[default]
	Allow,
	Block,
}

impl FromStr for UnsupportedTargetPolicy {
	type Err = ();

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value.trim().to_ascii_lowercase().as_str() {
			"allow" | "pass" | "pass-through" | "passthrough" => {
				Ok(Self::Allow)
			}
			"block" | "deny" => Ok(Self::Block),
			_ => Err(()),
		}
	}
}

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactScannerKind {
	#[default]
	Disabled,
	Trivy,
	Grype,
}

impl FromStr for ArtifactScannerKind {
	type Err = ();

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value.trim().to_ascii_lowercase().as_str() {
			"disabled" | "none" | "off" => Ok(Self::Disabled),
			"trivy" => Ok(Self::Trivy),
			"grype" => Ok(Self::Grype),
			_ => Err(()),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
	pub bind_addr: SocketAddr,
	pub upstream_base_url: String,
	pub repository_format: String,
	pub osv_ecosystem: Option<String>,
	pub osv_api_url: String,
	pub fail_open: bool,
	pub unsupported_target_policy: UnsupportedTargetPolicy,
	pub cache_allowed_ttl_secs: u64,
	pub cache_blocked_ttl_secs: u64,
	pub cache_max_capacity: u64,
	pub request_timeout_secs: u64,
	pub artifact_scanner: ArtifactScannerKind,
	pub artifact_scanner_command: String,
	pub artifact_scanner_skip_db_update: bool,
	pub artifact_scanner_offline: bool,
	pub artifact_scanner_timeout_secs: u64,
	pub artifact_scan_max_bytes: u64,
	pub artifact_scanner_concurrency: u64,
	pub artifact_tmp_dir: Option<String>,
	pub security_policy: SecurityPolicy,
}

impl AppConfig {
	pub fn from_env() -> Result<Self, ConfigError> {
		Self::from_env_vars(|name| env::var(name).ok())
	}

	fn from_env_vars(
		mut lookup: impl FnMut(&'static str) -> Option<String>,
	) -> Result<Self, ConfigError> {
		let bind_addr = socket_addr_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_BIND_ADDR",
			DEFAULT_BIND_ADDR,
		)?;
		let upstream_base_url = required_string_env_with_fallback(
			&mut lookup,
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			Some("NEXUS_SEC_PROXY_UPSTREAM_REGISTRY"),
		)?;
		let repository_format = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_REPOSITORY_FORMAT",
			DEFAULT_REPOSITORY_FORMAT,
		);
		let osv_ecosystem =
			optional_string_env(&mut lookup, "NEXUS_SEC_PROXY_OSV_ECOSYSTEM")
				.or_else(|| {
					default_osv_ecosystem_for_format(&repository_format)
						.map(str::to_owned)
				});
		let osv_api_url = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_OSV_API_URL",
			DEFAULT_OSV_API_URL,
		);
		let fail_open =
			bool_env(&mut lookup, "NEXUS_SEC_PROXY_FAIL_OPEN", true)?;
		let unsupported_target_policy = unsupported_target_policy_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY",
			UnsupportedTargetPolicy::Allow,
		)?;
		let cache_allowed_ttl_secs = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_CACHE_ALLOWED_TTL_SECS",
			DEFAULT_CACHE_ALLOWED_TTL_SECS,
		)?;
		let cache_blocked_ttl_secs = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_CACHE_BLOCKED_TTL_SECS",
			DEFAULT_CACHE_BLOCKED_TTL_SECS,
		)?;
		let cache_max_capacity = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_CACHE_MAX_CAPACITY",
			DEFAULT_CACHE_MAX_CAPACITY,
		)?;
		let request_timeout_secs = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_REQUEST_TIMEOUT_SECS",
			DEFAULT_REQUEST_TIMEOUT_SECS,
		)?;
		let artifact_scanner = artifact_scanner_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_SCANNER",
			ArtifactScannerKind::Disabled,
		)?;
		let artifact_scanner_command = optional_string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_SCANNER_COMMAND",
		)
		.unwrap_or_else(|| default_artifact_scanner_command(artifact_scanner));
		let artifact_scanner_skip_db_update = bool_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_SCANNER_SKIP_DB_UPDATE",
			true,
		)?;
		let artifact_scanner_offline = bool_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_SCANNER_OFFLINE",
			true,
		)?;
		let artifact_scanner_timeout_secs = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_SCANNER_TIMEOUT_SECS",
			DEFAULT_ARTIFACT_SCANNER_TIMEOUT_SECS,
		)?;
		let artifact_scan_max_bytes = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_SCAN_MAX_BYTES",
			DEFAULT_ARTIFACT_SCAN_MAX_BYTES,
		)?;
		let artifact_scanner_concurrency = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_SCANNER_CONCURRENCY",
			DEFAULT_ARTIFACT_SCANNER_CONCURRENCY,
		)?;
		let artifact_tmp_dir = optional_string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_TMP_DIR",
		);
		let security_policy = security_policy_env(&mut lookup)?;

		Ok(Self {
			bind_addr,
			upstream_base_url,
			repository_format,
			osv_ecosystem,
			osv_api_url,
			fail_open,
			unsupported_target_policy,
			cache_allowed_ttl_secs,
			cache_blocked_ttl_secs,
			cache_max_capacity,
			request_timeout_secs,
			artifact_scanner,
			artifact_scanner_command,
			artifact_scanner_skip_db_update,
			artifact_scanner_offline,
			artifact_scanner_timeout_secs,
			artifact_scan_max_bytes,
			artifact_scanner_concurrency,
			artifact_tmp_dir,
			security_policy,
		})
	}
}

fn security_policy_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
) -> Result<SecurityPolicy, ConfigError> {
	let minimum_blocking_severity = severity_env(
		lookup,
		"NEXUS_SEC_PROXY_MINIMUM_BLOCKING_SEVERITY",
		Some("NEXUS_SEC_PROXY_MINIMUM_SEVERITY"),
		Severity::High,
	)?;
	let allowed_vulnerability_ids =
		list_env(lookup, "NEXUS_SEC_PROXY_ALLOWED_VULNERABILITY_IDS");
	let limits = VulnerabilityLimits {
		total: optional_u32_env(
			lookup,
			"NEXUS_SEC_PROXY_MAX_TOTAL_VULNERABILITIES",
		)?,
		low: optional_u32_env(
			lookup,
			"NEXUS_SEC_PROXY_MAX_LOW_VULNERABILITIES",
		)?,
		medium: optional_u32_env(
			lookup,
			"NEXUS_SEC_PROXY_MAX_MEDIUM_VULNERABILITIES",
		)?,
		high: optional_u32_env(
			lookup,
			"NEXUS_SEC_PROXY_MAX_HIGH_VULNERABILITIES",
		)?,
		critical: optional_u32_env(
			lookup,
			"NEXUS_SEC_PROXY_MAX_CRITICAL_VULNERABILITIES",
		)?,
	};

	Ok(SecurityPolicy::new(
		minimum_blocking_severity,
		allowed_vulnerability_ids,
		limits,
	))
}

fn string_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	default: &str,
) -> String {
	optional_string_env(lookup, name).unwrap_or_else(|| default.to_owned())
}

fn required_string_env_with_fallback(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	legacy_name: Option<&'static str>,
) -> Result<String, ConfigError> {
	optional_string_env(lookup, name)
		.or_else(|| {
			legacy_name.and_then(|name| optional_string_env(lookup, name))
		})
		.ok_or(ConfigError::MissingRequired { name })
}

fn optional_string_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
) -> Option<String> {
	lookup(name).and_then(|value| {
		let trimmed = value.trim();

		(!trimmed.is_empty()).then(|| trimmed.to_owned())
	})
}

fn bool_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	default: bool,
) -> Result<bool, ConfigError> {
	match optional_string_env(lookup, name) {
		Some(value) => {
			value.parse().map_err(|source| ConfigError::InvalidBool {
				name,
				value,
				source,
			})
		}
		None => Ok(default),
	}
}

fn socket_addr_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	default: &str,
) -> Result<SocketAddr, ConfigError> {
	let value = string_env(lookup, name, default);

	value
		.parse()
		.map_err(|source| ConfigError::InvalidSocketAddr {
			name,
			value,
			source,
		})
}

fn severity_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	legacy_name: Option<&'static str>,
	default: Severity,
) -> Result<Severity, ConfigError> {
	let (source_name, value) =
		if let Some(value) = optional_string_env(lookup, name) {
			(name, value)
		} else if let Some(legacy_name) = legacy_name {
			optional_string_env(lookup, legacy_name)
				.map(|value| (legacy_name, value))
				.unwrap_or_else(|| (name, default.to_string()))
		} else {
			(name, default.to_string())
		};

	value
		.parse()
		.map_err(|source| ConfigError::InvalidSeverity {
			name: source_name,
			value,
			source,
		})
}

fn optional_u32_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
) -> Result<Option<u32>, ConfigError> {
	optional_string_env(lookup, name)
		.map(|value| {
			value.parse().map(Some).map_err(|source| {
				ConfigError::InvalidUnsignedInt {
					name,
					value,
					source,
				}
			})
		})
		.unwrap_or(Ok(None))
}

fn u64_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	default: u64,
) -> Result<u64, ConfigError> {
	optional_string_env(lookup, name)
		.map(|value| {
			value
				.parse()
				.map_err(|source| ConfigError::InvalidUnsignedInt {
					name,
					value,
					source,
				})
		})
		.unwrap_or(Ok(default))
}

fn unsupported_target_policy_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	default: UnsupportedTargetPolicy,
) -> Result<UnsupportedTargetPolicy, ConfigError> {
	optional_string_env(lookup, name)
		.map(|value| {
			value.parse().map_err(|()| {
				ConfigError::InvalidUnsupportedTargetPolicy { name, value }
			})
		})
		.unwrap_or(Ok(default))
}

fn artifact_scanner_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	default: ArtifactScannerKind,
) -> Result<ArtifactScannerKind, ConfigError> {
	optional_string_env(lookup, name)
		.map(|value| {
			value
				.parse()
				.map_err(|()| ConfigError::InvalidArtifactScanner {
					name,
					value,
				})
		})
		.unwrap_or(Ok(default))
}

fn default_artifact_scanner_command(scanner: ArtifactScannerKind) -> String {
	match scanner {
		ArtifactScannerKind::Disabled => String::new(),
		ArtifactScannerKind::Trivy => "trivy".to_owned(),
		ArtifactScannerKind::Grype => "grype".to_owned(),
	}
}

fn list_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
) -> Vec<String> {
	optional_string_env(lookup, name)
		.map(|value| {
			value
				.split(',')
				.filter_map(|item| {
					let trimmed = item.trim();

					(!trimmed.is_empty()).then(|| trimmed.to_owned())
				})
				.collect()
		})
		.unwrap_or_default()
}

#[cfg(test)]
mod tests {
	use std::collections::BTreeMap;

	use super::*;

	#[test]
	fn default_config_uses_strict_high_and_critical_policy() {
		let env = BTreeMap::from([(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		)]);

		let config = AppConfig::from_env_vars(|name| {
			env.get(name).map(ToString::to_string)
		})
		.unwrap();

		assert_eq!(
			config.security_policy.minimum_blocking_severity,
			Severity::High
		);
		assert_eq!(
			config.security_policy.effective_limit(Severity::Medium),
			None
		);
		assert_eq!(
			config.security_policy.effective_limit(Severity::High),
			Some(0)
		);
		assert_eq!(
			config.security_policy.effective_limit(Severity::Critical),
			Some(0)
		);
	}

	#[test]
	fn parses_policy_controls_from_env() {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_MINIMUM_BLOCKING_SEVERITY", "MEDIUM"),
			(
				"NEXUS_SEC_PROXY_ALLOWED_VULNERABILITY_IDS",
				" CVE-2026-0001, GHSA-0002 ,,",
			),
			("NEXUS_SEC_PROXY_MAX_TOTAL_VULNERABILITIES", "5"),
			("NEXUS_SEC_PROXY_MAX_MEDIUM_VULNERABILITIES", "2"),
			("NEXUS_SEC_PROXY_MAX_HIGH_VULNERABILITIES", "1"),
			("NEXUS_SEC_PROXY_MAX_CRITICAL_VULNERABILITIES", "0"),
		]);

		let config = AppConfig::from_env_vars(|name| {
			env.get(name).map(ToString::to_string)
		})
		.unwrap();

		assert_eq!(
			config.security_policy.minimum_blocking_severity,
			Severity::Medium
		);
		assert!(
			config
				.security_policy
				.allowed_vulnerability_ids
				.contains("CVE-2026-0001")
		);
		assert!(
			config
				.security_policy
				.allowed_vulnerability_ids
				.contains("GHSA-0002")
		);
		assert_eq!(config.security_policy.limits.total, Some(5));
		assert_eq!(config.security_policy.limits.medium, Some(2));
		assert_eq!(config.security_policy.limits.high, Some(1));
		assert_eq!(config.security_policy.limits.critical, Some(0));
	}

	#[test]
	fn parses_artifact_scanner_config() {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_ARTIFACT_SCANNER", "trivy"),
			("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_COMMAND", "/usr/bin/trivy"),
			("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_SKIP_DB_UPDATE", "false"),
			("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_OFFLINE", "false"),
			("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_TIMEOUT_SECS", "120"),
			("NEXUS_SEC_PROXY_ARTIFACT_SCAN_MAX_BYTES", "1048576"),
			("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_CONCURRENCY", "4"),
			("NEXUS_SEC_PROXY_ARTIFACT_TMP_DIR", "/var/tmp/nsp"),
		]);

		let config = AppConfig::from_env_vars(|name| {
			env.get(name).map(ToString::to_string)
		})
		.unwrap();

		assert_eq!(config.artifact_scanner, ArtifactScannerKind::Trivy);
		assert_eq!(config.artifact_scanner_command, "/usr/bin/trivy");
		assert!(!config.artifact_scanner_skip_db_update);
		assert!(!config.artifact_scanner_offline);
		assert_eq!(config.artifact_scanner_timeout_secs, 120);
		assert_eq!(config.artifact_scan_max_bytes, 1_048_576);
		assert_eq!(config.artifact_scanner_concurrency, 4);
		assert_eq!(config.artifact_tmp_dir.as_deref(), Some("/var/tmp/nsp"));
	}

	#[test]
	fn rejects_invalid_severity() {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_MINIMUM_BLOCKING_SEVERITY", "extreme"),
		]);

		let error = AppConfig::from_env_vars(|name| {
			env.get(name).map(ToString::to_string)
		})
		.unwrap_err();

		assert!(matches!(error, ConfigError::InvalidSeverity { .. }));
	}

	#[test]
	fn requires_generic_upstream_base_url() {
		let error = AppConfig::from_env_vars(|_| None).unwrap_err();

		assert!(matches!(error, ConfigError::MissingRequired { .. }));
	}

	#[test]
	fn derives_osv_ecosystem_from_repository_format() {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_REPOSITORY_FORMAT", "maven2"),
		]);

		let config = AppConfig::from_env_vars(|name| {
			env.get(name).map(ToString::to_string)
		})
		.unwrap();

		assert_eq!(config.repository_format, "maven2");
		assert_eq!(config.osv_ecosystem.as_deref(), Some("Maven"));
	}

	#[test]
	fn explicit_osv_ecosystem_overrides_format_mapping() {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_REPOSITORY_FORMAT", "raw"),
			("NEXUS_SEC_PROXY_OSV_ECOSYSTEM", "PyPI"),
		]);

		let config = AppConfig::from_env_vars(|name| {
			env.get(name).map(ToString::to_string)
		})
		.unwrap();

		assert_eq!(config.repository_format, "raw");
		assert_eq!(config.osv_ecosystem.as_deref(), Some("PyPI"));
	}
}
