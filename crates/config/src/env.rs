use std::collections::BTreeMap;
use std::net::SocketAddr;

use nexus_sec_proxy_security::{SecurityPolicy, Severity, VulnerabilityLimits};

use crate::{ArtifactScannerKind, ConfigError, UnsupportedTargetPolicy};

pub(crate) const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
pub(crate) const DEFAULT_OSV_API_URL: &str = "https://api.osv.dev/v1/query";
pub(crate) const DEFAULT_YANDEX_MESSENGER_API_URL: &str =
	"https://botapi.messenger.yandex.net";
pub(crate) const DEFAULT_REPOSITORY_NAME: &str = "default";
pub(crate) const DEFAULT_REPOSITORY_FORMAT: &str = "generic";
pub(crate) const DEFAULT_CACHE_ALLOWED_TTL_SECS: u64 = 24 * 60 * 60;
pub(crate) const DEFAULT_CACHE_BLOCKED_TTL_SECS: u64 = 60 * 60;
pub(crate) const DEFAULT_CACHE_MAX_CAPACITY: u64 = 100_000;
pub(crate) const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
pub(crate) const DEFAULT_ARTIFACT_SCANNER_TIMEOUT_SECS: u64 = 5 * 60;
pub(crate) const DEFAULT_ARTIFACT_SCAN_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const DEFAULT_ARTIFACT_SCANNER_CONCURRENCY: u64 = 2;
pub(crate) const DEFAULT_TRUST_REPORT_DIR: &str =
	"/var/lib/nexus-sec-proxy/trust-reports";
pub(crate) const DEFAULT_TRUST_REPORT_RETENTION_DAYS: u64 = 30;
pub(crate) fn security_policy_env(
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
pub(crate) fn string_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	default: &str,
) -> String {
	optional_string_env(lookup, name).unwrap_or_else(|| default.to_owned())
}

pub(crate) fn required_string_env_with_fallbacks(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	legacy_names: &[&'static str],
) -> Result<String, ConfigError> {
	optional_string_env(lookup, name)
		.or_else(|| {
			legacy_names.iter().find_map(|legacy_name| {
				optional_string_env(lookup, legacy_name)
			})
		})
		.ok_or(ConfigError::MissingRequired { name })
}

pub(crate) fn optional_string_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
) -> Option<String> {
	lookup(name).and_then(|value| {
		let trimmed = value.trim();

		(!trimmed.is_empty()).then(|| trimmed.to_owned())
	})
}

pub(crate) fn bool_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
	default: bool,
) -> Result<bool, ConfigError> {
	Ok(optional_bool_env(lookup, name)?.unwrap_or(default))
}

pub(crate) fn optional_bool_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
) -> Result<Option<bool>, ConfigError> {
	optional_string_env(lookup, name)
		.map(|value| {
			value
				.parse()
				.map(Some)
				.map_err(|source| ConfigError::InvalidBool {
					name,
					value,
					source,
				})
		})
		.unwrap_or(Ok(None))
}

pub(crate) fn socket_addr_env(
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

pub(crate) fn severity_env(
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

pub(crate) fn optional_u32_env(
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

pub(crate) fn u64_env(
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

pub(crate) fn unsupported_target_policy_env(
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

pub(crate) fn artifact_scanner_env(
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

pub(crate) fn default_artifact_scanner_command(
	scanner: ArtifactScannerKind,
) -> String {
	match scanner {
		ArtifactScannerKind::Disabled => String::new(),
		ArtifactScannerKind::Trivy => "trivy".to_owned(),
		ArtifactScannerKind::Grype => "grype".to_owned(),
	}
}

pub(crate) fn list_env(
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

pub(crate) fn osv_ecosystem_overrides_env(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
) -> Result<BTreeMap<String, String>, ConfigError> {
	let Some(value) = optional_string_env(lookup, name) else {
		return Ok(BTreeMap::new());
	};
	let mut overrides = BTreeMap::new();

	for item in value.split(',') {
		let trimmed = item.trim();
		if trimmed.is_empty() {
			continue;
		}

		let Some((repository, ecosystem)) = trimmed.split_once('=') else {
			return Err(ConfigError::InvalidOsvEcosystemOverride {
				name,
				value: trimmed.to_owned(),
			});
		};
		let repository = repository.trim();
		let ecosystem = ecosystem.trim();

		if repository.is_empty() || ecosystem.is_empty() {
			return Err(ConfigError::InvalidOsvEcosystemOverride {
				name,
				value: trimmed.to_owned(),
			});
		}

		overrides.insert(repository.to_owned(), ecosystem.to_owned());
	}

	Ok(overrides)
}
