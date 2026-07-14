use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;

use nexus_sec_proxy_security::{
	PolicySet, SecurityPolicy, default_osv_ecosystem_for_format,
};
use serde::Serialize;

use crate::env::{
	DEFAULT_ARTIFACT_SCAN_MAX_BYTES, DEFAULT_ARTIFACT_SCANNER_CONCURRENCY,
	DEFAULT_ARTIFACT_SCANNER_TIMEOUT_SECS, DEFAULT_BIND_ADDR,
	DEFAULT_CACHE_ALLOWED_TTL_SECS, DEFAULT_CACHE_BLOCKED_TTL_SECS,
	DEFAULT_CACHE_MAX_CAPACITY, DEFAULT_HELM_BINARY, DEFAULT_OSV_API_URL,
	DEFAULT_REPOSITORY_FORMAT, DEFAULT_REPOSITORY_NAME,
	DEFAULT_REPOSITORY_REFRESH_INTERVAL_SECS, DEFAULT_REQUEST_TIMEOUT_SECS,
	DEFAULT_TRUST_REPORT_DIR, DEFAULT_TRUST_REPORT_RETENTION_DAYS,
	DEFAULT_YANDEX_MESSENGER_API_URL, artifact_scanner_formats_env, bool_env,
	normalize_artifact_format, optional_string_env,
	osv_ecosystem_overrides_env, required_string_env_with_fallbacks,
	secret_env, socket_addr_env, string_env, u64_env,
	unsupported_target_policy_env,
};
use crate::policy_file::load_policy;
use crate::{ArtifactScannerKind, ConfigError, UnsupportedTargetPolicy};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppConfig {
	pub bind_addr: SocketAddr,
	pub nexus_base_url: String,
	pub upstream_base_url: String,
	pub repository_name: String,
	pub repository_format: String,
	pub docker_registry_base_url: Option<String>,
	pub docker_repository_name: Option<String>,
	pub osv_ecosystem: Option<String>,
	pub osv_ecosystem_overrides: BTreeMap<String, String>,
	pub nexus_username: Option<String>,
	#[serde(skip_serializing)]
	pub nexus_password: Option<String>,
	pub repository_refresh_interval_secs: u64,
	pub osv_api_url: String,
	pub policy_file: Option<String>,
	#[serde(skip_serializing)]
	pub admin_token: Option<String>,
	#[serde(skip_serializing)]
	pub yandex_messenger_token: Option<String>,
	pub yandex_messenger_template_file: Option<String>,
	pub yandex_messenger_api_url: String,
	pub yandex_messenger_enabled: bool,
	pub trust_base_url: String,
	pub trust_report_dir: String,
	pub trust_report_retention_days: u64,
	pub log_json: bool,
	pub fail_open: bool,
	pub unsupported_target_policy: UnsupportedTargetPolicy,
	pub cache_allowed_ttl_secs: u64,
	pub cache_blocked_ttl_secs: u64,
	pub cache_max_capacity: u64,
	pub request_timeout_secs: u64,
	pub artifact_scanner_formats: BTreeMap<String, ArtifactScannerKind>,
	pub artifact_scanner_skip_db_update: bool,
	pub artifact_scanner_offline: bool,
	pub artifact_scanner_timeout_secs: u64,
	pub artifact_scan_max_bytes: u64,
	pub artifact_scanner_concurrency: u64,
	pub artifact_tmp_dir: Option<String>,
	pub helm_binary: String,
	pub security_policy: SecurityPolicy,
	pub policy_set: PolicySet,
}

impl AppConfig {
	pub fn from_env() -> Result<Self, ConfigError> {
		Self::from_env_vars(|name| env::var(name).ok())
	}

	pub(crate) fn from_env_vars(
		mut lookup: impl FnMut(&'static str) -> Option<String>,
	) -> Result<Self, ConfigError> {
		let bind_addr = socket_addr_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_BIND_ADDR",
			DEFAULT_BIND_ADDR,
		)?;
		let nexus_base_url = required_string_env_with_fallbacks(
			&mut lookup,
			"NEXUS_SEC_PROXY_NEXUS_BASE_URL",
			&[
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"NEXUS_SEC_PROXY_UPSTREAM_REGISTRY",
			],
		)?;
		let upstream_base_url = nexus_base_url.clone();
		let repository_name = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_REPOSITORY_NAME",
			DEFAULT_REPOSITORY_NAME,
		);
		let repository_format = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_REPOSITORY_FORMAT",
			DEFAULT_REPOSITORY_FORMAT,
		);
		let docker_registry_base_url = docker_registry_base_url(
			&mut lookup,
			"NEXUS_SEC_PROXY_DOCKER_REGISTRY_BASE_URL",
		)?;
		let docker_repository_name = optional_string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_DOCKER_REPOSITORY_NAME",
		);
		if docker_registry_base_url.is_some()
			&& docker_repository_name.is_none()
		{
			return Err(ConfigError::MissingRequired {
				name: "NEXUS_SEC_PROXY_DOCKER_REPOSITORY_NAME",
			});
		}
		let osv_ecosystem =
			optional_string_env(&mut lookup, "NEXUS_SEC_PROXY_OSV_ECOSYSTEM")
				.or_else(|| {
					default_osv_ecosystem_for_format(&repository_format)
						.map(str::to_owned)
				});
		let osv_ecosystem_overrides = osv_ecosystem_overrides_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_OSV_ECOSYSTEM_OVERRIDES",
		)?;
		let nexus_username =
			optional_string_env(&mut lookup, "NEXUS_SEC_PROXY_NEXUS_USERNAME");
		let nexus_password = secret_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_NEXUS_PASSWORD",
			"NEXUS_SEC_PROXY_NEXUS_PASSWORD_FILE",
		)?;
		let repository_refresh_interval_secs = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_REPOSITORY_REFRESH_INTERVAL_SECS",
			DEFAULT_REPOSITORY_REFRESH_INTERVAL_SECS,
		)?;
		let osv_api_url = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_OSV_API_URL",
			DEFAULT_OSV_API_URL,
		);
		let policy_file =
			optional_string_env(&mut lookup, "NEXUS_SEC_PROXY_POLICY_FILE");
		let admin_token =
			optional_string_env(&mut lookup, "NEXUS_SEC_PROXY_ADMIN_TOKEN");
		let yandex_messenger_token = secret_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN",
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN_FILE",
		)?;
		let yandex_messenger_template_file = optional_string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TEMPLATE_FILE",
		);
		let yandex_messenger_api_url = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_API_URL",
			DEFAULT_YANDEX_MESSENGER_API_URL,
		);
		let yandex_messenger_enabled = bool_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_ENABLED",
			false,
		)?;
		if yandex_messenger_enabled {
			for (name, present) in [
				(
					"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN",
					yandex_messenger_token.is_some(),
				),
				(
					"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TEMPLATE_FILE",
					yandex_messenger_template_file.is_some(),
				),
				("NEXUS_SEC_PROXY_NEXUS_USERNAME", nexus_username.is_some()),
				("NEXUS_SEC_PROXY_NEXUS_PASSWORD", nexus_password.is_some()),
			] {
				if !present {
					return Err(ConfigError::MissingRequired { name });
				}
			}
		}
		let trust_base_url =
			trust_base_url(&mut lookup, "NEXUS_SEC_PROXY_TRUST_BASE_URL")?;
		let trust_report_dir = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_TRUST_REPORT_DIR",
			DEFAULT_TRUST_REPORT_DIR,
		);
		let trust_report_retention_days = u64_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_TRUST_REPORT_RETENTION_DAYS",
			DEFAULT_TRUST_REPORT_RETENTION_DAYS,
		)?;
		if trust_report_retention_days < 1 {
			return Err(ConfigError::ValueBelowMinimum {
				name: "NEXUS_SEC_PROXY_TRUST_REPORT_RETENTION_DAYS",
				value: trust_report_retention_days,
				minimum: 1,
			});
		}
		let log_json =
			bool_env(&mut lookup, "NEXUS_SEC_PROXY_LOG_JSON", false)?;
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
		let artifact_scanner_formats = artifact_scanner_formats_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_ARTIFACT_SCANNER_FORMATS",
		)?;
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
		let helm_binary = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_HELM_BINARY",
			DEFAULT_HELM_BINARY,
		);
		let (security_policy, policy_set) =
			load_policy(&mut lookup, policy_file.as_deref())?;

		Ok(Self {
			bind_addr,
			nexus_base_url,
			upstream_base_url,
			repository_name,
			repository_format,
			docker_registry_base_url,
			docker_repository_name,
			osv_ecosystem,
			osv_ecosystem_overrides,
			nexus_username,
			nexus_password,
			repository_refresh_interval_secs,
			osv_api_url,
			policy_file,
			admin_token,
			yandex_messenger_token,
			yandex_messenger_template_file,
			yandex_messenger_api_url,
			yandex_messenger_enabled,
			trust_base_url,
			trust_report_dir,
			trust_report_retention_days,
			log_json,
			fail_open,
			unsupported_target_policy,
			cache_allowed_ttl_secs,
			cache_blocked_ttl_secs,
			cache_max_capacity,
			request_timeout_secs,
			artifact_scanner_formats,
			artifact_scanner_skip_db_update,
			artifact_scanner_offline,
			artifact_scanner_timeout_secs,
			artifact_scan_max_bytes,
			artifact_scanner_concurrency,
			artifact_tmp_dir,
			helm_binary,
			security_policy,
			policy_set,
		})
	}

	#[must_use]
	pub fn artifact_scanner_for_format(
		&self,
		format: &str,
	) -> Option<ArtifactScannerKind> {
		self.artifact_scanner_formats
			.get(&normalize_artifact_format(format))
			.copied()
	}

	#[must_use]
	pub fn docker_registry_configured(&self) -> bool {
		self.docker_registry_base_url.is_some()
			&& self.docker_repository_name.is_some()
	}
}

fn docker_registry_base_url(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
) -> Result<Option<String>, ConfigError> {
	let Some(value) = optional_string_env(lookup, name) else {
		return Ok(None);
	};
	let parsed = url::Url::parse(&value).map_err(|error| {
		ConfigError::InvalidDockerRegistryBaseUrl {
			name,
			value: value.clone(),
			reason: error.to_string(),
		}
	})?;

	if !matches!(parsed.scheme(), "http" | "https") {
		return Err(ConfigError::InvalidDockerRegistryBaseUrl {
			name,
			value,
			reason: "scheme must be http or https".to_owned(),
		});
	}
	if parsed.host_str().is_none() || parsed.cannot_be_a_base() {
		return Err(ConfigError::InvalidDockerRegistryBaseUrl {
			name,
			value,
			reason: "URL must include a host".to_owned(),
		});
	}
	if parsed.query().is_some() || parsed.fragment().is_some() {
		return Err(ConfigError::InvalidDockerRegistryBaseUrl {
			name,
			value,
			reason: "query and fragment are not allowed".to_owned(),
		});
	}
	let path = parsed.path();
	if path != "/" && !path.is_empty() {
		return Err(ConfigError::InvalidDockerRegistryBaseUrl {
			name,
			value,
			reason: "path must be empty or /".to_owned(),
		});
	}

	Ok(Some(value))
}

fn trust_base_url(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	name: &'static str,
) -> Result<String, ConfigError> {
	let value = optional_string_env(lookup, name)
		.ok_or(ConfigError::MissingRequired { name })?;
	let parsed = url::Url::parse(&value).map_err(|error| {
		ConfigError::InvalidTrustBaseUrl {
			name,
			value: value.clone(),
			reason: error.to_string(),
		}
	})?;

	if !matches!(parsed.scheme(), "http" | "https") {
		return Err(ConfigError::InvalidTrustBaseUrl {
			name,
			value,
			reason: "scheme must be http or https".to_owned(),
		});
	}
	if parsed.host_str().is_none() || parsed.cannot_be_a_base() {
		return Err(ConfigError::InvalidTrustBaseUrl {
			name,
			value,
			reason: "URL must include a host".to_owned(),
		});
	}
	if parsed.query().is_some() || parsed.fragment().is_some() {
		return Err(ConfigError::InvalidTrustBaseUrl {
			name,
			value,
			reason: "query and fragment are not allowed".to_owned(),
		});
	}

	Ok(value.trim_end_matches('/').to_owned())
}
