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
	DEFAULT_CACHE_MAX_CAPACITY, DEFAULT_OSV_API_URL, DEFAULT_REPOSITORY_FORMAT,
	DEFAULT_REPOSITORY_NAME, DEFAULT_REQUEST_TIMEOUT_SECS,
	DEFAULT_YANDEX_MESSENGER_API_URL, artifact_scanner_env, bool_env,
	default_artifact_scanner_command, optional_bool_env, optional_string_env,
	osv_ecosystem_overrides_env, required_string_env_with_fallbacks,
	socket_addr_env, string_env, u64_env, unsupported_target_policy_env,
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
	pub osv_ecosystem: Option<String>,
	pub osv_ecosystem_overrides: BTreeMap<String, String>,
	pub nexus_username: Option<String>,
	#[serde(skip_serializing)]
	pub nexus_password: Option<String>,
	pub osv_api_url: String,
	pub policy_file: Option<String>,
	#[serde(skip_serializing)]
	pub admin_token: Option<String>,
	#[serde(skip_serializing)]
	pub yandex_messenger_token: Option<String>,
	pub yandex_messenger_template_file: Option<String>,
	pub yandex_messenger_api_url: String,
	pub yandex_messenger_enabled: bool,
	pub log_json: bool,
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
		let nexus_password =
			optional_string_env(&mut lookup, "NEXUS_SEC_PROXY_NEXUS_PASSWORD");
		let osv_api_url = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_OSV_API_URL",
			DEFAULT_OSV_API_URL,
		);
		let policy_file =
			optional_string_env(&mut lookup, "NEXUS_SEC_PROXY_POLICY_FILE");
		let admin_token =
			optional_string_env(&mut lookup, "NEXUS_SEC_PROXY_ADMIN_TOKEN");
		let yandex_messenger_token = optional_string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN",
		);
		let yandex_messenger_template_file = optional_string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TEMPLATE_FILE",
		);
		let yandex_messenger_api_url = string_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_API_URL",
			DEFAULT_YANDEX_MESSENGER_API_URL,
		);
		let yandex_messenger_configured = yandex_messenger_token.is_some()
			&& yandex_messenger_template_file.is_some();
		let yandex_messenger_enabled = optional_bool_env(
			&mut lookup,
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_ENABLED",
		)?
		.unwrap_or(yandex_messenger_configured)
			&& yandex_messenger_configured;
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
		let (security_policy, policy_set) =
			load_policy(&mut lookup, policy_file.as_deref())?;

		Ok(Self {
			bind_addr,
			nexus_base_url,
			upstream_base_url,
			repository_name,
			repository_format,
			osv_ecosystem,
			osv_ecosystem_overrides,
			nexus_username,
			nexus_password,
			osv_api_url,
			policy_file,
			admin_token,
			yandex_messenger_token,
			yandex_messenger_template_file,
			yandex_messenger_api_url,
			yandex_messenger_enabled,
			log_json,
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
			policy_set,
		})
	}
}
