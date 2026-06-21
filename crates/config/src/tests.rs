use std::collections::BTreeMap;
use std::io::Write;

use super::*;
use nexus_sec_proxy_security::Severity;

#[test]
fn default_config_uses_strict_high_and_critical_policy() {
	let env = BTreeMap::from([(
		"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
		"https://repo.example.invalid",
	)]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(
		config.security_policy.minimum_blocking_severity,
		Severity::High
	);
	assert_eq!(config.nexus_base_url, "https://repo.example.invalid");
	assert_eq!(config.upstream_base_url, config.nexus_base_url);
	assert_eq!(config.repository_name, "default");
	assert_eq!(config.policy_file, None);
	assert_eq!(config.admin_token, None);
	assert_eq!(config.yandex_messenger_token, None);
	assert_eq!(config.yandex_messenger_template_file, None);
	assert_eq!(
		config.yandex_messenger_api_url,
		"https://botapi.messenger.yandex.net"
	);
	assert!(!config.yandex_messenger_enabled);
	assert!(!config.log_json);
	assert_eq!(config.policy_set.default_policy.id, "default");
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
fn parses_yandex_messenger_config_and_effective_enabled_state() {
	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN", " token "),
		(
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TEMPLATE_FILE",
			" /etc/nsp/yandex-message.txt ",
		),
		(
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_API_URL",
			" https://messenger.example.invalid ",
		),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(config.yandex_messenger_token.as_deref(), Some("token"));
	assert_eq!(
		config.yandex_messenger_template_file.as_deref(),
		Some("/etc/nsp/yandex-message.txt")
	);
	assert_eq!(
		config.yandex_messenger_api_url,
		"https://messenger.example.invalid"
	);
	assert!(config.yandex_messenger_enabled);

	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN", "token"),
		(
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TEMPLATE_FILE",
			"/etc/nsp/yandex-message.txt",
		),
		("NEXUS_SEC_PROXY_YANDEX_MESSENGER_ENABLED", "false"),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert!(!config.yandex_messenger_enabled);

	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_YANDEX_MESSENGER_ENABLED", "true"),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert!(!config.yandex_messenger_enabled);
}

#[test]
fn yandex_messenger_token_is_redacted_from_serialized_config() {
	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_ADMIN_TOKEN", "admin-secret"),
		("NEXUS_SEC_PROXY_NEXUS_PASSWORD", "nexus-secret"),
		("NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN", "bot-secret"),
		(
			"NEXUS_SEC_PROXY_YANDEX_MESSENGER_TEMPLATE_FILE",
			"/etc/nsp/yandex-message.txt",
		),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();
	let value = serde_json::to_value(config).unwrap();

	assert!(value.get("admin_token").is_none());
	assert!(value.get("nexus_password").is_none());
	assert!(value.get("yandex_messenger_token").is_none());
	assert_eq!(
		value["yandex_messenger_template_file"],
		"/etc/nsp/yandex-message.txt"
	);
	assert_eq!(value["yandex_messenger_enabled"], true);
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

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
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
	assert_eq!(
		config
			.policy_set
			.default_policy
			.policy
			.minimum_blocking_severity,
		Severity::Medium
	);
}

#[test]
fn parses_admin_token_and_treats_empty_as_disabled() {
	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_ADMIN_TOKEN", " secret-token "),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(config.admin_token.as_deref(), Some("secret-token"));

	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_ADMIN_TOKEN", "   "),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(config.admin_token, None);
}

#[test]
fn loads_policy_file_and_ignores_legacy_policy_env() {
	let mut policy_file = tempfile::NamedTempFile::new().unwrap();
	write!(
		policy_file,
		r#"
		[default_policy]
		id = "file-default"
		minimum_blocking_severity = "critical"
		mode = "report_only"
		"#
	)
	.unwrap();
	let path = policy_file.path().to_string_lossy().into_owned();
	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_POLICY_FILE", path.as_str()),
		("NEXUS_SEC_PROXY_REPOSITORY_NAME", "npm-internal"),
		("NEXUS_SEC_PROXY_LOG_JSON", "true"),
		("NEXUS_SEC_PROXY_MINIMUM_BLOCKING_SEVERITY", "LOW"),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(config.repository_name, "npm-internal");
	assert_eq!(config.policy_file.as_deref(), Some(path.as_str()));
	assert!(config.log_json);
	assert_eq!(config.policy_set.default_policy.id, "file-default");
	assert_eq!(
		config.security_policy.minimum_blocking_severity,
		Severity::Critical
	);
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

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
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

	let error =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap_err();

	assert!(matches!(error, ConfigError::InvalidSeverity { .. }));
}

#[test]
fn requires_generic_upstream_base_url() {
	let error = AppConfig::from_env_vars(|_| None).unwrap_err();

	assert!(matches!(error, ConfigError::MissingRequired { .. }));
}

#[test]
fn prefers_nexus_base_url_and_accepts_legacy_upstream_fallbacks() {
	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_NEXUS_BASE_URL",
			"https://nexus.example.invalid",
		),
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://legacy.example.invalid",
		),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(config.nexus_base_url, "https://nexus.example.invalid");
	assert_eq!(config.upstream_base_url, config.nexus_base_url);

	let env = BTreeMap::from([(
		"NEXUS_SEC_PROXY_UPSTREAM_REGISTRY",
		"https://oldest.example.invalid",
	)]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(config.nexus_base_url, "https://oldest.example.invalid");
}

#[test]
fn parses_repository_osv_ecosystem_overrides_and_nexus_auth() {
	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_NEXUS_BASE_URL",
			"https://nexus.example.invalid",
		),
		(
			"NEXUS_SEC_PROXY_OSV_ECOSYSTEM_OVERRIDES",
			" apt-proxy=Ubuntu OS, yum-proxy=Rocky Linux ,,",
		),
		("NEXUS_SEC_PROXY_NEXUS_USERNAME", " admin "),
		("NEXUS_SEC_PROXY_NEXUS_PASSWORD", " secret "),
	]);

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(
		config.osv_ecosystem_overrides.get("apt-proxy"),
		Some(&"Ubuntu OS".to_owned())
	);
	assert_eq!(
		config.osv_ecosystem_overrides.get("yum-proxy"),
		Some(&"Rocky Linux".to_owned())
	);
	assert_eq!(config.nexus_username.as_deref(), Some("admin"));
	assert_eq!(config.nexus_password.as_deref(), Some("secret"));
}

#[test]
fn rejects_malformed_repository_osv_ecosystem_override() {
	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_NEXUS_BASE_URL",
			"https://nexus.example.invalid",
		),
		("NEXUS_SEC_PROXY_OSV_ECOSYSTEM_OVERRIDES", " apt-proxy "),
	]);

	let error =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap_err();

	assert!(matches!(
		error,
		ConfigError::InvalidOsvEcosystemOverride { .. }
	));
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

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
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

	let config =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap();

	assert_eq!(config.repository_format, "raw");
	assert_eq!(config.osv_ecosystem.as_deref(), Some("PyPI"));
}
