use std::collections::BTreeMap;
use std::io::Write;

use super::*;
use nexus_sec_proxy_security::Severity;

fn config_from_env(
	env: &BTreeMap<&str, &str>,
) -> Result<AppConfig, ConfigError> {
	AppConfig::from_env_vars(|name| {
		env.get(name).map(ToString::to_string).or_else(|| {
			(name == "NEXUS_SEC_PROXY_TRUST_BASE_URL")
				.then(|| "https://proxy.example.invalid".to_owned())
		})
	})
}

#[test]
fn default_config_uses_strict_high_and_critical_policy() {
	let env = BTreeMap::from([(
		"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
		"https://repo.example.invalid",
	)]);

	let config = config_from_env(&env).unwrap();

	assert_eq!(
		config.security_policy.minimum_blocking_severity,
		Severity::High
	);
	assert_eq!(config.nexus_base_url, "https://repo.example.invalid");
	assert_eq!(config.upstream_base_url, config.nexus_base_url);
	assert_eq!(config.repository_name, "default");
	assert_eq!(config.docker_registry_base_url, None);
	assert_eq!(config.docker_repository_name, None);
	assert!(!config.docker_registry_configured());
	assert_eq!(config.repository_refresh_interval_secs, 60);
	assert_eq!(config.policy_file, None);
	assert_eq!(config.admin_token, None);
	assert_eq!(config.yandex_messenger_token, None);
	assert_eq!(config.yandex_messenger_template_file, None);
	assert_eq!(
		config.yandex_messenger_api_url,
		"https://botapi.messenger.yandex.net"
	);
	assert_eq!(config.trust_base_url, "https://proxy.example.invalid");
	assert_eq!(
		config.trust_report_dir,
		"/var/lib/nexus-sec-proxy/trust-reports"
	);
	assert_eq!(config.trust_report_retention_days, 30);
	assert!(!config.yandex_messenger_enabled);
	assert!(!config.log_json);
	assert!(config.artifact_scanner_formats.is_empty());
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
fn parses_repository_refresh_interval() {
	for (value, expected) in [("15", 15), ("0", 0)] {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_REPOSITORY_REFRESH_INTERVAL_SECS", value),
		]);

		let config = config_from_env(&env).unwrap();

		assert_eq!(config.repository_refresh_interval_secs, expected);
	}

	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_REPOSITORY_REFRESH_INTERVAL_SECS", "soon"),
	]);

	let error = config_from_env(&env).unwrap_err();

	assert!(matches!(
		error,
		ConfigError::InvalidUnsignedInt {
			name: "NEXUS_SEC_PROXY_REPOSITORY_REFRESH_INTERVAL_SECS",
			..
		}
	));
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

	let config = config_from_env(&env).unwrap();

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

	let config = config_from_env(&env).unwrap();

	assert!(!config.yandex_messenger_enabled);

	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_YANDEX_MESSENGER_ENABLED", "true"),
	]);

	let config = config_from_env(&env).unwrap();

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

	let config = config_from_env(&env).unwrap();
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

	let config = config_from_env(&env).unwrap();

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

	let config = config_from_env(&env).unwrap();

	assert_eq!(config.admin_token.as_deref(), Some("secret-token"));

	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		("NEXUS_SEC_PROXY_ADMIN_TOKEN", "   "),
	]);

	let config = config_from_env(&env).unwrap();

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

	let config = config_from_env(&env).unwrap();

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
		(
			"NEXUS_SEC_PROXY_ARTIFACT_SCANNER_FORMATS",
			" helm = trivy, docker = trivy ",
		),
		(
			"NEXUS_SEC_PROXY_DOCKER_REGISTRY_BASE_URL",
			"http://nexus.example.invalid:5000/",
		),
		("NEXUS_SEC_PROXY_DOCKER_REPOSITORY_NAME", "docker-proxy"),
		("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_SKIP_DB_UPDATE", "false"),
		("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_OFFLINE", "false"),
		("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_TIMEOUT_SECS", "120"),
		("NEXUS_SEC_PROXY_ARTIFACT_SCAN_MAX_BYTES", "1048576"),
		("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_CONCURRENCY", "4"),
		("NEXUS_SEC_PROXY_ARTIFACT_TMP_DIR", "/var/tmp/nsp"),
	]);

	let config = config_from_env(&env).unwrap();

	assert_eq!(
		config.artifact_scanner_formats.get("helm"),
		Some(&ArtifactScannerKind::Trivy)
	);
	assert_eq!(
		config.artifact_scanner_for_format(" Helm "),
		Some(ArtifactScannerKind::Trivy)
	);
	assert_eq!(
		config.artifact_scanner_for_format("docker"),
		Some(ArtifactScannerKind::Trivy)
	);
	assert_eq!(
		config.docker_registry_base_url.as_deref(),
		Some("http://nexus.example.invalid:5000/")
	);
	assert_eq!(
		config.docker_repository_name.as_deref(),
		Some("docker-proxy")
	);
	assert!(config.docker_registry_configured());
	assert!(!config.artifact_scanner_skip_db_update);
	assert!(!config.artifact_scanner_offline);
	assert_eq!(config.artifact_scanner_timeout_secs, 120);
	assert_eq!(config.artifact_scan_max_bytes, 1_048_576);
	assert_eq!(config.artifact_scanner_concurrency, 4);
	assert_eq!(config.artifact_tmp_dir.as_deref(), Some("/var/tmp/nsp"));
}

#[test]
fn rejects_docker_registry_base_without_repository_name() {
	let env = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
			"https://repo.example.invalid",
		),
		(
			"NEXUS_SEC_PROXY_DOCKER_REGISTRY_BASE_URL",
			"http://nexus.example.invalid:5000",
		),
	]);

	let error = config_from_env(&env).unwrap_err();

	assert!(matches!(
		error,
		ConfigError::MissingRequired {
			name: "NEXUS_SEC_PROXY_DOCKER_REPOSITORY_NAME"
		}
	));
}

#[test]
fn rejects_invalid_docker_registry_base_url() {
	for value in [
		"not a url",
		"ftp://nexus.example.invalid",
		"http://",
		"http://nexus.example.invalid:5000/repository/docker",
		"http://nexus.example.invalid:5000/?x=1",
	] {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_DOCKER_REGISTRY_BASE_URL", value),
			("NEXUS_SEC_PROXY_DOCKER_REPOSITORY_NAME", "docker-proxy"),
		]);

		let error = config_from_env(&env).unwrap_err();

		assert!(matches!(
			error,
			ConfigError::InvalidDockerRegistryBaseUrl { .. }
		));
	}
}

#[test]
fn rejects_invalid_artifact_scanner_format_map() {
	for value in [
		"helm",
		"=trivy",
		"helm=clair",
		"helm=disabled",
		"helm=trivy,Helm=trivy",
		"helm=trivy,,docker=trivy",
	] {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_UPSTREAM_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_ARTIFACT_SCANNER_FORMATS", value),
		]);

		let error = config_from_env(&env).unwrap_err();

		assert!(matches!(
			error,
			ConfigError::InvalidArtifactScannerFormatMap { .. }
		));
	}
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

	let error = config_from_env(&env).unwrap_err();

	assert!(matches!(error, ConfigError::InvalidSeverity { .. }));
}

#[test]
fn requires_generic_upstream_base_url() {
	let error = AppConfig::from_env_vars(|_| None).unwrap_err();

	assert!(matches!(error, ConfigError::MissingRequired { .. }));

	let env = BTreeMap::from([(
		"NEXUS_SEC_PROXY_NEXUS_BASE_URL",
		"https://repo.example.invalid",
	)]);
	let error =
		AppConfig::from_env_vars(|name| env.get(name).map(ToString::to_string))
			.unwrap_err();
	assert!(matches!(
		error,
		ConfigError::MissingRequired {
			name: "NEXUS_SEC_PROXY_TRUST_BASE_URL"
		}
	));
}

#[test]
fn validates_trust_report_configuration() {
	let valid = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_NEXUS_BASE_URL",
			"https://repo.example.invalid",
		),
		(
			"NEXUS_SEC_PROXY_TRUST_BASE_URL",
			"https://proxy.example.invalid/base/",
		),
		(
			"NEXUS_SEC_PROXY_TRUST_REPORT_DIR",
			"/srv/shared/trust-reports",
		),
		("NEXUS_SEC_PROXY_TRUST_REPORT_RETENTION_DAYS", "7"),
	]);
	let config = AppConfig::from_env_vars(|name| {
		valid.get(name).map(ToString::to_string)
	})
	.unwrap();
	assert_eq!(config.trust_base_url, "https://proxy.example.invalid/base");
	assert_eq!(config.trust_report_dir, "/srv/shared/trust-reports");
	assert_eq!(config.trust_report_retention_days, 7);

	for invalid_url in [
		"ftp://proxy.example.invalid",
		"https://proxy.example.invalid/path?token=secret",
		"https://proxy.example.invalid/path#fragment",
		"not a URL",
	] {
		let env = BTreeMap::from([
			(
				"NEXUS_SEC_PROXY_NEXUS_BASE_URL",
				"https://repo.example.invalid",
			),
			("NEXUS_SEC_PROXY_TRUST_BASE_URL", invalid_url),
		]);
		let error = AppConfig::from_env_vars(|name| {
			env.get(name).map(ToString::to_string)
		})
		.unwrap_err();
		assert!(matches!(error, ConfigError::InvalidTrustBaseUrl { .. }));
	}

	let zero_retention = BTreeMap::from([
		(
			"NEXUS_SEC_PROXY_NEXUS_BASE_URL",
			"https://repo.example.invalid",
		),
		(
			"NEXUS_SEC_PROXY_TRUST_BASE_URL",
			"https://proxy.example.invalid",
		),
		("NEXUS_SEC_PROXY_TRUST_REPORT_RETENTION_DAYS", "0"),
	]);
	let error = AppConfig::from_env_vars(|name| {
		zero_retention.get(name).map(ToString::to_string)
	})
	.unwrap_err();
	assert!(matches!(error, ConfigError::ValueBelowMinimum { .. }));
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

	let config = config_from_env(&env).unwrap();

	assert_eq!(config.nexus_base_url, "https://nexus.example.invalid");
	assert_eq!(config.upstream_base_url, config.nexus_base_url);

	let env = BTreeMap::from([(
		"NEXUS_SEC_PROXY_UPSTREAM_REGISTRY",
		"https://oldest.example.invalid",
	)]);

	let config = config_from_env(&env).unwrap();

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

	let config = config_from_env(&env).unwrap();

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

	let error = config_from_env(&env).unwrap_err();

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

	let config = config_from_env(&env).unwrap();

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

	let config = config_from_env(&env).unwrap();

	assert_eq!(config.repository_format, "raw");
	assert_eq!(config.osv_ecosystem.as_deref(), Some("PyPI"));
}
