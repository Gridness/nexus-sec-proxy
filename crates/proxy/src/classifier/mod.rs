use axum::http::Method;
#[cfg(test)]
use axum::http::Uri;
#[cfg(test)]
use nexus_sec_proxy_config::AppConfig;
use nexus_sec_proxy_security::{
	PackageCoordinate, ScanTarget, default_osv_ecosystem_for_format,
};
use percent_encoding::percent_decode_str;

mod formats;

use formats::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestClassification {
	ProxyOnly,
	Scan(ScanTarget),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationContext {
	pub repository_format: String,
	pub osv_ecosystem: Option<String>,
}

impl ClassificationContext {
	pub fn new(
		repository_format: impl Into<String>,
		osv_ecosystem: Option<String>,
	) -> Self {
		Self {
			repository_format: repository_format.into(),
			osv_ecosystem,
		}
	}

	#[cfg(test)]
	pub fn from_config(config: &AppConfig) -> Self {
		Self::new(
			config.repository_format.clone(),
			config.osv_ecosystem.clone(),
		)
	}
}

#[cfg(test)]
pub fn classify_request(
	config: &AppConfig,
	method: &Method,
	uri: &Uri,
) -> RequestClassification {
	classify_path(
		&ClassificationContext::from_config(config),
		method,
		uri.path(),
	)
}

pub fn classify_path(
	context: &ClassificationContext,
	method: &Method,
	path: &str,
) -> RequestClassification {
	if method != Method::GET && method != Method::HEAD {
		return RequestClassification::ProxyOnly;
	}

	let segments = decoded_segments(path);
	let format = normalize_format(&context.repository_format);

	let target = match format.as_str() {
		"maven" | "maven2" => classify_maven(context, &segments),
		"npm" => classify_npm(context, &segments),
		"pypi" | "python" => classify_pypi(context, &segments),
		"cargo" | "rust" | "rustcargo" => classify_cargo(context, &segments),
		"go" | "golang" => classify_go(context, &segments),
		"docker" => classify_docker(context, path, &segments),
		"helm" => classify_helm(context, path, &segments),
		// Ansible, Terraform, and Conan have no vulnerability database that
		// can be queried by a proxy tier. They pass through to Nexus without
		// scanning to avoid giving a false impression of security.
		"ansible" | "terraform" | "conan" => {
			tracing::debug!(
				format = %format,
				"format is not vulnerability-scanned; passing through"
			);
			None
		}
		_ => None,
	};

	target
		.map(RequestClassification::Scan)
		.unwrap_or(RequestClassification::ProxyOnly)
}

fn package_target(
	context: &ClassificationContext,
	default_ecosystem: &str,
	name: String,
	version: String,
) -> ScanTarget {
	let ecosystem = context
		.osv_ecosystem
		.clone()
		.or_else(|| {
			default_osv_ecosystem_for_format(&context.repository_format)
				.map(str::to_owned)
		})
		.unwrap_or_else(|| default_ecosystem.to_owned());

	ScanTarget::Package(PackageCoordinate::from_osv(ecosystem, name, version))
}

fn decoded_segments(path: &str) -> Vec<String> {
	path.trim_start_matches('/')
		.split('/')
		.filter(|segment| !segment.is_empty())
		.map(|segment| percent_decode_str(segment).decode_utf8_lossy().into())
		.collect()
}

fn normalize_format(format: &str) -> String {
	format
		.chars()
		.filter(|character| character.is_ascii_alphanumeric())
		.flat_map(char::to_lowercase)
		.collect()
}

fn strip_archive_suffix<'a>(
	file: &'a str,
	suffixes: &[&str],
) -> Option<&'a str> {
	suffixes.iter().find_map(|suffix| file.strip_suffix(suffix))
}

#[cfg(test)]
mod tests {
	use axum::http::Uri;
	use nexus_sec_proxy_config::{AppConfig, UnsupportedTargetPolicy};
	use nexus_sec_proxy_security::{
		PackageIdentity, PolicySet, SecurityPolicy,
	};

	use super::*;

	#[test]
	fn classifies_maven_artifact() {
		let config = config("maven2", Some("Maven"));
		let uri = uri("/com/example/demo/1.2.3/demo-1.2.3.jar");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "Maven", "com.example:demo", "1.2.3");
	}

	#[test]
	fn classifies_stripped_nexus_repository_path() {
		let context = ClassificationContext::new("maven2", None);

		let classification = classify_path(
			&context,
			&Method::GET,
			"/com/example/demo/1.2.3/demo-1.2.3.jar",
		);

		assert_package(classification, "Maven", "com.example:demo", "1.2.3");
	}

	#[test]
	fn classifies_scoped_npm_tarball() {
		let config = config("npm", Some("npm"));
		let uri = uri("/@scope/pkg/-/pkg-1.2.3.tgz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "npm", "@scope/pkg", "1.2.3");
	}

	#[test]
	fn classifies_pypi_wheel() {
		let config = config("pypi", Some("PyPI"));
		let uri = uri("/packages/aa/bb/My_Pkg-1.2.3-py3-none-any.whl");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "PyPI", "my-pkg", "1.2.3");
	}

	#[test]
	fn docker_blob_is_proxy_only_for_legacy_repository_path() {
		let config = config("docker", None);
		let uri = uri("/v2/library/alpine/blobs/sha256:abc123");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_eq!(classification, RequestClassification::ProxyOnly);
	}

	#[test]
	fn terraform_is_pass_through() {
		let config = config("terraform", None);
		let uri =
			uri("/v1/providers/hashicorp/aws/5.30.0/download/linux/amd64");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_eq!(classification, RequestClassification::ProxyOnly);
	}

	#[test]
	fn ansible_is_pass_through() {
		let config = config("ansible", None);
		let uri = uri("/downloads/community-general-8.0.0.tar.gz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_eq!(classification, RequestClassification::ProxyOnly);
	}

	#[test]
	fn conan_is_pass_through() {
		let config = config("conan", None);
		let uri = uri("/v2/openssl/1.1.1w/openssl-1.1.1w.tgz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_eq!(classification, RequestClassification::ProxyOnly);
	}

	#[test]
	fn helm_chart_is_artifact_scan_target() {
		let config = config("helm", None);
		let uri = uri("/charts/nginx-15.4.4.tgz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_artifact(classification, "helm", None);
	}

	#[test]
	fn unknown_format_is_pass_through() {
		let config = config("raw", None);
		let uri = uri("/some/random/file.bin");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_eq!(classification, RequestClassification::ProxyOnly);
	}

	#[test]
	fn sidecar_checksum_is_proxy_only() {
		let config = config("maven2", Some("Maven"));
		let uri = uri("/com/example/demo/1.2.3/demo-1.2.3.jar.sha1");

		assert_eq!(
			classify_request(&config, &Method::GET, &uri),
			RequestClassification::ProxyOnly
		);
	}

	fn config(format: &str, ecosystem: Option<&str>) -> AppConfig {
		AppConfig {
			bind_addr: "127.0.0.1:3000".parse().unwrap(),
			nexus_base_url: "https://repo.example.invalid".to_owned(),
			upstream_base_url: "https://repo.example.invalid".to_owned(),
			repository_name: "default".to_owned(),
			repository_format: format.to_owned(),
			docker_registry_base_url: None,
			docker_repository_name: None,
			osv_ecosystem: ecosystem.map(str::to_owned),
			osv_ecosystem_overrides: Default::default(),
			nexus_username: None,
			nexus_password: None,
			repository_refresh_interval_secs: 60,
			osv_api_url: "https://api.osv.dev/v1/query".to_owned(),
			policy_file: None,
			admin_token: None,
			yandex_messenger_token: None,
			yandex_messenger_template_file: None,
			yandex_messenger_api_url: "https://botapi.messenger.yandex.net"
				.to_owned(),
			yandex_messenger_enabled: false,
			trust_base_url: "https://proxy.example.invalid".to_owned(),
			trust_report_dir: "/tmp/nexus-sec-proxy-test-reports".to_owned(),
			trust_report_retention_days: 30,
			log_json: false,
			fail_open: true,
			unsupported_target_policy: UnsupportedTargetPolicy::Allow,
			cache_allowed_ttl_secs: 86_400,
			cache_blocked_ttl_secs: 3_600,
			cache_max_capacity: 100,
			request_timeout_secs: 30,
			artifact_scanner_formats: Default::default(),
			artifact_scanner_skip_db_update: true,
			artifact_scanner_offline: true,
			artifact_scanner_timeout_secs: 300,
			artifact_scan_max_bytes: 512 * 1024 * 1024,
			artifact_scanner_concurrency: 2,
			artifact_tmp_dir: None,
			helm_binary: "helm".to_owned(),
			security_policy: SecurityPolicy::default(),
			policy_set: PolicySet::default(),
		}
	}

	fn uri(path: &str) -> Uri {
		path.parse().unwrap()
	}

	fn assert_package(
		classification: RequestClassification,
		ecosystem: &str,
		name: &str,
		version: &str,
	) {
		match classification {
			RequestClassification::Scan(ScanTarget::Package(package)) => {
				assert_eq!(package.version.as_deref(), Some(version));
				assert_eq!(
					package.identity,
					PackageIdentity::Osv {
						ecosystem: ecosystem.to_owned(),
						name: name.to_owned(),
					}
				);
			}
			other => panic!("unexpected classification: {other:?}"),
		}
	}

	fn assert_artifact(
		classification: RequestClassification,
		source_format: &str,
		digest: Option<&str>,
	) {
		match classification {
			RequestClassification::Scan(ScanTarget::Artifact(artifact)) => {
				assert_eq!(artifact.source_format, source_format);
				assert_eq!(artifact.digest.as_deref(), digest);
			}
			other => panic!("unexpected classification: {other:?}"),
		}
	}
}
