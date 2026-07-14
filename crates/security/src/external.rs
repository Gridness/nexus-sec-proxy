use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use tokio::process::Command;
use tokio::time as tokio_time;

use crate::osv::severity_from_text_or_score;
use crate::{Reference, ScanTarget, SecurityError, Vulnerability};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalScannerKind {
	Trivy,
}

#[derive(Debug, Clone)]
pub struct ExternalScanner {
	kind: ExternalScannerKind,
	command: String,
	timeout: Duration,
	skip_db_update: bool,
	offline: bool,
}

impl ExternalScanner {
	#[must_use]
	pub fn new(
		kind: ExternalScannerKind,
		command: impl Into<String>,
		timeout: Duration,
		skip_db_update: bool,
		offline: bool,
	) -> Self {
		Self {
			kind,
			command: command.into(),
			timeout,
			skip_db_update,
			offline,
		}
	}

	pub async fn scan_path(
		&self,
		target: &ScanTarget,
		path: &Path,
	) -> Result<Vec<Vulnerability>, SecurityError> {
		let mut command = Command::new(&self.command);

		match self.kind {
			ExternalScannerKind::Trivy => {
				command
					.arg("filesystem")
					.arg("--format")
					.arg("json")
					.arg("--quiet")
					.arg("--scanners")
					.arg("vuln")
					.arg("--exit-code")
					.arg("0");

				if self.skip_db_update {
					command.arg("--skip-db-update");
					command.arg("--skip-java-db-update");
				}

				if self.offline {
					command.arg("--offline-scan");
				}

				command.arg(path);
			}
		}

		let output = tokio_time::timeout(self.timeout, command.output())
			.await
			.map_err(|_| SecurityError::ScannerTimeout(self.timeout))?
			.map_err(|error| SecurityError::Request(error.to_string()))?;

		if !output.status.success() {
			return Err(SecurityError::ScannerFailed {
				status: output.status.to_string(),
				stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
			});
		}

		match self.kind {
			ExternalScannerKind::Trivy => {
				parse_trivy_output(target, &output.stdout)
			}
		}
	}

	pub async fn scan_image(
		&self,
		target: &ScanTarget,
		image: &str,
		docker_config: Option<&Path>,
		insecure_registry: bool,
	) -> Result<Vec<Vulnerability>, SecurityError> {
		let mut command = Command::new(&self.command);
		if let Some(docker_config) = docker_config {
			command.env("DOCKER_CONFIG", docker_config);
		}

		match self.kind {
			ExternalScannerKind::Trivy => {
				command
					.arg("image")
					.arg("--format")
					.arg("json")
					.arg("--quiet")
					.arg("--scanners")
					.arg("vuln")
					.arg("--exit-code")
					.arg("0")
					.arg("--image-src")
					.arg("remote");

				if insecure_registry {
					command.arg("--insecure");
				}

				if self.skip_db_update {
					command.arg("--skip-db-update");
					command.arg("--skip-java-db-update");
				}

				if self.offline {
					command.arg("--offline-scan");
				}

				command.arg(image);
			}
		}

		let output = tokio_time::timeout(self.timeout, command.output())
			.await
			.map_err(|_| SecurityError::ScannerTimeout(self.timeout))?
			.map_err(|error| SecurityError::Request(error.to_string()))?;

		if !output.status.success() {
			return Err(SecurityError::ScannerFailed {
				status: output.status.to_string(),
				stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
			});
		}

		match self.kind {
			ExternalScannerKind::Trivy => {
				parse_trivy_output(target, &output.stdout)
			}
		}
	}
}
pub(crate) fn parse_trivy_output(
	target: &ScanTarget,
	output: &[u8],
) -> Result<Vec<Vulnerability>, SecurityError> {
	let report: TrivyReport = serde_json::from_slice(output)
		.map_err(|error| SecurityError::InvalidResponse(error.to_string()))?;

	Ok(report
		.results
		.into_iter()
		.flat_map(|result| {
			result.vulnerabilities.into_iter().map(|vulnerability| {
				trivy_to_vulnerability(target, vulnerability)
			})
		})
		.collect())
}

fn trivy_to_vulnerability(
	target: &ScanTarget,
	vulnerability: TrivyVulnerability,
) -> Vulnerability {
	let mut aliases = vulnerability.cve_ids;
	for id in vulnerability
		.references
		.iter()
		.filter_map(|reference| vulnerability_id_from_url(reference))
	{
		if id != vulnerability.vulnerability_id && !aliases.contains(&id) {
			aliases.push(id);
		}
	}

	let mut references: Vec<_> = vulnerability
		.references
		.into_iter()
		.map(|url| Reference {
			url,
			kind: Some("WEB".to_owned()),
		})
		.collect();

	if let Some(primary_url) = vulnerability.primary_url
		&& !references
			.iter()
			.any(|reference| reference.url == primary_url)
	{
		references.insert(
			0,
			Reference {
				url: primary_url,
				kind: Some("WEB".to_owned()),
			},
		);
	}

	Vulnerability {
		id: vulnerability.vulnerability_id,
		aliases,
		summary: vulnerability.title.or_else(|| {
			Some(format!(
				"{} in {}",
				vulnerability.pkg_name,
				target.display_name()
			))
		}),
		details: vulnerability.description,
		severity: vulnerability
			.severity
			.as_deref()
			.and_then(severity_from_text_or_score),
		references,
	}
}

fn vulnerability_id_from_url(url: &str) -> Option<String> {
	url.rsplit(['/', '#', '?'])
		.find(|segment| {
			segment.starts_with("CVE-")
				|| segment.starts_with("GHSA-")
				|| segment.starts_with("OSV-")
		})
		.map(str::to_owned)
}

#[derive(Debug, Deserialize)]
struct TrivyReport {
	#[serde(default, rename = "Results")]
	results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
struct TrivyResult {
	#[serde(default, rename = "Vulnerabilities")]
	vulnerabilities: Vec<TrivyVulnerability>,
}

#[derive(Debug, Deserialize)]
struct TrivyVulnerability {
	#[serde(rename = "VulnerabilityID")]
	vulnerability_id: String,
	#[serde(default, rename = "PkgName")]
	pkg_name: String,
	#[serde(rename = "Title")]
	title: Option<String>,
	#[serde(rename = "Description")]
	description: Option<String>,
	#[serde(rename = "Severity")]
	severity: Option<String>,
	#[serde(rename = "PrimaryURL")]
	primary_url: Option<String>,
	#[serde(default, rename = "References")]
	references: Vec<String>,
	#[serde(default, rename = "CveIDs")]
	cve_ids: Vec<String>,
}
