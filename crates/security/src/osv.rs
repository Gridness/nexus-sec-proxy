use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
	PackageCoordinate, PackageIdentity, Reference, ScanTarget, SecurityError,
	Severity, Vulnerability, VulnerabilitySource,
};

#[derive(Debug, Clone)]
pub struct OsvClient {
	client: reqwest::Client,
	endpoint: String,
}

impl OsvClient {
	#[must_use]
	pub fn new(client: reqwest::Client, endpoint: impl Into<String>) -> Self {
		Self {
			client,
			endpoint: endpoint.into(),
		}
	}

	async fn query_package(
		&self,
		package: &PackageCoordinate,
	) -> Result<Vec<Vulnerability>, SecurityError> {
		let mut vulnerabilities = Vec::new();
		let mut page_token = None;

		loop {
			let query = OsvQuery::from_package(package, page_token.clone())?;
			let response = self
				.client
				.post(&self.endpoint)
				.json(&query)
				.send()
				.await
				.map_err(|error| SecurityError::Request(error.to_string()))?;
			let status = response.status();

			if !status.is_success() {
				let body = response.text().await.unwrap_or_else(|error| {
					format!("failed to read OSV error body: {error}")
				});
				return Err(SecurityError::UnexpectedStatus { status, body });
			}

			let response =
				response.json::<OsvResponse>().await.map_err(|error| {
					SecurityError::InvalidResponse(error.to_string())
				})?;

			vulnerabilities.extend(
				response
					.vulns
					.into_iter()
					.map(OsvVulnerability::into_vulnerability),
			);

			match response.next_page_token {
				Some(next_page_token) if !next_page_token.is_empty() => {
					page_token = Some(next_page_token);
				}
				_ => break,
			}
		}

		Ok(vulnerabilities)
	}
}

#[async_trait]
impl VulnerabilitySource for OsvClient {
	async fn vulnerabilities(
		&self,
		target: &ScanTarget,
	) -> Result<Vec<Vulnerability>, SecurityError> {
		match target {
			ScanTarget::Package(package) => self.query_package(package).await,
			ScanTarget::Artifact(artifact) => {
				Err(SecurityError::UnsupportedTarget(format!(
					"OSV cannot scan {} artifacts by URL or bytes",
					artifact.source_format
				)))
			}
		}
	}
}

#[derive(Debug, Serialize)]
struct OsvQuery {
	#[serde(skip_serializing_if = "Option::is_none")]
	commit: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	version: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	package: Option<OsvPackage>,
	#[serde(skip_serializing_if = "Option::is_none")]
	page_token: Option<String>,
}

impl OsvQuery {
	fn from_package(
		package: &PackageCoordinate,
		page_token: Option<String>,
	) -> Result<Self, SecurityError> {
		match &package.identity {
			PackageIdentity::Osv { ecosystem, name } => Ok(Self {
				commit: None,
				version: package.version.clone(),
				package: Some(OsvPackage {
					name: Some(name.clone()),
					ecosystem: Some(ecosystem.clone()),
					purl: None,
				}),
				page_token,
			}),
			PackageIdentity::Purl { purl } => Ok(Self {
				commit: None,
				version: package
					.version
					.clone()
					.filter(|_| !purl_contains_version(purl)),
				package: Some(OsvPackage {
					name: None,
					ecosystem: None,
					purl: Some(purl.clone()),
				}),
				page_token,
			}),
			PackageIdentity::GitCommit { commit } => Ok(Self {
				commit: Some(commit.clone()),
				version: None,
				package: None,
				page_token,
			}),
		}
	}
}

#[derive(Debug, Serialize)]
struct OsvPackage {
	#[serde(skip_serializing_if = "Option::is_none")]
	name: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	ecosystem: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	purl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
	#[serde(default)]
	vulns: Vec<OsvVulnerability>,
	next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
	id: String,
	#[serde(default)]
	aliases: Vec<String>,
	summary: Option<String>,
	details: Option<String>,
	#[serde(default)]
	severity: Vec<OsvSeverity>,
	#[serde(default)]
	references: Vec<OsvReference>,
	#[serde(default)]
	affected: Vec<OsvAffected>,
	#[serde(default)]
	database_specific: Value,
}

impl OsvVulnerability {
	fn into_vulnerability(self) -> Vulnerability {
		let severity = severity_from_osv(&self);
		let references = self
			.references
			.into_iter()
			.map(|reference| Reference {
				url: reference.url,
				kind: reference.kind,
			})
			.collect();

		Vulnerability {
			id: self.id,
			aliases: self.aliases,
			summary: self.summary,
			details: self.details,
			severity,
			references,
		}
	}
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
	#[serde(rename = "type")]
	kind: Option<String>,
	score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
	#[serde(rename = "type")]
	kind: Option<String>,
	url: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
	#[serde(default)]
	ecosystem_specific: Value,
	#[serde(default)]
	database_specific: Value,
}
fn severity_from_osv(vulnerability: &OsvVulnerability) -> Option<Severity> {
	severity_from_json(&vulnerability.database_specific)
		.or_else(|| {
			vulnerability.affected.iter().find_map(|affected| {
				severity_from_json(&affected.ecosystem_specific)
					.or_else(|| severity_from_json(&affected.database_specific))
			})
		})
		.or_else(|| {
			vulnerability.severity.iter().find_map(|severity| {
				severity
					.score
					.as_deref()
					.and_then(severity_from_text_or_score)
					.or_else(|| {
						severity
							.kind
							.as_deref()
							.and_then(severity_from_text_or_score)
					})
			})
		})
}

fn severity_from_json(value: &Value) -> Option<Severity> {
	match value {
		Value::String(value) => severity_from_text_or_score(value),
		Value::Number(value) => value.as_f64().and_then(severity_from_cvss),
		Value::Array(values) => values.iter().find_map(severity_from_json),
		Value::Object(values) => values.iter().find_map(|(key, value)| {
			if key.eq_ignore_ascii_case("severity") {
				severity_from_json(value)
			} else {
				None
			}
			.or_else(|| severity_from_json(value))
		}),
		_ => None,
	}
}

pub(crate) fn severity_from_text_or_score(value: &str) -> Option<Severity> {
	value
		.parse()
		.ok()
		.or_else(|| value.parse::<f64>().ok().and_then(severity_from_cvss))
}

fn severity_from_cvss(score: f64) -> Option<Severity> {
	match score {
		score if (9.0..=10.0).contains(&score) => Some(Severity::Critical),
		score if (7.0..9.0).contains(&score) => Some(Severity::High),
		score if (4.0..7.0).contains(&score) => Some(Severity::Medium),
		score if (0.1..4.0).contains(&score) => Some(Severity::Low),
		_ => None,
	}
}
fn purl_contains_version(purl: &str) -> bool {
	purl.rsplit('/')
		.next()
		.is_some_and(|tail| tail.contains('@'))
}
