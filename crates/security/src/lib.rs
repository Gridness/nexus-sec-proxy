use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::process::Command;
use tokio::time;

#[derive(Debug, Error)]
pub enum SecurityError {
	#[error("scanner request failed: {0}")]
	Request(String),
	#[error("scanner returned {status}: {body}")]
	UnexpectedStatus { status: StatusCode, body: String },
	#[error("invalid scanner response: {0}")]
	InvalidResponse(String),
	#[error("invalid package reference: {0}")]
	InvalidPackageReference(String),
	#[error("unsupported scan target: {0}")]
	UnsupportedTarget(String),
	#[error("external scanner timed out after {0:?}")]
	ScannerTimeout(Duration),
	#[error("external scanner exited with {status}: {stderr}")]
	ScannerFailed { status: String, stderr: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageCoordinate {
	pub source_format: String,
	pub identity: PackageIdentity,
	pub version: Option<String>,
}

impl PackageCoordinate {
	#[must_use]
	pub fn new(
		ecosystem: impl Into<String>,
		name: impl Into<String>,
		version: impl Into<String>,
	) -> Self {
		Self::from_osv(ecosystem, name, version)
	}

	#[must_use]
	pub fn from_osv(
		ecosystem: impl Into<String>,
		name: impl Into<String>,
		version: impl Into<String>,
	) -> Self {
		let ecosystem = ecosystem.into();

		Self {
			source_format: ecosystem.clone(),
			identity: PackageIdentity::Osv {
				ecosystem,
				name: name.into(),
			},
			version: Some(version.into()),
		}
	}

	#[must_use]
	pub fn from_purl(
		source_format: impl Into<String>,
		purl: impl Into<String>,
		version: Option<impl Into<String>>,
	) -> Self {
		Self {
			source_format: source_format.into(),
			identity: PackageIdentity::Purl { purl: purl.into() },
			version: version.map(Into::into),
		}
	}

	#[must_use]
	pub fn from_git_commit(commit: impl Into<String>) -> Self {
		Self {
			source_format: "git".to_owned(),
			identity: PackageIdentity::GitCommit {
				commit: commit.into(),
			},
			version: None,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PackageIdentity {
	Osv { ecosystem: String, name: String },
	Purl { purl: String },
	GitCommit { commit: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactTarget {
	pub source_format: String,
	pub uri: String,
	pub digest: Option<String>,
}

impl ArtifactTarget {
	#[must_use]
	pub fn new(
		source_format: impl Into<String>,
		uri: impl Into<String>,
	) -> Self {
		Self {
			source_format: source_format.into(),
			uri: uri.into(),
			digest: None,
		}
	}

	#[must_use]
	pub fn with_digest(
		source_format: impl Into<String>,
		uri: impl Into<String>,
		digest: impl Into<String>,
	) -> Self {
		Self {
			source_format: source_format.into(),
			uri: uri.into(),
			digest: Some(digest.into()),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanTarget {
	Package(PackageCoordinate),
	Artifact(ArtifactTarget),
}

impl ScanTarget {
	#[must_use]
	pub fn cache_namespace(&self) -> &str {
		match self {
			Self::Package(package) => &package.source_format,
			Self::Artifact(artifact) => &artifact.source_format,
		}
	}

	#[must_use]
	pub fn cache_identifier(&self) -> String {
		match self {
			Self::Package(package) => match &package.identity {
				PackageIdentity::Osv { ecosystem, name } => {
					format!("{ecosystem}/{name}")
				}
				PackageIdentity::Purl { purl } => purl.clone(),
				PackageIdentity::GitCommit { commit } => commit.clone(),
			},
			Self::Artifact(artifact) => artifact
				.digest
				.clone()
				.unwrap_or_else(|| artifact.uri.clone()),
		}
	}

	#[must_use]
	pub fn cache_version(&self) -> Option<&str> {
		match self {
			Self::Package(package) => package.version.as_deref(),
			Self::Artifact(_) => None,
		}
	}

	#[must_use]
	pub fn display_name(&self) -> String {
		match self {
			Self::Package(package) => match &package.identity {
				PackageIdentity::Osv { ecosystem, name } => {
					match package.version.as_deref() {
						Some(version) => {
							format!("{ecosystem}:{name}@{version}")
						}
						None => format!("{ecosystem}:{name}"),
					}
				}
				PackageIdentity::Purl { purl } => purl.clone(),
				PackageIdentity::GitCommit { commit } => {
					format!("git commit {commit}")
				}
			},
			Self::Artifact(artifact) => match artifact.digest.as_deref() {
				Some(digest) => {
					format!("{} artifact {}", artifact.source_format, digest)
				}
				None => {
					format!(
						"{} artifact {}",
						artifact.source_format, artifact.uri
					)
				}
			},
		}
	}
}

#[must_use]
pub fn default_osv_ecosystem_for_format(
	repository_format: &str,
) -> Option<&'static str> {
	match normalize_repository_format(repository_format).as_str() {
		"alpine" => Some("Alpine"),
		"apk" => Some("Alpine"),
		"cran" | "r" => Some("R"),
		"cargo" | "rust" | "rustcargo" => Some("crates.io"),
		"composer" | "phpcomposer" => Some("Packagist"),
		"debian" => Some("Debian GNU/Linux"),
		"go" | "golang" => Some("Go"),
		"maven" | "maven2" => Some("Maven"),
		"npm" | "node" => Some("npm"),
		"nuget" => Some("NuGet"),
		"packagist" => Some("Packagist"),
		"pub" | "flutter" | "dart" => Some("Pub"),
		"pypi" | "python" => Some("PyPI"),
		"rockylinux" | "rocky" => Some("Rocky Linux"),
		"rubygems" | "gem" | "ruby" => Some("RubyGems"),
		"swift" => Some("SwiftURL"),
		"ubuntu" => Some("Ubuntu OS"),
		_ => None,
	}
}

fn normalize_repository_format(repository_format: &str) -> String {
	repository_format
		.chars()
		.filter(|character| character.is_ascii_alphanumeric())
		.flat_map(char::to_lowercase)
		.collect()
}

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
	Low,
	Medium,
	High,
	Critical,
}

impl Severity {
	#[must_use]
	pub fn all() -> [Self; 4] {
		[Self::Low, Self::Medium, Self::High, Self::Critical]
	}

	#[must_use]
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Low => "LOW",
			Self::Medium => "MEDIUM",
			Self::High => "HIGH",
			Self::Critical => "CRITICAL",
		}
	}
}

impl fmt::Display for Severity {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(self.as_str())
	}
}

impl FromStr for Severity {
	type Err = SeverityParseError;

	fn from_str(input: &str) -> Result<Self, Self::Err> {
		match input.trim().to_ascii_uppercase().as_str() {
			"LOW" => Ok(Self::Low),
			"MEDIUM" | "MODERATE" => Ok(Self::Medium),
			"HIGH" => Ok(Self::High),
			"CRITICAL" => Ok(Self::Critical),
			_ => Err(SeverityParseError {
				input: input.to_owned(),
			}),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid severity: {input}")]
pub struct SeverityParseError {
	input: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
	pub url: String,
	pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vulnerability {
	pub id: String,
	pub aliases: Vec<String>,
	pub summary: Option<String>,
	pub details: Option<String>,
	pub severity: Option<Severity>,
	pub references: Vec<Reference>,
}

impl Vulnerability {
	pub fn identifiers(&self) -> impl Iterator<Item = &str> {
		std::iter::once(self.id.as_str())
			.chain(self.aliases.iter().map(String::as_str))
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
	pub minimum_blocking_severity: Severity,
	pub allowed_vulnerability_ids: BTreeSet<String>,
	pub limits: VulnerabilityLimits,
}

impl Default for SecurityPolicy {
	fn default() -> Self {
		Self {
			minimum_blocking_severity: Severity::High,
			allowed_vulnerability_ids: BTreeSet::new(),
			limits: VulnerabilityLimits::default(),
		}
	}
}

impl SecurityPolicy {
	#[must_use]
	pub fn new(
		minimum_blocking_severity: Severity,
		allowed_vulnerability_ids: impl IntoIterator<Item = impl Into<String>>,
		limits: VulnerabilityLimits,
	) -> Self {
		Self {
			minimum_blocking_severity,
			allowed_vulnerability_ids: allowed_vulnerability_ids
				.into_iter()
				.filter_map(|id| normalize_vulnerability_id(&id.into()))
				.collect(),
			limits,
		}
	}

	#[must_use]
	pub fn allows_vulnerability(&self, vulnerability: &Vulnerability) -> bool {
		vulnerability.identifiers().any(|id| {
			normalize_vulnerability_id(id).is_some_and(|normalized_id| {
				self.allowed_vulnerability_ids.iter().any(|allowed_id| {
					normalize_vulnerability_id(allowed_id).as_ref()
						== Some(&normalized_id)
				})
			})
		})
	}

	#[must_use]
	pub fn effective_limit(&self, severity: Severity) -> Option<u32> {
		self.limits.for_severity(severity).or_else(|| {
			(severity >= self.minimum_blocking_severity).then_some(0)
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VulnerabilityLimits {
	pub total: Option<u32>,
	pub low: Option<u32>,
	pub medium: Option<u32>,
	pub high: Option<u32>,
	pub critical: Option<u32>,
}

impl VulnerabilityLimits {
	#[must_use]
	pub fn for_severity(&self, severity: Severity) -> Option<u32> {
		match severity {
			Severity::Low => self.low,
			Severity::Medium => self.medium,
			Severity::High => self.high,
			Severity::Critical => self.critical,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
	pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockReport {
	pub target: ScanTarget,
	pub reason: String,
	pub policy_violations: Vec<PolicyViolation>,
	pub vulnerabilities: Vec<Vulnerability>,
}

impl BlockReport {
	#[must_use]
	pub fn unsupported(target: ScanTarget, reason: impl Into<String>) -> Self {
		Self {
			target,
			reason: reason.into(),
			policy_violations: Vec::new(),
			vulnerabilities: Vec::new(),
		}
	}

	#[must_use]
	pub fn to_plain_text(&self) -> String {
		let mut body = format!(
			"Package blocked by nexus-sec-proxy\n\nTarget: {}\nReason: {}\n",
			self.target.display_name(),
			self.reason
		);

		if !self.policy_violations.is_empty() {
			body.push_str("\nPolicy violations:\n");
			for violation in &self.policy_violations {
				body.push_str("- ");
				body.push_str(&violation.reason);
				body.push('\n');
			}
		}

		if !self.vulnerabilities.is_empty() {
			body.push_str("\nVulnerabilities:\n");
			for vulnerability in &self.vulnerabilities {
				let severity = vulnerability
					.severity
					.map_or("UNKNOWN".to_owned(), |severity| {
						severity.to_string()
					});
				body.push_str("- ");
				body.push_str(&vulnerability.id);
				body.push_str(" [");
				body.push_str(&severity);
				body.push(']');

				if !vulnerability.aliases.is_empty() {
					body.push_str(" aliases=");
					body.push_str(&vulnerability.aliases.join(","));
				}

				if let Some(summary) = vulnerability.summary.as_deref() {
					body.push_str(": ");
					body.push_str(summary);
				}

				body.push('\n');

				for reference in &vulnerability.references {
					body.push_str("  ref: ");
					body.push_str(&reference.url);
					body.push('\n');
				}
			}
		}

		body
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanDecision {
	Allowed,
	Blocked(BlockReport),
}

impl ScanDecision {
	#[must_use]
	pub fn is_blocked(&self) -> bool {
		matches!(self, Self::Blocked(_))
	}
}

#[async_trait]
pub trait VulnerabilitySource: Send + Sync {
	async fn vulnerabilities(
		&self,
		target: &ScanTarget,
	) -> Result<Vec<Vulnerability>, SecurityError>;
}

pub trait VulnerabilityEvaluator: Send + Sync {
	fn evaluate(
		&self,
		target: &ScanTarget,
		vulnerabilities: Vec<Vulnerability>,
	) -> ScanDecision;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluator {
	policy: SecurityPolicy,
}

impl PolicyEvaluator {
	#[must_use]
	pub fn new(policy: SecurityPolicy) -> Self {
		Self { policy }
	}

	#[must_use]
	pub fn policy(&self) -> &SecurityPolicy {
		&self.policy
	}
}

impl Default for PolicyEvaluator {
	fn default() -> Self {
		Self::new(SecurityPolicy::default())
	}
}

impl VulnerabilityEvaluator for PolicyEvaluator {
	fn evaluate(
		&self,
		target: &ScanTarget,
		vulnerabilities: Vec<Vulnerability>,
	) -> ScanDecision {
		let evaluated_vulnerabilities: Vec<_> = vulnerabilities
			.into_iter()
			.filter(|vulnerability| {
				!self.policy.allows_vulnerability(vulnerability)
			})
			.collect();
		let violations =
			policy_violations(&self.policy, &evaluated_vulnerabilities);

		if violations.is_empty() {
			ScanDecision::Allowed
		} else {
			ScanDecision::Blocked(BlockReport {
				target: target.clone(),
				reason: "vulnerability policy was violated".to_owned(),
				policy_violations: violations,
				vulnerabilities: evaluated_vulnerabilities,
			})
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalScannerKind {
	Trivy,
	Grype,
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
			ExternalScannerKind::Grype => {
				command.arg(path).arg("-o").arg("json");
			}
		}

		let output = time::timeout(self.timeout, command.output())
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
			ExternalScannerKind::Grype => {
				parse_grype_output(target, &output.stdout)
			}
		}
	}
}

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

fn policy_violations(
	policy: &SecurityPolicy,
	vulnerabilities: &[Vulnerability],
) -> Vec<PolicyViolation> {
	let mut violations = Vec::new();

	if policy
		.limits
		.total
		.is_some_and(|limit| vulnerabilities.len() > limit as usize)
	{
		let limit = policy.limits.total.expect("checked by is_some_and");
		violations.push(PolicyViolation {
			reason: format!(
				"{} non-allowlisted vulnerabilities exceeds total limit of {limit}",
				vulnerabilities.len()
			),
		});
	}

	for severity in Severity::all() {
		if let Some(limit) = policy.effective_limit(severity) {
			let count = vulnerabilities
				.iter()
				.filter(|vulnerability| {
					vulnerability.severity == Some(severity)
				})
				.count();

			if count > limit as usize {
				violations.push(PolicyViolation {
					reason: format!(
						"{count} {severity} vulnerabilities exceeds limit of {limit}"
					),
				});
			}
		}
	}

	violations
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

fn severity_from_text_or_score(value: &str) -> Option<Severity> {
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

fn normalize_vulnerability_id(id: &str) -> Option<String> {
	let normalized = id.trim().to_ascii_uppercase();

	(!normalized.is_empty()).then_some(normalized)
}

fn purl_contains_version(purl: &str) -> bool {
	purl.rsplit('/')
		.next()
		.is_some_and(|tail| tail.contains('@'))
}

fn parse_trivy_output(
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

fn parse_grype_output(
	target: &ScanTarget,
	output: &[u8],
) -> Result<Vec<Vulnerability>, SecurityError> {
	let report: GrypeReport = serde_json::from_slice(output)
		.map_err(|error| SecurityError::InvalidResponse(error.to_string()))?;

	Ok(report
		.matches
		.into_iter()
		.map(|matched| grype_to_vulnerability(target, matched))
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

fn grype_to_vulnerability(
	target: &ScanTarget,
	matched: GrypeMatch,
) -> Vulnerability {
	let mut aliases = matched
		.vulnerability
		.aliases
		.into_iter()
		.map(|alias| alias.id)
		.collect::<Vec<_>>();
	aliases.extend(
		matched
			.related_vulnerabilities
			.into_iter()
			.map(|vulnerability| vulnerability.id),
	);
	aliases.sort();
	aliases.dedup();

	let references = matched
		.vulnerability
		.urls
		.into_iter()
		.map(|url| Reference {
			url,
			kind: Some("WEB".to_owned()),
		})
		.collect();

	Vulnerability {
		id: matched.vulnerability.id,
		aliases,
		summary: Some(format!(
			"{} {} in {}",
			matched.artifact.name,
			matched.artifact.version.unwrap_or_default(),
			target.display_name()
		)),
		details: matched.vulnerability.description,
		severity: severity_from_text_or_score(&matched.vulnerability.severity),
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

#[derive(Debug, Deserialize)]
struct GrypeReport {
	#[serde(default)]
	matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
struct GrypeMatch {
	vulnerability: GrypeVulnerability,
	#[serde(default, rename = "relatedVulnerabilities")]
	related_vulnerabilities: Vec<GrypeRelatedVulnerability>,
	artifact: GrypeArtifact,
}

#[derive(Debug, Deserialize)]
struct GrypeVulnerability {
	id: String,
	severity: String,
	description: Option<String>,
	#[serde(default)]
	urls: Vec<String>,
	#[serde(default)]
	aliases: Vec<GrypeRelatedVulnerability>,
}

#[derive(Debug, Deserialize)]
struct GrypeRelatedVulnerability {
	id: String,
}

#[derive(Debug, Deserialize)]
struct GrypeArtifact {
	name: String,
	version: Option<String>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_policy_blocks_high_and_critical_only() {
		let target = package_target();
		let evaluator = PolicyEvaluator::default();

		let medium_decision = evaluator.evaluate(
			&target,
			vec![vulnerability("CVE-1", Severity::Medium, [])],
		);
		let high_decision = evaluator.evaluate(
			&target,
			vec![vulnerability("CVE-2", Severity::High, [])],
		);
		let critical_decision = evaluator.evaluate(
			&target,
			vec![vulnerability("CVE-3", Severity::Critical, [])],
		);

		assert_eq!(medium_decision, ScanDecision::Allowed);
		assert!(high_decision.is_blocked());
		assert!(critical_decision.is_blocked());
	}

	#[test]
	fn allowlist_matches_aliases_case_insensitively() {
		let target = package_target();
		let policy = SecurityPolicy::new(
			Severity::High,
			[" cve-2026-0001 "],
			VulnerabilityLimits::default(),
		);
		let evaluator = PolicyEvaluator::new(policy);

		let decision = evaluator.evaluate(
			&target,
			vec![vulnerability(
				"GHSA-0000",
				Severity::Critical,
				["CVE-2026-0001"],
			)],
		);

		assert_eq!(decision, ScanDecision::Allowed);
	}

	#[test]
	fn per_severity_limit_blocks_when_count_is_exceeded() {
		let target = package_target();
		let policy = SecurityPolicy::new(
			Severity::Critical,
			std::iter::empty::<&str>(),
			VulnerabilityLimits {
				medium: Some(1),
				..VulnerabilityLimits::default()
			},
		);
		let evaluator = PolicyEvaluator::new(policy);

		let decision = evaluator.evaluate(
			&target,
			vec![
				vulnerability("CVE-1", Severity::Medium, []),
				vulnerability("CVE-2", Severity::Medium, []),
			],
		);

		assert!(decision.is_blocked());
	}

	#[test]
	fn total_limit_is_applied_after_allowlist() {
		let target = package_target();
		let policy = SecurityPolicy::new(
			Severity::Low,
			["CVE-1"],
			VulnerabilityLimits {
				total: Some(1),
				low: Some(10),
				..VulnerabilityLimits::default()
			},
		);
		let evaluator = PolicyEvaluator::new(policy);

		let decision = evaluator.evaluate(
			&target,
			vec![
				vulnerability("CVE-1", Severity::Low, []),
				vulnerability("CVE-2", Severity::Low, []),
				vulnerability("CVE-3", Severity::Low, []),
			],
		);

		assert!(decision.is_blocked());
	}

	#[test]
	fn block_report_includes_references() {
		let report = BlockReport {
			target: package_target(),
			reason: "test".to_owned(),
			policy_violations: vec![PolicyViolation {
				reason: "critical limit exceeded".to_owned(),
			}],
			vulnerabilities: vec![Vulnerability {
				id: "CVE-2026-0001".to_owned(),
				aliases: vec!["GHSA-0001".to_owned()],
				summary: Some("bad package".to_owned()),
				details: None,
				severity: Some(Severity::Critical),
				references: vec![Reference {
					url: "https://osv.dev/vulnerability/CVE-2026-0001"
						.to_owned(),
					kind: Some("WEB".to_owned()),
				}],
			}],
		};

		let body = report.to_plain_text();

		assert!(body.contains("CVE-2026-0001"));
		assert!(body.contains("https://osv.dev/vulnerability/CVE-2026-0001"));
	}

	#[test]
	fn parses_severity_names_and_scores() {
		assert_eq!("critical".parse::<Severity>(), Ok(Severity::Critical));
		assert_eq!("moderate".parse::<Severity>(), Ok(Severity::Medium));
		assert_eq!(
			severity_from_text_or_score("9.8"),
			Some(Severity::Critical)
		);
		assert!("unknown".parse::<Severity>().is_err());
	}

	#[test]
	fn package_coordinate_supports_purl_identity() {
		let package = ScanTarget::Package(PackageCoordinate::from_purl(
			"pypi",
			"pkg:pypi/jinja2@3.1.4",
			None::<&str>,
		));

		assert_eq!(package.cache_namespace(), "pypi");
		assert_eq!(package.cache_identifier(), "pkg:pypi/jinja2@3.1.4");
		assert_eq!(package.cache_version(), None);
	}

	#[test]
	fn maps_known_nexus_formats_to_osv_ecosystems() {
		assert_eq!(default_osv_ecosystem_for_format("maven2"), Some("Maven"));
		assert_eq!(default_osv_ecosystem_for_format("PyPI"), Some("PyPI"));
		assert_eq!(
			default_osv_ecosystem_for_format("rust / cargo"),
			Some("crates.io")
		);
		assert_eq!(default_osv_ecosystem_for_format("docker"), None);
	}

	#[test]
	fn parses_trivy_json_output() {
		let target = artifact_target();
		let output = br#"{
			"Results": [{
				"Target": "artifact.tar",
				"Vulnerabilities": [{
					"VulnerabilityID": "CVE-2026-0001",
					"PkgName": "openssl",
					"InstalledVersion": "1.0.0",
					"Title": "openssl issue",
					"Description": "bad crypto",
					"Severity": "CRITICAL",
					"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-0001",
					"References": ["https://example.invalid/CVE-2026-0001"]
				}]
			}]
		}"#;

		let vulnerabilities = parse_trivy_output(&target, output).unwrap();

		assert_eq!(vulnerabilities.len(), 1);
		assert_eq!(vulnerabilities[0].id, "CVE-2026-0001");
		assert_eq!(vulnerabilities[0].severity, Some(Severity::Critical));
		assert_eq!(vulnerabilities[0].references.len(), 2);
	}

	#[test]
	fn parses_grype_json_output() {
		let target = artifact_target();
		let output = br#"{
			"matches": [{
				"vulnerability": {
					"id": "GHSA-0000",
					"severity": "High",
					"description": "bad library",
					"urls": ["https://github.com/advisories/GHSA-0000"],
					"aliases": [{"id": "CVE-2026-0002"}]
				},
				"relatedVulnerabilities": [{"id": "CVE-2026-0003"}],
				"artifact": {
					"name": "demo",
					"version": "1.0.0"
				}
			}]
		}"#;

		let vulnerabilities = parse_grype_output(&target, output).unwrap();

		assert_eq!(vulnerabilities.len(), 1);
		assert_eq!(vulnerabilities[0].id, "GHSA-0000");
		assert_eq!(vulnerabilities[0].severity, Some(Severity::High));
		assert!(
			vulnerabilities[0]
				.aliases
				.contains(&"CVE-2026-0002".to_owned())
		);
		assert!(
			vulnerabilities[0]
				.aliases
				.contains(&"CVE-2026-0003".to_owned())
		);
	}

	fn package_target() -> ScanTarget {
		ScanTarget::Package(PackageCoordinate::new("npm", "left-pad", "1.0.0"))
	}

	fn artifact_target() -> ScanTarget {
		ScanTarget::Artifact(ArtifactTarget::new("raw", "/artifact.tar"))
	}

	fn vulnerability<const N: usize>(
		id: &str,
		severity: Severity,
		aliases: [&str; N],
	) -> Vulnerability {
		Vulnerability {
			id: id.to_owned(),
			aliases: aliases.into_iter().map(str::to_owned).collect(),
			summary: None,
			details: None,
			severity: Some(severity),
			references: Vec::new(),
		}
	}
}
