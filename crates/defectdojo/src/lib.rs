use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nexus_sec_proxy_security::{Severity, TrustReport, Vulnerability};
use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;
use uuid::Uuid;

const SCAN_TYPE: &str = "Generic Findings Import";
const REPORT_TYPE: &str = "Nexus Security Proxy";

pub struct DefectDojoConfig {
	base_url: Url,
	token: String,
	engagement_id: NonZeroU64,
}

impl DefectDojoConfig {
	#[must_use]
	pub fn new(
		base_url: Url,
		token: impl Into<String>,
		engagement_id: NonZeroU64,
	) -> Self {
		Self {
			base_url,
			token: token.into(),
			engagement_id,
		}
	}
}

#[derive(Clone)]
pub struct DefectDojoClient {
	http_client: reqwest::Client,
	config: Arc<DefectDojoConfig>,
	status: Arc<DeliveryStatus>,
}

impl DefectDojoClient {
	#[must_use]
	pub fn new(config: DefectDojoConfig, http_client: reqwest::Client) -> Self {
		Self {
			http_client,
			config: Arc::new(config),
			status: Arc::new(DeliveryStatus::default()),
		}
	}

	pub async fn submit(
		&self,
		report: &TrustReport,
	) -> Result<CreatedReport, DefectDojoError> {
		self.status.submitted.fetch_add(1, Ordering::Relaxed);
		let result = self.submit_inner(report).await;

		match &result {
			Ok(created) => {
				self.status.record_success();
				let status = self.status();
				tracing::info!(
					defectdojo_available = true,
					defectdojo_enabled = true,
					submitted = status.submitted,
					failed = status.failed,
					last_success_at = ?status.last_success_at,
					last_failure_at = ?status.last_failure_at,
					last_failure_category = ?status.last_failure_category,
					report_url = %created.url,
					"DefectDojo report created"
				);
			}
			Err(error) => {
				self.status.record_failure(error.category());
				let status = self.status();
				tracing::warn!(
					defectdojo_available = true,
					defectdojo_enabled = true,
					submitted = status.submitted,
					failed = status.failed,
					last_success_at = ?status.last_success_at,
					last_failure_at = ?status.last_failure_at,
					last_failure_category = ?status.last_failure_category,
					%error,
					"DefectDojo report creation failed"
				);
			}
		}
		result
	}

	#[must_use]
	pub fn status(&self) -> DefectDojoStatus {
		let last = self
			.status
			.last
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);

		DefectDojoStatus {
			submitted: self.status.submitted.load(Ordering::Relaxed),
			failed: self.status.failed.load(Ordering::Relaxed),
			last_success_at: last.last_success_at.clone(),
			last_failure_at: last.last_failure_at.clone(),
			last_failure_category: last.last_failure_category.clone(),
		}
	}

	async fn submit_inner(
		&self,
		report: &TrustReport,
	) -> Result<CreatedReport, DefectDojoError> {
		let bytes = serde_json::to_vec(&GenericReport::from(report))
			.map_err(DefectDojoError::Serialize)?;
		let file = Part::bytes(bytes)
			.file_name("nexus-sec-proxy.json")
			.mime_str("application/json")
			.map_err(DefectDojoError::Multipart)?;
		let form = Form::new()
			.text("scan_type", SCAN_TYPE)
			.text("engagement", self.config.engagement_id.to_string())
			.text("background_import", "false")
			.text("minimum_severity", "Info")
			.text("active", "true")
			.text("verified", "true")
			.text("skip_duplicates", "false")
			.text(
				"test_title",
				format!("Nexus Security Proxy block {}", report.id),
			)
			.part("file", file);
		let response = self
			.http_client
			.post(url_with_path(&self.config.base_url, "api/v2/import-scan/"))
			.header(
				reqwest::header::AUTHORIZATION,
				format!("Token {}", self.config.token),
			)
			.multipart(form)
			.send()
			.await
			.map_err(DefectDojoError::Request)?;
		let status = response.status();

		if !status.is_success() {
			let body = response.text().await.unwrap_or_default();
			return Err(DefectDojoError::Rejected {
				status,
				body: body.chars().take(4096).collect(),
			});
		}

		let response = response
			.json::<ImportResponse>()
			.await
			.map_err(DefectDojoError::InvalidResponse)?;
		let test_id = response
			.test_id
			.or(response.test)
			.filter(|test_id| *test_id > 0)
			.ok_or(DefectDojoError::MissingTestId)?;

		Ok(CreatedReport {
			url: url_with_path(
				&self.config.base_url,
				&format!("test/{test_id}"),
			)
			.to_string(),
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedReport {
	pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefectDojoStatus {
	pub submitted: u64,
	pub failed: u64,
	pub last_success_at: Option<String>,
	pub last_failure_at: Option<String>,
	pub last_failure_category: Option<String>,
}

#[derive(Debug, Error)]
pub enum DefectDojoError {
	#[error("failed to serialize Generic Findings report: {0}")]
	Serialize(serde_json::Error),
	#[error("failed to build multipart report: {0}")]
	Multipart(reqwest::Error),
	#[error("DefectDojo request failed: {0}")]
	Request(reqwest::Error),
	#[error("DefectDojo rejected the report with {status}: {body}")]
	Rejected {
		status: reqwest::StatusCode,
		body: String,
	},
	#[error("DefectDojo returned malformed JSON: {0}")]
	InvalidResponse(reqwest::Error),
	#[error("DefectDojo response did not identify the created Test")]
	MissingTestId,
}

impl DefectDojoError {
	fn category(&self) -> &'static str {
		match self {
			Self::Serialize(_) | Self::Multipart(_) => "report_encoding",
			Self::Request(error) if error.is_timeout() => "timeout",
			Self::Request(_) => "transport",
			Self::Rejected { .. } => "rejected",
			Self::InvalidResponse(_) | Self::MissingTestId => {
				"invalid_response"
			}
		}
	}
}

#[derive(Debug, Default)]
struct DeliveryStatus {
	submitted: AtomicU64,
	failed: AtomicU64,
	last: Mutex<LastDelivery>,
}

impl DeliveryStatus {
	fn record_success(&self) {
		let mut last = self
			.last
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		last.last_success_at = Some(now_rfc3339());
	}

	fn record_failure(&self, category: &str) {
		self.failed.fetch_add(1, Ordering::Relaxed);
		let mut last = self
			.last
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		last.last_failure_at = Some(now_rfc3339());
		last.last_failure_category = Some(category.to_owned());
	}
}

#[derive(Debug, Default)]
struct LastDelivery {
	last_success_at: Option<String>,
	last_failure_at: Option<String>,
	last_failure_category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportResponse {
	test_id: Option<u64>,
	test: Option<u64>,
}

#[derive(Debug, Serialize)]
struct GenericReport {
	name: String,
	#[serde(rename = "type")]
	kind: &'static str,
	findings: Vec<GenericFinding>,
}

impl From<&TrustReport> for GenericReport {
	fn from(report: &TrustReport) -> Self {
		let findings = if report.block.vulnerabilities.is_empty() {
			vec![GenericFinding::policy(report)]
		} else {
			report
				.block
				.vulnerabilities
				.iter()
				.map(|vulnerability| {
					GenericFinding::vulnerability(report, vulnerability)
				})
				.collect()
		};

		Self {
			name: format!("Nexus Security Proxy block {}", report.id),
			kind: REPORT_TYPE,
			findings,
		}
	}
}

#[derive(Debug, Serialize)]
struct GenericFinding {
	title: String,
	severity: &'static str,
	description: String,
	vuln_id_from_tool: String,
	unique_id_from_tool: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	cve: Option<String>,
	#[serde(skip_serializing_if = "String::is_empty")]
	references: String,
	component_name: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	component_version: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	mitigation: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	fix_available: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none")]
	fix_version: Option<String>,
	tags: Vec<String>,
}

impl GenericFinding {
	fn vulnerability(
		report: &TrustReport,
		vulnerability: &Vulnerability,
	) -> Self {
		let target = report.block.target.display_name();
		let cve = vulnerability.identifiers().find_map(normalized_cve);
		let references = references(vulnerability, cve.as_deref());
		let mitigation = vulnerability.mitigation(&target);
		let component_version = vulnerability
			.component_version
			.clone()
			.or_else(|| report.block.target.cache_version().map(str::to_owned));

		Self {
			title: format!("{} in {target}", vulnerability.id),
			severity: defectdojo_severity(vulnerability.severity),
			description: description(report, vulnerability),
			vuln_id_from_tool: vulnerability.id.clone(),
			unique_id_from_tool: vulnerability_identity(report, vulnerability),
			cve,
			references,
			component_name: vulnerability
				.component_name
				.clone()
				.unwrap_or(target),
			component_version,
			mitigation,
			fix_available: (!vulnerability.fixed_versions.is_empty())
				.then_some(true),
			fix_version: (!vulnerability.fixed_versions.is_empty())
				.then(|| vulnerability.fixed_versions.join(", ")),
			tags: report_tags(report),
		}
	}

	fn policy(report: &TrustReport) -> Self {
		let target = report.block.target.display_name();
		Self {
			title: format!("Policy block: {target}"),
			severity: "Info",
			description: report_context(report),
			vuln_id_from_tool: "NEXUS-SEC-PROXY-POLICY".to_owned(),
			unique_id_from_tool: Uuid::new_v5(
				&Uuid::NAMESPACE_URL,
				format!("nexus-sec-proxy\0policy\0{}", report.id).as_bytes(),
			)
			.to_string(),
			cve: None,
			references: String::new(),
			component_name: target,
			component_version: None,
			mitigation: None,
			fix_available: None,
			fix_version: None,
			tags: report_tags(report),
		}
	}
}

fn description(report: &TrustReport, vulnerability: &Vulnerability) -> String {
	let mut value = String::new();
	if let Some(summary) = vulnerability.summary.as_deref() {
		value.push_str(summary);
		value.push_str("\n\n");
	}
	if let Some(details) = vulnerability.details.as_deref() {
		value.push_str(details);
		value.push_str("\n\n");
	}
	value.push_str(&report_context(report));
	value
}

fn report_context(report: &TrustReport) -> String {
	let violations = if report.block.policy_violations.is_empty() {
		"Unavailable".to_owned()
	} else {
		report
			.block
			.policy_violations
			.iter()
			.map(|violation| format!("- {}", violation.reason))
			.collect::<Vec<_>>()
			.join("\n")
	};
	format!(
		"Reason: {}\nRepository: {}\nArtifact format: {}\nTarget: {}\nTeam: {}\nPolicy: {}\nRequester: {}\nBlocked at: {}\nReport UUID: {}\nSeverity counts: critical={}, high={}, medium={}, low={}, unknown={}\nPolicy violations:\n{}",
		report.block.reason,
		report.context.repository,
		report.context.format,
		report.block.target.display_name(),
		report.context.team.as_deref().unwrap_or("Unavailable"),
		report
			.block
			.policy_id
			.as_deref()
			.unwrap_or("Unsupported target policy"),
		report.requester.as_deref().unwrap_or("Unavailable"),
		report.created_at,
		report.id,
		report.severity_counts.critical,
		report.severity_counts.high,
		report.severity_counts.medium,
		report.severity_counts.low,
		report.severity_counts.unknown,
		violations
	)
}

fn vulnerability_identity(
	report: &TrustReport,
	vulnerability: &Vulnerability,
) -> String {
	let target = &report.block.target;
	let identity = format!(
		"nexus-sec-proxy\0{}\0{}\0{}\0{}\0{}",
		report.context.repository,
		target.cache_namespace(),
		target.cache_identifier(),
		target.cache_version().unwrap_or_default(),
		vulnerability.id
	);
	Uuid::new_v5(&Uuid::NAMESPACE_URL, identity.as_bytes()).to_string()
}

fn normalized_cve(value: &str) -> Option<String> {
	let value = value.trim().to_ascii_uppercase();
	let mut parts = value.split('-');
	let valid = parts.next() == Some("CVE")
		&& parts.next().is_some_and(|year| {
			year.len() == 4 && year.chars().all(|value| value.is_ascii_digit())
		}) && parts.next().is_some_and(|id| {
		id.len() >= 4 && id.chars().all(|value| value.is_ascii_digit())
	}) && parts.next().is_none();
	valid.then_some(value)
}

fn references(vulnerability: &Vulnerability, cve: Option<&str>) -> String {
	let mut references = vulnerability
		.references
		.iter()
		.map(|reference| reference.url.clone())
		.collect::<Vec<_>>();
	if let Some(cve) = cve {
		let cve_reference = format!("https://nvd.nist.gov/vuln/detail/{cve}");
		if !references
			.iter()
			.any(|reference| reference == &cve_reference)
		{
			references.push(cve_reference);
		}
	}
	references.join("\n")
}

fn report_tags(report: &TrustReport) -> Vec<String> {
	let mut tags = vec![
		format!("repository:{}", report.context.repository),
		format!("format:{}", report.context.format),
		format!("report:{}", report.id),
	];
	if let Some(team) = report.context.team.as_deref() {
		tags.push(format!("team:{team}"));
	}
	if let Some(policy) = report.block.policy_id.as_deref() {
		tags.push(format!("policy:{policy}"));
	}
	tags
}

fn defectdojo_severity(severity: Option<Severity>) -> &'static str {
	match severity {
		Some(Severity::Critical) => "Critical",
		Some(Severity::High) => "High",
		Some(Severity::Medium) => "Medium",
		Some(Severity::Low) => "Low",
		None => "Info",
	}
}

fn url_with_path(base_url: &Url, path: &str) -> Url {
	let mut url = base_url.clone();
	url.set_path(&format!(
		"{}/{}",
		base_url.path().trim_end_matches('/'),
		path.trim_start_matches('/')
	));
	url.set_query(None);
	url.set_fragment(None);
	url
}

fn now_rfc3339() -> String {
	let now = OffsetDateTime::now_utc();
	now.format(&Rfc3339)
		.unwrap_or_else(|_| now.unix_timestamp().to_string())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
