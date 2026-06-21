use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::normalize::{
	matches_case_insensitive_selector, normalize_context_value,
	normalize_match_value, normalize_vulnerability_id,
	normalized_selector_list,
};
use crate::{PackageIdentity, ScanTarget, Severity, Vulnerability};

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

#[derive(Debug, Error)]
pub enum PolicySetError {
	#[error("invalid policy file TOML: {0}")]
	Parse(#[from] toml::de::Error),
	#[error("policy id is required for [[policies]] entry at index {index}")]
	MissingPolicyId { index: usize },
	#[error("{entity} field {field} must not be empty")]
	EmptyField {
		entity: &'static str,
		field: &'static str,
	},
	#[error("duplicate policy id: {id}")]
	DuplicatePolicyId { id: String },
	#[error("duplicate exception id: {id}")]
	DuplicateExceptionId { id: String },
	#[error("invalid expires_at for exception {id}: {expires_at}")]
	InvalidExceptionExpiry {
		id: String,
		expires_at: String,
		#[source]
		source: time::error::Parse,
	},
	#[error("exception {id} must list at least one vulnerability id")]
	EmptyExceptionVulnerabilityIds { id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[cfg_attr(feature = "policy-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
	#[default]
	Enforce,
	ReportOnly,
}

impl EnforcementMode {
	#[must_use]
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Enforce => "enforce",
			Self::ReportOnly => "report_only",
		}
	}
}

impl fmt::Display for EnforcementMode {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(self.as_str())
	}
}

impl FromStr for EnforcementMode {
	type Err = ();

	fn from_str(input: &str) -> Result<Self, Self::Err> {
		match input.trim().to_ascii_lowercase().as_str() {
			"enforce" | "enforced" | "block" | "blocking" => Ok(Self::Enforce),
			"report_only" | "report-only" | "reportonly" | "audit" => {
				Ok(Self::ReportOnly)
			}
			_ => Err(()),
		}
	}
}

impl<'de> Deserialize<'de> for EnforcementMode {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct EnforcementModeVisitor;

		impl<'de> Visitor<'de> for EnforcementModeVisitor {
			type Value = EnforcementMode;

			fn expecting(
				&self,
				formatter: &mut fmt::Formatter<'_>,
			) -> fmt::Result {
				formatter.write_str("enforce or report_only")
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				value.parse().map_err(|()| {
					E::custom(format!("invalid enforcement mode: {value}"))
				})
			}
		}

		deserializer.deserialize_str(EnforcementModeVisitor)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PolicyScope {
	#[serde(default)]
	pub repositories: Vec<String>,
	#[serde(default)]
	pub formats: Vec<String>,
	#[serde(default)]
	pub teams: Vec<String>,
}

impl PolicyScope {
	#[must_use]
	pub fn new(
		repositories: Vec<String>,
		formats: Vec<String>,
		teams: Vec<String>,
	) -> Self {
		Self {
			repositories: normalized_selector_list(repositories),
			formats: normalized_selector_list(formats),
			teams: normalized_selector_list(teams),
		}
	}

	#[must_use]
	pub fn matches(&self, context: &PolicyContext) -> bool {
		matches_case_insensitive_selector(
			&self.repositories,
			Some(&context.repository),
		) && matches_case_insensitive_selector(
			&self.formats,
			Some(&context.format),
		) && matches_case_insensitive_selector(
			&self.teams,
			context.team.as_deref(),
		)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRule {
	pub id: String,
	pub mode: EnforcementMode,
	pub scope: PolicyScope,
	pub policy: SecurityPolicy,
}

impl PolicyRule {
	#[must_use]
	pub fn new(
		id: impl Into<String>,
		mode: EnforcementMode,
		scope: PolicyScope,
		policy: SecurityPolicy,
	) -> Self {
		Self {
			id: id.into(),
			mode,
			scope,
			policy,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepositoryPolicy {
	pub team: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyExceptionScope {
	pub repositories: Vec<String>,
	pub formats: Vec<String>,
	pub teams: Vec<String>,
	pub packages: Vec<String>,
	pub versions: Vec<String>,
}

impl PolicyExceptionScope {
	#[must_use]
	pub fn new(
		repositories: Vec<String>,
		formats: Vec<String>,
		teams: Vec<String>,
		packages: Vec<String>,
		versions: Vec<String>,
	) -> Self {
		Self {
			repositories: normalized_selector_list(repositories),
			formats: normalized_selector_list(formats),
			teams: normalized_selector_list(teams),
			packages: normalized_selector_list(packages),
			versions: normalized_selector_list(versions),
		}
	}

	#[must_use]
	pub fn matches(
		&self,
		context: &PolicyContext,
		target: &ScanTarget,
	) -> bool {
		matches_case_insensitive_selector(
			&self.repositories,
			Some(&context.repository),
		) && matches_case_insensitive_selector(
			&self.formats,
			Some(&context.format),
		) && matches_case_insensitive_selector(
			&self.teams,
			context.team.as_deref(),
		) && matches_case_insensitive_selector(
			&self.packages,
			Some(&target_policy_package_name(target)),
		) && matches_case_insensitive_selector(
			&self.versions,
			target.cache_version(),
		)
	}
}

fn target_policy_package_name(target: &ScanTarget) -> String {
	match target {
		ScanTarget::Package(package) => match &package.identity {
			PackageIdentity::Osv { name, .. } => name.clone(),
			PackageIdentity::Purl { purl } => purl.clone(),
			PackageIdentity::GitCommit { commit } => commit.clone(),
		},
		ScanTarget::Artifact(artifact) => artifact
			.digest
			.clone()
			.unwrap_or_else(|| artifact.uri.clone()),
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyException {
	pub id: String,
	pub owner: String,
	pub ticket: String,
	pub reason: String,
	pub expires_at: OffsetDateTime,
	pub vulnerability_ids: BTreeSet<String>,
	pub scope: PolicyExceptionScope,
}

impl PolicyException {
	#[must_use]
	pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
		now < self.expires_at
	}

	#[must_use]
	pub fn matches_vulnerability(&self, vulnerability: &Vulnerability) -> bool {
		vulnerability.identifiers().any(|id| {
			normalize_vulnerability_id(id).is_some_and(|normalized_id| {
				self.vulnerability_ids.contains(&normalized_id)
			})
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyExceptionMetadata {
	pub id: String,
	pub owner: String,
	pub ticket: String,
	pub reason: String,
	pub expires_at: String,
	pub vulnerability_ids: Vec<String>,
}

impl PolicyExceptionMetadata {
	pub(super) fn from_exception(exception: &PolicyException) -> Self {
		Self {
			id: exception.id.clone(),
			owner: exception.owner.clone(),
			ticket: exception.ticket.clone(),
			reason: exception.reason.clone(),
			expires_at: format_rfc3339(exception.expires_at),
			vulnerability_ids: exception
				.vulnerability_ids
				.iter()
				.cloned()
				.collect(),
		}
	}
}

fn format_rfc3339(value: OffsetDateTime) -> String {
	value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySet {
	pub default_policy: PolicyRule,
	pub repositories: BTreeMap<String, RepositoryPolicy>,
	pub policies: Vec<PolicyRule>,
	pub exceptions: Vec<PolicyException>,
}

impl PolicySet {
	#[must_use]
	pub fn from_legacy_policy(policy: SecurityPolicy) -> Self {
		Self {
			default_policy: PolicyRule::new(
				"default",
				EnforcementMode::Enforce,
				PolicyScope::default(),
				policy,
			),
			repositories: BTreeMap::new(),
			policies: Vec::new(),
			exceptions: Vec::new(),
		}
	}

	#[must_use]
	pub fn context(
		&self,
		repository: impl Into<String>,
		format: impl Into<String>,
	) -> PolicyContext {
		let repository = repository.into();
		let team = self.team_for_repository(&repository).map(str::to_owned);

		PolicyContext::new(repository, format, team)
	}

	#[must_use]
	pub fn team_for_repository(&self, repository: &str) -> Option<&str> {
		let normalized_repository = normalize_match_value(repository)?;

		self.repositories
			.iter()
			.find(|(candidate, _)| {
				normalize_match_value(candidate).as_ref()
					== Some(&normalized_repository)
			})
			.map(|(_, repository)| repository.team.as_str())
	}

	#[must_use]
	pub fn select_policy(&self, context: &PolicyContext) -> &PolicyRule {
		self.policies
			.iter()
			.find(|policy| policy.scope.matches(context))
			.unwrap_or(&self.default_policy)
	}
}

impl Default for PolicySet {
	fn default() -> Self {
		Self::from_legacy_policy(SecurityPolicy::default())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
	pub repository: String,
	pub format: String,
	pub team: Option<String>,
}

impl PolicyContext {
	#[must_use]
	pub fn new(
		repository: impl Into<String>,
		format: impl Into<String>,
		team: Option<impl Into<String>>,
	) -> Self {
		Self {
			repository: normalize_context_value(repository, "default"),
			format: normalize_context_value(format, "generic"),
			team: team.and_then(|team| normalize_match_value(&team.into())),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyEvaluation {
	pub outcome: PolicyOutcome,
	pub policy_id: String,
	pub mode: EnforcementMode,
	pub applied_exceptions: Vec<PolicyExceptionMetadata>,
	pub expired_exceptions: Vec<PolicyExceptionMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PolicyOutcome {
	Allowed,
	ReportOnly(BlockReport),
	Blocked(BlockReport),
}

impl PolicyEvaluation {
	#[must_use]
	pub fn is_blocked(&self) -> bool {
		matches!(self.outcome, PolicyOutcome::Blocked(_))
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
	pub policy_id: Option<String>,
	pub policy_violations: Vec<PolicyViolation>,
	pub vulnerabilities: Vec<Vulnerability>,
}

impl BlockReport {
	#[must_use]
	pub fn unsupported(target: ScanTarget, reason: impl Into<String>) -> Self {
		Self {
			target,
			reason: reason.into(),
			policy_id: None,
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

		if let Some(policy_id) = self.policy_id.as_deref() {
			body.push_str("Policy: ");
			body.push_str(policy_id);
			body.push('\n');
		}

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
