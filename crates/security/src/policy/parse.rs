use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::Severity;
use crate::normalize::{normalize_match_value, normalize_vulnerability_id};

use super::model::{
	EnforcementMode, PolicyException, PolicyExceptionScope, PolicyRule,
	PolicyScope, PolicySet, PolicySetError, RepositoryPolicy, SecurityPolicy,
	VulnerabilityLimits,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicySet {
	default_policy: RawPolicyRule,
	#[serde(default)]
	repositories: BTreeMap<String, RawRepositoryPolicy>,
	#[serde(default)]
	policies: Vec<RawPolicyRule>,
	#[serde(default)]
	exceptions: Vec<RawPolicyException>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepositoryPolicy {
	team: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyRule {
	id: Option<String>,
	#[serde(default)]
	mode: EnforcementMode,
	#[serde(default = "default_minimum_blocking_severity")]
	minimum_blocking_severity: Severity,
	#[serde(default)]
	allowed_vulnerability_ids: Vec<String>,
	max_total_vulnerabilities: Option<u32>,
	max_low_vulnerabilities: Option<u32>,
	max_medium_vulnerabilities: Option<u32>,
	max_high_vulnerabilities: Option<u32>,
	max_critical_vulnerabilities: Option<u32>,
	#[serde(default)]
	repositories: Vec<String>,
	#[serde(default)]
	formats: Vec<String>,
	#[serde(default)]
	teams: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyException {
	id: String,
	owner: String,
	ticket: String,
	reason: String,
	expires_at: String,
	vulnerability_ids: Vec<String>,
	#[serde(default)]
	repositories: Vec<String>,
	#[serde(default)]
	formats: Vec<String>,
	#[serde(default)]
	teams: Vec<String>,
	#[serde(default)]
	packages: Vec<String>,
	#[serde(default)]
	versions: Vec<String>,
}

impl PolicySet {
	pub fn from_toml_str(input: &str) -> Result<Self, PolicySetError> {
		let raw = toml::from_str::<RawPolicySet>(input)?;
		Self::from_raw(raw)
	}
	fn from_raw(raw: RawPolicySet) -> Result<Self, PolicySetError> {
		let default_policy = raw_policy_rule_to_policy_rule(
			raw.default_policy,
			Some("default"),
			0,
		)?;
		let mut policies = Vec::with_capacity(raw.policies.len());

		for (index, raw_policy) in raw.policies.into_iter().enumerate() {
			policies
				.push(raw_policy_rule_to_policy_rule(raw_policy, None, index)?);
		}

		let repositories = raw
			.repositories
			.into_iter()
			.map(|(name, repository)| {
				Ok((
					trim_required(name, "repository", "name")?,
					RepositoryPolicy {
						team: trim_required(
							repository.team,
							"repository",
							"team",
						)?,
					},
				))
			})
			.collect::<Result<BTreeMap<_, _>, PolicySetError>>()?;

		let exceptions = raw
			.exceptions
			.into_iter()
			.map(raw_exception_to_exception)
			.collect::<Result<Vec<_>, _>>()?;

		validate_unique_ids(&default_policy, &policies, &exceptions)?;

		Ok(Self {
			default_policy,
			repositories,
			policies,
			exceptions,
		})
	}
}

fn raw_policy_rule_to_policy_rule(
	raw: RawPolicyRule,
	default_id: Option<&str>,
	index: usize,
) -> Result<PolicyRule, PolicySetError> {
	let id = match (raw.id, default_id) {
		(Some(id), _) => trim_required(id, "policy", "id")?,
		(None, Some(default_id)) => default_id.to_owned(),
		(None, None) => return Err(PolicySetError::MissingPolicyId { index }),
	};
	let limits = VulnerabilityLimits {
		total: raw.max_total_vulnerabilities,
		low: raw.max_low_vulnerabilities,
		medium: raw.max_medium_vulnerabilities,
		high: raw.max_high_vulnerabilities,
		critical: raw.max_critical_vulnerabilities,
	};
	let policy = SecurityPolicy::new(
		raw.minimum_blocking_severity,
		raw.allowed_vulnerability_ids,
		limits,
	);

	Ok(PolicyRule::new(
		id,
		raw.mode,
		PolicyScope::new(raw.repositories, raw.formats, raw.teams),
		policy,
	))
}

fn raw_exception_to_exception(
	raw: RawPolicyException,
) -> Result<PolicyException, PolicySetError> {
	let id = trim_required(raw.id, "exception", "id")?;
	let expires_at = trim_required(raw.expires_at, "exception", "expires_at")?;
	let expires_at =
		OffsetDateTime::parse(&expires_at, &Rfc3339).map_err(|source| {
			PolicySetError::InvalidExceptionExpiry {
				id: id.clone(),
				expires_at: expires_at.clone(),
				source,
			}
		})?;
	let vulnerability_ids = raw
		.vulnerability_ids
		.into_iter()
		.filter_map(|id| normalize_vulnerability_id(&id))
		.collect::<BTreeSet<_>>();

	if vulnerability_ids.is_empty() {
		return Err(PolicySetError::EmptyExceptionVulnerabilityIds { id });
	}

	Ok(PolicyException {
		id,
		owner: trim_required(raw.owner, "exception", "owner")?,
		ticket: trim_required(raw.ticket, "exception", "ticket")?,
		reason: trim_required(raw.reason, "exception", "reason")?,
		expires_at,
		vulnerability_ids,
		scope: PolicyExceptionScope::new(
			raw.repositories,
			raw.formats,
			raw.teams,
			raw.packages,
			raw.versions,
		),
	})
}

fn validate_unique_ids(
	default_policy: &PolicyRule,
	policies: &[PolicyRule],
	exceptions: &[PolicyException],
) -> Result<(), PolicySetError> {
	let mut policy_ids = BTreeSet::new();
	insert_policy_id(&mut policy_ids, &default_policy.id)?;

	for policy in policies {
		insert_policy_id(&mut policy_ids, &policy.id)?;
	}

	let mut exception_ids = BTreeSet::new();
	for exception in exceptions {
		let id = normalize_match_value(&exception.id).ok_or(
			PolicySetError::EmptyField {
				entity: "exception",
				field: "id",
			},
		)?;
		if !exception_ids.insert(id) {
			return Err(PolicySetError::DuplicateExceptionId {
				id: exception.id.clone(),
			});
		}
	}

	Ok(())
}

fn insert_policy_id(
	policy_ids: &mut BTreeSet<String>,
	id: &str,
) -> Result<(), PolicySetError> {
	let normalized_id =
		normalize_match_value(id).ok_or(PolicySetError::EmptyField {
			entity: "policy",
			field: "id",
		})?;

	if !policy_ids.insert(normalized_id) {
		return Err(PolicySetError::DuplicatePolicyId { id: id.to_owned() });
	}

	Ok(())
}

fn default_minimum_blocking_severity() -> Severity {
	Severity::High
}

fn trim_required(
	value: String,
	entity: &'static str,
	field: &'static str,
) -> Result<String, PolicySetError> {
	let trimmed = value.trim();

	if trimmed.is_empty() {
		Err(PolicySetError::EmptyField { entity, field })
	} else {
		Ok(trimmed.to_owned())
	}
}
