use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::normalize::normalize_match_value;
use crate::{ScanTarget, Severity, Vulnerability};

use super::{
	BlockReport, EnforcementMode, PolicyContext, PolicyEvaluation,
	PolicyException, PolicyExceptionMetadata, PolicyOutcome, PolicySet,
	PolicyViolation, ScanDecision, SecurityPolicy, VulnerabilityEvaluator,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluator {
	policy_set: PolicySet,
}

impl PolicyEvaluator {
	#[must_use]
	pub fn new(policy: SecurityPolicy) -> Self {
		Self::from_policy_set(PolicySet::from_legacy_policy(policy))
	}

	#[must_use]
	pub fn from_policy_set(policy_set: PolicySet) -> Self {
		Self { policy_set }
	}

	#[must_use]
	pub fn policy(&self) -> &SecurityPolicy {
		&self.policy_set.default_policy.policy
	}

	#[must_use]
	pub fn policy_set(&self) -> &PolicySet {
		&self.policy_set
	}

	#[must_use]
	pub fn evaluate_with_context(
		&self,
		context: &PolicyContext,
		target: &ScanTarget,
		vulnerabilities: Vec<Vulnerability>,
	) -> PolicyEvaluation {
		self.evaluate_at(
			context,
			target,
			vulnerabilities,
			OffsetDateTime::now_utc(),
		)
	}

	#[must_use]
	pub fn evaluate_at(
		&self,
		context: &PolicyContext,
		target: &ScanTarget,
		vulnerabilities: Vec<Vulnerability>,
		now: OffsetDateTime,
	) -> PolicyEvaluation {
		let rule = self.policy_set.select_policy(context);
		let mut applied_exceptions = BTreeMap::new();
		let mut expired_exceptions = BTreeMap::new();
		let evaluated_vulnerabilities = vulnerabilities
			.into_iter()
			.filter(|vulnerability| {
				let exception_applies = matching_exception_applies(
					&self.policy_set.exceptions,
					context,
					target,
					vulnerability,
					now,
					&mut applied_exceptions,
					&mut expired_exceptions,
				);

				!exception_applies
					&& !rule.policy.allows_vulnerability(vulnerability)
			})
			.collect::<Vec<_>>();
		let violations =
			policy_violations(&rule.policy, &evaluated_vulnerabilities);
		let applied_exceptions =
			applied_exceptions.into_values().collect::<Vec<_>>();
		let expired_exceptions =
			expired_exceptions.into_values().collect::<Vec<_>>();

		let outcome = if violations.is_empty() {
			PolicyOutcome::Allowed
		} else {
			let report = BlockReport {
				target: target.clone(),
				reason: "vulnerability policy was violated".to_owned(),
				policy_id: Some(rule.id.clone()),
				policy_violations: violations,
				vulnerabilities: evaluated_vulnerabilities,
			};

			match rule.mode {
				EnforcementMode::Enforce => PolicyOutcome::Blocked(report),
				EnforcementMode::ReportOnly => {
					PolicyOutcome::ReportOnly(report)
				}
			}
		};

		PolicyEvaluation {
			outcome,
			policy_id: rule.id.clone(),
			mode: rule.mode,
			applied_exceptions,
			expired_exceptions,
		}
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
		let context = PolicyContext::new(
			"default",
			target.cache_namespace(),
			None::<String>,
		);

		match self
			.evaluate_with_context(&context, target, vulnerabilities)
			.outcome
		{
			PolicyOutcome::Allowed | PolicyOutcome::ReportOnly(_) => {
				ScanDecision::Allowed
			}
			PolicyOutcome::Blocked(report) => ScanDecision::Blocked(report),
		}
	}
}

fn matching_exception_applies(
	exceptions: &[PolicyException],
	context: &PolicyContext,
	target: &ScanTarget,
	vulnerability: &Vulnerability,
	now: OffsetDateTime,
	applied_exceptions: &mut BTreeMap<String, PolicyExceptionMetadata>,
	expired_exceptions: &mut BTreeMap<String, PolicyExceptionMetadata>,
) -> bool {
	let mut active_match = false;

	for exception in exceptions {
		if !exception.scope.matches(context, target)
			|| !exception.matches_vulnerability(vulnerability)
		{
			continue;
		}

		let key = normalize_match_value(&exception.id)
			.unwrap_or_else(|| exception.id.clone());
		if exception.is_active_at(now) {
			active_match = true;
			applied_exceptions.entry(key).or_insert_with(|| {
				PolicyExceptionMetadata::from_exception(exception)
			});
		} else {
			expired_exceptions.entry(key).or_insert_with(|| {
				PolicyExceptionMetadata::from_exception(exception)
			});
		}
	}

	active_match
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
