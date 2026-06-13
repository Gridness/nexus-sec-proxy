use nexus_sec_proxy_security::{
	BlockReport, PolicyContext, PolicyEvaluation, PolicyOutcome, ScanTarget,
};
use tracing::{info, warn};

pub(crate) fn audit_policy_evaluation(
	context: &PolicyContext,
	target: &ScanTarget,
	evaluation: &PolicyEvaluation,
) {
	let target_display = target.display_name();
	let team = context.team.as_deref().unwrap_or("");

	for exception in &evaluation.applied_exceptions {
		info!(
			repository = %context.repository,
			format = %context.format,
			team = %team,
			policy_id = %evaluation.policy_id,
			mode = %evaluation.mode,
			target = %target_display,
			vulnerability_ids = ?exception.vulnerability_ids,
			exception_id = %exception.id,
			exception_owner = %exception.owner,
			exception_ticket = %exception.ticket,
			exception_reason = %exception.reason,
			exception_expires_at = %exception.expires_at,
			"policy_exception_applied"
		);
	}

	for exception in &evaluation.expired_exceptions {
		warn!(
			repository = %context.repository,
			format = %context.format,
			team = %team,
			policy_id = %evaluation.policy_id,
			mode = %evaluation.mode,
			target = %target_display,
			vulnerability_ids = ?exception.vulnerability_ids,
			exception_id = %exception.id,
			exception_owner = %exception.owner,
			exception_ticket = %exception.ticket,
			exception_reason = %exception.reason,
			exception_expires_at = %exception.expires_at,
			"policy_exception_expired_match"
		);
	}

	match &evaluation.outcome {
		PolicyOutcome::Allowed => {}
		PolicyOutcome::ReportOnly(report) => {
			warn!(
				repository = %context.repository,
				format = %context.format,
				team = %team,
				policy_id = %evaluation.policy_id,
				mode = %evaluation.mode,
				target = %target_display,
				vulnerability_ids = ?vulnerability_ids(report),
				applied_exceptions = ?evaluation.applied_exceptions,
				expired_exceptions = ?evaluation.expired_exceptions,
				"policy_report_only_violation"
			);
		}
		PolicyOutcome::Blocked(report) => {
			warn!(
				repository = %context.repository,
				format = %context.format,
				team = %team,
				policy_id = %evaluation.policy_id,
				mode = %evaluation.mode,
				target = %target_display,
				vulnerability_ids = ?vulnerability_ids(report),
				applied_exceptions = ?evaluation.applied_exceptions,
				expired_exceptions = ?evaluation.expired_exceptions,
				"policy_blocked"
			);
		}
	}
}

pub(crate) fn vulnerability_ids(report: &BlockReport) -> Vec<String> {
	report
		.vulnerabilities
		.iter()
		.map(|vulnerability| vulnerability.id.clone())
		.collect()
}
