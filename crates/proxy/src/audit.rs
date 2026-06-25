use nexus_sec_proxy_security::{
	BlockReport, PolicyContext, PolicyEvaluation, PolicyOutcome, ScanTarget,
};
use tracing::{info, warn};

pub(crate) fn audit_policy_evaluation(
	context: &PolicyContext,
	target: &ScanTarget,
	evaluation: &PolicyEvaluation,
	report_url: Option<&str>,
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
			let report_url = report_url.unwrap_or("");
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
				report_url = %report_url,
				"policy_blocked"
			);
		}
	}
}

pub(crate) fn audit_unsupported_block(
	context: &PolicyContext,
	report: &BlockReport,
	report_url: &str,
) {
	warn!(
		repository = %context.repository,
		format = %context.format,
		team = %context.team.as_deref().unwrap_or(""),
		policy_id = "",
		mode = "enforce",
		target = %report.target.display_name(),
		vulnerability_ids = ?vulnerability_ids(report),
		report_url = %report_url,
		reason = %report.reason,
		"policy_blocked"
	);
}

pub(crate) fn vulnerability_ids(report: &BlockReport) -> Vec<String> {
	report
		.vulnerabilities
		.iter()
		.map(|vulnerability| vulnerability.id.clone())
		.collect()
}

#[cfg(test)]
mod tests {
	use std::io::{self, Write};
	use std::sync::{Arc, Mutex};

	use nexus_sec_proxy_security::{
		PackageCoordinate, PolicyEvaluator, ScanTarget, Severity, Vulnerability,
	};
	use tracing_subscriber::fmt;

	use super::*;

	#[derive(Clone, Default)]
	struct Buffer(Arc<Mutex<Vec<u8>>>);

	struct BufferWriter(Arc<Mutex<Vec<u8>>>);

	impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
		type Writer = BufferWriter;

		fn make_writer(&'a self) -> Self::Writer {
			BufferWriter(Arc::clone(&self.0))
		}
	}

	impl Write for BufferWriter {
		fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
			self.0.lock().unwrap().extend_from_slice(bytes);
			Ok(bytes.len())
		}

		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}

	#[test]
	fn policy_blocked_log_contains_report_url() {
		let target = ScanTarget::Package(PackageCoordinate::new(
			"npm", "left-pad", "1.0.0",
		));
		let context = PolicyContext::new("npm-proxy", "npm", Some("platform"));
		let evaluation = PolicyEvaluator::default().evaluate_with_context(
			&context,
			&target,
			vec![Vulnerability {
				id: "CVE-2026-0001".to_owned(),
				aliases: Vec::new(),
				summary: None,
				details: None,
				severity: Some(Severity::High),
				references: Vec::new(),
			}],
		);
		let report_url = "https://proxy.example.invalid/trust/reports/123";
		let buffer = Buffer::default();
		let subscriber = fmt()
			.json()
			.without_time()
			.with_ansi(false)
			.with_writer(buffer.clone())
			.finish();

		tracing::subscriber::with_default(subscriber, || {
			audit_policy_evaluation(
				&context,
				&target,
				&evaluation,
				Some(report_url),
			);
		});

		let output =
			String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
		let event: serde_json::Value =
			serde_json::from_str(output.trim()).unwrap();
		assert_eq!(event["fields"]["message"], "policy_blocked");
		assert_eq!(event["fields"]["report_url"], report_url);
	}
}
