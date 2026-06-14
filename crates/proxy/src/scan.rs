use std::time::Duration;

use axum::body::Body;
use axum::http::{Response, StatusCode};
use nexus_sec_proxy_cache::{CacheKey, CachedScan, ScanCache};
use nexus_sec_proxy_config::{
	AppConfig, ArtifactScannerKind, UnsupportedTargetPolicy,
};
use nexus_sec_proxy_security::{
	BlockReport, ExternalScanner, ExternalScannerKind, PolicyContext,
	PolicyEvaluation, PolicyOutcome, ScanTarget, SecurityError,
	VulnerabilitySource,
};
use nexus_sec_proxy_yandex_messenger::BlockNotification;
use tracing::{error, warn};

use crate::audit::{audit_policy_evaluation, vulnerability_ids};
use crate::catalog::NexusRepository;
use crate::decisions::{DecisionOutcome, record_decision};
use crate::responses::response_with_text;
use crate::state::AppState;

pub(crate) async fn authorize_package_target(
	state: &AppState,
	repository: &NexusRepository,
	target: ScanTarget,
	requester_login: Option<&str>,
) -> Result<(), Box<Response<Body>>> {
	let cache_key = cache_key_for_target(&target);

	match state.cache.get(&cache_key).await {
		Ok(Some(scan)) => {
			let active_policy = state.active_policy();
			let context =
				active_policy.context_for(&repository.name, &repository.format);
			return handle_policy_evaluation(
				state,
				&context,
				&target,
				active_policy.evaluator.evaluate_with_context(
					&context,
					&target,
					scan.vulnerabilities,
				),
				requester_login,
			);
		}
		Ok(None) => {}
		Err(error) => {
			error!(%error, target = %target.display_name(), "cache lookup failed");
		}
	}

	let (context, decision) = match state.osv.vulnerabilities(&target).await {
		Ok(vulnerabilities) => {
			put_cache(
				state,
				cache_key,
				CachedScan::new(vulnerabilities.clone()),
				&target,
			)
			.await;
			let active_policy = state.active_policy();
			let context =
				active_policy.context_for(&repository.name, &repository.format);
			let decision = active_policy.evaluator.evaluate_with_context(
				&context,
				&target,
				vulnerabilities,
			);
			(context, decision)
		}
		Err(SecurityError::UnsupportedTarget(reason)) => {
			return handle_unsupported_target(
				state,
				repository,
				target,
				reason,
				requester_login,
			)
			.await;
		}
		Err(error) => {
			error!(%error, target = %target.display_name(), "scanner failed");

			if state.config.fail_open {
				warn!(
					target = %target.display_name(),
					"allowing request because scanner failed and fail_open=true"
				);
				return Ok(());
			}

			return Err(Box::new(response_with_text(
				StatusCode::SERVICE_UNAVAILABLE,
				format!(
					"Package scan failed and fail_open=false\n\nTarget: {}\nReason: {error}\n",
					target.display_name()
				),
			)));
		}
	};

	handle_policy_evaluation(
		state,
		&context,
		&target,
		decision,
		requester_login,
	)
}

pub(crate) async fn handle_unsupported_target(
	state: &AppState,
	repository: &NexusRepository,
	target: ScanTarget,
	reason: String,
	requester_login: Option<&str>,
) -> Result<(), Box<Response<Body>>> {
	match state.config.unsupported_target_policy {
		UnsupportedTargetPolicy::Allow => {
			warn!(
				target = %target.display_name(),
				reason,
				"allowing request for unsupported scan target"
			);
			Ok(())
		}
		UnsupportedTargetPolicy::Block => {
			let report = BlockReport::unsupported(target, reason);
			let active_policy = state.active_policy();
			let context =
				active_policy.context_for(&repository.name, &repository.format);
			record_decision(state, &context, DecisionOutcome::Blocked, &report);
			notify_blocked(state, requester_login, &context, &report);
			Err(Box::new(response_with_text(
				StatusCode::FORBIDDEN,
				report.to_plain_text(),
			)))
		}
	}
}

pub(crate) fn handle_policy_evaluation(
	state: &AppState,
	context: &PolicyContext,
	target: &ScanTarget,
	evaluation: PolicyEvaluation,
	requester_login: Option<&str>,
) -> Result<(), Box<Response<Body>>> {
	audit_policy_evaluation(context, target, &evaluation);

	match &evaluation.outcome {
		PolicyOutcome::Allowed => {}
		PolicyOutcome::ReportOnly(report) => {
			record_decision(
				state,
				context,
				DecisionOutcome::ReportOnly,
				report,
			);
		}
		PolicyOutcome::Blocked(report) => {
			record_decision(state, context, DecisionOutcome::Blocked, report);
			notify_blocked(state, requester_login, context, report);
		}
	}

	match evaluation.outcome {
		PolicyOutcome::Allowed | PolicyOutcome::ReportOnly(_) => Ok(()),
		PolicyOutcome::Blocked(report) => Err(Box::new(response_with_text(
			StatusCode::FORBIDDEN,
			report.to_plain_text(),
		))),
	}
}

fn notify_blocked(
	state: &AppState,
	requester_login: Option<&str>,
	context: &PolicyContext,
	report: &BlockReport,
) {
	let (Some(login), Some(notifier)) =
		(requester_login, state.yandex_messenger.as_ref())
	else {
		return;
	};

	notifier.notify_blocked(BlockNotification {
		login: login.to_owned(),
		repository: context.repository.clone(),
		format: context.format.clone(),
		target: report.target.display_name(),
		reason: report.reason.clone(),
		policy_id: report.policy_id.clone(),
		vulnerability_ids: vulnerability_ids(report),
	});
}

async fn put_cache(
	state: &AppState,
	key: CacheKey,
	scan: CachedScan,
	target: &ScanTarget,
) {
	if let Err(error) = state.cache.put(key, scan).await {
		error!(%error, target = %target.display_name(), "cache write failed");
	}
}

pub(crate) fn external_scanner_from_config(
	config: &AppConfig,
) -> Option<ExternalScanner> {
	let kind = match config.artifact_scanner {
		ArtifactScannerKind::Disabled => return None,
		ArtifactScannerKind::Trivy => ExternalScannerKind::Trivy,
		ArtifactScannerKind::Grype => ExternalScannerKind::Grype,
	};

	Some(ExternalScanner::new(
		kind,
		config.artifact_scanner_command.clone(),
		Duration::from_secs(config.artifact_scanner_timeout_secs),
		config.artifact_scanner_skip_db_update,
		config.artifact_scanner_offline,
	))
}
fn cache_key_for_target(target: &ScanTarget) -> CacheKey {
	CacheKey::from_parts(
		target.cache_namespace(),
		target.cache_identifier(),
		target.cache_version(),
	)
}
