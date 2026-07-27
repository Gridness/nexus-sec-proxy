use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use nexus_sec_proxy_defectdojo::{DefectDojoClient, DefectDojoConfig};
use nexus_sec_proxy_security::{
	PackageCoordinate, PolicyContext, PolicySet, ScanTarget, Severity,
	Vulnerability,
};
use tower::ServiceExt;

use super::*;
use crate::tests::{response_text, spawn_server, test_state};
use crate::trust_reports::ReportBackend;

#[derive(Clone)]
struct ImportState {
	requests: Arc<AtomicUsize>,
	status: StatusCode,
}

async fn import_scan(State(state): State<ImportState>) -> (StatusCode, String) {
	let test_id = state.requests.fetch_add(1, Ordering::SeqCst) + 1;
	if state.status.is_success() {
		(state.status, format!(r#"{{"test_id":{test_id}}}"#))
	} else {
		(state.status, "rejected".to_owned())
	}
}

#[tokio::test]
async fn defectdojo_backend_owns_repeated_block_reports_and_local_route_is_absent()
 {
	let requests = Arc::new(AtomicUsize::new(0));
	let (client, state) =
		defectdojo_state(StatusCode::CREATED, Arc::clone(&requests)).await;
	let (context, target, evaluation) = blocked_evaluation(&state);

	let first =
		handle_policy_evaluation(&state, &context, &target, evaluation, None)
			.await
			.unwrap_err();
	assert_eq!(first.status(), StatusCode::FORBIDDEN);
	let first_body = response_text(*first).await;
	assert!(first_body.contains("/test/1"));

	let (_, _, evaluation) = blocked_evaluation(&state);
	let second =
		handle_policy_evaluation(&state, &context, &target, evaluation, None)
			.await
			.unwrap_err();
	assert_eq!(second.status(), StatusCode::FORBIDDEN);
	assert!(response_text(*second).await.contains("/test/2"));

	assert_eq!(requests.load(Ordering::SeqCst), 2);
	assert_eq!(state.decision_log.list(10).len(), 2);
	assert_eq!(client.status().submitted, 2);
	assert_eq!(client.status().failed, 0);

	let status = build_app(Arc::clone(&state))
		.oneshot(
			Request::builder()
				.uri("/admin/api/status")
				.header("authorization", "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	let status: serde_json::Value =
		serde_json::from_str(&response_text(status).await).unwrap();
	assert_eq!(status["defectdojo"]["enabled"], true);
	assert_eq!(status["defectdojo"]["submitted"], 2);
	assert_eq!(status["defectdojo"]["failed"], 0);
	assert!(!status.to_string().contains("dojo-secret"));

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/trust/reports/00000000-0000-4000-8000-000000000000")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn defectdojo_failure_returns_503_without_recording_a_block_decision() {
	let requests = Arc::new(AtomicUsize::new(0));
	let (client, state) =
		defectdojo_state(StatusCode::BAD_GATEWAY, Arc::clone(&requests)).await;
	let (context, target, evaluation) = blocked_evaluation(&state);

	let response =
		handle_policy_evaluation(&state, &context, &target, evaluation, None)
			.await
			.unwrap_err();

	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	assert!(state.decision_log.list(10).is_empty());
	assert_eq!(requests.load(Ordering::SeqCst), 1);
	assert_eq!(client.status().submitted, 1);
	assert_eq!(client.status().failed, 1);
}

#[tokio::test]
async fn report_only_does_not_submit_to_defectdojo() {
	let requests = Arc::new(AtomicUsize::new(0));
	let policy = PolicySet::from_toml_str(
		r#"
		[default_policy]
		id = "report"
		minimum_blocking_severity = "HIGH"
		mode = "report_only"
		"#,
	)
	.unwrap();
	let mut state = test_state(None, None, policy);
	let base_url =
		spawn_import_server(StatusCode::CREATED, Arc::clone(&requests)).await;
	Arc::get_mut(&mut state).unwrap().report_backend =
		ReportBackend::DefectDojo(client(base_url));
	let active = state.active_policy();
	let context = PolicyContext::new("default", "npm", None::<String>);
	let target =
		ScanTarget::Package(PackageCoordinate::new("npm", "left-pad", "1.0.0"));
	let evaluation = active.evaluator.evaluate_with_context(
		&context,
		&target,
		vec![vulnerability()],
	);

	handle_policy_evaluation(&state, &context, &target, evaluation, None)
		.await
		.unwrap();

	assert_eq!(requests.load(Ordering::SeqCst), 0);
	assert_eq!(state.decision_log.list(10).len(), 1);
}

#[tokio::test]
async fn health_does_not_contact_defectdojo() {
	let requests = Arc::new(AtomicUsize::new(0));
	let (_, state) =
		defectdojo_state(StatusCode::CREATED, Arc::clone(&requests)).await;

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/healthz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	let body: serde_json::Value =
		serde_json::from_str(&response_text(response).await).unwrap();

	assert_eq!(body["checks"]["trust_reports"], "unused");
	assert_eq!(requests.load(Ordering::SeqCst), 0);
}

async fn defectdojo_state(
	status: StatusCode,
	requests: Arc<AtomicUsize>,
) -> (DefectDojoClient, Arc<AppState>) {
	let base_url = spawn_import_server(status, requests).await;
	let client = client(base_url.clone());
	let mut state = test_state(Some("secret"), None, PolicySet::default());
	let state_mut = Arc::get_mut(&mut state).unwrap();
	let mut config = (*state_mut.config).clone();
	config.defectdojo_enabled = true;
	config.defectdojo_url = Some(base_url.to_string());
	config.defectdojo_token = Some("dojo-secret".to_owned());
	config.defectdojo_engagement_id = Some(17);
	state_mut.config = Arc::new(config);
	state_mut.report_backend = ReportBackend::DefectDojo(client.clone());
	(client, state)
}

async fn spawn_import_server(
	status: StatusCode,
	requests: Arc<AtomicUsize>,
) -> url::Url {
	spawn_server(
		Router::new()
			.route("/api/v2/import-scan/", post(import_scan))
			.with_state(ImportState { requests, status }),
	)
	.await
}

fn client(base_url: url::Url) -> DefectDojoClient {
	let http_client = reqwest::Client::builder()
		.timeout(Duration::from_secs(1))
		.build()
		.unwrap();
	DefectDojoClient::new(
		DefectDojoConfig::new(base_url, "token", NonZeroU64::new(17).unwrap()),
		http_client,
	)
}

fn blocked_evaluation(
	state: &AppState,
) -> (
	PolicyContext,
	ScanTarget,
	nexus_sec_proxy_security::PolicyEvaluation,
) {
	let active = state.active_policy();
	let context = PolicyContext::new("default", "npm", None::<String>);
	let target =
		ScanTarget::Package(PackageCoordinate::new("npm", "left-pad", "1.0.0"));
	let evaluation = active.evaluator.evaluate_with_context(
		&context,
		&target,
		vec![vulnerability()],
	);
	(context, target, evaluation)
}

fn vulnerability() -> Vulnerability {
	Vulnerability {
		id: "CVE-2026-0001".to_owned(),
		aliases: Vec::new(),
		summary: None,
		details: None,
		severity: Some(Severity::High),
		references: Vec::new(),
		component_name: Some("left-pad".to_owned()),
		component_version: Some("1.0.0".to_owned()),
		fixed_versions: vec!["1.0.1".to_owned()],
	}
}
