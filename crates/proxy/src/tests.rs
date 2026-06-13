use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::to_bytes;
use nexus_sec_proxy_security::{PackageCoordinate, Severity, Vulnerability};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::{Json, Router};
use nexus_sec_proxy_cache::MokaScanCache;
use nexus_sec_proxy_config::{
	AppConfig, ArtifactScannerKind, UnsupportedTargetPolicy,
};
use nexus_sec_proxy_security::{OsvClient, PolicySet, ScanTarget};
use tokio::sync::Semaphore;
use url::Url;

#[derive(Debug, Clone)]
struct RecordedRequest {
	method: Method,
	path_and_query: String,
	headers: HeaderMap,
	body: Vec<u8>,
}

#[derive(Clone)]
struct OsvMockState {
	request_count: Arc<AtomicUsize>,
	response: Value,
	status: StatusCode,
}

async fn spawn_server(app: Router) -> Url {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});

	Url::parse(&format!("http://{addr}")).unwrap()
}

async fn record_nexus_request(
	State(records): State<Arc<Mutex<Vec<RecordedRequest>>>>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	body: Body,
) -> Response<Body> {
	let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
	records.lock().unwrap().push(RecordedRequest {
		method,
		path_and_query: uri
			.path_and_query()
			.map(|value| value.as_str().to_owned())
			.unwrap_or_else(|| uri.path().to_owned()),
		headers,
		body,
	});

	response_with_text(StatusCode::OK, "nexus\n")
}

async fn mock_osv(
	State(state): State<OsvMockState>,
	body: Body,
) -> Response<Body> {
	let _ = to_bytes(body, usize::MAX).await.unwrap();
	state.request_count.fetch_add(1, Ordering::SeqCst);

	(state.status, Json(state.response)).into_response()
}

#[test]
fn joins_nexus_base_path_and_request_path() {
	let base = Url::parse("https://repo.example.invalid/root").unwrap();
	let uri: Uri = "/nested/pkg.tgz?download=1".parse().unwrap();

	let joined = build_nexus_url(&base, &uri);

	assert_eq!(
		joined.as_str(),
		"https://repo.example.invalid/root/nested/pkg.tgz?download=1"
	);
}

#[test]
fn root_base_preserves_request_path() {
	let base = Url::parse("https://repo.example.invalid/").unwrap();
	let uri: Uri = "/pkg.tgz".parse().unwrap();

	let joined = build_nexus_url(&base, &uri);

	assert_eq!(joined.as_str(), "https://repo.example.invalid/pkg.tgz");
}

#[tokio::test]
async fn repository_catalog_loads_repositories_and_overrides() {
	let app = Router::new().route(
		"/service/rest/v1/repositories",
		get(|| async {
			Json(json!([
				{
					"name": "npm-proxy",
					"format": "npm",
					"type": "proxy",
					"url": "http://nexus/repository/npm-proxy",
					"online": true
				},
				{
					"name": "apt-proxy",
					"format": "apt",
					"type": "proxy"
				}
			]))
		}),
	);
	let nexus_base_url = spawn_server(app).await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_base_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config
		.osv_ecosystem_overrides
		.insert("apt-proxy".to_owned(), "Ubuntu OS".to_owned());
	let client = reqwest::Client::new();

	let catalog = load_repository_catalog(&client, &nexus_base_url, &config, 7)
		.await
		.unwrap();

	assert_eq!(catalog.generation, 7);
	assert_eq!(catalog.repositories.len(), 2);
	assert_eq!(catalog.get("npm-proxy").unwrap().format, "npm".to_owned());
	assert_eq!(
		catalog.get("apt-proxy").unwrap().osv_ecosystem.as_deref(),
		Some("Ubuntu OS")
	);
}

#[tokio::test]
async fn repository_catalog_reports_auth_malformed_and_empty_failures() {
	let client = reqwest::Client::new();

	let auth_app = Router::new().route(
		"/service/rest/v1/repositories",
		get(|| async { (StatusCode::UNAUTHORIZED, "no") }),
	);
	let auth_url = spawn_server(auth_app).await;
	let config = test_config(
		None,
		None,
		PolicySet::default(),
		auth_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	let error = load_repository_catalog(&client, &auth_url, &config, 1)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("returned 401"));

	let malformed_app = Router::new().route(
		"/service/rest/v1/repositories",
		get(|| async { (StatusCode::OK, "not json") }),
	);
	let malformed_url = spawn_server(malformed_app).await;
	let config = test_config(
		None,
		None,
		PolicySet::default(),
		malformed_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	let error = load_repository_catalog(&client, &malformed_url, &config, 1)
		.await
		.unwrap_err();
	assert!(
		error
			.to_string()
			.contains("invalid Nexus repository catalog")
	);

	let empty_app = Router::new().route(
		"/service/rest/v1/repositories",
		get(|| async { Json(json!([])) }),
	);
	let empty_url = spawn_server(empty_app).await;
	let config = test_config(
		None,
		None,
		PolicySet::default(),
		empty_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	let error = load_repository_catalog(&client, &empty_url, &config, 1)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("catalog is empty"));
}

#[test]
fn parses_repository_path_and_strips_prefix() {
	let parsed = parse_repository_path(
		"/repository/maven-central/com/example/demo/1.0/demo-1.0.jar",
	)
	.unwrap();

	assert_eq!(parsed.repository, "maven-central");
	assert_eq!(parsed.stripped_path, "/com/example/demo/1.0/demo-1.0.jar");

	let parsed = parse_repository_path("/repository/npm%2Dproxy").unwrap();

	assert_eq!(parsed.repository, "npm-proxy");
	assert_eq!(parsed.stripped_path, "/");
	assert_eq!(parse_repository_path("/service/rest/v1/status"), None);
	assert_eq!(parse_repository_path("/repository/"), None);
}

#[tokio::test]
async fn disabled_admin_routes_do_not_proxy_to_nexus() {
	let app = build_app(test_state(None, None, PolicySet::default()));

	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/admin/api/status")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	let status = response.status();
	let body = response_text(response).await;

	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body, "admin API is disabled\n");

	let response = app
		.oneshot(
			Request::builder()
				.uri("/adminfoo")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	let status = response.status();
	let body = response_text(response).await;

	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body, "admin API is disabled\n");
}

#[tokio::test]
async fn blocked_package_returns_403_before_nexus() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let osv_count = Arc::new(AtomicUsize::new(0));
	let osv_url =
		spawn_server(Router::new().route("/osv", post(mock_osv)).with_state(
			OsvMockState {
				request_count: Arc::clone(&osv_count),
				response: blocking_osv_response(),
				status: StatusCode::OK,
			},
		))
		.await;
	let state = proxy_test_state(
		nexus_url.as_str(),
		&format!("{osv_url}osv"),
		PolicySet::default(),
		UnsupportedTargetPolicy::Allow,
		vec![test_repository("maven-central", "maven2", None)],
	);
	let app = build_app(state);

	let response = app
		.oneshot(
			Request::builder()
				.uri(
					"/repository/maven-central/com/example/demo/1.2.3/demo-1.2.3.jar",
				)
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
	assert_eq!(osv_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn report_only_package_forwards_to_nexus_once() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let osv_count = Arc::new(AtomicUsize::new(0));
	let osv_url =
		spawn_server(Router::new().route("/osv", post(mock_osv)).with_state(
			OsvMockState {
				request_count: Arc::clone(&osv_count),
				response: blocking_osv_response(),
				status: StatusCode::OK,
			},
		))
		.await;
	let report_only_policy = PolicySet::from_toml_str(
		r#"
		[default_policy]
		id = "audit"
		mode = "report_only"
		minimum_blocking_severity = "high"
		"#,
	)
	.unwrap();
	let state = proxy_test_state(
		nexus_url.as_str(),
		&format!("{osv_url}osv"),
		report_only_policy,
		UnsupportedTargetPolicy::Allow,
		vec![test_repository("npm-proxy", "npm", Some("npm"))],
	);
	let app = build_app(state.clone());

	let response = app
		.oneshot(
			Request::builder()
				.uri("/repository/npm-proxy/left-pad/-/left-pad-1.0.0.tgz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(nexus_records.lock().unwrap().len(), 1);
	assert_eq!(osv_count.load(Ordering::SeqCst), 1);
	assert_eq!(
		state.decision_log.list(10)[0].outcome,
		DecisionOutcome::ReportOnly
	);
}

#[tokio::test]
async fn metadata_and_sidecar_requests_forward_without_osv() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let osv_count = Arc::new(AtomicUsize::new(0));
	let osv_url =
		spawn_server(Router::new().route("/osv", post(mock_osv)).with_state(
			OsvMockState {
				request_count: Arc::clone(&osv_count),
				response: blocking_osv_response(),
				status: StatusCode::OK,
			},
		))
		.await;
	let state = proxy_test_state(
		nexus_url.as_str(),
		&format!("{osv_url}osv"),
		PolicySet::default(),
		UnsupportedTargetPolicy::Allow,
		vec![test_repository("maven-central", "maven2", None)],
	);
	let app = build_app(state);

	for uri in [
		"/repository/maven-central/com/example/demo/maven-metadata.xml",
		"/repository/maven-central/com/example/demo/1.2.3/demo-1.2.3.jar.sha1",
	] {
		let response = app
			.clone()
			.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
	}

	assert_eq!(nexus_records.lock().unwrap().len(), 2);
	assert_eq!(osv_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_get_repository_request_forwards_method_headers_query_and_body() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let state = proxy_test_state(
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		PolicySet::default(),
		UnsupportedTargetPolicy::Allow,
		vec![test_repository("npm-proxy", "npm", Some("npm"))],
	);
	let app = build_app(state);

	let response = app
		.oneshot(
			Request::builder()
				.method(Method::PUT)
				.uri("/repository/npm-proxy/upload/path?checksum=1")
				.header("x-custom", "kept")
				.body(Body::from("request body"))
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	let records = nexus_records.lock().unwrap();
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].method, Method::PUT);
	assert_eq!(
		records[0].path_and_query,
		"/repository/npm-proxy/upload/path?checksum=1"
	);
	assert_eq!(records[0].headers["x-custom"], "kept");
	assert_eq!(records[0].body, b"request body");
}

#[tokio::test]
async fn unknown_repository_fails_closed_before_nexus() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let state = proxy_test_state(
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		PolicySet::default(),
		UnsupportedTargetPolicy::Allow,
		vec![test_repository("known", "npm", Some("npm"))],
	);
	let app = build_app(state);

	let response = app
		.oneshot(
			Request::builder()
				.uri("/repository/unknown/left-pad/-/left-pad-1.0.0.tgz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn artifact_target_with_block_policy_returns_403_before_nexus() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let state = proxy_test_state(
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		PolicySet::default(),
		UnsupportedTargetPolicy::Block,
		vec![test_repository("docker-proxy", "docker", None)],
	);
	let app = build_app(state.clone());

	let response = app
		.oneshot(
			Request::builder()
				.uri(
					"/repository/docker-proxy/v2/library/alpine/blobs/sha256:abc123",
				)
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
	assert_eq!(
		state.decision_log.list(10)[0].repository,
		"docker-proxy".to_owned()
	);
}

#[tokio::test]
async fn admin_api_rejects_missing_or_wrong_token_and_accepts_correct_token() {
	let app = build_app(test_state(Some("secret"), None, PolicySet::default()));

	let missing = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/admin/api/status")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

	let wrong = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/admin/api/status")
				.header(AUTHORIZATION, "Bearer wrong")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

	let correct = app
		.oneshot(
			Request::builder()
				.uri("/admin/api/status")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(correct.status(), StatusCode::OK);
}

#[tokio::test]
async fn policy_validate_returns_selected_policy_or_422() {
	let app = build_app(test_state(Some("secret"), None, PolicySet::default()));
	let valid_policy = r#"
		[default_policy]
		id = "default"
		minimum_blocking_severity = "critical"

		[[policies]]
		id = "npm-report"
		mode = "report_only"
		repositories = ["npm-internal"]
		formats = ["npm"]
		minimum_blocking_severity = "low"
	"#;

	let response = app
		.clone()
		.oneshot(json_request(
			"/admin/api/policy/validate",
			json!({
				"policy_toml": valid_policy,
				"repository_name": "npm-internal",
				"repository_format": "npm",
			}),
		))
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);

	let body = response_json(response).await;
	assert_eq!(body["valid"], true);
	assert_eq!(body["selected_policy_id"], "npm-report");
	assert_eq!(body["context"]["team"], Value::Null);

	let response = app
		.oneshot(json_request(
			"/admin/api/policy/validate",
			json!({
				"policy_toml": "[default_policy]\nminimum_blocking_severity = \"urgent\"",
			}),
		))
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn admin_repositories_lists_and_reloads_catalog() {
	let nexus_app = Router::new().route(
		"/service/rest/v1/repositories",
		get(|| async {
			Json(json!([
				{
					"name": "pypi-proxy",
					"format": "pypi",
					"type": "proxy"
				}
			]))
		}),
	);
	let nexus_url = spawn_server(nexus_app).await;
	let policy_set = PolicySet::default();
	let config = test_config(
		Some("secret"),
		None,
		policy_set.clone(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	let state = test_state_from_config(
		config,
		policy_set,
		None,
		vec![test_repository("npm-proxy", "npm", Some("npm"))],
	);
	let app = build_app(state.clone());

	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/admin/api/repositories")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	let body = response_json(response).await;
	assert_eq!(body["repositories"][0]["name"], "npm-proxy");

	let response = app
		.oneshot(
			Request::builder()
				.method(Method::POST)
				.uri("/admin/api/repositories/reload")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(
		state.repository_catalog().get("pypi-proxy").unwrap().format,
		"pypi"
	);
	assert_eq!(state.repository_catalog().generation, 2);
}

#[tokio::test]
async fn policy_reload_swaps_only_on_success_and_requires_policy_file() {
	let policy_file = tempfile::NamedTempFile::new().unwrap();
	let policy_path = policy_file.path().to_string_lossy().into_owned();
	std::fs::write(
		&policy_path,
		r#"
		[default_policy]
		id = "reloaded"
		minimum_blocking_severity = "critical"
		"#,
	)
	.unwrap();
	let state = test_state(
		Some("secret"),
		Some(policy_path.clone()),
		PolicySet::default(),
	);
	let app = build_app(state.clone());

	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.method(Method::POST)
				.uri("/admin/api/policy/reload")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(
		state.active_policy().policy_set.default_policy.id,
		"reloaded"
	);
	assert_eq!(state.active_policy().generation, 2);

	std::fs::write(
		&policy_path,
		"[default_policy]\nminimum_blocking_severity = \"urgent\"",
	)
	.unwrap();
	let response = app
		.oneshot(
			Request::builder()
				.method(Method::POST)
				.uri("/admin/api/policy/reload")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
	assert_eq!(
		state.active_policy().policy_set.default_policy.id,
		"reloaded"
	);
	assert_eq!(state.active_policy().generation, 2);

	let app = build_app(test_state(Some("secret"), None, PolicySet::default()));
	let response = app
		.oneshot(
			Request::builder()
				.method(Method::POST)
				.uri("/admin/api/policy/reload")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[test]
fn decision_log_keeps_capacity_and_newest_first_order() {
	let log = DecisionLog::new(2);

	log.push(recent_decision("old"));
	log.push(recent_decision("middle"));
	log.push(recent_decision("new"));

	let decisions = log.list(10);
	assert_eq!(decisions.len(), 2);
	assert_eq!(decisions[0].target, "new");
	assert_eq!(decisions[1].target, "middle");
}

#[test]
fn policy_evaluation_records_blocked_and_report_only_decisions() {
	let target =
		ScanTarget::Package(PackageCoordinate::new("npm", "left-pad", "1.0.0"));
	let vulnerability = vulnerability("CVE-2026-0001", Severity::High);

	let blocked_state = test_state(Some("secret"), None, PolicySet::default());
	let active_policy = blocked_state.active_policy();
	let context = active_policy.context_for("default", "npm");
	let evaluation = active_policy.evaluator.evaluate_with_context(
		&context,
		&target,
		vec![vulnerability.clone()],
	);
	let response =
		handle_policy_evaluation(&blocked_state, &context, &target, evaluation)
			.unwrap_err();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	let decisions = blocked_state.decision_log.list(10);
	assert_eq!(decisions.len(), 1);
	assert_eq!(decisions[0].outcome, DecisionOutcome::Blocked);
	assert_eq!(
		decisions[0].vulnerability_ids,
		vec!["CVE-2026-0001".to_owned()]
	);

	let report_only_policy = PolicySet::from_toml_str(
		r#"
		[default_policy]
		id = "audit"
		mode = "report_only"
		minimum_blocking_severity = "high"
		"#,
	)
	.unwrap();
	let report_only_state =
		test_state(Some("secret"), None, report_only_policy);
	let active_policy = report_only_state.active_policy();
	let context = active_policy.context_for("default", "npm");
	let evaluation = active_policy.evaluator.evaluate_with_context(
		&context,
		&target,
		vec![vulnerability],
	);
	handle_policy_evaluation(&report_only_state, &context, &target, evaluation)
		.unwrap();

	let decisions = report_only_state.decision_log.list(10);
	assert_eq!(decisions.len(), 1);
	assert_eq!(decisions[0].outcome, DecisionOutcome::ReportOnly);
	assert_eq!(decisions[0].policy_id.as_deref(), Some("audit"));
}

#[test]
fn scanner_db_age_reports_missing_empty_and_db_files() {
	let missing_dir = tempfile::tempdir().unwrap();
	let missing_path = missing_dir.path().join("missing");
	let summary = scanner_db_summary_for_dir("TRIVY_CACHE_DIR", &missing_path);

	assert_eq!(summary.status, ScannerDbStatus::Missing);
	assert_eq!(summary.age_seconds, None);

	let empty_dir = tempfile::tempdir().unwrap();
	let summary =
		scanner_db_summary_for_dir("TRIVY_CACHE_DIR", empty_dir.path());

	assert_eq!(summary.status, ScannerDbStatus::NotFound);

	let db_dir = tempfile::tempdir().unwrap();
	std::fs::create_dir(db_dir.path().join("db")).unwrap();
	let metadata_path = db_dir.path().join("db").join("metadata.json");
	std::fs::write(&metadata_path, "{}").unwrap();

	let summary = scanner_db_summary_for_dir("TRIVY_CACHE_DIR", db_dir.path());

	assert_eq!(summary.status, ScannerDbStatus::Found);
	assert_eq!(
		summary.db_file.as_deref(),
		Some(metadata_path.to_string_lossy().as_ref())
	);
	assert!(summary.modified_at.is_some());
	assert!(summary.age_seconds.is_some());

	let grype_dir = tempfile::tempdir().unwrap();
	let db_path = grype_dir.path().join("vulnerability.db");
	std::fs::write(&db_path, "db").unwrap();

	let summary =
		scanner_db_summary_for_dir("GRYPE_DB_CACHE_DIR", grype_dir.path());

	assert_eq!(summary.status, ScannerDbStatus::Found);
	assert_eq!(
		summary.db_file.as_deref(),
		Some(db_path.to_string_lossy().as_ref())
	);
}

async fn response_text(response: Response<Body>) -> String {
	let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

	String::from_utf8(bytes.to_vec()).unwrap()
}

async fn response_json(response: Response<Body>) -> Value {
	let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();

	serde_json::from_slice(&bytes).unwrap()
}

fn json_request(uri: &str, body: Value) -> Request<Body> {
	Request::builder()
		.method(Method::POST)
		.uri(uri)
		.header(AUTHORIZATION, "Bearer secret")
		.header(CONTENT_TYPE, "application/json")
		.body(Body::from(serde_json::to_vec(&body).unwrap()))
		.unwrap()
}

fn recent_decision(target: &str) -> RecentDecision {
	RecentDecision {
		timestamp: "2026-06-11T00:00:00Z".to_owned(),
		repository: "default".to_owned(),
		format: "npm".to_owned(),
		team: None,
		target: target.to_owned(),
		outcome: DecisionOutcome::Blocked,
		policy_id: Some("default".to_owned()),
		reason: "blocked".to_owned(),
		vulnerability_ids: Vec::new(),
	}
}

fn test_repository_catalog(
	repositories: Vec<NexusRepository>,
) -> RepositoryCatalog {
	RepositoryCatalog::new(repositories, 1).unwrap()
}

fn test_repository(
	name: &str,
	format: &str,
	osv_ecosystem: Option<&str>,
) -> NexusRepository {
	NexusRepository {
		name: name.to_owned(),
		format: format.to_owned(),
		repository_type: Some("proxy".to_owned()),
		url: None,
		online: Some(true),
		osv_ecosystem: osv_ecosystem.map(str::to_owned),
	}
}

fn blocking_osv_response() -> Value {
	json!({
		"vulns": [
			{
				"id": "CVE-2026-0001",
				"database_specific": {
					"severity": "HIGH"
				}
			}
		]
	})
}

fn proxy_test_state(
	nexus_base_url: &str,
	osv_api_url: &str,
	policy_set: PolicySet,
	unsupported_target_policy: UnsupportedTargetPolicy,
	repositories: Vec<NexusRepository>,
) -> Arc<AppState> {
	let config = test_config(
		None,
		None,
		policy_set.clone(),
		nexus_base_url,
		osv_api_url,
		unsupported_target_policy,
	);

	test_state_from_config(config, policy_set, None, repositories)
}

fn test_config(
	admin_token: Option<&str>,
	policy_file: Option<String>,
	policy_set: PolicySet,
	nexus_base_url: &str,
	osv_api_url: &str,
	unsupported_target_policy: UnsupportedTargetPolicy,
) -> AppConfig {
	let security_policy = policy_set.default_policy.policy.clone();

	AppConfig {
		bind_addr: "127.0.0.1:3000".parse().unwrap(),
		nexus_base_url: nexus_base_url.to_owned(),
		upstream_base_url: nexus_base_url.to_owned(),
		repository_name: "default".to_owned(),
		repository_format: "npm".to_owned(),
		osv_ecosystem: None,
		osv_ecosystem_overrides: Default::default(),
		nexus_username: None,
		nexus_password: None,
		osv_api_url: osv_api_url.to_owned(),
		policy_file,
		admin_token: admin_token.map(str::to_owned),
		log_json: false,
		fail_open: true,
		unsupported_target_policy,
		cache_allowed_ttl_secs: 86_400,
		cache_blocked_ttl_secs: 3_600,
		cache_max_capacity: 100,
		request_timeout_secs: 1,
		artifact_scanner: ArtifactScannerKind::Disabled,
		artifact_scanner_command: String::new(),
		artifact_scanner_skip_db_update: true,
		artifact_scanner_offline: true,
		artifact_scanner_timeout_secs: 300,
		artifact_scan_max_bytes: 512 * 1024 * 1024,
		artifact_scanner_concurrency: 2,
		artifact_tmp_dir: None,
		security_policy,
		policy_set,
	}
}

fn test_state(
	admin_token: Option<&str>,
	policy_file: Option<String>,
	policy_set: PolicySet,
) -> Arc<AppState> {
	let config = test_config(
		admin_token,
		policy_file.clone(),
		policy_set.clone(),
		"http://127.0.0.1:9",
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	test_state_from_config(
		config,
		policy_set,
		policy_file,
		vec![NexusRepository {
			name: "default".to_owned(),
			format: "npm".to_owned(),
			repository_type: Some("proxy".to_owned()),
			url: None,
			online: Some(true),
			osv_ecosystem: Some("npm".to_owned()),
		}],
	)
}

fn test_state_from_config(
	config: AppConfig,
	policy_set: PolicySet,
	policy_file: Option<String>,
	repositories: Vec<NexusRepository>,
) -> Arc<AppState> {
	let http_client = reqwest::Client::builder()
		.timeout(Duration::from_secs(1))
		.build()
		.unwrap();
	let nexus_base_url = Url::parse(&config.nexus_base_url).unwrap();
	let osv_api_url = config.osv_api_url.clone();

	Arc::new(AppState {
		config: Arc::new(config),
		nexus_base_url,
		http_client: http_client.clone(),
		cache: MokaScanCache::new(
			100,
			Duration::from_secs(60),
			Duration::from_secs(60),
		),
		osv: OsvClient::new(http_client, osv_api_url),
		artifact_scanner: None,
		artifact_scanner_semaphore: Arc::new(Semaphore::new(2)),
		active_policy: Arc::new(RwLock::new(Arc::new(ActivePolicy::new(
			policy_set,
			policy_file,
			1,
		)))),
		repository_catalog: Arc::new(RwLock::new(Arc::new(
			test_repository_catalog(repositories),
		))),
		decision_log: DecisionLog::new(100),
		started_at: Instant::now(),
		started_at_rfc3339: now_rfc3339(),
	})
}

fn vulnerability(id: &str, severity: Severity) -> Vulnerability {
	Vulnerability {
		id: id.to_owned(),
		aliases: Vec::new(),
		summary: None,
		details: None,
		severity: Some(severity),
		references: Vec::new(),
	}
}
