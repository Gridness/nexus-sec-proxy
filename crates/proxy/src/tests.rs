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
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
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

#[derive(Debug, Clone)]
struct CatalogMockResponse {
	status: StatusCode,
	body: String,
}

#[derive(Clone)]
struct CatalogMockState {
	response: Arc<Mutex<CatalogMockResponse>>,
	request_count: Arc<AtomicUsize>,
	active_requests: Arc<AtomicUsize>,
	max_concurrent_requests: Arc<AtomicUsize>,
	delay: Duration,
}

#[cfg(feature = "yandex-messenger")]
#[derive(Clone)]
struct YandexMockState {
	records: Arc<Mutex<Vec<RecordedRequest>>>,
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

fn catalog_mock(body: Value, delay: Duration) -> CatalogMockState {
	CatalogMockState {
		response: Arc::new(Mutex::new(CatalogMockResponse {
			status: StatusCode::OK,
			body: body.to_string(),
		})),
		request_count: Arc::new(AtomicUsize::new(0)),
		active_requests: Arc::new(AtomicUsize::new(0)),
		max_concurrent_requests: Arc::new(AtomicUsize::new(0)),
		delay,
	}
}

fn set_catalog_response(
	state: &CatalogMockState,
	status: StatusCode,
	body: impl Into<String>,
) {
	*state.response.lock().unwrap() = CatalogMockResponse {
		status,
		body: body.into(),
	};
}

async fn wait_for_request_count(state: &CatalogMockState, expected: usize) {
	tokio::time::timeout(Duration::from_secs(2), async {
		while state.request_count.load(Ordering::SeqCst) < expected {
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
	})
	.await
	.unwrap();
}

async fn wait_for_catalog(
	state: &AppState,
	mut predicate: impl FnMut(&RepositoryCatalog) -> bool,
) {
	tokio::time::timeout(Duration::from_secs(2), async {
		loop {
			let catalog = state.repository_catalog();
			if predicate(&catalog) {
				break;
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
	})
	.await
	.unwrap();
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

async fn mock_catalog(State(state): State<CatalogMockState>) -> Response<Body> {
	state.request_count.fetch_add(1, Ordering::SeqCst);
	let active = state.active_requests.fetch_add(1, Ordering::SeqCst) + 1;
	state
		.max_concurrent_requests
		.fetch_max(active, Ordering::SeqCst);

	if !state.delay.is_zero() {
		tokio::time::sleep(state.delay).await;
	}

	state.active_requests.fetch_sub(1, Ordering::SeqCst);
	let response = state.response.lock().unwrap().clone();
	Response::builder()
		.status(response.status)
		.header(CONTENT_TYPE, "application/json")
		.body(Body::from(response.body))
		.unwrap()
}

#[cfg(feature = "yandex-messenger")]
async fn mock_yandex_messenger(
	State(state): State<YandexMockState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	body: Body,
) -> Response<Body> {
	let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
	state.records.lock().unwrap().push(RecordedRequest {
		method,
		path_and_query: uri
			.path_and_query()
			.map(|value| value.as_str().to_owned())
			.unwrap_or_else(|| uri.path().to_owned()),
		headers,
		body,
	});

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

#[test]
fn extracts_basic_auth_username_only_from_valid_basic_headers() {
	let mut headers = HeaderMap::new();
	assert_eq!(basic_auth_username(&headers), None);

	headers.insert(AUTHORIZATION, "Bearer token".parse().unwrap());
	assert_eq!(basic_auth_username(&headers), None);

	headers.insert(AUTHORIZATION, "Basic !!!".parse().unwrap());
	assert_eq!(basic_auth_username(&headers), None);

	headers.insert(AUTHORIZATION, "Basic bm9jb2xvbg==".parse().unwrap());
	assert_eq!(basic_auth_username(&headers), None);

	headers.insert(AUTHORIZATION, "Basic OnNlY3JldA==".parse().unwrap());
	assert_eq!(basic_auth_username(&headers), None);

	headers.insert(
		AUTHORIZATION,
		"Basic YWxpY2U6c2VjcmV0OnRhaWw=".parse().unwrap(),
	);
	assert_eq!(basic_auth_username(&headers).as_deref(), Some("alice"));

	headers.insert(AUTHORIZATION, "basic Ym9iOnNlY3JldA==".parse().unwrap());
	assert_eq!(basic_auth_username(&headers).as_deref(), Some("bob"));
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

#[tokio::test]
async fn repository_catalog_refresh_failures_preserve_last_valid_catalog() {
	let mock = catalog_mock(json!([]), Duration::ZERO);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(mock.clone()),
	)
	.await;
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

	set_catalog_response(
		&mock,
		StatusCode::BAD_GATEWAY,
		"upstream unavailable",
	);
	let response = build_app(state.clone())
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
	assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
	assert_eq!(state.repository_catalog().generation, 1);
	assert!(state.repository_catalog().get("npm-proxy").is_some());

	set_catalog_response(&mock, StatusCode::OK, "not json");
	assert!(state.reload_repository_catalog().await.is_err());
	assert_eq!(state.repository_catalog().generation, 1);
	assert!(state.repository_catalog().get("npm-proxy").is_some());

	set_catalog_response(&mock, StatusCode::OK, "[]");
	assert!(state.reload_repository_catalog().await.is_err());
	assert_eq!(state.repository_catalog().generation, 1);
	assert!(state.repository_catalog().get("npm-proxy").is_some());
}

#[tokio::test]
async fn periodic_repository_refresh_adds_modifies_and_deletes_repositories() {
	let mock = catalog_mock(
		json!([
			{
				"name": "npm-proxy",
				"format": "npm",
				"type": "proxy",
				"online": false
			},
			{
				"name": "pypi-proxy",
				"format": "pypi",
				"type": "proxy",
				"online": true
			}
		]),
		Duration::ZERO,
	);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(mock.clone()),
	)
	.await;
	let policy_set = PolicySet::default();
	let config = test_config(
		None,
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
	let cancellation = CancellationToken::new();
	let task = spawn_repository_catalog_refresh_with_interval(
		state.clone(),
		Duration::from_millis(100),
		cancellation.clone(),
	);

	tokio::time::sleep(Duration::from_millis(30)).await;
	assert_eq!(mock.request_count.load(Ordering::SeqCst), 0);

	wait_for_catalog(&state, |catalog| {
		catalog.generation >= 2 && catalog.get("pypi-proxy").is_some()
	})
	.await;
	assert_eq!(
		state.repository_catalog().get("npm-proxy").unwrap().online,
		Some(false)
	);

	set_catalog_response(
		&mock,
		StatusCode::OK,
		json!([
			{
				"name": "pypi-proxy",
				"format": "raw",
				"type": "hosted",
				"online": false
			}
		])
		.to_string(),
	);
	wait_for_catalog(&state, |catalog| {
		catalog.generation >= 3
			&& catalog.get("npm-proxy").is_none()
			&& catalog
				.get("pypi-proxy")
				.is_some_and(|repository| repository.format == "raw")
	})
	.await;

	cancellation.cancel();
	task.await.unwrap();
}

#[tokio::test]
async fn manual_and_background_repository_reloads_are_serialized() {
	let mock = catalog_mock(
		json!([
			{
				"name": "npm-proxy",
				"format": "npm",
				"type": "proxy"
			}
		]),
		Duration::from_millis(50),
	);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(mock.clone()),
	)
	.await;
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
	let background = tokio::spawn({
		let state = state.clone();
		async move { state.reload_repository_catalog().await }
	});
	wait_for_request_count(&mock, 1).await;

	let response = build_app(state.clone())
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
	background.await.unwrap().unwrap();
	assert_eq!(mock.request_count.load(Ordering::SeqCst), 2);
	assert_eq!(mock.max_concurrent_requests.load(Ordering::SeqCst), 1);
	assert_eq!(state.repository_catalog().generation, 3);
}

#[tokio::test]
async fn repository_refresh_can_be_disabled_and_cancelled() {
	let mock = catalog_mock(
		json!([
			{
				"name": "npm-proxy",
				"format": "npm",
				"type": "proxy"
			}
		]),
		Duration::from_secs(60),
	);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(mock.clone()),
	)
	.await;
	let policy_set = PolicySet::default();
	let mut config = test_config(
		None,
		None,
		policy_set.clone(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config.repository_refresh_interval_secs = 0;
	let state = test_state_from_config(
		config,
		policy_set,
		None,
		vec![test_repository("npm-proxy", "npm", Some("npm"))],
	);
	let disabled_cancellation = CancellationToken::new();

	assert!(
		spawn_repository_catalog_refresh(state.clone(), disabled_cancellation)
			.is_none()
	);
	tokio::time::sleep(Duration::from_millis(30)).await;
	assert_eq!(mock.request_count.load(Ordering::SeqCst), 0);

	let idle_cancellation = CancellationToken::new();
	let idle_task = spawn_repository_catalog_refresh_with_interval(
		state.clone(),
		Duration::from_secs(60),
		idle_cancellation.clone(),
	);
	idle_cancellation.cancel();
	tokio::time::timeout(Duration::from_millis(200), idle_task)
		.await
		.unwrap()
		.unwrap();
	assert_eq!(mock.request_count.load(Ordering::SeqCst), 0);

	let active_cancellation = CancellationToken::new();
	let active_task = spawn_repository_catalog_refresh_with_interval(
		state.clone(),
		Duration::from_millis(10),
		active_cancellation.clone(),
	);
	wait_for_request_count(&mock, 1).await;
	active_cancellation.cancel();
	tokio::time::timeout(Duration::from_millis(200), active_task)
		.await
		.unwrap()
		.unwrap();
	assert_eq!(state.repository_catalog().generation, 1);
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
		.clone()
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
	let app = build_app(state.clone());

	let response = app
		.clone()
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

	let status = response.status();
	let body = response_text(response).await;

	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_block_body(&body);
	let report_url = report_url_from_body(&body).to_owned();
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
	assert_eq!(osv_count.load(Ordering::SeqCst), 1);
	assert_eq!(
		state.decision_log.list(1)[0].report_url.as_deref(),
		Some(report_url.as_str())
	);

	let report_response = app
		.oneshot(
			Request::builder()
				.uri(Url::parse(&report_url).unwrap().path())
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(report_response.status(), StatusCode::OK);
	assert_eq!(
		report_response.headers()["cache-control"],
		"no-store, no-cache, must-revalidate, max-age=0"
	);
	assert_eq!(
		report_response.headers()["x-content-type-options"],
		"nosniff"
	);
	assert_eq!(report_response.headers()["referrer-policy"], "no-referrer");
	assert_eq!(report_response.headers()["x-frame-options"], "DENY");
	assert!(
		report_response.headers()["content-security-policy"]
			.to_str()
			.unwrap()
			.contains("frame-ancestors 'none'")
	);
	let report_html = response_text(report_response).await;
	assert!(report_html.contains("Maven:com.example:demo@1.2.3"));
	assert!(report_html.contains("CVE-2026-0001"));
}

#[cfg(feature = "yandex-messenger")]
#[tokio::test]
async fn blocked_package_with_basic_auth_notifies_yandex_and_cached_blocks() {
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
	let yandex_records = Arc::new(Mutex::new(Vec::new()));
	let yandex_url = spawn_server(
		Router::new()
			.route("/bot/v1/messages/sendText/", post(mock_yandex_messenger))
			.with_state(YandexMockState {
				records: Arc::clone(&yandex_records),
				response: json!({ "ok": true }),
				status: StatusCode::OK,
			}),
	)
	.await;
	let template_file = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(
		template_file.path(),
		"User={user}; repo={repository}; format={format}; target={target}; reason={reason}; policy={policy_id}; vulns={vulnerability_ids}; at={timestamp}; {kept}",
	)
	.unwrap();
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		&format!("{osv_url}osv"),
		UnsupportedTargetPolicy::Allow,
	);
	config.yandex_messenger_token = Some("bot-token".to_owned());
	config.yandex_messenger_template_file =
		Some(template_file.path().to_string_lossy().into_owned());
	config.yandex_messenger_api_url = yandex_url.to_string();
	config.yandex_messenger_enabled = true;
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("maven-central", "maven2", None)],
	);
	let app = build_app(state);

	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.uri(
					"/repository/maven-central/com/example/demo/1.2.3/demo-1.2.3.jar",
				)
				.header(AUTHORIZATION, "Basic YWxpY2U6c2VjcmV0")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	let status = response.status();
	let body = response_text(response).await;

	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_block_body(&body);
	let first_report_url = report_url_from_body(&body).to_owned();
	wait_for_record_count(&yandex_records, 1).await;
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
	assert_eq!(osv_count.load(Ordering::SeqCst), 1);

	{
		let records = yandex_records.lock().unwrap();
		assert_eq!(records[0].method, Method::POST);
		assert_eq!(records[0].path_and_query, "/bot/v1/messages/sendText/");
		assert_eq!(records[0].headers[AUTHORIZATION], "OAuth bot-token");
		let body: Value = serde_json::from_slice(&records[0].body).unwrap();
		assert_eq!(body["login"], "alice");
		assert!(
			body["payload_id"]
				.as_str()
				.unwrap()
				.starts_with("nexus-sec-proxy-")
		);
		let text = body["text"].as_str().unwrap();
		assert!(text.contains("User=alice"));
		assert!(text.contains("repo=maven-central"));
		assert!(text.contains("format=maven2"));
		assert!(text.contains("target=Maven:com.example:demo@1.2.3"));
		assert!(text.contains("reason=vulnerability policy was violated"));
		assert!(text.contains("policy=default"));
		assert!(text.contains("vulns=CVE-2026-0001"));
		assert!(text.contains("{kept}"));
		assert!(text.contains(&format!("Report: {first_report_url}")));
	}

	let response = app
		.oneshot(
			Request::builder()
				.uri(
					"/repository/maven-central/com/example/demo/1.2.3/demo-1.2.3.jar",
				)
				.header(AUTHORIZATION, "Basic YWxpY2U6c2VjcmV0")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	let second_body = response_text(response).await;
	let second_report_url = report_url_from_body(&second_body);
	assert_ne!(first_report_url, second_report_url);
	wait_for_record_count(&yandex_records, 2).await;
	assert_eq!(osv_count.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "yandex-messenger")]
#[tokio::test]
async fn blocked_package_without_basic_auth_skips_yandex_notification() {
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
	let yandex_records = Arc::new(Mutex::new(Vec::new()));
	let yandex_url = spawn_server(
		Router::new()
			.route("/bot/v1/messages/sendText/", post(mock_yandex_messenger))
			.with_state(YandexMockState {
				records: Arc::clone(&yandex_records),
				response: json!({ "ok": true }),
				status: StatusCode::OK,
			}),
	)
	.await;
	let template_file = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(template_file.path(), "blocked {user}").unwrap();
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		&format!("{osv_url}osv"),
		UnsupportedTargetPolicy::Allow,
	);
	config.yandex_messenger_token = Some("bot-token".to_owned());
	config.yandex_messenger_template_file =
		Some(template_file.path().to_string_lossy().into_owned());
	config.yandex_messenger_api_url = yandex_url.to_string();
	config.yandex_messenger_enabled = true;
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
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
	assert_eq!(yandex_records.lock().unwrap().len(), 0);
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
	assert_eq!(osv_count.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "yandex-messenger")]
#[tokio::test]
async fn yandex_failure_does_not_change_block_response() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let osv_url =
		spawn_server(Router::new().route("/osv", post(mock_osv)).with_state(
			OsvMockState {
				request_count: Arc::new(AtomicUsize::new(0)),
				response: blocking_osv_response(),
				status: StatusCode::OK,
			},
		))
		.await;
	let yandex_records = Arc::new(Mutex::new(Vec::new()));
	let yandex_url = spawn_server(
		Router::new()
			.route("/bot/v1/messages/sendText/", post(mock_yandex_messenger))
			.with_state(YandexMockState {
				records: Arc::clone(&yandex_records),
				response: json!({ "ok": false }),
				status: StatusCode::OK,
			}),
	)
	.await;
	let template_file = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(template_file.path(), "blocked {user}").unwrap();
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		&format!("{osv_url}osv"),
		UnsupportedTargetPolicy::Allow,
	);
	config.yandex_messenger_token = Some("bot-token".to_owned());
	config.yandex_messenger_template_file =
		Some(template_file.path().to_string_lossy().into_owned());
	config.yandex_messenger_api_url = yandex_url.to_string();
	config.yandex_messenger_enabled = true;
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("maven-central", "maven2", None)],
	);
	let app = build_app(state);

	let response = app
		.oneshot(
			Request::builder()
				.uri(
					"/repository/maven-central/com/example/demo/1.2.3/demo-1.2.3.jar",
				)
				.header(AUTHORIZATION, "Basic YWxpY2U6c2VjcmV0")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	let status = response.status();
	let body = response_text(response).await;

	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_block_body(&body);
	wait_for_record_count(&yandex_records, 1).await;
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
}

#[cfg(not(feature = "yandex-messenger"))]
#[tokio::test]
async fn yandex_config_is_ignored_when_feature_disabled() {
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
	let yandex_records = Arc::new(Mutex::new(Vec::new()));
	let yandex_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&yandex_records)),
	)
	.await;
	let template_file = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(template_file.path(), "blocked {user}").unwrap();
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		&format!("{osv_url}osv"),
		UnsupportedTargetPolicy::Allow,
	);
	config.yandex_messenger_token = Some("bot-token".to_owned());
	config.yandex_messenger_template_file =
		Some(template_file.path().to_string_lossy().into_owned());
	config.yandex_messenger_api_url = yandex_url.to_string();
	config.yandex_messenger_enabled = true;
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("maven-central", "maven2", None)],
	);
	let app = build_app(state);

	let response = app
		.oneshot(
			Request::builder()
				.uri(
					"/repository/maven-central/com/example/demo/1.2.3/demo-1.2.3.jar",
				)
				.header(AUTHORIZATION, "Basic YWxpY2U6c2VjcmV0")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	assert_eq!(yandex_records.lock().unwrap().len(), 0);
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
		.clone()
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
	assert_eq!(state.decision_log.list(10)[0].report_url, None);
	assert_eq!(
		std::fs::read_dir(state.report_store.directory())
			.unwrap()
			.count(),
		0
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
		.clone()
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
	let body = response_text(response).await;
	let report_url = report_url_from_body(&body);
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
	assert_eq!(
		state.decision_log.list(10)[0].repository,
		"docker-proxy".to_owned()
	);
	assert_eq!(
		state.decision_log.list(10)[0].report_url.as_deref(),
		Some(report_url)
	);
	let report_response = app
		.oneshot(
			Request::builder()
				.uri(Url::parse(report_url).unwrap().path())
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(report_response.status(), StatusCode::OK);
	let report_html = response_text(report_response).await;
	assert!(report_html.contains(
		"artifact targets cannot be scanned before contacting Nexus"
	));
	assert!(
		report_html
			.contains("No vulnerabilities are associated with this block.")
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
async fn invalid_trust_report_id_returns_hardened_404() {
	let app = build_app(test_state(None, None, PolicySet::default()));

	let response = app
		.oneshot(
			Request::builder()
				.uri("/trust/reports/not-a-uuid")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::NOT_FOUND);
	assert_eq!(
		response.headers()["cache-control"],
		"no-store, no-cache, must-revalidate, max-age=0"
	);
	assert_eq!(response.headers()["x-content-type-options"], "nosniff");
	assert_eq!(response.headers()["referrer-policy"], "no-referrer");
}

#[tokio::test]
async fn admin_status_reports_yandex_config_without_token() {
	let mut config = test_config(
		Some("secret"),
		None,
		PolicySet::default(),
		"http://127.0.0.1:9",
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config.yandex_messenger_token = Some("bot-secret".to_owned());
	config.yandex_messenger_template_file =
		Some("/etc/nsp/yandex-message.txt".to_owned());
	config.yandex_messenger_api_url =
		"https://messenger.example.invalid".to_owned();
	config.yandex_messenger_enabled = true;
	let app = build_app(test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("default", "npm", Some("npm"))],
	));

	let response = app
		.oneshot(
			Request::builder()
				.uri("/admin/api/status")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	let body = response_json(response).await;
	let immutable_config = &body["immutable_config"];
	assert_eq!(
		immutable_config["yandex_messenger_available"],
		cfg!(feature = "yandex-messenger")
	);
	assert_eq!(
		immutable_config["yandex_messenger_enabled"],
		cfg!(feature = "yandex-messenger")
	);
	assert_eq!(immutable_config["yandex_messenger_token_configured"], true);
	assert_eq!(
		immutable_config["yandex_messenger_template_file"],
		"/etc/nsp/yandex-message.txt"
	);
	assert_eq!(
		immutable_config["yandex_messenger_api_url"],
		"https://messenger.example.invalid"
	);
	assert_eq!(immutable_config["repository_refresh_interval_secs"], 60);
	assert!(!body.to_string().contains("bot-secret"));
}

#[cfg(not(feature = "yandex-messenger"))]
#[tokio::test]
async fn admin_status_reports_yandex_unavailable_when_feature_disabled() {
	let mut config = test_config(
		Some("secret"),
		None,
		PolicySet::default(),
		"http://127.0.0.1:9",
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config.yandex_messenger_token = Some("bot-secret".to_owned());
	config.yandex_messenger_template_file =
		Some("/etc/nsp/yandex-message.txt".to_owned());
	config.yandex_messenger_api_url =
		"https://messenger.example.invalid".to_owned();
	config.yandex_messenger_enabled = true;
	let app = build_app(test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("default", "npm", Some("npm"))],
	));

	let response = app
		.oneshot(
			Request::builder()
				.uri("/admin/api/status")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	let body = response_json(response).await;
	let immutable_config = &body["immutable_config"];
	assert_eq!(immutable_config["yandex_messenger_available"], false);
	assert_eq!(immutable_config["yandex_messenger_enabled"], false);
	assert_eq!(immutable_config["yandex_messenger_token_configured"], true);
	assert!(!body.to_string().contains("bot-secret"));
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

#[tokio::test]
async fn policy_evaluation_records_blocked_and_report_only_decisions() {
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
	let response = handle_policy_evaluation(
		&blocked_state,
		&context,
		&target,
		evaluation,
		None,
	)
	.await
	.unwrap_err();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	let decisions = blocked_state.decision_log.list(10);
	assert_eq!(decisions.len(), 1);
	assert_eq!(decisions[0].outcome, DecisionOutcome::Blocked);
	assert_eq!(
		decisions[0].vulnerability_ids,
		vec!["CVE-2026-0001".to_owned()]
	);
	let report_url = decisions[0].report_url.clone().unwrap();
	let decisions_response = build_app(blocked_state.clone())
		.oneshot(
			Request::builder()
				.uri("/admin/api/decisions?limit=1")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(decisions_response.status(), StatusCode::OK);
	assert_eq!(
		response_json(decisions_response).await["decisions"][0]["report_url"],
		report_url
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
	handle_policy_evaluation(
		&report_only_state,
		&context,
		&target,
		evaluation,
		None,
	)
	.await
	.unwrap();

	let decisions = report_only_state.decision_log.list(10);
	assert_eq!(decisions.len(), 1);
	assert_eq!(decisions[0].outcome, DecisionOutcome::ReportOnly);
	assert_eq!(decisions[0].policy_id.as_deref(), Some("audit"));
}

#[tokio::test]
async fn report_write_failure_returns_503_without_recording_block() {
	let state = test_state(None, None, PolicySet::default());
	let report_directory = state.report_store.directory().to_owned();
	std::fs::remove_dir_all(&report_directory).unwrap();
	std::fs::write(&report_directory, "not a directory").unwrap();
	let active_policy = state.active_policy();
	let context = active_policy.context_for("default", "npm");
	let target =
		ScanTarget::Package(PackageCoordinate::new("npm", "left-pad", "1.0.0"));
	let evaluation = active_policy.evaluator.evaluate_with_context(
		&context,
		&target,
		vec![vulnerability("CVE-2026-0001", Severity::High)],
	);

	let response =
		handle_policy_evaluation(&state, &context, &target, evaluation, None)
			.await
			.unwrap_err();
	let status = response.status();
	let body = response_text(*response).await;

	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
	assert!(body.contains("Trust report could not be created"));
	assert!(state.decision_log.list(10).is_empty());
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

#[cfg(feature = "yandex-messenger")]
async fn wait_for_record_count(
	records: &Arc<Mutex<Vec<RecordedRequest>>>,
	expected: usize,
) {
	for _ in 0..100 {
		if records.lock().unwrap().len() >= expected {
			return;
		}

		tokio::time::sleep(Duration::from_millis(10)).await;
	}

	panic!(
		"timed out waiting for {expected} records, got {}",
		records.lock().unwrap().len()
	);
}

fn expected_maven_block_body() -> &'static str {
	concat!(
		"Package blocked by nexus-sec-proxy\n",
		"\n",
		"Target: Maven:com.example:demo@1.2.3\n",
		"Reason: vulnerability policy was violated\n",
		"Policy: default\n",
		"\n",
		"Policy violations:\n",
		"- 1 HIGH vulnerabilities exceeds limit of 0\n",
		"\n",
		"Vulnerabilities:\n",
		"- CVE-2026-0001 [HIGH]\n",
	)
}

fn assert_block_body(body: &str) {
	assert!(body.starts_with(expected_maven_block_body()));
	let report_url = report_url_from_body(body);
	let parsed = Url::parse(report_url).unwrap();
	assert_eq!(parsed.scheme(), "https");
	assert_eq!(parsed.host_str(), Some("proxy.example.invalid"));
	let id = parsed.path().rsplit('/').next().unwrap();
	assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 4);
}

fn report_url_from_body(body: &str) -> &str {
	body.lines()
		.find_map(|line| line.strip_prefix("Full report: "))
		.expect("block response contains Trust report URL")
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
		report_url: Some(
			"https://proxy.example.invalid/trust/reports/00000000-0000-4000-8000-000000000000"
				.to_owned(),
		),
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
		repository_refresh_interval_secs: 60,
		osv_api_url: osv_api_url.to_owned(),
		policy_file,
		admin_token: admin_token.map(str::to_owned),
		yandex_messenger_token: None,
		yandex_messenger_template_file: None,
		yandex_messenger_api_url: "https://botapi.messenger.yandex.net"
			.to_owned(),
		yandex_messenger_enabled: false,
		trust_base_url: "https://proxy.example.invalid".to_owned(),
		trust_report_dir: "/tmp/nexus-sec-proxy-test-reports".to_owned(),
		trust_report_retention_days: 30,
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
	#[cfg(feature = "yandex-messenger")]
	let yandex_messenger =
		yandex_messenger_from_config(&config, http_client.clone());

	Arc::new(AppState {
		config: Arc::new(config),
		nexus_base_url,
		http_client: http_client.clone(),
		cache: MokaScanCache::new(
			100,
			Duration::from_secs(60),
			Duration::from_secs(60),
		),
		osv: OsvClient::new(http_client.clone(), osv_api_url),
		artifact_scanner: None,
		#[cfg(feature = "yandex-messenger")]
		yandex_messenger,
		artifact_scanner_semaphore: Arc::new(Semaphore::new(2)),
		active_policy: Arc::new(RwLock::new(Arc::new(ActivePolicy::new(
			policy_set,
			policy_file,
			1,
		)))),
		repository_catalog: Arc::new(RwLock::new(Arc::new(
			test_repository_catalog(repositories),
		))),
		repository_catalog_reload: Arc::new(AsyncMutex::new(())),
		decision_log: DecisionLog::new(100),
		report_store: {
			let directory = tempfile::tempdir().unwrap().keep();
			crate::trust_reports::ReportStore::for_test(
				directory,
				"https://proxy.example.invalid",
				30,
			)
		},
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
