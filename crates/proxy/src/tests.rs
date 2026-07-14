use std::ffi::OsString;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::to_bytes;
#[cfg(feature = "yandex-messenger")]
use base64::Engine;
use nexus_sec_proxy_security::{PackageCoordinate, Severity, Vulnerability};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::{Json, Router};
use nexus_sec_proxy_cache::{CacheKey, CachedScan, MokaScanCache, ScanCache};
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

#[derive(Debug, Clone)]
struct DockerRegistryMockResponse {
	status: StatusCode,
	content_type: Option<String>,
	digest: Option<String>,
	headers: HeaderMap,
	body: String,
}

#[derive(Clone)]
struct DockerRegistryMockState {
	records: Arc<Mutex<Vec<RecordedRequest>>>,
	response: Arc<Mutex<DockerRegistryMockResponse>>,
}

#[cfg(feature = "yandex-messenger")]
#[derive(Clone)]
struct YandexMockState {
	records: Arc<Mutex<Vec<RecordedRequest>>>,
	response: Value,
	status: StatusCode,
}

#[cfg(feature = "yandex-messenger")]
#[derive(Clone)]
struct YandexRetryMockState {
	records: Arc<Mutex<Vec<RecordedRequest>>>,
	attempts: Arc<AtomicUsize>,
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

fn docker_registry_mock(
	response: DockerRegistryMockResponse,
) -> DockerRegistryMockState {
	DockerRegistryMockState {
		records: Arc::new(Mutex::new(Vec::new())),
		response: Arc::new(Mutex::new(response)),
	}
}

fn docker_response(
	content_type: Option<&str>,
	digest: Option<&str>,
	body: &str,
) -> DockerRegistryMockResponse {
	DockerRegistryMockResponse {
		status: StatusCode::OK,
		content_type: content_type.map(str::to_owned),
		digest: digest.map(str::to_owned),
		headers: HeaderMap::new(),
		body: body.to_owned(),
	}
}

fn set_docker_response(
	state: &DockerRegistryMockState,
	response: DockerRegistryMockResponse,
) {
	*state.response.lock().unwrap() = response;
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
	let path = uri.path().to_owned();
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

	if path == "/service/rest/v1/security/users" {
		return (
			StatusCode::OK,
			Json(json!([{
				"userId": "alice",
				"emailAddress": "alice@example.com",
				"status": "active"
			}])),
		)
			.into_response();
	}

	response_with_text(StatusCode::OK, "nexus\n")
}

async fn mock_docker_registry(
	State(state): State<DockerRegistryMockState>,
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

	let response = state.response.lock().unwrap().clone();
	let mut builder = Response::builder().status(response.status);
	if let Some(content_type) = response.content_type {
		builder = builder.header(CONTENT_TYPE, content_type);
	}
	if let Some(digest) = response.digest {
		builder = builder.header("Docker-Content-Digest", digest);
	}
	for (name, value) in &response.headers {
		builder = builder.header(name, value);
	}

	builder.body(Body::from(response.body)).unwrap()
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

#[cfg(feature = "yandex-messenger")]
async fn mock_retrying_yandex_messenger(
	State(state): State<YandexRetryMockState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	body: Body,
) -> Response<Body> {
	let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
	state.records.lock().unwrap().push(RecordedRequest {
		method,
		path_and_query: uri.path().to_owned(),
		headers,
		body,
	});
	let attempt = state.attempts.fetch_add(1, Ordering::SeqCst);
	if attempt < 2 {
		(
			StatusCode::SERVICE_UNAVAILABLE,
			Json(json!({ "ok": false })),
		)
			.into_response()
	} else {
		(StatusCode::OK, Json(json!({ "ok": true }))).into_response()
	}
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
async fn repository_catalog_validates_configured_docker_repository() {
	let app = Router::new().route(
		"/service/rest/v1/repositories",
		get(|| async {
			Json(json!([
				{
					"name": "docker-proxy",
					"format": "docker",
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
	config.docker_registry_base_url =
		Some("http://nexus.example.invalid:5000".to_owned());
	config.docker_repository_name = Some("docker-proxy".to_owned());
	let client = reqwest::Client::new();

	let catalog = load_repository_catalog(&client, &nexus_base_url, &config, 1)
		.await
		.unwrap();

	assert_eq!(catalog.get("docker-proxy").unwrap().format, "docker");
	assert_eq!(
		config.artifact_scanner_for_format("docker"),
		None,
		"repository config alone must not enable Docker scanning"
	);
}

#[tokio::test]
async fn repository_catalog_rejects_missing_or_non_docker_configured_repository()
 {
	for (body, expected) in [
		(
			json!([
				{"name": "npm-proxy", "format": "npm", "type": "proxy"}
			]),
			"was not found",
		),
		(
			json!([
				{"name": "docker-proxy", "format": "raw", "type": "proxy"}
			]),
			"expected docker",
		),
	] {
		let app = Router::new().route(
			"/service/rest/v1/repositories",
			get({
				let body = body.clone();
				move || async move { Json(body) }
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
		config.docker_registry_base_url =
			Some("http://nexus.example.invalid:5000".to_owned());
		config.docker_repository_name = Some("docker-proxy".to_owned());
		let client = reqwest::Client::new();

		let error =
			load_repository_catalog(&client, &nexus_base_url, &config, 1)
				.await
				.unwrap_err();

		assert!(error.to_string().contains(expected));
	}
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
	assert_eq!(
		report_response.headers()["x-robots-tag"],
		"noindex, nofollow, noarchive"
	);
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
async fn yandex_transient_retries_reuse_payload_id_and_update_status() {
	let records = Arc::new(Mutex::new(Vec::new()));
	let url = spawn_server(
		Router::new()
			.route(
				"/bot/v1/messages/sendText/",
				post(mock_retrying_yandex_messenger),
			)
			.with_state(YandexRetryMockState {
				records: Arc::clone(&records),
				attempts: Arc::new(AtomicUsize::new(0)),
			}),
	)
	.await;
	let template = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(template.path(), "blocked {user}").unwrap();
	let notifier =
		nexus_sec_proxy_yandex_messenger::YandexMessengerNotifier::new(
			nexus_sec_proxy_yandex_messenger::YandexMessengerConfig::new(
				"bot-token",
				template.path(),
				url,
			),
			reqwest::Client::new(),
		);
	notifier.notify_blocked(
		nexus_sec_proxy_yandex_messenger::BlockNotification {
			login: "alice@example.com".to_owned(),
			repository: "maven-central".to_owned(),
			format: "maven2".to_owned(),
			target: "Maven:com.example:demo@1.2.3".to_owned(),
			reason: "blocked".to_owned(),
			policy_id: Some("default".to_owned()),
			vulnerability_ids: vec!["CVE-2026-0001".to_owned()],
			report_url: "https://proxy.example.invalid/trust/reports/id"
				.to_owned(),
		},
	);
	tokio::time::timeout(Duration::from_secs(2), async {
		while notifier.status().sent != 1 {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.unwrap();

	let status = notifier.status();
	assert_eq!(status.sent, 1);
	assert_eq!(status.retried, 2);
	assert_eq!(status.failed, 0);
	let payload_ids = records
		.lock()
		.unwrap()
		.iter()
		.map(|record| {
			serde_json::from_slice::<Value>(&record.body).unwrap()["payload_id"]
				.as_str()
				.unwrap()
				.to_owned()
		})
		.collect::<Vec<_>>();
	assert_eq!(payload_ids.len(), 3);
	assert!(payload_ids.windows(2).all(|pair| pair[0] == pair[1]));
	notifier.shutdown(Duration::from_secs(1)).await;
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
	config.nexus_username = Some("service-user".to_owned());
	config.nexus_password = Some("service-password".to_owned());
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
	assert_eq!(nexus_records.lock().unwrap().len(), 2);
	{
		let records = nexus_records.lock().unwrap();
		assert_eq!(records[0].method, Method::HEAD);
		assert_eq!(records[0].headers[AUTHORIZATION], "Basic YWxpY2U6c2VjcmV0");
		assert_eq!(records[1].method, Method::GET);
		assert_eq!(
			records[1].path_and_query,
			"/service/rest/v1/security/users?userId=alice"
		);
		assert_eq!(
			records[1].headers[AUTHORIZATION],
			"Basic c2VydmljZS11c2VyOnNlcnZpY2UtcGFzc3dvcmQ="
		);
	}
	assert_eq!(osv_count.load(Ordering::SeqCst), 1);

	{
		let records = yandex_records.lock().unwrap();
		assert_eq!(records[0].method, Method::POST);
		assert_eq!(records[0].path_and_query, "/bot/v1/messages/sendText/");
		assert_eq!(records[0].headers[AUTHORIZATION], "OAuth bot-token");
		let body: Value = serde_json::from_slice(&records[0].body).unwrap();
		assert_eq!(body["login"], "alice@example.com");
		assert!(
			body["payload_id"]
				.as_str()
				.unwrap()
				.starts_with("nexus-sec-proxy-")
		);
		let text = body["text"].as_str().unwrap();
		assert!(text.contains("User=alice@example.com"));
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
	assert_eq!(nexus_records.lock().unwrap().len(), 4);
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
	config.nexus_username = Some("service-user".to_owned());
	config.nexus_password = Some("service-password".to_owned());
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
	config.nexus_username = Some("service-user".to_owned());
	config.nexus_password = Some("service-password".to_owned());
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
	assert_eq!(nexus_records.lock().unwrap().len(), 2);
}

#[cfg(feature = "yandex-messenger")]
#[tokio::test]
async fn rejected_basic_credentials_return_nexus_response_without_report_or_message()
 {
	let nexus_url = spawn_server(
		Router::new().fallback(any(|| async { StatusCode::UNAUTHORIZED })),
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
	config.nexus_username = Some("service-user".to_owned());
	config.nexus_password = Some("service-password".to_owned());
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("maven-central", "maven2", None)],
	);
	let app = build_app(Arc::clone(&state));

	let response = app
		.oneshot(
			Request::builder()
				.uri(
					"/repository/maven-central/com/example/demo/1.2.3/demo-1.2.3.jar",
				)
				.header(AUTHORIZATION, "Basic YWxpY2U6d3Jvbmc=")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	assert!(state.decision_log.list(10).is_empty());
	assert_eq!(
		std::fs::read_dir(state.report_store.directory())
			.unwrap()
			.count(),
		0
	);
	assert!(yandex_records.lock().unwrap().is_empty());
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
async fn unmapped_artifact_target_with_block_policy_returns_403_before_nexus() {
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
		vec![test_repository("helm-proxy", "helm", None)],
	);
	let app = build_app(state.clone());

	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/repository/helm-proxy/charts/demo-1.2.3.tgz")
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
		"helm-proxy".to_owned()
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
	assert!(
		report_html.contains("artifact format helm is not mapped to a scanner")
	);
	assert!(
		report_html
			.contains("No vulnerabilities are associated with this block.")
	);
}

#[tokio::test]
async fn docker_v2_ping_and_blob_requests_forward_to_docker_registry() {
	let docker = docker_registry_mock(docker_response(None, None, "docker\n"));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker.clone()),
	)
	.await;
	let state =
		docker_test_state(&docker_url, Some(ArtifactScannerKind::Trivy));
	let app = build_app(state);

	let ping = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/v2/")
				.header("Authorization", "Bearer client-token")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(ping.status(), StatusCode::OK);
	assert_eq!(response_text(ping).await, "docker\n");

	let blob = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/v2/library/alpine/blobs/sha256:abc123")
				.header("Range", "bytes=0-10")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(blob.status(), StatusCode::OK);

	let unsupported = app
		.oneshot(
			Request::builder()
				.method(Method::POST)
				.uri("/v2/library/alpine/blobs/uploads/")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(unsupported.status(), StatusCode::METHOD_NOT_ALLOWED);
	let unsupported_body = response_json(unsupported).await;
	assert_eq!(unsupported_body["errors"][0]["code"], "UNSUPPORTED");

	let records = docker.records.lock().unwrap();
	assert_eq!(records.len(), 2);
	assert_eq!(records[0].path_and_query, "/v2/");
	assert_eq!(
		records[0]
			.headers
			.get("Authorization")
			.and_then(|value| value.to_str().ok()),
		Some("Bearer client-token")
	);
	assert_eq!(
		records[1].path_and_query,
		"/v2/library/alpine/blobs/sha256:abc123"
	);
	assert_eq!(
		records[1]
			.headers
			.get("Range")
			.and_then(|value| value.to_str().ok()),
		Some("bytes=0-10")
	);
}

#[tokio::test]
async fn docker_auth_challenge_rewrites_realm_to_proxy_host() {
	let docker = docker_registry_mock(docker_response(None, None, ""));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker.clone()),
	)
	.await;
	let internal_realm = docker_url.join("/v2/token").unwrap();
	let mut registry_response = docker_response(None, None, "unauthorized\n");
	registry_response.status = StatusCode::UNAUTHORIZED;
	registry_response.headers.insert(
		WWW_AUTHENTICATE,
		format!(
			"Bearer realm=\"{internal_realm}\",service=\"{internal_realm}\""
		)
		.parse()
		.unwrap(),
	);
	set_docker_response(&docker, registry_response);
	let state =
		docker_test_state(&docker_url, Some(ArtifactScannerKind::Trivy));

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/v2/")
				.header("Host", "proxy.example.test")
				.header("X-Forwarded-Proto", "https")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	let challenge = response
		.headers()
		.get(WWW_AUTHENTICATE)
		.and_then(|value| value.to_str().ok())
		.unwrap();
	assert!(
		challenge.contains("realm=\"https://proxy.example.test/v2/token\"")
	);
	assert!(challenge.contains(&format!("service=\"{internal_realm}\"")));
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn docker_manifest_index_forwards_without_scanner() {
	let temp_dir = tempfile::tempdir().unwrap();
	let scanner_record = temp_dir.path().join("scanner-paths.txt");
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_trivy(temp_dir.path(), &scanner_record, r#"{"Results":[]}"#);
	let docker = docker_registry_mock(docker_response(
		Some("application/vnd.docker.distribution.manifest.list.v2+json"),
		Some("sha256:index"),
		r#"{"schemaVersion":2,"manifests":[]}"#,
	));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker.clone()),
	)
	.await;
	let state =
		docker_test_state(&docker_url, Some(ArtifactScannerKind::Trivy));
	let app = build_app(state);

	let response = app
		.oneshot(
			Request::builder()
				.uri("/v2/library/alpine/manifests/latest")
				.header(
					"Accept",
					"application/vnd.docker.distribution.manifest.list.v2+json",
				)
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(
		response.headers().get(CONTENT_TYPE).unwrap(),
		"application/vnd.docker.distribution.manifest.list.v2+json"
	);
	assert!(!scanner_record.exists());
	assert_eq!(docker.records.lock().unwrap().len(), 1);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn docker_attestation_manifest_forwards_without_scanner() {
	let temp_dir = tempfile::tempdir().unwrap();
	let scanner_record = temp_dir.path().join("scanner-paths.txt");
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_trivy(temp_dir.path(), &scanner_record, r#"{"Results":[]}"#);
	let docker = docker_registry_mock(docker_response(
		Some("application/vnd.oci.image.manifest.v1+json"),
		Some("sha256:attestation"),
		r#"{"schemaVersion":2,"layers":[{"mediaType":"application/vnd.in-toto+json","digest":"sha256:abc","size":42}]}"#,
	));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker.clone()),
	)
	.await;
	let state =
		docker_test_state(&docker_url, Some(ArtifactScannerKind::Trivy));

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/v2/library/alpine/manifests/sha256:attestation")
				.header("Accept", "application/vnd.oci.image.manifest.v1+json")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	assert!(response_text(response).await.contains("in-toto"));
	assert_eq!(docker.records.lock().unwrap().len(), 1);
	assert!(!scanner_record.exists());
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn docker_concrete_manifest_scans_by_digest_and_reuses_cache() {
	let temp_dir = tempfile::tempdir().unwrap();
	let scanner_record = temp_dir.path().join("scanner-paths.txt");
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_trivy(temp_dir.path(), &scanner_record, r#"{"Results":[]}"#);
	let digest = "sha256:1111222233334444";
	let docker = docker_registry_mock(docker_response(
		Some("application/vnd.docker.distribution.manifest.v2+json"),
		Some(digest),
		r#"{"schemaVersion":2,"config":{},"layers":[]}"#,
	));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker.clone()),
	)
	.await;
	let state =
		docker_test_state(&docker_url, Some(ArtifactScannerKind::Trivy));
	let app = build_app(state);

	let latest = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/v2/library/alpine/manifests/latest")
				.header(
					"Accept",
					"application/vnd.docker.distribution.manifest.v2+json",
				)
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(latest.status(), StatusCode::OK);
	assert_eq!(
		response_text(latest).await,
		r#"{"schemaVersion":2,"config":{},"layers":[]}"#
	);

	set_docker_response(
		&docker,
		docker_response(
			Some("application/vnd.docker.distribution.manifest.v2+json"),
			None,
			r#"{"schemaVersion":2,"config":{},"layers":[]}"#,
		),
	);
	let by_digest = app
		.oneshot(
			Request::builder()
				.uri(format!("/v2/library/alpine/manifests/{digest}"))
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(by_digest.status(), StatusCode::OK);

	let records = docker.records.lock().unwrap();
	assert_eq!(records.len(), 2);
	assert_eq!(
		records[0].path_and_query,
		"/v2/library/alpine/manifests/latest"
	);
	assert_eq!(
		records[0]
			.headers
			.get("Accept")
			.and_then(|value| value.to_str().ok()),
		Some("application/vnd.docker.distribution.manifest.v2+json")
	);
	assert_eq!(
		records[1].path_and_query,
		format!("/v2/library/alpine/manifests/{digest}")
	);
	drop(records);

	let scanner_paths = std::fs::read_to_string(scanner_record).unwrap();
	let scanner_paths = scanner_paths.lines().collect::<Vec<_>>();
	assert_eq!(scanner_paths.len(), 1);
	assert_eq!(
		scanner_paths[0],
		format!(
			"{}:{}/library/alpine@{digest}",
			docker_url.host_str().unwrap(),
			docker_url.port().unwrap()
		)
	);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn docker_blocked_manifest_creates_trust_report() {
	let temp_dir = tempfile::tempdir().unwrap();
	let scanner_record = temp_dir.path().join("scanner-paths.txt");
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_trivy(
		temp_dir.path(),
		&scanner_record,
		r#"{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","Title":"bad image","Description":"bad","Severity":"HIGH","References":[]}]}]}"#,
	);
	let docker = docker_registry_mock(docker_response(
		Some("application/vnd.oci.image.manifest.v1+json"),
		Some("sha256:blockme"),
		r#"{"schemaVersion":2}"#,
	));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker),
	)
	.await;
	let state =
		docker_test_state(&docker_url, Some(ArtifactScannerKind::Trivy));
	let app = build_app(state.clone());

	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.uri("/v2/library/alpine/manifests/3.20")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	let body = response_text(response).await;
	assert!(body.contains("CVE-2026-0001"));
	let report_url = report_url_from_body(&body);
	let decisions = state.decision_log.list(10);
	assert_eq!(decisions[0].repository, "docker-proxy");
	assert_eq!(decisions[0].format, "docker");
	assert_eq!(decisions[0].report_url.as_deref(), Some(report_url));

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
	assert!(
		response_text(report_response)
			.await
			.contains("CVE-2026-0001")
	);
}

#[cfg(all(unix, feature = "yandex-messenger"))]
#[tokio::test(flavor = "current_thread")]
async fn accepted_docker_bearer_subject_resolves_nexus_email_for_yandex() {
	let temp_dir = tempfile::tempdir().unwrap();
	let scanner_record = temp_dir.path().join("scanner-paths.txt");
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_trivy(
		temp_dir.path(),
		&scanner_record,
		r#"{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","Severity":"HIGH","References":[]}]}]}"#,
	);
	let docker = docker_registry_mock(docker_response(
		Some("application/vnd.oci.image.manifest.v1+json"),
		Some("sha256:blockme"),
		r#"{"schemaVersion":2}"#,
	));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker.clone()),
	)
	.await;
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
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
	let template = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(template.path(), "blocked {user}").unwrap();
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config.docker_registry_base_url = Some(docker_url.to_string());
	config.docker_repository_name = Some("docker-proxy".to_owned());
	config
		.artifact_scanner_formats
		.insert("docker".to_owned(), ArtifactScannerKind::Trivy);
	config.fail_open = false;
	config.yandex_messenger_enabled = true;
	config.yandex_messenger_token = Some("bot-token".to_owned());
	config.yandex_messenger_template_file =
		Some(template.path().to_string_lossy().into_owned());
	config.yandex_messenger_api_url = yandex_url.to_string();
	config.nexus_username = Some("service-user".to_owned());
	config.nexus_password = Some("service-password".to_owned());
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("docker-proxy", "docker", None)],
	);
	let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
		.encode(br#"{"sub":"alice"}"#);
	let authorization = format!("Bearer e30.{payload}.signature");

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/v2/library/alpine/manifests/3.20")
				.header(AUTHORIZATION, &authorization)
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	wait_for_record_count(&yandex_records, 1).await;
	let yandex_body: Value =
		serde_json::from_slice(&yandex_records.lock().unwrap()[0].body)
			.unwrap();
	assert_eq!(yandex_body["login"], "alice@example.com");
	assert_eq!(nexus_records.lock().unwrap().len(), 1);
	assert_eq!(nexus_records.lock().unwrap()[0].method, Method::GET);
	assert_eq!(
		docker.records.lock().unwrap()[0].headers[AUTHORIZATION],
		authorization
	);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn docker_scanner_failures_follow_fail_open() {
	let temp_dir = tempfile::tempdir().unwrap();
	let scanner_record = temp_dir.path().join("scanner-paths.txt");
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_trivy(temp_dir.path(), &scanner_record, "not json");
	let docker = docker_registry_mock(docker_response(
		Some("application/vnd.docker.distribution.manifest.v2+json"),
		Some("sha256:badscan"),
		"manifest",
	));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker.clone()),
	)
	.await;

	for (fail_open, expected_status) in [
		(true, StatusCode::OK),
		(false, StatusCode::SERVICE_UNAVAILABLE),
	] {
		let mut config = test_config(
			None,
			None,
			PolicySet::default(),
			"http://127.0.0.1:9",
			"http://127.0.0.1:9/osv",
			UnsupportedTargetPolicy::Allow,
		);
		config.docker_registry_base_url = Some(docker_url.as_str().to_owned());
		config.docker_repository_name = Some("docker-proxy".to_owned());
		config.fail_open = fail_open;
		config
			.artifact_scanner_formats
			.insert("docker".to_owned(), ArtifactScannerKind::Trivy);
		let state = test_state_from_config(
			config,
			PolicySet::default(),
			None,
			vec![test_repository("docker-proxy", "docker", None)],
		);
		let response = build_app(state)
			.oneshot(
				Request::builder()
					.uri(format!("/v2/library/alpine/manifests/{fail_open}"))
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), expected_status);
	}
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn docker_scanner_auth_config_is_temporary() {
	let temp_dir = tempfile::tempdir().unwrap();
	let scanner_record = temp_dir.path().join("scanner-auth.txt");
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_trivy_auth_recorder(temp_dir.path(), &scanner_record);
	let docker = docker_registry_mock(docker_response(
		Some("application/vnd.docker.distribution.manifest.v2+json"),
		Some("sha256:auth"),
		"manifest",
	));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker),
	)
	.await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		"http://127.0.0.1:9",
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config.docker_registry_base_url = Some(docker_url.as_str().to_owned());
	config.docker_repository_name = Some("docker-proxy".to_owned());
	config.nexus_username = Some("svc".to_owned());
	config.nexus_password = Some("secret".to_owned());
	config.fail_open = false;
	config
		.artifact_scanner_formats
		.insert("docker".to_owned(), ArtifactScannerKind::Trivy);
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("docker-proxy", "docker", None)],
	);

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/v2/library/alpine/manifests/latest")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	let record = std::fs::read_to_string(scanner_record).unwrap();
	let mut lines = record.lines();
	let docker_config = lines.next().unwrap();
	assert!(lines.next().unwrap().contains(r#""auths""#));
	assert!(lines.next().unwrap().contains("c3ZjOnNlY3JldA=="));
	assert!(
		!std::path::Path::new(docker_config).exists(),
		"temporary DOCKER_CONFIG directory should be removed after scan"
	);
}

#[tokio::test]
async fn mapped_artifact_range_uses_unsupported_target_policy() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Block,
	);
	config
		.artifact_scanner_formats
		.insert("helm".to_owned(), ArtifactScannerKind::Trivy);
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("helm-proxy", "helm", None)],
	);
	let app = build_app(state);

	let response = app
		.oneshot(
			Request::builder()
				.uri("/repository/helm-proxy/charts/demo-1.2.3.tgz")
				.header("Range", "bytes=0-10")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
	assert!(
		response_text(response)
			.await
			.contains("artifact range requests cannot be scanned")
	);
}

#[tokio::test]
async fn cached_artifact_block_is_re_evaluated_before_nexus() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config
		.artifact_scanner_formats
		.insert("helm".to_owned(), ArtifactScannerKind::Trivy);
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("helm-proxy", "helm", None)],
	);
	state
		.cache
		.put(
			CacheKey::from_parts(
				"helm",
				"helm-proxy\n/repository/helm-proxy/charts/demo-1.2.3.tgz",
				None::<String>,
			),
			CachedScan::new(vec![vulnerability(
				"CVE-2026-0001",
				Severity::High,
			)]),
		)
		.await
		.unwrap();
	let app = build_app(state);

	let response = app
		.oneshot(
			Request::builder()
				.uri("/repository/helm-proxy/charts/demo-1.2.3.tgz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	assert_eq!(nexus_records.lock().unwrap().len(), 0);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn mapped_artifact_prefetches_once_strips_conditionals_and_reuses_cache()
{
	let temp_dir = tempfile::tempdir().unwrap();
	let scanner_record = temp_dir.path().join("scanner-images.txt");
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_helm(temp_dir.path(), "image: nginx:1.25\n");
	write_fake_trivy(temp_dir.path(), &scanner_record, r#"{"Results":[]}"#);
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config.fail_open = false;
	config.docker_registry_base_url =
		Some(format!("http://{}", nexus_url.host_str().unwrap()));
	config.docker_repository_name = Some("docker-proxy".to_owned());
	config
		.artifact_scanner_formats
		.insert("helm".to_owned(), ArtifactScannerKind::Trivy);
	config.artifact_tmp_dir =
		Some(temp_dir.path().to_string_lossy().into_owned());
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("helm-proxy", "helm", None)],
	);
	let app = build_app(state);

	for _ in 0..2 {
		let response = app
			.clone()
			.oneshot(
				Request::builder()
					.uri(
						"/repository/helm-proxy/charts/demo-1.2.3.tgz?download=1",
					)
					.header("If-None-Match", r#""old""#)
					.header(
						"If-Modified-Since",
						"Wed, 21 Oct 2015 07:28:00 GMT",
					)
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		assert_eq!(response_text(response).await, "nexus\n");
	}

	let records = nexus_records.lock().unwrap();
	assert_eq!(records.len(), 2);
	assert!(records[0].headers.get("If-None-Match").is_none());
	assert!(records[0].headers.get("If-Modified-Since").is_none());
	assert_eq!(
		records[1]
			.headers
			.get("If-None-Match")
			.and_then(|value| value.to_str().ok()),
		Some(r#""old""#)
	);
	drop(records);

	// The scanner is called once (cached on the second request). The recorded
	// argument is the resolved image reference, not the chart file path.
	let scanner_args = std::fs::read_to_string(scanner_record).unwrap();
	let scanner_args = scanner_args.lines().collect::<Vec<_>>();
	assert_eq!(scanner_args.len(), 1);
	assert!(scanner_args[0].contains("nginx:1.25"));
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn helm_chart_blocked_when_image_has_vulnerabilities() {
	let temp_dir = tempfile::tempdir().unwrap();
	let _path_guard = prepend_path(temp_dir.path());
	write_fake_helm(temp_dir.path(), "image: nginx:1.25\n");
	write_fake_trivy(
		temp_dir.path(),
		&temp_dir.path().join("unused-record.txt"),
		r#"{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"nginx","Severity":"CRITICAL","Description":"bad nginx"}]}]}"#,
	);
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Block,
	);
	config.docker_registry_base_url =
		Some(format!("http://{}", nexus_url.host_str().unwrap()));
	config.docker_repository_name = Some("docker-proxy".to_owned());
	config
		.artifact_scanner_formats
		.insert("helm".to_owned(), ArtifactScannerKind::Trivy);
	config.artifact_tmp_dir =
		Some(temp_dir.path().to_string_lossy().into_owned());
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("helm-proxy", "helm", None)],
	);

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/repository/helm-proxy/charts/demo-1.2.3.tgz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	let body = response_text(response).await;
	assert!(body.contains("CVE-2026-0001"));
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn helm_chart_passes_through_when_no_scanner_configured() {
	let nexus_records = Arc::new(Mutex::new(Vec::new()));
	let nexus_url = spawn_server(
		Router::new()
			.fallback(any(record_nexus_request))
			.with_state(Arc::clone(&nexus_records)),
	)
	.await;
	let config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("helm-proxy", "helm", None)],
	);

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/repository/helm-proxy/charts/demo-1.2.3.tgz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response_text(response).await, "nexus\n");
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
	assert_eq!(
		body["yandex_messenger"]["available"],
		cfg!(feature = "yandex-messenger")
	);
	assert_eq!(
		body["yandex_messenger"]["enabled"],
		cfg!(feature = "yandex-messenger")
	);
	assert_eq!(body["yandex_messenger"]["sent"], 0);
	assert_eq!(body["yandex_messenger"]["retried"], 0);
	assert_eq!(body["yandex_messenger"]["failed"], 0);
	assert!(!body.to_string().contains("bot-secret"));
}

#[tokio::test]
async fn admin_scanner_reports_format_routes_and_limits() {
	let mut config = test_config(
		Some("secret"),
		None,
		PolicySet::default(),
		"http://127.0.0.1:9",
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config
		.artifact_scanner_formats
		.insert("helm".to_owned(), ArtifactScannerKind::Trivy);
	config.artifact_scanner_timeout_secs = 120;
	config.artifact_scan_max_bytes = 1024;
	config.artifact_scanner_concurrency = 3;
	let app = build_app(test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("default", "npm", Some("npm"))],
	));

	let response = app
		.oneshot(
			Request::builder()
				.uri("/admin/api/scanner")
				.header(AUTHORIZATION, "Bearer secret")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	let body = response_json(response).await;
	assert_eq!(body["enabled"], true);
	assert_eq!(body["routes"]["helm"], "trivy");
	assert_eq!(body["docker_registry_configured"], false);
	assert_eq!(body["docker_repository_name"], Value::Null);
	assert_eq!(body["docker_scanner"], Value::Null);
	assert_eq!(body["timeout_secs"], 120);
	assert_eq!(body["max_bytes"], 1024);
	assert_eq!(body["concurrency"], 3);
	assert_eq!(body["available_permits"], 2);
	assert!(!body["db_files"].as_array().unwrap().is_empty());
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
}

#[tokio::test]
async fn healthz_reports_live_checks_and_unused_scanners() {
	let catalog_state = catalog_mock(
		json!([
			{"name": "npm-proxy", "format": "npm", "type": "proxy"}
		]),
		Duration::ZERO,
	);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(catalog_state),
	)
	.await;
	let state = proxy_test_state(
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		PolicySet::default(),
		UnsupportedTargetPolicy::Allow,
		vec![test_repository("npm-proxy", "npm", Some("npm"))],
	);
	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/healthz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	let body = response_json(response).await;
	assert_eq!(body["status"], "ok");
	assert_eq!(body["checks"]["nexus"], "ok");
	assert_eq!(body["checks"]["trust_reports"], "ok");
	assert_eq!(body["checks"]["docker_registry"], "unused");
	assert_eq!(body["checks"]["trivy"], "unused");
}

#[tokio::test]
async fn healthz_reports_configured_docker_registry() {
	let catalog_state = catalog_mock(
		json!([
			{"name": "docker-proxy", "format": "docker", "type": "proxy"}
		]),
		Duration::ZERO,
	);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(catalog_state),
	)
	.await;
	let docker = docker_registry_mock(docker_response(None, None, ""));
	let docker_url = spawn_server(
		Router::new()
			.fallback(any(mock_docker_registry))
			.with_state(docker),
	)
	.await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config.docker_registry_base_url = Some(docker_url.as_str().to_owned());
	config.docker_repository_name = Some("docker-proxy".to_owned());
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("docker-proxy", "docker", None)],
	);

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/healthz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::OK);
	let body = response_json(response).await;
	assert_eq!(body["checks"]["docker_registry"], "ok");
}

#[tokio::test]
async fn healthz_fails_when_nexus_catalog_is_unavailable() {
	let state = proxy_test_state(
		"http://127.0.0.1:9",
		"http://127.0.0.1:9/osv",
		PolicySet::default(),
		UnsupportedTargetPolicy::Allow,
		vec![test_repository("npm-proxy", "npm", Some("npm"))],
	);
	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/healthz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	let body = response_json(response).await;
	assert_eq!(body["status"], "failed");
	assert_eq!(body["checks"]["nexus"], "failed");
}

#[tokio::test]
async fn healthz_fails_when_trust_report_storage_is_unwritable() {
	let catalog_state = catalog_mock(
		json!([
			{"name": "npm-proxy", "format": "npm", "type": "proxy"}
		]),
		Duration::ZERO,
	);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(catalog_state),
	)
	.await;
	let state = proxy_test_state(
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		PolicySet::default(),
		UnsupportedTargetPolicy::Allow,
		vec![test_repository("npm-proxy", "npm", Some("npm"))],
	);
	let report_directory = state.report_store.directory().to_owned();
	std::fs::remove_dir_all(&report_directory).unwrap();
	std::fs::write(&report_directory, "not a directory").unwrap();

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/healthz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	let body = response_json(response).await;
	assert_eq!(body["checks"]["trust_reports"], "failed");
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn healthz_fails_when_used_scanner_database_is_missing() {
	let missing_db = tempfile::tempdir().unwrap().path().join("missing");
	let _env_guard = set_env_var("TRIVY_CACHE_DIR", missing_db.as_os_str());
	let catalog_state = catalog_mock(
		json!([
			{"name": "helm-proxy", "format": "helm", "type": "proxy"}
		]),
		Duration::ZERO,
	);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(catalog_state),
	)
	.await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config
		.artifact_scanner_formats
		.insert("helm".to_owned(), ArtifactScannerKind::Trivy);
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("helm-proxy", "helm", None)],
	);

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/healthz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	let body = response_json(response).await;
	assert_eq!(body["checks"]["trivy"], "failed");
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn healthz_fails_when_used_scanner_executable_is_missing() {
	let empty_path = tempfile::tempdir().unwrap();
	let db_dir = tempfile::tempdir().unwrap();
	std::fs::create_dir(db_dir.path().join("db")).unwrap();
	std::fs::write(db_dir.path().join("db").join("metadata.json"), "{}")
		.unwrap();
	let _env_guard = set_env_vars(vec![
		("PATH", empty_path.path().as_os_str().to_os_string()),
		("TRIVY_CACHE_DIR", db_dir.path().as_os_str().to_os_string()),
	]);
	let catalog_state = catalog_mock(
		json!([
			{"name": "helm-proxy", "format": "helm", "type": "proxy"}
		]),
		Duration::ZERO,
	);
	let nexus_url = spawn_server(
		Router::new()
			.route("/service/rest/v1/repositories", get(mock_catalog))
			.with_state(catalog_state),
	)
	.await;
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		nexus_url.as_str(),
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config
		.artifact_scanner_formats
		.insert("helm".to_owned(), ArtifactScannerKind::Trivy);
	let state = test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("helm-proxy", "helm", None)],
	);

	let response = build_app(state)
		.oneshot(
			Request::builder()
				.uri("/healthz")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	let body = response_json(response).await;
	assert_eq!(body["checks"]["trivy"], "failed");
}

#[cfg(unix)]
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[cfg(unix)]
struct PathGuard {
	_guard: std::sync::MutexGuard<'static, ()>,
	old_path: Option<OsString>,
}

#[cfg(unix)]
impl Drop for PathGuard {
	fn drop(&mut self) {
		match &self.old_path {
			Some(path) => unsafe {
				std::env::set_var("PATH", path);
			},
			None => unsafe {
				std::env::remove_var("PATH");
			},
		}
	}
}

#[cfg(unix)]
fn prepend_path(path: &std::path::Path) -> PathGuard {
	let guard = ENV_LOCK.lock().unwrap();
	let old_path = std::env::var_os("PATH");
	let mut paths = vec![path.to_path_buf()];
	if let Some(old_path) = &old_path {
		paths.extend(std::env::split_paths(old_path));
	}
	let joined = std::env::join_paths(paths).unwrap();
	unsafe {
		std::env::set_var("PATH", joined);
	}

	PathGuard {
		_guard: guard,
		old_path,
	}
}

#[cfg(unix)]
struct EnvVarGuard {
	_guard: std::sync::MutexGuard<'static, ()>,
	name: &'static str,
	old_value: Option<OsString>,
}

#[cfg(unix)]
impl Drop for EnvVarGuard {
	fn drop(&mut self) {
		match &self.old_value {
			Some(value) => unsafe {
				std::env::set_var(self.name, value);
			},
			None => unsafe {
				std::env::remove_var(self.name);
			},
		}
	}
}

#[cfg(unix)]
fn set_env_var(name: &'static str, value: &std::ffi::OsStr) -> EnvVarGuard {
	let guard = ENV_LOCK.lock().unwrap();
	let old_value = std::env::var_os(name);
	unsafe {
		std::env::set_var(name, value);
	}

	EnvVarGuard {
		_guard: guard,
		name,
		old_value,
	}
}

#[cfg(unix)]
struct EnvVarsGuard {
	_guard: std::sync::MutexGuard<'static, ()>,
	old_values: Vec<(&'static str, Option<OsString>)>,
}

#[cfg(unix)]
impl Drop for EnvVarsGuard {
	fn drop(&mut self) {
		for (name, old_value) in &self.old_values {
			match old_value {
				Some(value) => unsafe {
					std::env::set_var(*name, value);
				},
				None => unsafe {
					std::env::remove_var(*name);
				},
			}
		}
	}
}

#[cfg(unix)]
fn set_env_vars(values: Vec<(&'static str, OsString)>) -> EnvVarsGuard {
	let guard = ENV_LOCK.lock().unwrap();
	let old_values = values
		.iter()
		.map(|(name, _)| (*name, std::env::var_os(name)))
		.collect();
	for (name, value) in values {
		unsafe {
			std::env::set_var(name, value);
		}
	}

	EnvVarsGuard {
		_guard: guard,
		old_values,
	}
}

#[cfg(unix)]
fn write_fake_trivy(
	directory: &std::path::Path,
	record_path: &std::path::Path,
	output: &str,
) {
	use std::os::unix::fs::PermissionsExt;

	let script = format!(
		r#"#!/bin/sh
if [ "$1" = "--version" ]; then
	echo "Version: fake"
	exit 0
fi
last=""
for arg in "$@"; do
	last="$arg"
done
printf '%s\n' "$last" >> "{}"
cat <<'JSON'
{}
JSON
"#,
		record_path.display(),
		output
	);
	let path = directory.join("trivy");
	std::fs::write(&path, script).unwrap();
	let mut permissions = std::fs::metadata(&path).unwrap().permissions();
	permissions.set_mode(0o755);
	std::fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn write_fake_helm(directory: &std::path::Path, rendered: &str) {
	use std::os::unix::fs::PermissionsExt;

	let script = format!(
		r#"#!/bin/sh
# fake helm: ignore args, print rendered manifests
cat <<'YAML'
{rendered}
YAML
"#,
	);
	let path = directory.join("helm");
	std::fs::write(&path, script).unwrap();
	let mut permissions = std::fs::metadata(&path).unwrap().permissions();
	permissions.set_mode(0o755);
	std::fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn write_fake_trivy_auth_recorder(
	directory: &std::path::Path,
	record_path: &std::path::Path,
) {
	use std::os::unix::fs::PermissionsExt;

	let script = format!(
		r#"#!/bin/sh
if [ "$1" = "--version" ]; then
	echo "Version: fake"
	exit 0
fi
printf '%s\n' "$DOCKER_CONFIG" >> "{record}"
cat "$DOCKER_CONFIG/config.json" >> "{record}"
printf '\n' >> "{record}"
grep '"auth"' "$DOCKER_CONFIG/config.json" >> "{record}"
cat <<'JSON'
{{"Results":[]}}
JSON
"#,
		record = record_path.display(),
	);
	let path = directory.join("trivy");
	std::fs::write(&path, script).unwrap();
	let mut permissions = std::fs::metadata(&path).unwrap().permissions();
	permissions.set_mode(0o755);
	std::fs::set_permissions(path, permissions).unwrap();
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

fn docker_test_state(
	docker_registry_url: &Url,
	scanner: Option<ArtifactScannerKind>,
) -> Arc<AppState> {
	let mut config = test_config(
		None,
		None,
		PolicySet::default(),
		"http://127.0.0.1:9",
		"http://127.0.0.1:9/osv",
		UnsupportedTargetPolicy::Allow,
	);
	config.docker_registry_base_url =
		Some(docker_registry_url.as_str().to_owned());
	config.docker_repository_name = Some("docker-proxy".to_owned());
	config.fail_open = false;
	if let Some(scanner) = scanner {
		config
			.artifact_scanner_formats
			.insert("docker".to_owned(), scanner);
	}

	test_state_from_config(
		config,
		PolicySet::default(),
		None,
		vec![test_repository("docker-proxy", "docker", None)],
	)
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
		docker_registry_base_url: None,
		docker_repository_name: None,
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
		artifact_scanner_formats: Default::default(),
		artifact_scanner_skip_db_update: true,
		artifact_scanner_offline: true,
		artifact_scanner_timeout_secs: 300,
		artifact_scan_max_bytes: 512 * 1024 * 1024,
		artifact_scanner_concurrency: 2,
		artifact_tmp_dir: None,
		helm_binary: "helm".to_owned(),
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
		if config.yandex_messenger_enabled {
			Some(nexus_sec_proxy_yandex_messenger::YandexMessengerNotifier::new(
			nexus_sec_proxy_yandex_messenger::YandexMessengerConfig::new(
				config.yandex_messenger_token.clone().unwrap(),
				config.yandex_messenger_template_file.clone().unwrap(),
				config.yandex_messenger_api_url.clone(),
			),
			http_client.clone(),
		))
		} else {
			None
		};

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
