mod classifier;

use std::collections::VecDeque;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header::{
	AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST, TRANSFER_ENCODING,
};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::{Json, Router};
use classifier::{RequestClassification, classify_request};
use futures_util::StreamExt;
use nexus_sec_proxy_cache::{
	CacheKey, CacheStats, CachedScan, MokaScanCache, ScanCache,
};
use nexus_sec_proxy_config::{
	AppConfig, ArtifactScannerKind, UnsupportedTargetPolicy, load_policy_file,
	parse_policy_toml,
};
use nexus_sec_proxy_security::{
	BlockReport, EnforcementMode, ExternalScanner, ExternalScannerKind,
	OsvClient, PolicyContext, PolicyEvaluation, PolicyEvaluator, PolicyOutcome,
	PolicySet, ScanTarget, SecurityError, VulnerabilitySource,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio_util::io::ReaderStream;
use tracing::{error, info, warn};
use url::Url;

#[derive(Clone)]
struct AppState {
	config: Arc<AppConfig>,
	upstream_base_url: Url,
	http_client: reqwest::Client,
	cache: MokaScanCache,
	osv: OsvClient,
	artifact_scanner: Option<ExternalScanner>,
	artifact_scanner_semaphore: Arc<Semaphore>,
	active_policy: Arc<RwLock<Arc<ActivePolicy>>>,
	decision_log: DecisionLog,
	started_at: Instant,
	started_at_rfc3339: String,
}

impl AppState {
	fn active_policy(&self) -> Arc<ActivePolicy> {
		match self.active_policy.read() {
			Ok(policy) => Arc::clone(&policy),
			Err(error) => {
				error!("active policy lock was poisoned");
				let policy = error.into_inner();
				Arc::clone(&policy)
			}
		}
	}

	fn reload_active_policy(
		&self,
		policy_set: PolicySet,
		source_path: Option<String>,
	) -> Arc<ActivePolicy> {
		match self.active_policy.write() {
			Ok(mut active_policy) => {
				let generation = active_policy.generation + 1;
				let next = Arc::new(ActivePolicy::new(
					policy_set,
					&self.config.repository_name,
					&self.config.repository_format,
					source_path,
					generation,
				));
				*active_policy = Arc::clone(&next);
				next
			}
			Err(error) => {
				error!("active policy lock was poisoned while reloading");
				let mut active_policy = error.into_inner();
				let generation = active_policy.generation + 1;
				let next = Arc::new(ActivePolicy::new(
					policy_set,
					&self.config.repository_name,
					&self.config.repository_format,
					source_path,
					generation,
				));
				*active_policy = Arc::clone(&next);
				next
			}
		}
	}
}

#[derive(Debug, Clone)]
struct ActivePolicy {
	policy_set: PolicySet,
	evaluator: PolicyEvaluator,
	context: PolicyContext,
	source_path: Option<String>,
	loaded_at: String,
	generation: u64,
	selected_policy_id: String,
	selected_policy_mode: EnforcementMode,
}

impl ActivePolicy {
	fn new(
		policy_set: PolicySet,
		repository_name: &str,
		repository_format: &str,
		source_path: Option<String>,
		generation: u64,
	) -> Self {
		let context = policy_set.context(repository_name, repository_format);
		let selected_policy = policy_set.select_policy(&context);
		let selected_policy_id = selected_policy.id.clone();
		let selected_policy_mode = selected_policy.mode;
		let evaluator = PolicyEvaluator::from_policy_set(policy_set.clone());

		Self {
			policy_set,
			evaluator,
			context,
			source_path,
			loaded_at: now_rfc3339(),
			generation,
			selected_policy_id,
			selected_policy_mode,
		}
	}

	fn summary(&self) -> ActivePolicySummary {
		ActivePolicySummary {
			generation: self.generation,
			source_path: self.source_path.clone(),
			loaded_at: self.loaded_at.clone(),
			context: self.context.clone(),
			selected_policy_id: self.selected_policy_id.clone(),
			selected_policy_mode: self.selected_policy_mode,
		}
	}
}

#[derive(Debug, Clone)]
struct DecisionLog {
	inner: Arc<Mutex<VecDeque<RecentDecision>>>,
	capacity: usize,
}

impl DecisionLog {
	fn new(capacity: usize) -> Self {
		Self {
			inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
			capacity,
		}
	}

	fn push(&self, decision: RecentDecision) {
		match self.inner.lock() {
			Ok(mut decisions) => {
				decisions.push_front(decision);
				while decisions.len() > self.capacity {
					decisions.pop_back();
				}
			}
			Err(error) => {
				error!("decision log lock was poisoned");
				let mut decisions = error.into_inner();
				decisions.push_front(decision);
				while decisions.len() > self.capacity {
					decisions.pop_back();
				}
			}
		}
	}

	fn list(&self, limit: usize) -> Vec<RecentDecision> {
		match self.inner.lock() {
			Ok(decisions) => decisions.iter().take(limit).cloned().collect(),
			Err(error) => {
				error!("decision log lock was poisoned");
				error.into_inner().iter().take(limit).cloned().collect()
			}
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RecentDecision {
	timestamp: String,
	repository: String,
	format: String,
	team: Option<String>,
	target: String,
	outcome: DecisionOutcome,
	policy_id: Option<String>,
	reason: String,
	vulnerability_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DecisionOutcome {
	Blocked,
	ReportOnly,
}

#[derive(Debug, Clone, Serialize)]
struct ActivePolicySummary {
	generation: u64,
	source_path: Option<String>,
	loaded_at: String,
	context: PolicyContext,
	selected_policy_id: String,
	selected_policy_mode: EnforcementMode,
}

#[derive(Debug, Clone, Serialize)]
struct ImmutableConfigSummary {
	bind_addr: String,
	upstream_base_url: String,
	repository_name: String,
	repository_format: String,
	osv_ecosystem: Option<String>,
	osv_api_url: String,
	policy_file: Option<String>,
	fail_open: bool,
	unsupported_target_policy: UnsupportedTargetPolicy,
	request_timeout_secs: u64,
	artifact_tmp_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CacheSummary {
	clean_entry_count: u64,
	vulnerable_entry_count: u64,
	total_entry_count: u64,
	allowed_ttl_secs: u64,
	blocked_ttl_secs: u64,
	max_capacity: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ScannerSummary {
	enabled: bool,
	kind: ArtifactScannerKind,
	command: String,
	skip_db_update: bool,
	offline: bool,
	timeout_secs: u64,
	max_bytes: u64,
	concurrency: u64,
	available_permits: usize,
	db_files: Vec<ScannerDbSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ScannerDbSummary {
	env_var: String,
	cache_dir: Option<String>,
	status: ScannerDbStatus,
	db_file: Option<String>,
	modified_at: Option<String>,
	age_seconds: Option<u64>,
	error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScannerDbStatus {
	NotConfigured,
	Missing,
	NotDirectory,
	NotFound,
	Unreadable,
	Found,
}

#[derive(Debug, Clone, Serialize)]
struct StatusResponse {
	started_at: String,
	uptime_seconds: u64,
	immutable_config: ImmutableConfigSummary,
	active_policy: ActivePolicySummary,
	cache: CacheSummary,
	scanner: ScannerSummary,
}

#[derive(Debug, Clone, Serialize)]
struct PolicyResponse {
	active_policy: ActivePolicySummary,
	policy_set: PolicySet,
}

#[derive(Debug, Clone, Serialize)]
struct ReloadPolicyResponse {
	reloaded: bool,
	active_policy: ActivePolicySummary,
}

#[derive(Debug, Clone, Deserialize)]
struct ValidatePolicyRequest {
	policy_toml: String,
	repository_name: Option<String>,
	repository_format: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ValidatePolicyResponse {
	valid: bool,
	context: PolicyContext,
	selected_policy_id: String,
	selected_policy_mode: EnforcementMode,
}

#[derive(Debug, Clone, Deserialize)]
struct DecisionsQuery {
	limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct DecisionsResponse {
	limit: usize,
	decisions: Vec<RecentDecision>,
}

#[derive(Debug, Clone, Serialize)]
struct ErrorResponse {
	error: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	details: Option<String>,
}

const ADMIN_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nexus-sec-proxy admin</title>
<style>
:root {
	color-scheme: light dark;
	font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
	background: #f6f7f9;
	color: #17202a;
}
body {
	margin: 0;
}
main {
	max-width: 1180px;
	margin: 0 auto;
	padding: 24px;
}
header {
	display: flex;
	gap: 16px;
	align-items: center;
	justify-content: space-between;
	margin-bottom: 18px;
}
h1 {
	font-size: 22px;
	margin: 0;
	font-weight: 650;
}
.token {
	display: flex;
	gap: 8px;
	align-items: center;
}
input {
	min-width: 280px;
	padding: 8px 10px;
	border: 1px solid #b8c0cc;
	border-radius: 6px;
	background: #fff;
	color: inherit;
}
button {
	border: 1px solid #8592a3;
	border-radius: 6px;
	background: #fff;
	color: inherit;
	padding: 8px 11px;
	cursor: pointer;
}
button.primary {
	background: #155eef;
	border-color: #155eef;
	color: #fff;
}
.grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
	gap: 14px;
}
section {
	background: #fff;
	border: 1px solid #d7dce3;
	border-radius: 8px;
	padding: 14px;
	min-width: 0;
}
h2 {
	font-size: 15px;
	margin: 0 0 10px;
}
pre {
	white-space: pre-wrap;
	word-break: break-word;
	margin: 0;
	font-size: 12px;
	line-height: 1.45;
}
.error {
	color: #b42318;
}
@media (prefers-color-scheme: dark) {
	:root {
		background: #121417;
		color: #e5e7eb;
	}
	section, button, input {
		background: #191d23;
		border-color: #343b45;
	}
	button.primary {
		background: #3b82f6;
		border-color: #3b82f6;
	}
}
</style>
</head>
<body>
<main>
<header>
<h1>nexus-sec-proxy admin</h1>
<div class="token">
<input id="token" type="password" autocomplete="current-password" placeholder="Bearer token">
<button id="save">Save</button>
<button class="primary" id="refresh">Refresh</button>
</div>
</header>
<div class="grid">
<section><h2>Status</h2><pre id="status">No data loaded.</pre></section>
<section><h2>Policy</h2><pre id="policy">No data loaded.</pre></section>
<section><h2>Cache</h2><pre id="cache">No data loaded.</pre></section>
<section><h2>Scanner</h2><pre id="scanner">No data loaded.</pre></section>
<section><h2>Recent Decisions</h2><pre id="decisions">No data loaded.</pre></section>
</div>
</main>
<script>
const tokenInput = document.querySelector("#token");
const saveButton = document.querySelector("#save");
const refreshButton = document.querySelector("#refresh");
const endpoints = [
	["status", "/admin/api/status"],
	["policy", "/admin/api/policy"],
	["cache", "/admin/api/cache"],
	["scanner", "/admin/api/scanner"],
	["decisions", "/admin/api/decisions?limit=25"],
];

tokenInput.value = localStorage.getItem("nexus-sec-proxy-admin-token") || "";

saveButton.addEventListener("click", () => {
	localStorage.setItem("nexus-sec-proxy-admin-token", tokenInput.value);
	refresh();
});
refreshButton.addEventListener("click", refresh);
tokenInput.addEventListener("keydown", event => {
	if (event.key === "Enter") {
		localStorage.setItem("nexus-sec-proxy-admin-token", tokenInput.value);
		refresh();
	}
});

async function refresh() {
	const token = tokenInput.value;
	for (const [id, url] of endpoints) {
		const node = document.querySelector("#" + id);
		node.classList.remove("error");
		node.textContent = "Loading...";
		try {
			const response = await fetch(url, {
				headers: { "Authorization": "Bearer " + token },
			});
			const text = await response.text();
			let parsed;
			try {
				parsed = JSON.parse(text);
			} catch {
				parsed = text;
			}
			if (!response.ok) {
				node.classList.add("error");
			}
			node.textContent = typeof parsed === "string"
				? parsed
				: JSON.stringify(parsed, null, 2);
		} catch (error) {
			node.classList.add("error");
			node.textContent = String(error);
		}
	}
}
</script>
</body>
</html>
"##;

struct PrefetchedArtifact {
	status: StatusCode,
	headers: HeaderMap,
	temp_file: tempfile::NamedTempFile,
	bytes_written: u64,
}

enum ArtifactFetch {
	Prefetched(PrefetchedArtifact),
	Upstream(Response<Body>),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	init_tracing(env_log_json());

	let config = AppConfig::from_env().map_err(|error| {
		error!(%error, "failed to load configuration");
		anyhow::Error::new(error).context("failed to load configuration")
	})?;
	let bind_addr = config.bind_addr;
	let upstream_base_url = Url::parse(&config.upstream_base_url)
		.with_context(|| {
			format!("invalid upstream base URL: {}", config.upstream_base_url)
		})?;
	let http_client = reqwest::Client::builder()
		.timeout(Duration::from_secs(config.request_timeout_secs))
		.build()
		.context("failed to build HTTP client")?;
	let cache = MokaScanCache::new(
		config.cache_max_capacity,
		Duration::from_secs(config.cache_allowed_ttl_secs),
		Duration::from_secs(config.cache_blocked_ttl_secs),
	);
	let osv = OsvClient::new(http_client.clone(), config.osv_api_url.clone());
	let artifact_scanner = external_scanner_from_config(&config);
	let artifact_scanner_semaphore = Arc::new(Semaphore::new(
		config.artifact_scanner_concurrency.max(1) as usize,
	));
	let active_policy = Arc::new(RwLock::new(Arc::new(ActivePolicy::new(
		config.policy_set.clone(),
		&config.repository_name,
		&config.repository_format,
		config.policy_file.clone(),
		1,
	))));
	let started_at = Instant::now();
	let started_at_rfc3339 = now_rfc3339();
	let state = Arc::new(AppState {
		config: Arc::new(config),
		upstream_base_url,
		http_client,
		cache,
		osv,
		artifact_scanner,
		artifact_scanner_semaphore,
		active_policy,
		decision_log: DecisionLog::new(100),
		started_at,
		started_at_rfc3339,
	});
	let active_policy = state.active_policy();

	info!(
		bind_addr = %bind_addr,
		upstream_base_url = %state.config.upstream_base_url,
		repository_name = %state.config.repository_name,
		repository_format = %state.config.repository_format,
		team = active_policy.context.team.as_deref().unwrap_or(""),
		osv_ecosystem = ?state.config.osv_ecosystem,
		osv_api_url = %state.config.osv_api_url,
		policy_file = ?state.config.policy_file,
		admin_enabled = state.config.admin_token.is_some(),
		fail_open = state.config.fail_open,
		unsupported_target_policy = ?state.config.unsupported_target_policy,
		artifact_scanner = ?state.config.artifact_scanner,
		artifact_scanner_command = %state.config.artifact_scanner_command,
		cache_max_capacity = state.config.cache_max_capacity,
		"starting nexus security proxy"
	);

	let app = build_app(state);
	let listener = tokio::net::TcpListener::bind(bind_addr)
		.await
		.with_context(|| format!("failed to bind {bind_addr}"))?;

	axum::serve(listener, app)
		.with_graceful_shutdown(shutdown_signal())
		.await
		.context("server failed")?;

	Ok(())
}

fn build_app(state: Arc<AppState>) -> Router {
	let app = Router::new().route("/healthz", get(healthz));
	let app = if state.config.admin_token.is_some() {
		app.route("/admin", get(admin_ui))
			.route("/admin/api/status", get(admin_status))
			.route("/admin/api/policy", get(admin_policy))
			.route("/admin/api/policy/reload", post(admin_reload_policy))
			.route("/admin/api/policy/validate", post(admin_validate_policy))
			.route("/admin/api/cache", get(admin_cache))
			.route("/admin/api/scanner", get(admin_scanner))
			.route("/admin/api/decisions", get(admin_decisions))
			.route("/admin/{*path}", any(admin_unknown))
	} else {
		app.route("/admin", any(admin_disabled))
			.route("/admin/{*path}", any(admin_disabled))
	};

	app.fallback(proxy_handler).with_state(state)
}

fn init_tracing(json: bool) {
	let filter = tracing_subscriber::EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| "nexus_sec_proxy=info,tower_http=info".into());

	if json {
		tracing_subscriber::fmt()
			.json()
			.with_env_filter(filter)
			.init();
	} else {
		tracing_subscriber::fmt().with_env_filter(filter).init();
	}
}

fn env_log_json() -> bool {
	env::var("NEXUS_SEC_PROXY_LOG_JSON")
		.ok()
		.and_then(|value| value.parse().ok())
		.unwrap_or(false)
}

async fn healthz() -> &'static str {
	"ok\n"
}

async fn admin_ui() -> Response<Body> {
	([(CONTENT_TYPE, "text/html; charset=utf-8")], ADMIN_HTML).into_response()
}

async fn admin_disabled() -> Response<Body> {
	response_with_text(StatusCode::NOT_FOUND, "admin API is disabled\n")
}

async fn admin_unknown() -> Response<Body> {
	response_with_text(StatusCode::NOT_FOUND, "admin route not found\n")
}

async fn admin_status(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	let active_policy = state.active_policy();
	Json(StatusResponse {
		started_at: state.started_at_rfc3339.clone(),
		uptime_seconds: state.started_at.elapsed().as_secs(),
		immutable_config: immutable_config_summary(&state.config),
		active_policy: active_policy.summary(),
		cache: cache_summary(&state).await,
		scanner: scanner_summary(&state),
	})
	.into_response()
}

async fn admin_policy(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	let active_policy = state.active_policy();
	Json(PolicyResponse {
		active_policy: active_policy.summary(),
		policy_set: active_policy.policy_set.clone(),
	})
	.into_response()
}

async fn admin_reload_policy(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	let Some(path) = state.config.policy_file.as_deref() else {
		return json_error(
			StatusCode::CONFLICT,
			"policy reload requires NEXUS_SEC_PROXY_POLICY_FILE",
			None,
		);
	};

	match load_policy_file(path) {
		Ok(policy_set) => {
			let active_policy =
				state.reload_active_policy(policy_set, Some(path.to_owned()));

			info!(
				policy_file = %path,
				generation = active_policy.generation,
				selected_policy_id = %active_policy.selected_policy_id,
				"policy reloaded"
			);

			Json(ReloadPolicyResponse {
				reloaded: true,
				active_policy: active_policy.summary(),
			})
			.into_response()
		}
		Err(error) => {
			error!(%error, policy_file = %path, "policy reload failed");
			json_error(
				StatusCode::UNPROCESSABLE_ENTITY,
				"policy reload failed",
				Some(error.to_string()),
			)
		}
	}
}

async fn admin_validate_policy(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
	Json(request): Json<ValidatePolicyRequest>,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	match parse_policy_toml(&request.policy_toml) {
		Ok(policy_set) => {
			let repository_name = request
				.repository_name
				.as_deref()
				.unwrap_or(&state.config.repository_name);
			let repository_format = request
				.repository_format
				.as_deref()
				.unwrap_or(&state.config.repository_format);
			let context =
				policy_set.context(repository_name, repository_format);
			let selected_policy = policy_set.select_policy(&context);

			Json(ValidatePolicyResponse {
				valid: true,
				context,
				selected_policy_id: selected_policy.id.clone(),
				selected_policy_mode: selected_policy.mode,
			})
			.into_response()
		}
		Err(error) => {
			warn!(%error, "policy validation failed");
			json_error(
				StatusCode::UNPROCESSABLE_ENTITY,
				"invalid policy TOML",
				Some(error.to_string()),
			)
		}
	}
}

async fn admin_cache(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	Json(cache_summary(&state).await).into_response()
}

async fn admin_scanner(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	Json(scanner_summary(&state)).into_response()
}

async fn admin_decisions(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
	Query(query): Query<DecisionsQuery>,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	let limit = query.limit.unwrap_or(25).clamp(1, 100);
	Json(DecisionsResponse {
		limit,
		decisions: state.decision_log.list(limit),
	})
	.into_response()
}

fn authorize_admin(
	state: &AppState,
	headers: &HeaderMap,
) -> Result<(), Response<Body>> {
	let Some(expected_token) = state.config.admin_token.as_deref() else {
		return Err(json_error(
			StatusCode::NOT_FOUND,
			"admin API is disabled",
			None,
		));
	};

	let Some(header) = headers.get(AUTHORIZATION) else {
		warn!("admin request rejected without authorization header");
		return Err(json_error(
			StatusCode::UNAUTHORIZED,
			"missing bearer token",
			None,
		));
	};

	let Ok(header) = header.to_str() else {
		warn!("admin request rejected with invalid authorization header");
		return Err(json_error(
			StatusCode::UNAUTHORIZED,
			"invalid authorization header",
			None,
		));
	};

	let Some(token) = header.strip_prefix("Bearer ") else {
		warn!("admin request rejected without bearer token");
		return Err(json_error(
			StatusCode::UNAUTHORIZED,
			"missing bearer token",
			None,
		));
	};

	if token != expected_token {
		warn!("admin request rejected with wrong bearer token");
		return Err(json_error(
			StatusCode::FORBIDDEN,
			"invalid bearer token",
			None,
		));
	}

	Ok(())
}

fn immutable_config_summary(config: &AppConfig) -> ImmutableConfigSummary {
	ImmutableConfigSummary {
		bind_addr: config.bind_addr.to_string(),
		upstream_base_url: config.upstream_base_url.clone(),
		repository_name: config.repository_name.clone(),
		repository_format: config.repository_format.clone(),
		osv_ecosystem: config.osv_ecosystem.clone(),
		osv_api_url: config.osv_api_url.clone(),
		policy_file: config.policy_file.clone(),
		fail_open: config.fail_open,
		unsupported_target_policy: config.unsupported_target_policy,
		request_timeout_secs: config.request_timeout_secs,
		artifact_tmp_dir: config.artifact_tmp_dir.clone(),
	}
}

async fn cache_summary(state: &AppState) -> CacheSummary {
	let CacheStats {
		clean_entry_count,
		vulnerable_entry_count,
		total_entry_count,
	} = state.cache.stats().await;

	CacheSummary {
		clean_entry_count,
		vulnerable_entry_count,
		total_entry_count,
		allowed_ttl_secs: state.config.cache_allowed_ttl_secs,
		blocked_ttl_secs: state.config.cache_blocked_ttl_secs,
		max_capacity: state.config.cache_max_capacity,
	}
}

fn scanner_summary(state: &AppState) -> ScannerSummary {
	ScannerSummary {
		enabled: state.artifact_scanner.is_some(),
		kind: state.config.artifact_scanner,
		command: state.config.artifact_scanner_command.clone(),
		skip_db_update: state.config.artifact_scanner_skip_db_update,
		offline: state.config.artifact_scanner_offline,
		timeout_secs: state.config.artifact_scanner_timeout_secs,
		max_bytes: state.config.artifact_scan_max_bytes,
		concurrency: state.config.artifact_scanner_concurrency.max(1),
		available_permits: state.artifact_scanner_semaphore.available_permits(),
		db_files: scanner_db_summaries_from_env(),
	}
}

fn json_error(
	status: StatusCode,
	error: impl Into<String>,
	details: Option<String>,
) -> Response<Body> {
	(
		status,
		Json(ErrorResponse {
			error: error.into(),
			details,
		}),
	)
		.into_response()
}

fn scanner_db_summaries_from_env() -> Vec<ScannerDbSummary> {
	[
		scanner_db_summary_from_env("TRIVY_CACHE_DIR"),
		scanner_db_summary_from_env("GRYPE_DB_CACHE_DIR"),
	]
	.into_iter()
	.collect()
}

fn scanner_db_summary_from_env(env_var: &'static str) -> ScannerDbSummary {
	match env::var(env_var)
		.ok()
		.map(|value| value.trim().to_owned())
		.filter(|value| !value.is_empty())
	{
		Some(cache_dir) => {
			scanner_db_summary_for_dir(env_var, Path::new(&cache_dir))
		}
		None => ScannerDbSummary {
			env_var: env_var.to_owned(),
			cache_dir: None,
			status: ScannerDbStatus::NotConfigured,
			db_file: None,
			modified_at: None,
			age_seconds: None,
			error: None,
		},
	}
}

fn scanner_db_summary_for_dir(
	env_var: &'static str,
	cache_dir: &Path,
) -> ScannerDbSummary {
	let cache_dir_display = cache_dir.display().to_string();
	let metadata = match fs::metadata(cache_dir) {
		Ok(metadata) => metadata,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			return ScannerDbSummary {
				env_var: env_var.to_owned(),
				cache_dir: Some(cache_dir_display),
				status: ScannerDbStatus::Missing,
				db_file: None,
				modified_at: None,
				age_seconds: None,
				error: None,
			};
		}
		Err(error) => {
			warn!(
				%error,
				env_var,
				cache_dir = %cache_dir_display,
				"failed to read scanner DB cache metadata"
			);
			return ScannerDbSummary {
				env_var: env_var.to_owned(),
				cache_dir: Some(cache_dir_display),
				status: ScannerDbStatus::Unreadable,
				db_file: None,
				modified_at: None,
				age_seconds: None,
				error: Some(error.to_string()),
			};
		}
	};

	if !metadata.is_dir() {
		return ScannerDbSummary {
			env_var: env_var.to_owned(),
			cache_dir: Some(cache_dir_display),
			status: ScannerDbStatus::NotDirectory,
			db_file: None,
			modified_at: None,
			age_seconds: None,
			error: None,
		};
	}

	match newest_scanner_db_file(cache_dir) {
		Ok(Some((path, modified))) => ScannerDbSummary {
			env_var: env_var.to_owned(),
			cache_dir: Some(cache_dir_display),
			status: ScannerDbStatus::Found,
			db_file: Some(path.display().to_string()),
			modified_at: Some(format_system_time(modified)),
			age_seconds: Some(system_time_age_seconds(modified)),
			error: None,
		},
		Ok(None) => ScannerDbSummary {
			env_var: env_var.to_owned(),
			cache_dir: Some(cache_dir_display),
			status: ScannerDbStatus::NotFound,
			db_file: None,
			modified_at: None,
			age_seconds: None,
			error: None,
		},
		Err(error) => {
			warn!(
				%error,
				env_var,
				cache_dir = %cache_dir_display,
				"failed to inspect scanner DB cache"
			);
			ScannerDbSummary {
				env_var: env_var.to_owned(),
				cache_dir: Some(cache_dir_display),
				status: ScannerDbStatus::Unreadable,
				db_file: None,
				modified_at: None,
				age_seconds: None,
				error: Some(error),
			}
		}
	}
}

fn newest_scanner_db_file(
	cache_dir: &Path,
) -> Result<Option<(PathBuf, SystemTime)>, String> {
	let mut newest = None;
	visit_scanner_db_files(cache_dir, 0, &mut newest)?;

	Ok(newest)
}

fn visit_scanner_db_files(
	dir: &Path,
	depth: usize,
	newest: &mut Option<(PathBuf, SystemTime)>,
) -> Result<(), String> {
	if depth > 4 {
		return Ok(());
	}

	let entries = fs::read_dir(dir).map_err(|error| {
		format!("failed to read {}: {error}", dir.display())
	})?;

	for entry in entries {
		let entry = match entry {
			Ok(entry) => entry,
			Err(error) => {
				warn!(%error, dir = %dir.display(), "failed to read cache directory entry");
				continue;
			}
		};
		let path = entry.path();
		let metadata = match entry.metadata() {
			Ok(metadata) => metadata,
			Err(error) => {
				warn!(
					%error,
					path = %path.display(),
					"failed to read cache file metadata"
				);
				continue;
			}
		};

		if metadata.is_dir() {
			visit_scanner_db_files(&path, depth + 1, newest)?;
		} else if metadata.is_file() && is_scanner_db_file(&path) {
			let modified = match metadata.modified() {
				Ok(modified) => modified,
				Err(error) => {
					warn!(
						%error,
						path = %path.display(),
						"failed to read scanner DB file modified time"
					);
					continue;
				}
			};

			let should_replace = newest
				.as_ref()
				.is_none_or(|(_, current)| modified > *current);
			if should_replace {
				*newest = Some((path, modified));
			}
		}
	}

	Ok(())
}

fn is_scanner_db_file(path: &Path) -> bool {
	let Some(file_name) = path.file_name().and_then(|name| name.to_str())
	else {
		return false;
	};
	let file_name = file_name.to_ascii_lowercase();

	file_name == "metadata.json" || file_name.ends_with(".db")
}

fn now_rfc3339() -> String {
	format_offset_datetime(OffsetDateTime::now_utc())
}

fn format_system_time(time: SystemTime) -> String {
	format_offset_datetime(OffsetDateTime::from(time))
}

fn format_offset_datetime(time: OffsetDateTime) -> String {
	time.format(&Rfc3339).unwrap_or_else(|error| {
		error!(%error, "failed to format RFC3339 timestamp");
		time.unix_timestamp().to_string()
	})
}

fn system_time_age_seconds(time: SystemTime) -> u64 {
	SystemTime::now()
		.duration_since(time)
		.unwrap_or(Duration::ZERO)
		.as_secs()
}

async fn proxy_handler(
	State(state): State<Arc<AppState>>,
	request: Request<Body>,
) -> Response<Body> {
	let method = request.method().clone();
	let uri = request.uri().clone();

	if uri.path().starts_with("/admin") {
		return if state.config.admin_token.is_some() {
			admin_unknown().await
		} else {
			admin_disabled().await
		};
	}

	if method != Method::GET && method != Method::HEAD {
		return response_with_text(
			StatusCode::METHOD_NOT_ALLOWED,
			"Only GET and HEAD are supported by this upstream proxy\n",
		);
	}

	let classification = classify_request(&state.config, &method, &uri);

	match classification {
		RequestClassification::ProxyOnly => {}
		RequestClassification::Scan(ScanTarget::Package(package)) => {
			if let Err(response) =
				authorize_package_target(&state, ScanTarget::Package(package))
					.await
			{
				return *response;
			}
		}
		RequestClassification::Scan(target @ ScanTarget::Artifact(_)) => {
			return handle_artifact_request(
				&state,
				method,
				uri,
				request.headers(),
				target,
			)
			.await;
		}
	}

	match forward_request(&state, method, uri, request.headers()).await {
		Ok(response) => response,
		Err(error) => {
			error!(%error, "failed to proxy upstream request");
			response_with_text(
				StatusCode::BAD_GATEWAY,
				format!("failed to proxy upstream request: {error}\n"),
			)
		}
	}
}

async fn authorize_package_target(
	state: &AppState,
	target: ScanTarget,
) -> Result<(), Box<Response<Body>>> {
	let cache_key = cache_key_for_target(&target);

	match state.cache.get(&cache_key).await {
		Ok(Some(scan)) => {
			let active_policy = state.active_policy();
			return handle_policy_evaluation(
				state,
				&active_policy,
				&target,
				active_policy.evaluator.evaluate_with_context(
					&active_policy.context,
					&target,
					scan.vulnerabilities,
				),
			);
		}
		Ok(None) => {}
		Err(error) => {
			error!(%error, target = %target.display_name(), "cache lookup failed");
		}
	}

	let (active_policy, decision) = match state
		.osv
		.vulnerabilities(&target)
		.await
	{
		Ok(vulnerabilities) => {
			put_cache(
				state,
				cache_key,
				CachedScan::new(vulnerabilities.clone()),
				&target,
			)
			.await;
			let active_policy = state.active_policy();
			let decision = active_policy.evaluator.evaluate_with_context(
				&active_policy.context,
				&target,
				vulnerabilities,
			);
			(active_policy, decision)
		}
		Err(SecurityError::UnsupportedTarget(reason)) => {
			return handle_unsupported_target(state, target, reason).await;
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

	handle_policy_evaluation(state, &active_policy, &target, decision)
}

async fn handle_artifact_request(
	state: &AppState,
	method: Method,
	uri: Uri,
	headers: &HeaderMap,
	target: ScanTarget,
) -> Response<Body> {
	if method == Method::HEAD {
		return forward_or_bad_gateway(state, method, uri, headers).await;
	}

	let cache_key = cache_key_for_target(&target);
	match state.cache.get(&cache_key).await {
		Ok(Some(scan)) => {
			let active_policy = state.active_policy();
			let evaluation = active_policy.evaluator.evaluate_with_context(
				&active_policy.context,
				&target,
				scan.vulnerabilities,
			);

			match handle_policy_evaluation(
				state,
				&active_policy,
				&target,
				evaluation,
			) {
				Ok(()) => {
					return forward_or_bad_gateway(state, method, uri, headers)
						.await;
				}
				Err(response) => return *response,
			}
		}
		Ok(None) => {}
		Err(error) => {
			error!(%error, target = %target.display_name(), "cache lookup failed");
		}
	}

	let Some(scanner) = state.artifact_scanner.as_ref() else {
		return match handle_unsupported_target(
			state,
			target,
			"artifact scanner is disabled".to_owned(),
		)
		.await
		{
			Ok(()) => forward_or_bad_gateway(state, method, uri, headers).await,
			Err(response) => *response,
		};
	};

	let prefetched = match prefetch_artifact(
		state,
		method.clone(),
		&uri,
		headers,
	)
	.await
	{
		Ok(ArtifactFetch::Prefetched(prefetched)) => prefetched,
		Ok(ArtifactFetch::Upstream(response)) => return response,
		Err(error) => {
			error!(
				%error,
				target = %target.display_name(),
				"failed to prefetch artifact for scanning"
			);

			if state.config.fail_open {
				warn!(
					target = %target.display_name(),
					"allowing request because artifact prefetch failed and fail_open=true"
				);
				return forward_or_bad_gateway(state, method, uri, headers)
					.await;
			}

			return response_with_text(
				StatusCode::SERVICE_UNAVAILABLE,
				format!(
					"Artifact scan failed and fail_open=false\n\nTarget: {}\nReason: {error}\n",
					target.display_name()
				),
			);
		}
	};

	let _permit = match state.artifact_scanner_semaphore.acquire().await {
		Ok(permit) => permit,
		Err(error) => {
			error!(%error, "artifact scanner semaphore was closed");
			return response_with_text(
				StatusCode::SERVICE_UNAVAILABLE,
				"artifact scanner is unavailable\n",
			);
		}
	};

	let (active_policy, decision) = match scanner
		.scan_path(&target, prefetched.temp_file.path())
		.await
	{
		Ok(vulnerabilities) => {
			put_cache(
				state,
				cache_key,
				CachedScan::new(vulnerabilities.clone()),
				&target,
			)
			.await;
			let active_policy = state.active_policy();
			let decision = active_policy.evaluator.evaluate_with_context(
				&active_policy.context,
				&target,
				vulnerabilities,
			);
			(active_policy, decision)
		}
		Err(error) => {
			error!(%error, target = %target.display_name(), "artifact scanner failed");

			if state.config.fail_open {
				warn!(
					target = %target.display_name(),
					"allowing request because artifact scanner failed and fail_open=true"
				);
				return prefetched_or_bad_gateway(prefetched).await;
			}

			return response_with_text(
				StatusCode::SERVICE_UNAVAILABLE,
				format!(
					"Artifact scan failed and fail_open=false\n\nTarget: {}\nReason: {error}\n",
					target.display_name()
				),
			);
		}
	};

	match handle_policy_evaluation(state, &active_policy, &target, decision) {
		Ok(()) => prefetched_or_bad_gateway(prefetched).await,
		Err(response) => *response,
	}
}

async fn handle_unsupported_target(
	state: &AppState,
	target: ScanTarget,
	reason: String,
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
			record_decision(
				state,
				&active_policy,
				DecisionOutcome::Blocked,
				&report,
			);
			Err(Box::new(response_with_text(
				StatusCode::FORBIDDEN,
				report.to_plain_text(),
			)))
		}
	}
}

fn handle_policy_evaluation(
	state: &AppState,
	active_policy: &ActivePolicy,
	target: &ScanTarget,
	evaluation: PolicyEvaluation,
) -> Result<(), Box<Response<Body>>> {
	audit_policy_evaluation(active_policy, target, &evaluation);

	match &evaluation.outcome {
		PolicyOutcome::Allowed => {}
		PolicyOutcome::ReportOnly(report) => {
			record_decision(
				state,
				active_policy,
				DecisionOutcome::ReportOnly,
				report,
			);
		}
		PolicyOutcome::Blocked(report) => {
			record_decision(
				state,
				active_policy,
				DecisionOutcome::Blocked,
				report,
			);
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

fn audit_policy_evaluation(
	active_policy: &ActivePolicy,
	target: &ScanTarget,
	evaluation: &PolicyEvaluation,
) {
	let context = &active_policy.context;
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

fn vulnerability_ids(report: &BlockReport) -> Vec<String> {
	report
		.vulnerabilities
		.iter()
		.map(|vulnerability| vulnerability.id.clone())
		.collect()
}

fn record_decision(
	state: &AppState,
	active_policy: &ActivePolicy,
	outcome: DecisionOutcome,
	report: &BlockReport,
) {
	state.decision_log.push(RecentDecision {
		timestamp: now_rfc3339(),
		repository: active_policy.context.repository.clone(),
		format: active_policy.context.format.clone(),
		team: active_policy.context.team.clone(),
		target: report.target.display_name(),
		outcome,
		policy_id: report.policy_id.clone(),
		reason: report.reason.clone(),
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

fn external_scanner_from_config(config: &AppConfig) -> Option<ExternalScanner> {
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

async fn prefetch_artifact(
	state: &AppState,
	method: Method,
	uri: &Uri,
	headers: &HeaderMap,
) -> anyhow::Result<ArtifactFetch> {
	let upstream_url = build_upstream_url(&state.upstream_base_url, uri);
	let reqwest_method =
		reqwest::Method::from_bytes(method.as_str().as_bytes())
			.context("invalid request method")?;
	let mut request = state.http_client.request(reqwest_method, upstream_url);

	for (name, value) in headers {
		if is_hop_by_hop_header(name.as_str()) {
			continue;
		}

		request = request.header(name, value);
	}

	let response = request.send().await.context("upstream request failed")?;
	let status = StatusCode::from_u16(response.status().as_u16())
		.context("invalid upstream status code")?;

	if !status.is_success() {
		return Ok(ArtifactFetch::Upstream(response_from_upstream(response)?));
	}

	let response_headers = response_headers(response.headers());
	let temp_file =
		if let Some(tmp_dir) = state.config.artifact_tmp_dir.as_deref() {
			tempfile::Builder::new()
				.prefix("nexus-sec-proxy-")
				.tempfile_in(tmp_dir)
				.with_context(|| {
					format!("failed to create temp file in {tmp_dir}")
				})?
		} else {
			tempfile::Builder::new()
				.prefix("nexus-sec-proxy-")
				.tempfile()
				.context("failed to create temp file")?
		};
	let mut file = tokio::fs::File::from_std(
		temp_file
			.reopen()
			.context("failed to reopen temp file for writing")?,
	);
	let mut bytes_written = 0_u64;

	let mut stream = response.bytes_stream();
	while let Some(chunk) = stream.next().await {
		let chunk = chunk.context("failed to read upstream artifact chunk")?;
		bytes_written += chunk.len() as u64;

		if bytes_written > state.config.artifact_scan_max_bytes {
			return Err(anyhow::anyhow!(
				"artifact size {bytes_written} exceeds scan limit {}",
				state.config.artifact_scan_max_bytes
			));
		}

		file.write_all(&chunk)
			.await
			.context("failed to write artifact temp file")?;
	}

	file.flush()
		.await
		.context("failed to flush artifact temp file")?;

	Ok(ArtifactFetch::Prefetched(PrefetchedArtifact {
		status,
		headers: response_headers,
		temp_file,
		bytes_written,
	}))
}

async fn forward_request(
	state: &AppState,
	method: Method,
	uri: Uri,
	headers: &HeaderMap,
) -> anyhow::Result<Response<Body>> {
	let upstream_url = build_upstream_url(&state.upstream_base_url, &uri);
	let reqwest_method =
		reqwest::Method::from_bytes(method.as_str().as_bytes())
			.context("invalid request method")?;
	let mut request = state.http_client.request(reqwest_method, upstream_url);

	for (name, value) in headers {
		if is_hop_by_hop_header(name.as_str()) {
			continue;
		}

		request = request.header(name, value);
	}

	let response = request.send().await.context("upstream request failed")?;
	response_from_upstream(response)
}

fn response_headers(headers: &reqwest::header::HeaderMap) -> HeaderMap {
	let mut response_headers = HeaderMap::new();

	for (name, value) in headers {
		if is_hop_by_hop_header(name.as_str()) {
			continue;
		}

		response_headers.insert(name.clone(), value.clone());
	}

	response_headers
}

fn response_from_upstream(
	response: reqwest::Response,
) -> anyhow::Result<Response<Body>> {
	let status = StatusCode::from_u16(response.status().as_u16())
		.context("invalid upstream status code")?;
	let mut builder = Response::builder().status(status);

	let headers = response_headers(response.headers());
	for (name, value) in &headers {
		builder = builder.header(name, value);
	}

	builder
		.body(Body::from_stream(response.bytes_stream()))
		.context("failed to build upstream response")
}

async fn prefetched_or_bad_gateway(
	prefetched: PrefetchedArtifact,
) -> Response<Body> {
	match response_from_prefetched(prefetched).await {
		Ok(response) => response,
		Err(error) => {
			error!(%error, "failed to stream prefetched artifact");
			response_with_text(
				StatusCode::BAD_GATEWAY,
				format!("failed to stream prefetched artifact: {error}\n"),
			)
		}
	}
}

async fn response_from_prefetched(
	prefetched: PrefetchedArtifact,
) -> anyhow::Result<Response<Body>> {
	let file = tokio::fs::File::open(prefetched.temp_file.path())
		.await
		.context("failed to open scanned artifact temp file")?;
	let mut builder = Response::builder().status(prefetched.status);
	let mut has_content_length = false;

	for (name, value) in &prefetched.headers {
		if name.as_str().eq_ignore_ascii_case("content-length") {
			has_content_length = true;
		}

		builder = builder.header(name, value);
	}

	if !has_content_length {
		builder = builder.header("content-length", prefetched.bytes_written);
	}

	builder
		.body(Body::from_stream(ReaderStream::new(file)))
		.context("failed to build scanned artifact response")
}

async fn forward_or_bad_gateway(
	state: &AppState,
	method: Method,
	uri: Uri,
	headers: &HeaderMap,
) -> Response<Body> {
	match forward_request(state, method, uri, headers).await {
		Ok(response) => response,
		Err(error) => {
			error!(%error, "failed to proxy upstream request");
			response_with_text(
				StatusCode::BAD_GATEWAY,
				format!("failed to proxy upstream request: {error}\n"),
			)
		}
	}
}

fn build_upstream_url(base: &Url, uri: &Uri) -> Url {
	let mut upstream_url = base.clone();
	let base_path = base.path().trim_end_matches('/');
	let request_path = uri.path();
	let path = if base_path.is_empty() || base_path == "/" {
		request_path.to_owned()
	} else if request_path == "/" {
		base_path.to_owned()
	} else {
		format!("{base_path}{request_path}")
	};

	upstream_url.set_path(&path);
	upstream_url.set_query(uri.query());
	upstream_url
}

fn cache_key_for_target(target: &ScanTarget) -> CacheKey {
	CacheKey::from_parts(
		target.cache_namespace(),
		target.cache_identifier(),
		target.cache_version(),
	)
}

fn response_with_text(
	status: StatusCode,
	body: impl Into<String>,
) -> Response<Body> {
	(
		status,
		[(CONTENT_TYPE, "text/plain; charset=utf-8")],
		body.into(),
	)
		.into_response()
}

fn is_hop_by_hop_header(name: &str) -> bool {
	name.eq_ignore_ascii_case(CONNECTION.as_str())
		|| name.eq_ignore_ascii_case(HOST.as_str())
		|| name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
		|| name.eq_ignore_ascii_case("keep-alive")
		|| name.eq_ignore_ascii_case("proxy-authenticate")
		|| name.eq_ignore_ascii_case("proxy-authorization")
		|| name.eq_ignore_ascii_case("te")
		|| name.eq_ignore_ascii_case("trailer")
		|| name.eq_ignore_ascii_case("upgrade")
}

async fn shutdown_signal() {
	let ctrl_c = async {
		if let Err(error) = tokio::signal::ctrl_c().await {
			error!(%error, "failed to install ctrl-c handler");
		}
	};

	#[cfg(unix)]
	let terminate = async {
		match tokio::signal::unix::signal(
			tokio::signal::unix::SignalKind::terminate(),
		) {
			Ok(mut signal) => {
				signal.recv().await;
			}
			Err(error) => {
				error!(%error, "failed to install SIGTERM handler");
				std::future::pending::<()>().await;
			}
		}
	};

	#[cfg(not(unix))]
	let terminate = std::future::pending::<()>();

	tokio::select! {
		() = ctrl_c => {},
		() = terminate => {},
	}
}

#[cfg(test)]
mod tests {
	use axum::body::to_bytes;
	use nexus_sec_proxy_security::{
		PackageCoordinate, Severity, Vulnerability,
	};
	use serde_json::{Value, json};
	use tower::ServiceExt;

	use super::*;

	#[test]
	fn joins_upstream_base_path_and_request_path() {
		let base = Url::parse("https://repo.example.invalid/root").unwrap();
		let uri: Uri = "/nested/pkg.tgz?download=1".parse().unwrap();

		let joined = build_upstream_url(&base, &uri);

		assert_eq!(
			joined.as_str(),
			"https://repo.example.invalid/root/nested/pkg.tgz?download=1"
		);
	}

	#[test]
	fn root_base_preserves_request_path() {
		let base = Url::parse("https://repo.example.invalid/").unwrap();
		let uri: Uri = "/pkg.tgz".parse().unwrap();

		let joined = build_upstream_url(&base, &uri);

		assert_eq!(joined.as_str(), "https://repo.example.invalid/pkg.tgz");
	}

	#[tokio::test]
	async fn disabled_admin_routes_do_not_proxy_upstream() {
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
	async fn admin_api_rejects_missing_or_wrong_token_and_accepts_correct_token()
	 {
		let app =
			build_app(test_state(Some("secret"), None, PolicySet::default()));

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
		let app =
			build_app(test_state(Some("secret"), None, PolicySet::default()));
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
		assert_eq!(state.active_policy().selected_policy_id, "reloaded");
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
		assert_eq!(state.active_policy().selected_policy_id, "reloaded");
		assert_eq!(state.active_policy().generation, 2);

		let app =
			build_app(test_state(Some("secret"), None, PolicySet::default()));
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
		let target = ScanTarget::Package(PackageCoordinate::new(
			"npm", "left-pad", "1.0.0",
		));
		let vulnerability = vulnerability("CVE-2026-0001", Severity::High);

		let blocked_state =
			test_state(Some("secret"), None, PolicySet::default());
		let active_policy = blocked_state.active_policy();
		let evaluation = active_policy.evaluator.evaluate_with_context(
			&active_policy.context,
			&target,
			vec![vulnerability.clone()],
		);
		let response = handle_policy_evaluation(
			&blocked_state,
			&active_policy,
			&target,
			evaluation,
		)
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
		let evaluation = active_policy.evaluator.evaluate_with_context(
			&active_policy.context,
			&target,
			vec![vulnerability],
		);
		handle_policy_evaluation(
			&report_only_state,
			&active_policy,
			&target,
			evaluation,
		)
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
		let summary =
			scanner_db_summary_for_dir("TRIVY_CACHE_DIR", &missing_path);

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

		let summary =
			scanner_db_summary_for_dir("TRIVY_CACHE_DIR", db_dir.path());

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

	fn test_state(
		admin_token: Option<&str>,
		policy_file: Option<String>,
		policy_set: PolicySet,
	) -> Arc<AppState> {
		let security_policy = policy_set.default_policy.policy.clone();
		let config = AppConfig {
			bind_addr: "127.0.0.1:3000".parse().unwrap(),
			upstream_base_url: "http://127.0.0.1:9".to_owned(),
			repository_name: "default".to_owned(),
			repository_format: "npm".to_owned(),
			osv_ecosystem: Some("npm".to_owned()),
			osv_api_url: "http://127.0.0.1:9/osv".to_owned(),
			policy_file: policy_file.clone(),
			admin_token: admin_token.map(str::to_owned),
			log_json: false,
			fail_open: true,
			unsupported_target_policy: UnsupportedTargetPolicy::Allow,
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
			policy_set: policy_set.clone(),
		};
		let http_client = reqwest::Client::builder()
			.timeout(Duration::from_secs(1))
			.build()
			.unwrap();

		Arc::new(AppState {
			config: Arc::new(config),
			upstream_base_url: Url::parse("http://127.0.0.1:9").unwrap(),
			http_client: http_client.clone(),
			cache: MokaScanCache::new(
				100,
				Duration::from_secs(60),
				Duration::from_secs(60),
			),
			osv: OsvClient::new(http_client, "http://127.0.0.1:9/osv"),
			artifact_scanner: None,
			artifact_scanner_semaphore: Arc::new(Semaphore::new(2)),
			active_policy: Arc::new(RwLock::new(Arc::new(ActivePolicy::new(
				policy_set,
				"default",
				"npm",
				policy_file,
				1,
			)))),
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
}
