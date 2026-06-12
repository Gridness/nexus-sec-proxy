mod classifier;

use std::collections::{BTreeMap, VecDeque};
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
use classifier::{ClassificationContext, RequestClassification, classify_path};
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
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use url::Url;

#[derive(Clone)]
struct AppState {
	config: Arc<AppConfig>,
	nexus_base_url: Url,
	http_client: reqwest::Client,
	cache: MokaScanCache,
	osv: OsvClient,
	artifact_scanner: Option<ExternalScanner>,
	artifact_scanner_semaphore: Arc<Semaphore>,
	active_policy: Arc<RwLock<Arc<ActivePolicy>>>,
	repository_catalog: Arc<RwLock<Arc<RepositoryCatalog>>>,
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

	fn repository_catalog(&self) -> Arc<RepositoryCatalog> {
		match self.repository_catalog.read() {
			Ok(catalog) => Arc::clone(&catalog),
			Err(error) => {
				error!("repository catalog lock was poisoned");
				let catalog = error.into_inner();
				Arc::clone(&catalog)
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
					source_path,
					generation,
				));
				*active_policy = Arc::clone(&next);
				next
			}
		}
	}

	fn replace_repository_catalog(
		&self,
		catalog: RepositoryCatalog,
	) -> Arc<RepositoryCatalog> {
		let catalog = Arc::new(catalog);

		match self.repository_catalog.write() {
			Ok(mut current) => {
				*current = Arc::clone(&catalog);
			}
			Err(error) => {
				error!("repository catalog lock was poisoned while reloading");
				let mut current = error.into_inner();
				*current = Arc::clone(&catalog);
			}
		}

		catalog
	}
}

#[derive(Debug, Clone)]
struct ActivePolicy {
	policy_set: PolicySet,
	evaluator: PolicyEvaluator,
	source_path: Option<String>,
	loaded_at: String,
	generation: u64,
}

impl ActivePolicy {
	fn new(
		policy_set: PolicySet,
		source_path: Option<String>,
		generation: u64,
	) -> Self {
		let evaluator = PolicyEvaluator::from_policy_set(policy_set.clone());

		Self {
			policy_set,
			evaluator,
			source_path,
			loaded_at: now_rfc3339(),
			generation,
		}
	}

	fn context_for(
		&self,
		repository_name: &str,
		repository_format: &str,
	) -> PolicyContext {
		self.policy_set.context(repository_name, repository_format)
	}

	fn summary(&self) -> ActivePolicySummary {
		ActivePolicySummary {
			generation: self.generation,
			source_path: self.source_path.clone(),
			loaded_at: self.loaded_at.clone(),
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
}

#[derive(Debug, Clone, Serialize)]
struct ImmutableConfigSummary {
	bind_addr: String,
	nexus_base_url: String,
	nexus_username_configured: bool,
	legacy_repository_name: String,
	legacy_repository_format: String,
	legacy_osv_ecosystem: Option<String>,
	osv_ecosystem_overrides: BTreeMap<String, String>,
	osv_api_url: String,
	policy_file: Option<String>,
	fail_open: bool,
	unsupported_target_policy: UnsupportedTargetPolicy,
	request_timeout_secs: u64,
	artifact_tmp_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct NexusRepository {
	name: String,
	format: String,
	#[serde(rename = "type")]
	repository_type: Option<String>,
	url: Option<String>,
	online: Option<bool>,
	osv_ecosystem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepositoryCatalog {
	repositories: BTreeMap<String, NexusRepository>,
	loaded_at: String,
	generation: u64,
}

impl RepositoryCatalog {
	fn new(
		repositories: Vec<NexusRepository>,
		generation: u64,
	) -> anyhow::Result<Self> {
		if repositories.is_empty() {
			anyhow::bail!("Nexus repository catalog is empty");
		}

		let mut by_name = BTreeMap::new();
		for repository in repositories {
			if repository.name.trim().is_empty() {
				anyhow::bail!(
					"Nexus repository catalog contains an empty repository name"
				);
			}
			if repository.format.trim().is_empty() {
				anyhow::bail!(
					"Nexus repository catalog contains an empty format for repository {}",
					repository.name
				);
			}
			by_name.insert(repository.name.clone(), repository);
		}

		Ok(Self {
			repositories: by_name,
			loaded_at: now_rfc3339(),
			generation,
		})
	}

	fn get(&self, name: &str) -> Option<NexusRepository> {
		self.repositories.get(name).cloned()
	}

	fn summary(&self) -> RepositoryCatalogSummary {
		RepositoryCatalogSummary {
			generation: self.generation,
			loaded_at: self.loaded_at.clone(),
			repository_count: self.repositories.len(),
		}
	}

	fn response(&self) -> RepositoriesResponse {
		RepositoriesResponse {
			generation: self.generation,
			loaded_at: self.loaded_at.clone(),
			repositories: self.repositories.values().cloned().collect(),
		}
	}
}

#[derive(Debug, Clone, Serialize)]
struct RepositoryCatalogSummary {
	generation: u64,
	loaded_at: String,
	repository_count: usize,
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
	repositories: RepositoryCatalogSummary,
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

#[derive(Debug, Clone, Serialize)]
struct RepositoriesResponse {
	generation: u64,
	loaded_at: String,
	repositories: Vec<NexusRepository>,
}

#[derive(Debug, Clone, Serialize)]
struct ReloadRepositoriesResponse {
	reloaded: bool,
	catalog: RepositoryCatalogSummary,
	repositories: Vec<NexusRepository>,
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
<section><h2>Repositories</h2><pre id="repositories">No data loaded.</pre></section>
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
	["repositories", "/admin/api/repositories"],
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	init_tracing(env_log_json());

	let config = AppConfig::from_env().map_err(|error| {
		error!(%error, "failed to load configuration");
		anyhow::Error::new(error).context("failed to load configuration")
	})?;
	let bind_addr = config.bind_addr;
	let nexus_base_url =
		Url::parse(&config.nexus_base_url).with_context(|| {
			format!("invalid Nexus base URL: {}", config.nexus_base_url)
		})?;
	let http_client = reqwest::Client::builder()
		.timeout(Duration::from_secs(config.request_timeout_secs))
		.build()
		.context("failed to build HTTP client")?;
	let repository_catalog =
		load_repository_catalog(&http_client, &nexus_base_url, &config, 1)
			.await
			.context("failed to load Nexus repository catalog")?;
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
		config.policy_file.clone(),
		1,
	))));
	let started_at = Instant::now();
	let started_at_rfc3339 = now_rfc3339();
	let state = Arc::new(AppState {
		config: Arc::new(config),
		nexus_base_url,
		http_client,
		cache,
		osv,
		artifact_scanner,
		artifact_scanner_semaphore,
		active_policy,
		repository_catalog: Arc::new(RwLock::new(Arc::new(repository_catalog))),
		decision_log: DecisionLog::new(100),
		started_at,
		started_at_rfc3339,
	});
	let repository_catalog = state.repository_catalog();

	info!(
		bind_addr = %bind_addr,
		nexus_base_url = %state.config.nexus_base_url,
		repository_count = repository_catalog.repositories.len(),
		repository_catalog_generation = repository_catalog.generation,
		osv_ecosystem = ?state.config.osv_ecosystem,
		osv_ecosystem_overrides = ?state.config.osv_ecosystem_overrides,
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
			.route("/admin/api/repositories", get(admin_repositories))
			.route(
				"/admin/api/repositories/reload",
				post(admin_reload_repositories),
			)
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
		repositories: state.repository_catalog().summary(),
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
			let repository_name =
				request.repository_name.as_deref().unwrap_or("default");
			let repository_format =
				request.repository_format.as_deref().unwrap_or("generic");
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

async fn admin_repositories(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	Json(state.repository_catalog().response()).into_response()
}

async fn admin_reload_repositories(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return response;
	}

	let generation = state.repository_catalog().generation + 1;
	match load_repository_catalog(
		&state.http_client,
		&state.nexus_base_url,
		&state.config,
		generation,
	)
	.await
	{
		Ok(catalog) => {
			let catalog = state.replace_repository_catalog(catalog);
			info!(
				generation = catalog.generation,
				repository_count = catalog.repositories.len(),
				"repository catalog reloaded"
			);

			Json(ReloadRepositoriesResponse {
				reloaded: true,
				catalog: catalog.summary(),
				repositories: catalog.response().repositories,
			})
			.into_response()
		}
		Err(error) => {
			error!(%error, "repository catalog reload failed");
			json_error(
				StatusCode::BAD_GATEWAY,
				"repository catalog reload failed",
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
		nexus_base_url: config.nexus_base_url.clone(),
		nexus_username_configured: config.nexus_username.is_some(),
		legacy_repository_name: config.repository_name.clone(),
		legacy_repository_format: config.repository_format.clone(),
		legacy_osv_ecosystem: config.osv_ecosystem.clone(),
		osv_ecosystem_overrides: config.osv_ecosystem_overrides.clone(),
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

#[derive(Debug, Deserialize)]
struct NexusRepositoryResponseItem {
	name: String,
	format: String,
	#[serde(rename = "type")]
	repository_type: Option<String>,
	url: Option<String>,
	online: Option<bool>,
}

async fn load_repository_catalog(
	client: &reqwest::Client,
	nexus_base_url: &Url,
	config: &AppConfig,
	generation: u64,
) -> anyhow::Result<RepositoryCatalog> {
	let mut repositories_url = nexus_base_url.clone();
	let base_path = nexus_base_url.path().trim_end_matches('/');
	let path = if base_path.is_empty() || base_path == "/" {
		"/service/rest/v1/repositories".to_owned()
	} else {
		format!("{base_path}/service/rest/v1/repositories")
	};
	repositories_url.set_path(&path);
	repositories_url.set_query(None);

	let mut request = client.get(repositories_url);
	if let Some(username) = config.nexus_username.as_deref() {
		request = request.basic_auth(username, config.nexus_password.clone());
	}

	let response = request
		.send()
		.await
		.context("Nexus repository catalog request failed")?;
	let status = response.status();
	if !status.is_success() {
		let body = response.text().await.unwrap_or_else(|error| {
			format!(
				"failed to read Nexus repository catalog error body: {error}"
			)
		});
		anyhow::bail!("Nexus repository catalog returned {status}: {body}");
	}

	let items = response
		.json::<Vec<NexusRepositoryResponseItem>>()
		.await
		.context("invalid Nexus repository catalog response")?;
	let repositories = items
		.into_iter()
		.map(|item| NexusRepository {
			osv_ecosystem: config
				.osv_ecosystem_overrides
				.get(&item.name)
				.cloned(),
			name: item.name,
			format: item.format,
			repository_type: item.repository_type,
			url: item.url,
			online: item.online,
		})
		.collect();

	RepositoryCatalog::new(repositories, generation)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepositoryPath {
	repository: String,
	stripped_path: String,
}

fn parse_repository_path(path: &str) -> Option<RepositoryPath> {
	let rest = path.strip_prefix("/repository/")?;
	let (repository, remainder) = rest.split_once('/').unwrap_or((rest, ""));
	if repository.is_empty() {
		return None;
	}

	let repository = percent_decode_str(repository)
		.decode_utf8_lossy()
		.into_owned();
	let stripped_path = if remainder.is_empty() {
		"/".to_owned()
	} else {
		format!("/{remainder}")
	};

	Some(RepositoryPath {
		repository,
		stripped_path,
	})
}

async fn proxy_handler(
	State(state): State<Arc<AppState>>,
	request: Request<Body>,
) -> Response<Body> {
	let (parts, body) = request.into_parts();
	let method = parts.method;
	let uri = parts.uri;
	let headers = parts.headers;

	if uri.path().starts_with("/admin") {
		return if state.config.admin_token.is_some() {
			admin_unknown().await
		} else {
			admin_disabled().await
		};
	}

	if let Some(repository_path) = parse_repository_path(uri.path()) {
		let catalog = state.repository_catalog();
		let Some(repository) = catalog.get(&repository_path.repository) else {
			return unknown_repository_response(&repository_path.repository);
		};

		if method == Method::GET || method == Method::HEAD {
			let classification_context = ClassificationContext::new(
				repository.format.clone(),
				repository.osv_ecosystem.clone(),
			);
			let classification = classify_path(
				&classification_context,
				&method,
				&repository_path.stripped_path,
			);

			match classification {
				RequestClassification::ProxyOnly => {}
				RequestClassification::Scan(ScanTarget::Package(package)) => {
					if let Err(response) = authorize_package_target(
						&state,
						&repository,
						ScanTarget::Package(package),
					)
					.await
					{
						return *response;
					}
				}
				RequestClassification::Scan(target @ ScanTarget::Artifact(_)) => {
					if let Err(response) = handle_unsupported_target(
						&state,
						&repository,
						target,
						"artifact targets cannot be scanned before contacting Nexus"
							.to_owned(),
					)
					.await
					{
						return *response;
					}
				}
			}
		}
	}

	match forward_request(&state, method, uri, &headers, body).await {
		Ok(response) => response,
		Err(error) => {
			error!(%error, "failed to proxy Nexus request");
			response_with_text(
				StatusCode::BAD_GATEWAY,
				format!("failed to proxy Nexus request: {error}\n"),
			)
		}
	}
}

async fn authorize_package_target(
	state: &AppState,
	repository: &NexusRepository,
	target: ScanTarget,
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
				state, repository, target, reason,
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

	handle_policy_evaluation(state, &context, &target, decision)
}

async fn handle_unsupported_target(
	state: &AppState,
	repository: &NexusRepository,
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
			let context =
				active_policy.context_for(&repository.name, &repository.format);
			record_decision(state, &context, DecisionOutcome::Blocked, &report);
			Err(Box::new(response_with_text(
				StatusCode::FORBIDDEN,
				report.to_plain_text(),
			)))
		}
	}
}

fn handle_policy_evaluation(
	state: &AppState,
	context: &PolicyContext,
	target: &ScanTarget,
	evaluation: PolicyEvaluation,
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

fn vulnerability_ids(report: &BlockReport) -> Vec<String> {
	report
		.vulnerabilities
		.iter()
		.map(|vulnerability| vulnerability.id.clone())
		.collect()
}

fn record_decision(
	state: &AppState,
	context: &PolicyContext,
	outcome: DecisionOutcome,
	report: &BlockReport,
) {
	state.decision_log.push(RecentDecision {
		timestamp: now_rfc3339(),
		repository: context.repository.clone(),
		format: context.format.clone(),
		team: context.team.clone(),
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

async fn forward_request(
	state: &AppState,
	method: Method,
	uri: Uri,
	headers: &HeaderMap,
	body: Body,
) -> anyhow::Result<Response<Body>> {
	let nexus_url = build_nexus_url(&state.nexus_base_url, &uri);
	let reqwest_method =
		reqwest::Method::from_bytes(method.as_str().as_bytes())
			.context("invalid request method")?;
	let mut request = state.http_client.request(reqwest_method, nexus_url);

	for (name, value) in headers {
		if is_hop_by_hop_header(name.as_str()) {
			continue;
		}

		request = request.header(name, value);
	}

	let response = request
		.body(reqwest::Body::wrap_stream(body.into_data_stream()))
		.send()
		.await
		.context("Nexus request failed")?;
	response_from_nexus(response)
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

fn response_from_nexus(
	response: reqwest::Response,
) -> anyhow::Result<Response<Body>> {
	let status = StatusCode::from_u16(response.status().as_u16())
		.context("invalid Nexus status code")?;
	let mut builder = Response::builder().status(status);

	let headers = response_headers(response.headers());
	for (name, value) in &headers {
		builder = builder.header(name, value);
	}

	builder
		.body(Body::from_stream(response.bytes_stream()))
		.context("failed to build Nexus response")
}

fn build_nexus_url(base: &Url, uri: &Uri) -> Url {
	let mut nexus_url = base.clone();
	let base_path = base.path().trim_end_matches('/');
	let request_path = uri.path();
	let path = if base_path.is_empty() || base_path == "/" {
		request_path.to_owned()
	} else if request_path == "/" {
		base_path.to_owned()
	} else {
		format!("{base_path}{request_path}")
	};

	nexus_url.set_path(&path);
	nexus_url.set_query(uri.query());
	nexus_url
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

fn unknown_repository_response(repository: &str) -> Response<Body> {
	response_with_text(
		StatusCode::FORBIDDEN,
		format!(
			"Repository blocked by nexus-sec-proxy\n\nRepository: {repository}\nReason: repository is not present in the Nexus catalog\n"
		),
	)
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
	use std::sync::atomic::{AtomicUsize, Ordering};

	use axum::body::to_bytes;
	use nexus_sec_proxy_security::{
		PackageCoordinate, Severity, Vulnerability,
	};
	use serde_json::{Value, json};
	use tower::ServiceExt;

	use super::*;

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
		let listener =
			tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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

		let catalog =
			load_repository_catalog(&client, &nexus_base_url, &config, 7)
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
		let error =
			load_repository_catalog(&client, &malformed_url, &config, 1)
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
		let osv_url = spawn_server(
			Router::new().route("/osv", post(mock_osv)).with_state(
				OsvMockState {
					request_count: Arc::clone(&osv_count),
					response: blocking_osv_response(),
					status: StatusCode::OK,
				},
			),
		)
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
		let osv_url = spawn_server(
			Router::new().route("/osv", post(mock_osv)).with_state(
				OsvMockState {
					request_count: Arc::clone(&osv_count),
					response: blocking_osv_response(),
					status: StatusCode::OK,
				},
			),
		)
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
		let osv_url = spawn_server(
			Router::new().route("/osv", post(mock_osv)).with_state(
				OsvMockState {
					request_count: Arc::clone(&osv_count),
					response: blocking_osv_response(),
					status: StatusCode::OK,
				},
			),
		)
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
				.oneshot(
					Request::builder().uri(uri).body(Body::empty()).unwrap(),
				)
				.await
				.unwrap();
			assert_eq!(response.status(), StatusCode::OK);
		}

		assert_eq!(nexus_records.lock().unwrap().len(), 2);
		assert_eq!(osv_count.load(Ordering::SeqCst), 0);
	}

	#[tokio::test]
	async fn non_get_repository_request_forwards_method_headers_query_and_body()
	{
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
}
