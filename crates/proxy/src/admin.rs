use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use nexus_sec_proxy_cache::CacheStats;
use nexus_sec_proxy_config::{
	AppConfig, ArtifactScannerKind, UnsupportedTargetPolicy, load_policy_file,
	parse_policy_toml,
};
use nexus_sec_proxy_security::{EnforcementMode, PolicyContext, PolicySet};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::catalog::{
	NexusRepository, RepositoryCatalogSummary, load_repository_catalog,
};
use crate::decisions::RecentDecision;
use crate::responses::{json_error, response_with_text};
use crate::scanner_db::{ScannerDbSummary, scanner_db_summaries_from_env};
use crate::state::{ActivePolicySummary, AppState};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ImmutableConfigSummary {
	bind_addr: String,
	nexus_base_url: String,
	nexus_username_configured: bool,
	yandex_messenger_available: bool,
	yandex_messenger_enabled: bool,
	yandex_messenger_token_configured: bool,
	yandex_messenger_template_file: Option<String>,
	yandex_messenger_api_url: String,
	trust_base_url: String,
	trust_report_dir: String,
	trust_report_retention_days: u64,
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
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CacheSummary {
	clean_entry_count: u64,
	vulnerable_entry_count: u64,
	total_entry_count: u64,
	allowed_ttl_secs: u64,
	blocked_ttl_secs: u64,
	max_capacity: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScannerSummary {
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
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StatusResponse {
	started_at: String,
	uptime_seconds: u64,
	immutable_config: ImmutableConfigSummary,
	active_policy: ActivePolicySummary,
	repositories: RepositoryCatalogSummary,
	cache: CacheSummary,
	scanner: ScannerSummary,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PolicyResponse {
	active_policy: ActivePolicySummary,
	policy_set: PolicySet,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReloadPolicyResponse {
	reloaded: bool,
	active_policy: ActivePolicySummary,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReloadRepositoriesResponse {
	reloaded: bool,
	catalog: RepositoryCatalogSummary,
	repositories: Vec<NexusRepository>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ValidatePolicyRequest {
	policy_toml: String,
	repository_name: Option<String>,
	repository_format: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ValidatePolicyResponse {
	valid: bool,
	context: PolicyContext,
	selected_policy_id: String,
	selected_policy_mode: EnforcementMode,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DecisionsQuery {
	limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DecisionsResponse {
	limit: usize,
	decisions: Vec<RecentDecision>,
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

pub(crate) async fn admin_ui() -> Response<Body> {
	([(CONTENT_TYPE, "text/html; charset=utf-8")], ADMIN_HTML).into_response()
}

pub(crate) async fn admin_disabled() -> Response<Body> {
	response_with_text(StatusCode::NOT_FOUND, "admin API is disabled\n")
}

pub(crate) async fn admin_unknown() -> Response<Body> {
	response_with_text(StatusCode::NOT_FOUND, "admin route not found\n")
}

pub(crate) async fn admin_status(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
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

pub(crate) async fn admin_policy(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
	}

	let active_policy = state.active_policy();
	Json(PolicyResponse {
		active_policy: active_policy.summary(),
		policy_set: active_policy.policy_set.clone(),
	})
	.into_response()
}

pub(crate) async fn admin_reload_policy(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
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

pub(crate) async fn admin_validate_policy(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
	Json(request): Json<ValidatePolicyRequest>,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
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

pub(crate) async fn admin_repositories(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
	}

	Json(state.repository_catalog().response()).into_response()
}

pub(crate) async fn admin_reload_repositories(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
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

pub(crate) async fn admin_cache(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
	}

	Json(cache_summary(&state).await).into_response()
}

pub(crate) async fn admin_scanner(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
	}

	Json(scanner_summary(&state)).into_response()
}

pub(crate) async fn admin_decisions(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
	Query(query): Query<DecisionsQuery>,
) -> Response<Body> {
	if let Err(response) = authorize_admin(&state, &headers) {
		return *response;
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
) -> Result<(), Box<Response<Body>>> {
	let Some(expected_token) = state.config.admin_token.as_deref() else {
		return Err(Box::new(json_error(
			StatusCode::NOT_FOUND,
			"admin API is disabled",
			None,
		)));
	};

	let Some(header) = headers.get(AUTHORIZATION) else {
		warn!("admin request rejected without authorization header");
		return Err(Box::new(json_error(
			StatusCode::UNAUTHORIZED,
			"missing bearer token",
			None,
		)));
	};

	let Ok(header) = header.to_str() else {
		warn!("admin request rejected with invalid authorization header");
		return Err(Box::new(json_error(
			StatusCode::UNAUTHORIZED,
			"invalid authorization header",
			None,
		)));
	};

	let Some(token) = header.strip_prefix("Bearer ") else {
		warn!("admin request rejected without bearer token");
		return Err(Box::new(json_error(
			StatusCode::UNAUTHORIZED,
			"missing bearer token",
			None,
		)));
	};

	if token != expected_token {
		warn!("admin request rejected with wrong bearer token");
		return Err(Box::new(json_error(
			StatusCode::FORBIDDEN,
			"invalid bearer token",
			None,
		)));
	}

	Ok(())
}

fn immutable_config_summary(config: &AppConfig) -> ImmutableConfigSummary {
	ImmutableConfigSummary {
		bind_addr: config.bind_addr.to_string(),
		nexus_base_url: config.nexus_base_url.clone(),
		nexus_username_configured: config.nexus_username.is_some(),
		yandex_messenger_available: cfg!(feature = "yandex-messenger"),
		yandex_messenger_enabled: cfg!(feature = "yandex-messenger")
			&& config.yandex_messenger_enabled,
		yandex_messenger_token_configured: config
			.yandex_messenger_token
			.is_some(),
		yandex_messenger_template_file: config
			.yandex_messenger_template_file
			.clone(),
		yandex_messenger_api_url: config.yandex_messenger_api_url.clone(),
		trust_base_url: config.trust_base_url.clone(),
		trust_report_dir: config.trust_report_dir.clone(),
		trust_report_retention_days: config.trust_report_retention_days,
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
