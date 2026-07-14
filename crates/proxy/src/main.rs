mod admin;
mod audit;
mod catalog;
mod classifier;
mod decisions;
mod docker;
mod gateway;
mod helm;
mod requester;
mod responses;
mod scan;
mod scanner_db;
mod state;
mod time_utils;
mod tracing_setup;
mod trust_reports;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use nexus_sec_proxy_cache::MokaScanCache;
use nexus_sec_proxy_config::{AppConfig, ArtifactScannerKind};
use nexus_sec_proxy_security::OsvClient;
#[cfg(feature = "yandex-messenger")]
use nexus_sec_proxy_yandex_messenger::{
	YandexMessengerConfig, YandexMessengerNotifier, validate_config,
};
use serde::Serialize;
use tokio::process::Command;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use url::Url;

use crate::admin::{
	admin_cache, admin_decisions, admin_disabled, admin_policy,
	admin_reload_policy, admin_reload_repositories, admin_repositories,
	admin_scanner, admin_status, admin_ui, admin_unknown,
	admin_validate_policy,
};
use crate::catalog::load_repository_catalog;
use crate::decisions::DecisionLog;
use crate::gateway::proxy_handler;
use crate::scanner_db::{ScannerDbStatus, scanner_db_summary_from_env};
use crate::state::{ActivePolicy, AppState};
use crate::time_utils::now_rfc3339;
use crate::tracing_setup::{env_log_json, init_tracing};
use crate::trust_reports::{ReportStore, serve_report};

#[cfg(test)]
pub(crate) use crate::catalog::{
	NexusRepository, RepositoryCatalog, parse_repository_path,
};
#[cfg(test)]
pub(crate) use crate::decisions::{DecisionOutcome, RecentDecision};
#[cfg(test)]
pub(crate) use crate::gateway::build_nexus_url;
#[cfg(test)]
pub(crate) use crate::requester::basic_auth_username;
#[cfg(test)]
pub(crate) use crate::responses::response_with_text;
#[cfg(test)]
pub(crate) use crate::scan::handle_policy_evaluation;
#[cfg(test)]
pub(crate) use crate::scanner_db::scanner_db_summary_for_dir;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	init_tracing(env_log_json());

	let config = AppConfig::from_env().map_err(|error| {
		error!(%error, "failed to load configuration");
		anyhow::Error::new(error).context("failed to load configuration")
	})?;
	#[cfg(not(feature = "yandex-messenger"))]
	if config.yandex_messenger_enabled {
		anyhow::bail!(
			"Yandex Messenger is enabled but this binary was built without the yandex-messenger feature"
		);
	}
	let bind_addr = config.bind_addr;
	let report_store = ReportStore::initialize(
		&config.trust_report_dir,
		&config.trust_base_url,
		config.trust_report_retention_days,
	)
	.await
	.with_context(|| {
		format!(
			"failed to initialize Trust report directory {}",
			config.trust_report_dir
		)
	})?;
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
	#[cfg(feature = "yandex-messenger")]
	let yandex_messenger =
		yandex_messenger_from_config(&config, http_client.clone()).await?;
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
		#[cfg(feature = "yandex-messenger")]
		yandex_messenger,
		artifact_scanner_semaphore,
		active_policy,
		repository_catalog: Arc::new(RwLock::new(Arc::new(repository_catalog))),
		repository_catalog_reload: Arc::new(Mutex::new(())),
		decision_log: DecisionLog::new(100),
		report_store,
		started_at,
		started_at_rfc3339,
	});
	let repository_catalog = state.repository_catalog();

	info!(
		bind_addr = %bind_addr,
		nexus_base_url = %state.config.nexus_base_url,
		repository_count = repository_catalog.repositories.len(),
		repository_catalog_generation = repository_catalog.generation,
		repository_refresh_interval_secs =
			state.config.repository_refresh_interval_secs,
		osv_ecosystem = ?state.config.osv_ecosystem,
		osv_ecosystem_overrides = ?state.config.osv_ecosystem_overrides,
		osv_api_url = %state.config.osv_api_url,
		policy_file = ?state.config.policy_file,
		admin_enabled = state.config.admin_token.is_some(),
		fail_open = state.config.fail_open,
		unsupported_target_policy = ?state.config.unsupported_target_policy,
		artifact_scanner_formats = ?state.config.artifact_scanner_formats,
		cache_max_capacity = state.config.cache_max_capacity,
		trust_base_url = %state.config.trust_base_url,
		trust_report_dir = %state.config.trust_report_dir,
		trust_report_retention_days = state.config.trust_report_retention_days,
		"starting nexus security proxy"
	);

	let app = build_app(Arc::clone(&state));
	let listener = tokio::net::TcpListener::bind(bind_addr)
		.await
		.with_context(|| format!("failed to bind {bind_addr}"))?;
	let cancellation = CancellationToken::new();
	let repository_refresh_task = spawn_repository_catalog_refresh(
		Arc::clone(&state),
		cancellation.clone(),
	);

	let server_result = axum::serve(listener, app)
		.with_graceful_shutdown({
			let cancellation = cancellation.clone();
			async move {
				shutdown_signal().await;
				cancellation.cancel();
			}
		})
		.await;
	cancellation.cancel();
	if let Some(task) = repository_refresh_task {
		task.await
			.context("repository catalog refresh task failed")?;
	}
	#[cfg(feature = "yandex-messenger")]
	if let Some(notifier) = state.yandex_messenger.as_ref() {
		notifier.shutdown(Duration::from_secs(10)).await;
	}
	server_result.context("server failed")?;

	Ok(())
}

#[cfg(feature = "yandex-messenger")]
async fn yandex_messenger_from_config(
	config: &AppConfig,
	http_client: reqwest::Client,
) -> anyhow::Result<Option<YandexMessengerNotifier>> {
	if !config.yandex_messenger_enabled {
		return Ok(None);
	}

	let token = config
		.yandex_messenger_token
		.as_deref()
		.context("Yandex Messenger token is missing")?;
	let template_file = config
		.yandex_messenger_template_file
		.as_deref()
		.context("Yandex Messenger template file is missing")?;
	let yandex_config = YandexMessengerConfig::new(
		token,
		template_file,
		config.yandex_messenger_api_url.clone(),
	);
	validate_config(&yandex_config).await?;

	Ok(Some(YandexMessengerNotifier::new(
		yandex_config,
		http_client,
	)))
}

fn build_app(state: Arc<AppState>) -> Router {
	let app = Router::new()
		.route("/healthz", get(healthz))
		.route("/trust/reports/{id}", get(serve_report));
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

#[derive(Debug, Serialize)]
struct HealthResponse {
	status: &'static str,
	checks: BTreeMap<&'static str, &'static str>,
}

async fn healthz(State(state): State<Arc<AppState>>) -> Response<Body> {
	let checks = match tokio::time::timeout(
		Duration::from_secs(2),
		health_checks(Arc::clone(&state)),
	)
	.await
	{
		Ok(checks) => checks,
		Err(_) => {
			error!("health check timed out");
			timed_out_health_checks(&state)
		}
	};
	let healthy = checks.values().all(|status| *status != "failed");
	let status = if healthy { "ok" } else { "failed" };
	let http_status = if healthy {
		StatusCode::OK
	} else {
		StatusCode::SERVICE_UNAVAILABLE
	};

	(http_status, axum::Json(HealthResponse { status, checks })).into_response()
}

async fn health_checks(
	state: Arc<AppState>,
) -> BTreeMap<&'static str, &'static str> {
	let scanners = used_artifact_scanners(&state.config);
	let nexus = check_nexus(Arc::clone(&state));
	let trust_reports = check_trust_reports(Arc::clone(&state));
	let docker_registry = check_docker_registry(Arc::clone(&state));
	let trivy = check_scanner(
		ArtifactScannerKind::Trivy,
		scanners.contains(&ArtifactScannerKind::Trivy),
	);
	let (nexus, trust_reports, docker_registry, trivy) =
		tokio::join!(nexus, trust_reports, docker_registry, trivy);

	BTreeMap::from([
		("nexus", nexus),
		("trust_reports", trust_reports),
		("docker_registry", docker_registry),
		("trivy", trivy),
	])
}

fn timed_out_health_checks(
	state: &AppState,
) -> BTreeMap<&'static str, &'static str> {
	let scanners = used_artifact_scanners(&state.config);

	BTreeMap::from([
		("nexus", "failed"),
		("trust_reports", "failed"),
		(
			"docker_registry",
			if state.config.docker_registry_configured() {
				"failed"
			} else {
				"unused"
			},
		),
		(
			"trivy",
			if scanners.contains(&ArtifactScannerKind::Trivy) {
				"failed"
			} else {
				"unused"
			},
		),
	])
}

async fn check_nexus(state: Arc<AppState>) -> &'static str {
	match load_repository_catalog(
		&state.http_client,
		&state.nexus_base_url,
		&state.config,
		0,
	)
	.await
	{
		Ok(_) => "ok",
		Err(error) => {
			error!(%error, "Nexus health check failed");
			"failed"
		}
	}
}

async fn check_trust_reports(state: Arc<AppState>) -> &'static str {
	match state.report_store.verify_writable().await {
		Ok(()) => "ok",
		Err(error) => {
			error!(%error, "Trust report storage health check failed");
			"failed"
		}
	}
}

async fn check_docker_registry(state: Arc<AppState>) -> &'static str {
	let Some(base_url) = state.config.docker_registry_base_url.as_deref()
	else {
		return "unused";
	};
	let mut url = match Url::parse(base_url) {
		Ok(url) => url,
		Err(error) => {
			error!(%error, "Docker registry base URL parse failed");
			return "failed";
		}
	};
	url.set_path("/v2/");
	url.set_query(None);

	let mut request = state.http_client.get(url);
	if let Some(username) = state.config.nexus_username.as_deref() {
		request =
			request.basic_auth(username, state.config.nexus_password.clone());
	}

	match request.send().await {
		Ok(response)
			if response.status().is_success()
				|| response.status().as_u16()
					== StatusCode::UNAUTHORIZED.as_u16() =>
		{
			"ok"
		}
		Ok(response) => {
			error!(
				status = %response.status(),
				"Docker registry health check failed"
			);
			"failed"
		}
		Err(error) => {
			error!(%error, "Docker registry health check failed");
			"failed"
		}
	}
}

async fn check_scanner(
	scanner: ArtifactScannerKind,
	used: bool,
) -> &'static str {
	if !used {
		return "unused";
	}

	let version_ok = scanner_version_ok(scanner).await;
	let db_summary = scanner_db_summary_from_env(scanner_db_env(scanner));
	let db_ok = db_summary.status == ScannerDbStatus::Found;

	if version_ok && db_ok {
		"ok"
	} else {
		if !db_ok {
			error!(
				?scanner,
				status = ?db_summary.status,
				cache_dir = ?db_summary.cache_dir,
				error = ?db_summary.error,
				"scanner DB health check failed"
			);
		}
		"failed"
	}
}

async fn scanner_version_ok(scanner: ArtifactScannerKind) -> bool {
	let mut command = Command::new(scanner.command());
	command.arg("--version");
	command.kill_on_drop(true);

	match command.output().await {
		Ok(output) if output.status.success() => true,
		Ok(output) => {
			error!(
				?scanner,
				status = %output.status,
				stderr = %String::from_utf8_lossy(&output.stderr),
				"scanner version health check failed"
			);
			false
		}
		Err(error) => {
			error!(?scanner, %error, "scanner version command failed");
			false
		}
	}
}

fn scanner_db_env(scanner: ArtifactScannerKind) -> &'static str {
	match scanner {
		ArtifactScannerKind::Trivy => "TRIVY_CACHE_DIR",
	}
}

fn used_artifact_scanners(config: &AppConfig) -> BTreeSet<ArtifactScannerKind> {
	config
		.artifact_scanner_formats
		.iter()
		.filter(|(format, _)| {
			format.as_str() != "docker" || config.docker_registry_configured()
		})
		.map(|(_, scanner)| *scanner)
		.collect()
}

fn spawn_repository_catalog_refresh(
	state: Arc<AppState>,
	cancellation: CancellationToken,
) -> Option<JoinHandle<()>> {
	let interval_secs = state.config.repository_refresh_interval_secs;
	if interval_secs == 0 {
		info!("automatic repository catalog refresh disabled");
		return None;
	}

	Some(spawn_repository_catalog_refresh_with_interval(
		state,
		Duration::from_secs(interval_secs),
		cancellation,
	))
}

fn spawn_repository_catalog_refresh_with_interval(
	state: Arc<AppState>,
	interval: Duration,
	cancellation: CancellationToken,
) -> JoinHandle<()> {
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval_at(
			tokio::time::Instant::now() + interval,
			interval,
		);
		ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

		loop {
			tokio::select! {
				biased;
				() = cancellation.cancelled() => break,
				_ = ticker.tick() => {
					tokio::select! {
						biased;
						() = cancellation.cancelled() => break,
						result = state.reload_repository_catalog() => {
							if let Err(error) = result {
								warn!(
									%error,
									"background repository catalog refresh failed"
								);
							}
						}
					}
				}
			}
		}
	})
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
mod tests;
