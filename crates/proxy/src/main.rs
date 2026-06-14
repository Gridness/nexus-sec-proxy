mod admin;
mod audit;
mod catalog;
mod classifier;
mod decisions;
mod gateway;
mod responses;
mod scan;
mod scanner_db;
mod state;
mod time_utils;
mod tracing_setup;

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::Router;
use axum::routing::{any, get, post};
use nexus_sec_proxy_cache::MokaScanCache;
use nexus_sec_proxy_config::AppConfig;
use nexus_sec_proxy_security::OsvClient;
use nexus_sec_proxy_yandex_messenger::{
	YandexMessengerConfig, YandexMessengerNotifier,
};
use tokio::sync::Semaphore;
use tracing::{error, info};
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
use crate::scan::external_scanner_from_config;
use crate::state::{ActivePolicy, AppState};
use crate::time_utils::now_rfc3339;
use crate::tracing_setup::{env_log_json, init_tracing};

#[cfg(test)]
pub(crate) use crate::catalog::{
	NexusRepository, RepositoryCatalog, parse_repository_path,
};
#[cfg(test)]
pub(crate) use crate::decisions::{DecisionOutcome, RecentDecision};
#[cfg(test)]
pub(crate) use crate::gateway::{basic_auth_username, build_nexus_url};
#[cfg(test)]
pub(crate) use crate::responses::response_with_text;
#[cfg(test)]
pub(crate) use crate::scan::handle_policy_evaluation;
#[cfg(test)]
pub(crate) use crate::scanner_db::{
	ScannerDbStatus, scanner_db_summary_for_dir,
};

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
	let yandex_messenger =
		yandex_messenger_from_config(&config, http_client.clone());
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
		yandex_messenger,
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

fn yandex_messenger_from_config(
	config: &AppConfig,
	http_client: reqwest::Client,
) -> Option<YandexMessengerNotifier> {
	if !config.yandex_messenger_enabled {
		return None;
	}

	let token = config.yandex_messenger_token.as_deref()?;
	let template_file = config.yandex_messenger_template_file.as_deref()?;
	let yandex_config = YandexMessengerConfig::new(
		token,
		template_file,
		config.yandex_messenger_api_url.clone(),
	);

	Some(YandexMessengerNotifier::new(yandex_config, http_client))
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

async fn healthz() -> &'static str {
	"ok\n"
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
