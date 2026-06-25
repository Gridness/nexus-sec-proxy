use std::sync::{Arc, RwLock};
use std::time::Instant;

use nexus_sec_proxy_cache::MokaScanCache;
use nexus_sec_proxy_config::AppConfig;
use nexus_sec_proxy_security::{
	ExternalScanner, OsvClient, PolicyContext, PolicyEvaluator, PolicySet,
};
#[cfg(feature = "yandex-messenger")]
use nexus_sec_proxy_yandex_messenger::YandexMessengerNotifier;
use serde::Serialize;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info};
use url::Url;

use crate::catalog::{RepositoryCatalog, load_repository_catalog};
use crate::decisions::DecisionLog;
use crate::time_utils::now_rfc3339;
use crate::trust_reports::ReportStore;

#[derive(Clone)]
pub(crate) struct AppState {
	pub(crate) config: Arc<AppConfig>,
	pub(crate) nexus_base_url: Url,
	pub(crate) http_client: reqwest::Client,
	pub(crate) cache: MokaScanCache,
	pub(crate) osv: OsvClient,
	pub(crate) artifact_scanner: Option<ExternalScanner>,
	#[cfg(feature = "yandex-messenger")]
	pub(crate) yandex_messenger: Option<YandexMessengerNotifier>,
	pub(crate) artifact_scanner_semaphore: Arc<Semaphore>,
	pub(crate) active_policy: Arc<RwLock<Arc<ActivePolicy>>>,
	pub(crate) repository_catalog: Arc<RwLock<Arc<RepositoryCatalog>>>,
	pub(crate) repository_catalog_reload: Arc<Mutex<()>>,
	pub(crate) decision_log: DecisionLog,
	pub(crate) report_store: ReportStore,
	pub(crate) started_at: Instant,
	pub(crate) started_at_rfc3339: String,
}

impl AppState {
	pub(crate) fn active_policy(&self) -> Arc<ActivePolicy> {
		match self.active_policy.read() {
			Ok(policy) => Arc::clone(&policy),
			Err(error) => {
				error!("active policy lock was poisoned");
				let policy = error.into_inner();
				Arc::clone(&policy)
			}
		}
	}

	pub(crate) fn repository_catalog(&self) -> Arc<RepositoryCatalog> {
		match self.repository_catalog.read() {
			Ok(catalog) => Arc::clone(&catalog),
			Err(error) => {
				error!("repository catalog lock was poisoned");
				let catalog = error.into_inner();
				Arc::clone(&catalog)
			}
		}
	}

	pub(crate) fn reload_active_policy(
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

	pub(crate) fn replace_repository_catalog(
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

	pub(crate) async fn reload_repository_catalog(
		&self,
	) -> anyhow::Result<Arc<RepositoryCatalog>> {
		let _reload = self.repository_catalog_reload.lock().await;
		let current = self.repository_catalog();
		let generation =
			current.generation.checked_add(1).ok_or_else(|| {
				anyhow::anyhow!("repository catalog generation overflow")
			})?;
		let next = load_repository_catalog(
			&self.http_client,
			&self.nexus_base_url,
			&self.config,
			generation,
		)
		.await?;
		let changed = current.repositories != next.repositories;
		let catalog = self.replace_repository_catalog(next);

		if changed {
			info!(
				generation = catalog.generation,
				repository_count = catalog.repositories.len(),
				"repository catalog changed"
			);
		} else {
			debug!(
				generation = catalog.generation,
				repository_count = catalog.repositories.len(),
				"repository catalog refresh completed without changes"
			);
		}

		Ok(catalog)
	}
}

#[derive(Debug, Clone)]
pub(crate) struct ActivePolicy {
	pub(crate) policy_set: PolicySet,
	pub(crate) evaluator: PolicyEvaluator,
	pub(crate) source_path: Option<String>,
	pub(crate) loaded_at: String,
	pub(crate) generation: u64,
}

impl ActivePolicy {
	pub(crate) fn new(
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

	pub(crate) fn context_for(
		&self,
		repository_name: &str,
		repository_format: &str,
	) -> PolicyContext {
		self.policy_set.context(repository_name, repository_format)
	}

	pub(crate) fn summary(&self) -> ActivePolicySummary {
		ActivePolicySummary {
			generation: self.generation,
			source_path: self.source_path.clone(),
			loaded_at: self.loaded_at.clone(),
		}
	}
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ActivePolicySummary {
	pub(crate) generation: u64,
	pub(crate) source_path: Option<String>,
	pub(crate) loaded_at: String,
}
