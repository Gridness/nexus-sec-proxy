use std::collections::BTreeMap;

use anyhow::Context;
use nexus_sec_proxy_config::AppConfig;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::time_utils::now_rfc3339;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NexusRepository {
	pub(crate) name: String,
	pub(crate) format: String,
	#[serde(rename = "type")]
	pub(crate) repository_type: Option<String>,
	pub(crate) url: Option<String>,
	pub(crate) online: Option<bool>,
	pub(crate) osv_ecosystem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositoryCatalog {
	pub(crate) repositories: BTreeMap<String, NexusRepository>,
	pub(crate) loaded_at: String,
	pub(crate) generation: u64,
}

impl RepositoryCatalog {
	pub(crate) fn new(
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

	pub(crate) fn get(&self, name: &str) -> Option<NexusRepository> {
		self.repositories.get(name).cloned()
	}

	pub(crate) fn summary(&self) -> RepositoryCatalogSummary {
		RepositoryCatalogSummary {
			generation: self.generation,
			loaded_at: self.loaded_at.clone(),
			repository_count: self.repositories.len(),
		}
	}

	pub(crate) fn response(&self) -> RepositoriesResponse {
		RepositoriesResponse {
			generation: self.generation,
			loaded_at: self.loaded_at.clone(),
			repositories: self.repositories.values().cloned().collect(),
		}
	}
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RepositoryCatalogSummary {
	pub(crate) generation: u64,
	pub(crate) loaded_at: String,
	pub(crate) repository_count: usize,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RepositoriesResponse {
	pub(crate) generation: u64,
	pub(crate) loaded_at: String,
	pub(crate) repositories: Vec<NexusRepository>,
}
#[derive(Debug, Deserialize)]
pub(crate) struct NexusRepositoryResponseItem {
	name: String,
	format: String,
	#[serde(rename = "type")]
	repository_type: Option<String>,
	url: Option<String>,
	online: Option<bool>,
}

pub(crate) async fn load_repository_catalog(
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

	let catalog = RepositoryCatalog::new(repositories, generation)?;
	validate_configured_repositories(&catalog, config)?;

	Ok(catalog)
}

fn validate_configured_repositories(
	catalog: &RepositoryCatalog,
	config: &AppConfig,
) -> anyhow::Result<()> {
	let Some(repository_name) = config.docker_repository_name.as_deref() else {
		return Ok(());
	};
	if !config.docker_registry_configured() {
		return Ok(());
	}

	let Some(repository) = catalog.get(repository_name) else {
		anyhow::bail!(
			"configured Docker repository {repository_name} was not found in Nexus catalog"
		);
	};
	if normalize_repository_format(&repository.format) != "docker" {
		anyhow::bail!(
			"configured Docker repository {repository_name} has format {}, expected docker",
			repository.format
		);
	}

	Ok(())
}

fn normalize_repository_format(format: &str) -> String {
	format
		.chars()
		.filter(|character| character.is_ascii_alphanumeric())
		.flat_map(char::to_lowercase)
		.collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositoryPath {
	pub(crate) repository: String,
	pub(crate) stripped_path: String,
}

pub(crate) fn parse_repository_path(path: &str) -> Option<RepositoryPath> {
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
