use std::path::Path;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nexus_sec_proxy_security::{ExternalScanner, ScanTarget, Vulnerability};
use tempfile::TempDir;
use tokio::process::Command;
use tracing::{debug, warn};
use url::Url;

use crate::state::AppState;

/// Render a Helm chart archive with `helm template` and extract container
/// image references from the rendered manifests.
///
/// Returns image references exactly as they appear in the chart templates
/// (for example `nginx:1.25` or `registry.example.com/myapp:1.0`). Duplicates
/// are removed.
pub(crate) async fn extract_chart_images(
	chart_path: &Path,
	helm_binary: &str,
) -> anyhow::Result<Vec<String>> {
	let output = Command::new(helm_binary)
		.arg("template")
		.arg("release")
		.arg(chart_path)
		.output()
		.await
		.context("failed to run helm template")?;

	if !output.status.success() {
		anyhow::bail!(
			"helm template failed: {}",
			String::from_utf8_lossy(&output.stderr)
		);
	}

	let rendered = String::from_utf8_lossy(&output.stdout);
	Ok(parse_image_references(&rendered))
}

/// Parse `image:` references from rendered Kubernetes manifests.
///
/// Handles the common forms:
/// - `image: nginx:1.25`
/// - `image: "nginx:1.25"`
/// - `image: 'nginx:1.25'`
/// - `image: registry.io/app:v1`
///
/// Lines that are comments or contain `imagePullPolicy` are skipped.
fn parse_image_references(rendered: &str) -> Vec<String> {
	let mut images = Vec::new();
	let mut seen = std::collections::HashSet::new();

	for line in rendered.lines() {
		let trimmed = line.trim();
		if trimmed.starts_with('#') {
			continue;
		}

		let Some(rest) = trimmed.strip_prefix("image:") else {
			continue;
		};

		let value = rest.trim();
		if value.is_empty() || value.starts_with("imagePullPolicy") {
			continue;
		}

		let image = unquote(value).to_owned();
		if image.is_empty() {
			continue;
		}

		if seen.insert(image.clone()) {
			images.push(image);
		}
	}

	images
}

fn unquote(value: &str) -> &str {
	let value = value.trim();
	if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
		|| (value.starts_with('\'')
			&& value.ends_with('\'')
			&& value.len() >= 2)
	{
		&value[1..value.len() - 1]
	} else {
		value
	}
}

/// Resolve a chart-referenced image to a full registry-prefixed reference
/// suitable for `trivy image`.
///
/// If the image already contains a registry host (the segment before the first
/// `/` contains a `.` or a `:`), it is returned unchanged. Otherwise the
/// configured Docker registry authority is prepended so trivy pulls through
/// the Nexus Docker proxy.
///
/// `nginx:1.25` has no `/`, so the first segment is the whole string — a
/// bare image name with a tag, not a registry host. `localhost:5000/app` has
/// a `/`, and the first segment `localhost:5000` contains a `:`, so it is a
/// registry host.
fn resolve_image_ref(image: &str, registry_authority: &str) -> String {
	// If there is no `/`, the whole string is a name:tag without a registry.
	let first_segment = image.split('/').next().unwrap_or(image);
	let has_registry =
		first_segment.contains('.') || first_segment.contains(':');

	if has_registry && image.contains('/') {
		image.to_owned()
	} else {
		format!("{registry_authority}/{image}")
	}
}

/// Scan a Helm chart's referenced container images and merge the results.
///
/// This is called from `authorize_artifact_target` when the repository format
/// is `helm`. It reuses the semaphore permit already acquired by the caller.
/// Each image is scanned by tag with the configured scanner (trivy). All
/// vulnerability lists are merged into a single flat list for policy
/// evaluation.
pub(crate) async fn scan_helm_chart(
	state: &AppState,
	scanner: ExternalScanner,
	target: &ScanTarget,
	chart_path: &Path,
) -> Result<Vec<Vulnerability>, String> {
	let images = extract_chart_images(chart_path, &state.config.helm_binary)
		.await
		.map_err(|error| {
			format!("helm chart image extraction failed: {error}")
		})?;

	if images.is_empty() {
		debug!("helm chart contains no image references");
		return Ok(Vec::new());
	}

	let docker_base_url = state
		.config
		.docker_registry_base_url
		.as_deref()
		.ok_or_else(|| {
			"helm chart scanning requires NEXUS_SEC_PROXY_DOCKER_REGISTRY_BASE_URL"
				.to_owned()
		})?;
	let docker_base_url = Url::parse(docker_base_url)
		.context("failed to parse Docker registry base URL")
		.map_err(|error| error.to_string())?;
	let registry_authority = docker_registry_authority(&docker_base_url)
		.map_err(|error| error.to_string())?;
	let insecure = docker_base_url.scheme() == "http";

	let auth_config = docker_auth_config(state, &docker_base_url)
		.await
		.map_err(|error| {
			format!("failed to create Docker auth config: {error}")
		})?;

	let mut all_vulnerabilities = Vec::new();
	for image in &images {
		let image_ref = resolve_image_ref(image, &registry_authority);
		debug!(%image_ref, "scanning helm chart image");

		match scanner
			.scan_image(
				target,
				&image_ref,
				auth_config.as_ref().map(TempDir::path),
				insecure,
			)
			.await
		{
			Ok(vulnerabilities) => {
				all_vulnerabilities.extend(vulnerabilities);
			}
			Err(error) => {
				if state.config.fail_open {
					warn!(
						%error,
						%image_ref,
						"allowing image because scanner failed and fail_open=true"
					);
					continue;
				}
				return Err(format!(
					"scanner failed for image {image_ref}: {error}"
				));
			}
		}
	}

	Ok(all_vulnerabilities)
}

async fn docker_auth_config(
	state: &AppState,
	docker_base_url: &Url,
) -> anyhow::Result<Option<TempDir>> {
	let (Some(username), Some(password)) = (
		state.config.nexus_username.as_deref(),
		state.config.nexus_password.as_deref(),
	) else {
		return Ok(None);
	};
	let registry = docker_registry_authority(docker_base_url)?;
	let auth = STANDARD.encode(format!("{username}:{password}"));
	let config = serde_json::json!({
		"auths": {
			registry: {
				"auth": auth
			}
		}
	});
	let directory =
		tempfile::tempdir().context("failed to create Docker auth temp dir")?;
	let path = directory.path().join("config.json");
	let bytes = serde_json::to_vec(&config)
		.context("failed to encode Docker auth config")?;
	tokio::fs::write(&path, bytes).await.with_context(|| {
		format!("failed to write Docker auth config {}", path.display())
	})?;

	Ok(Some(directory))
}

fn docker_registry_authority(docker_base_url: &Url) -> anyhow::Result<String> {
	let host = docker_base_url
		.host_str()
		.context("Docker registry base URL does not include a host")?;
	let host = if host.contains(':') && !host.starts_with('[') {
		format!("[{host}]")
	} else {
		host.to_owned()
	};

	Ok(match docker_base_url.port() {
		Some(port) => format!("{host}:{port}"),
		None => host,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_simple_image_reference() {
		let images = parse_image_references("image: nginx:1.25\n");
		assert_eq!(images, vec!["nginx:1.25"]);
	}

	#[test]
	fn parses_double_quoted_image_reference() {
		let images = parse_image_references("image: \"nginx:1.25\"\n");
		assert_eq!(images, vec!["nginx:1.25"]);
	}

	#[test]
	fn parses_single_quoted_image_reference() {
		let images = parse_image_references("image: 'nginx:1.25'\n");
		assert_eq!(images, vec!["nginx:1.25"]);
	}

	#[test]
	fn parses_registry_prefixed_image() {
		let images =
			parse_image_references("image: registry.example.com/app:v1\n");
		assert_eq!(images, vec!["registry.example.com/app:v1"]);
	}

	#[test]
	fn skips_comments_and_image_pull_policy() {
		let rendered = "\
# image: commented-out:1.0
image: nginx:1.25
imagePullPolicy: IfNotPresent
";
		let images = parse_image_references(rendered);
		assert_eq!(images, vec!["nginx:1.25"]);
	}

	#[test]
	fn deduplicates_identical_images() {
		let rendered = "\
image: nginx:1.25
image: nginx:1.25
image: redis:7.0
";
		let images = parse_image_references(rendered);
		assert_eq!(images, vec!["nginx:1.25", "redis:7.0"]);
	}

	#[test]
	fn resolves_unqualified_image_against_registry() {
		let resolved =
			resolve_image_ref("nginx:1.25", "nexus.example.invalid:5000");
		assert_eq!(resolved, "nexus.example.invalid:5000/nginx:1.25");
	}

	#[test]
	fn resolves_library_path_image_against_registry() {
		let resolved = resolve_image_ref(
			"library/nginx:1.25",
			"nexus.example.invalid:5000",
		);
		assert_eq!(resolved, "nexus.example.invalid:5000/library/nginx:1.25");
	}

	#[test]
	fn preserves_fully_qualified_image() {
		let resolved = resolve_image_ref(
			"registry.example.com/app:v1",
			"nexus.example.invalid:5000",
		);
		assert_eq!(resolved, "registry.example.com/app:v1");
	}

	#[test]
	fn preserves_localhost_registry_image() {
		let resolved = resolve_image_ref(
			"localhost:5000/app:v1",
			"nexus.example.invalid:5000",
		);
		assert_eq!(resolved, "localhost:5000/app:v1");
	}
}
