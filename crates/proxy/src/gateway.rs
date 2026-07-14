use std::sync::Arc;

use anyhow::Context;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CONNECTION, HOST, RANGE, TRANSFER_ENCODING};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use futures_util::StreamExt;
use nexus_sec_proxy_cache::{CacheKey, CachedScan, ScanCache};
use nexus_sec_proxy_security::ScanTarget;
use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use tokio::io::AsyncWriteExt;
use tracing::error;
use url::Url;

use crate::admin::{admin_disabled, admin_unknown};
use crate::catalog::parse_repository_path;
use crate::classifier::{
	ClassificationContext, RequestClassification, classify_path,
};
use crate::docker::{handle_docker_registry_request, is_docker_registry_path};
use crate::helm::scan_helm_chart;
use crate::requester::Requester;
use crate::responses::{response_with_text, unknown_repository_response};
use crate::scan::{
	authorize_package_target, external_scanner_for_kind,
	handle_policy_evaluation, handle_unsupported_target, put_cache,
};
use crate::state::AppState;

pub(crate) async fn proxy_handler(
	State(state): State<Arc<AppState>>,
	request: Request<Body>,
) -> Response<Body> {
	let (parts, body) = request.into_parts();
	let method = parts.method;
	let uri = parts.uri;
	let headers = parts.headers;
	let requester = Requester::basic(&uri, &headers);

	if uri.path().starts_with("/admin") {
		return if state.config.admin_token.is_some() {
			admin_unknown().await
		} else {
			admin_disabled().await
		};
	}
	if uri.path().starts_with("/trust/reports") {
		return response_with_text(
			StatusCode::NOT_FOUND,
			"Trust report not found\n",
		);
	}
	if state.config.docker_registry_configured()
		&& is_docker_registry_path(uri.path())
	{
		return handle_docker_registry_request(
			&state, method, uri, &headers, body,
		)
		.await;
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
						requester.as_ref(),
					)
					.await
					{
						return *response;
					}
				}
				RequestClassification::Scan(
					target @ ScanTarget::Artifact(_),
				) => {
					if let Some(scanner) = state
						.config
						.artifact_scanner_for_format(&repository.format)
					{
						if method == Method::HEAD {
							// HEAD has no bytes to scan.
						} else if headers.contains_key(RANGE) {
							if let Err(response) = handle_unsupported_target(
								&state,
								&repository,
								target,
								"artifact range requests cannot be scanned"
									.to_owned(),
								requester.as_ref(),
							)
							.await
							{
								return *response;
							}
						} else {
							match authorize_artifact_target(
								&state,
								&repository,
								target,
								scanner,
								&uri,
								&headers,
								requester.as_ref(),
							)
							.await
							{
								Ok(Some(response)) => return response,
								Ok(None) => {}
								Err(response) => return *response,
							}
						}
					} else if let Err(response) = handle_unsupported_target(
						&state,
						&repository,
						target,
						format!(
							"artifact format {} is not mapped to a scanner",
							repository.format
						),
						requester.as_ref(),
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
async fn forward_request(
	state: &AppState,
	method: Method,
	uri: Uri,
	headers: &HeaderMap,
	body: Body,
) -> anyhow::Result<Response<Body>> {
	forward_request_to_base(
		state,
		&state.nexus_base_url,
		method,
		uri,
		headers,
		body,
	)
	.await
}

pub(crate) async fn forward_request_to_base(
	state: &AppState,
	base_url: &Url,
	method: Method,
	uri: Uri,
	headers: &HeaderMap,
	body: Body,
) -> anyhow::Result<Response<Body>> {
	let nexus_url = build_nexus_url(base_url, &uri);
	let reqwest_method =
		reqwest::Method::from_bytes(method.as_str().as_bytes())
			.context("invalid request method")?;
	let request = copy_request_headers(
		state.http_client.request(reqwest_method, nexus_url),
		headers,
		false,
	);

	let response = request
		.body(reqwest::Body::wrap_stream(body.into_data_stream()))
		.send()
		.await
		.context("Nexus request failed")?;
	response_from_nexus(response)
}

async fn authorize_artifact_target(
	state: &AppState,
	repository: &crate::catalog::NexusRepository,
	target: ScanTarget,
	scanner: nexus_sec_proxy_config::ArtifactScannerKind,
	uri: &Uri,
	headers: &HeaderMap,
	requester: Option<&Requester>,
) -> Result<Option<Response<Body>>, Box<Response<Body>>> {
	let cache_key = artifact_cache_key(repository, &target, uri);

	match state.cache.get(&cache_key).await {
		Ok(Some(scan)) => {
			let active_policy = state.active_policy();
			let context =
				active_policy.context_for(&repository.name, &repository.format);
			handle_policy_evaluation(
				state,
				&context,
				&target,
				active_policy.evaluator.evaluate_with_context(
					&context,
					&target,
					scan.vulnerabilities,
				),
				requester,
			)
			.await?;
			return Ok(None);
		}
		Ok(None) => {}
		Err(error) => {
			error!(%error, target = %target.display_name(), "cache lookup failed");
		}
	}

	let permit = match state
		.artifact_scanner_semaphore
		.clone()
		.acquire_owned()
		.await
	{
		Ok(permit) => permit,
		Err(error) => {
			return artifact_scan_failure(
				state,
				&target,
				format!("scanner concurrency limiter failed: {error}"),
			);
		}
	};

	let prefetched = match prefetch_artifact(state, uri, headers, &target).await
	{
		Ok(PrefetchResult::Complete(prefetched)) => prefetched,
		Ok(PrefetchResult::Forward(response)) => {
			drop(permit);
			return Ok(Some(response));
		}
		Ok(PrefetchResult::TooLarge { nexus_response }) => {
			drop(permit);
			return oversized_artifact_response(
				state,
				repository,
				target,
				nexus_response,
				requester,
			)
			.await;
		}
		Err(error) => {
			drop(permit);
			return artifact_scan_failure(
				state,
				&target,
				format!("artifact prefetch failed: {error}"),
			);
		}
	};

	let scanner = external_scanner_for_kind(&state.config, scanner);
	let is_helm = repository
		.format
		.chars()
		.filter(|c| c.is_ascii_alphanumeric())
		.flat_map(char::to_lowercase)
		.collect::<String>()
		== "helm";
	let scan_result = if is_helm {
		scan_helm_chart(state, scanner, &target, prefetched.file.path()).await
	} else {
		scanner
			.scan_path(&target, prefetched.file.path())
			.await
			.map_err(|error| error.to_string())
	};
	let vulnerabilities = match scan_result {
		Ok(vulnerabilities) => vulnerabilities,
		Err(error) => {
			drop(permit);
			if state.config.fail_open {
				tracing::warn!(
					%error,
					target = %target.display_name(),
					"allowing artifact because scanner failed and fail_open=true"
				);
				return Ok(Some(prefetched.into_response()));
			}

			return Err(Box::new(response_with_text(
				StatusCode::SERVICE_UNAVAILABLE,
				format!(
					"Artifact scan failed and fail_open=false\n\nTarget: {}\nReason: {error}\n",
					target.display_name()
				),
			)));
		}
	};
	drop(permit);

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
	handle_policy_evaluation(
		state,
		&context,
		&target,
		active_policy.evaluator.evaluate_with_context(
			&context,
			&target,
			vulnerabilities,
		),
		requester,
	)
	.await?;

	Ok(Some(prefetched.into_response()))
}

enum PrefetchResult {
	Complete(PrefetchedArtifact),
	Forward(Response<Body>),
	TooLarge {
		nexus_response: Option<reqwest::Response>,
	},
}

struct PrefetchedArtifact {
	status: StatusCode,
	headers: HeaderMap,
	bytes: Vec<u8>,
	file: NamedTempFile,
}

impl PrefetchedArtifact {
	fn into_response(self) -> Response<Body> {
		let mut builder = Response::builder().status(self.status);
		for (name, value) in &self.headers {
			builder = builder.header(name, value);
		}
		builder
			.body(Body::from(self.bytes))
			.expect("prefetched Nexus response is valid")
	}
}

async fn prefetch_artifact(
	state: &AppState,
	uri: &Uri,
	headers: &HeaderMap,
	target: &ScanTarget,
) -> anyhow::Result<PrefetchResult> {
	let nexus_url = build_nexus_url(&state.nexus_base_url, uri);
	let request =
		copy_request_headers(state.http_client.get(nexus_url), headers, true);
	let response = request
		.send()
		.await
		.context("Nexus artifact request failed")?;
	let status = StatusCode::from_u16(response.status().as_u16())
		.context("invalid Nexus status code")?;

	if status != StatusCode::OK {
		return response_from_nexus(response).map(PrefetchResult::Forward);
	}

	if response
		.content_length()
		.is_some_and(|length| length > state.config.artifact_scan_max_bytes)
	{
		return Ok(PrefetchResult::TooLarge {
			nexus_response: Some(response),
		});
	}

	let headers = response_headers(response.headers());
	let file = temporary_artifact_file(state, uri)?;
	let mut writer = tokio::fs::File::from_std(
		file.reopen()
			.context("failed to reopen artifact temp file")?,
	);
	let mut bytes = Vec::new();
	let mut total_size = 0_u64;
	let mut stream = response.bytes_stream();

	while let Some(chunk) = stream.next().await {
		let chunk = chunk.context("failed to read Nexus artifact bytes")?;
		total_size = total_size
			.checked_add(chunk.len() as u64)
			.context("artifact size overflow")?;
		if total_size > state.config.artifact_scan_max_bytes {
			return Ok(PrefetchResult::TooLarge {
				nexus_response: None,
			});
		}
		writer
			.write_all(&chunk)
			.await
			.context("failed to write artifact temp file")?;
		bytes.extend_from_slice(&chunk);
	}
	writer
		.flush()
		.await
		.context("failed to flush artifact temp file")?;
	writer
		.sync_all()
		.await
		.context("failed to sync artifact temp file")?;
	drop(writer);

	tracing::debug!(
		target = %target.display_name(),
		bytes = total_size,
		path = %file.path().display(),
		"prefetched artifact for scanning"
	);

	Ok(PrefetchResult::Complete(PrefetchedArtifact {
		status,
		headers,
		bytes,
		file,
	}))
}

fn temporary_artifact_file(
	state: &AppState,
	uri: &Uri,
) -> anyhow::Result<NamedTempFile> {
	let mut builder = TempFileBuilder::new();
	builder.prefix("artifact-");
	let suffix = artifact_suffix(uri.path());
	if !suffix.is_empty() {
		builder.suffix(&suffix);
	}

	if let Some(dir) = state.config.artifact_tmp_dir.as_deref() {
		builder
			.tempfile_in(dir)
			.with_context(|| format!("failed to create temp file in {dir}"))
	} else {
		builder.tempfile().context("failed to create temp file")
	}
}

fn artifact_suffix(path: &str) -> String {
	let file_name = path.rsplit('/').next().unwrap_or_default();
	let Some(dot) = file_name.find('.') else {
		return String::new();
	};

	file_name[dot..].to_owned()
}

async fn oversized_artifact_response(
	state: &AppState,
	repository: &crate::catalog::NexusRepository,
	target: ScanTarget,
	nexus_response: Option<reqwest::Response>,
	requester: Option<&Requester>,
) -> Result<Option<Response<Body>>, Box<Response<Body>>> {
	let result = handle_unsupported_target(
		state,
		repository,
		target,
		format!(
			"artifact exceeds NEXUS_SEC_PROXY_ARTIFACT_SCAN_MAX_BYTES ({})",
			state.config.artifact_scan_max_bytes
		),
		requester,
	)
	.await;

	match result {
		Ok(()) => match nexus_response {
			Some(response) => {
				response_from_nexus(response).map(Some).map_err(|error| {
					Box::new(response_with_text(
						StatusCode::BAD_GATEWAY,
						format!("failed to proxy Nexus request: {error}\n"),
					))
				})
			}
			None => Ok(None),
		},
		Err(response) => Err(response),
	}
}

fn artifact_scan_failure(
	state: &AppState,
	target: &ScanTarget,
	reason: String,
) -> Result<Option<Response<Body>>, Box<Response<Body>>> {
	error!(target = %target.display_name(), reason, "artifact scanner failed");

	if state.config.fail_open {
		tracing::warn!(
			target = %target.display_name(),
			"allowing artifact because scanner failed and fail_open=true"
		);
		return Ok(None);
	}

	Err(Box::new(response_with_text(
		StatusCode::SERVICE_UNAVAILABLE,
		format!(
			"Artifact scan failed and fail_open=false\n\nTarget: {}\nReason: {reason}\n",
			target.display_name()
		),
	)))
}

fn artifact_cache_key(
	repository: &crate::catalog::NexusRepository,
	target: &ScanTarget,
	uri: &Uri,
) -> CacheKey {
	let ScanTarget::Artifact(artifact) = target else {
		unreachable!("artifact cache key requires an artifact target");
	};
	let identifier = artifact.digest.clone().unwrap_or_else(|| {
		let path_query = uri
			.path_and_query()
			.map(|value| value.as_str())
			.unwrap_or_else(|| uri.path());
		format!("{}\n{path_query}", repository.name)
	});

	CacheKey::from_parts(target.cache_namespace(), identifier, None::<String>)
}

pub(crate) fn copy_request_headers(
	mut request: reqwest::RequestBuilder,
	headers: &HeaderMap,
	strip_conditionals: bool,
) -> reqwest::RequestBuilder {
	for (name, value) in headers {
		if is_hop_by_hop_header(name.as_str())
			|| (strip_conditionals && is_conditional_header(name.as_str()))
		{
			continue;
		}

		request = request.header(name, value);
	}

	request
}

pub(crate) fn response_headers(
	headers: &reqwest::header::HeaderMap,
) -> HeaderMap {
	let mut response_headers = HeaderMap::new();

	for (name, value) in headers {
		if is_hop_by_hop_header(name.as_str()) {
			continue;
		}

		response_headers.insert(name.clone(), value.clone());
	}

	response_headers
}

pub(crate) fn response_from_nexus(
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

pub(crate) fn build_nexus_url(base: &Url, uri: &Uri) -> Url {
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

fn is_conditional_header(name: &str) -> bool {
	name.eq_ignore_ascii_case("if-match")
		|| name.eq_ignore_ascii_case("if-none-match")
		|| name.eq_ignore_ascii_case("if-modified-since")
		|| name.eq_ignore_ascii_case("if-unmodified-since")
		|| name.eq_ignore_ascii_case("if-range")
}
