use anyhow::Context;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, HOST, HeaderName, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nexus_sec_proxy_cache::{CacheKey, CachedScan, ScanCache};
use nexus_sec_proxy_config::ArtifactScannerKind;
use nexus_sec_proxy_security::{ArtifactTarget, ScanTarget};
use percent_encoding::percent_decode_str;
use serde_json::json;
use tempfile::TempDir;
use tracing::{error, warn};
use url::Url;

use crate::catalog::NexusRepository;
use crate::gateway::{
	build_nexus_url, copy_request_headers, forward_request_to_base,
	response_from_nexus, response_headers,
};
use crate::responses::response_with_text;
use crate::scan::{
	external_scanner_for_kind, handle_policy_evaluation, put_cache,
};
use crate::state::AppState;

const DOCKER_MANIFEST_V2: &str =
	"application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_MANIFEST_LIST_V2: &str =
	"application/vnd.docker.distribution.manifest.list.v2+json";
const OCI_IMAGE_MANIFEST_V1: &str =
	"application/vnd.oci.image.manifest.v1+json";
const OCI_IMAGE_INDEX_V1: &str = "application/vnd.oci.image.index.v1+json";

pub(crate) fn is_docker_registry_path(path: &str) -> bool {
	path == "/v2" || path == "/v2/" || path.starts_with("/v2/")
}

pub(crate) async fn handle_docker_registry_request(
	state: &AppState,
	method: Method,
	uri: Uri,
	headers: &HeaderMap,
	body: Body,
	requester_login: Option<&str>,
) -> Response<Body> {
	let docker_base_url = docker_registry_base_url(state);

	if method != Method::GET && method != Method::HEAD {
		return unsupported_response();
	}

	if method == Method::GET
		&& let Some(manifest_request) = parse_manifest_request_path(uri.path())
	{
		match docker_repository_and_scanner(state) {
			Ok(Some((repository, scanner))) => {
				let context = DockerManifestContext {
					state,
					docker_base_url: &docker_base_url,
					repository,
					headers,
					requester_login,
					scanner_kind: scanner,
				};
				return authorize_docker_manifest(
					context,
					manifest_request,
					uri,
				)
				.await;
			}
			Ok(None) => {}
			Err(reason) => {
				return response_with_text(
					StatusCode::SERVICE_UNAVAILABLE,
					format!(
						"Docker registry mode is misconfigured: {reason}\n"
					),
				);
			}
		}
	}

	match forward_request_to_base(
		state,
		&docker_base_url,
		method,
		uri,
		headers,
		body,
	)
	.await
	{
		Ok(response) => {
			rewrite_docker_auth_challenge(response, &docker_base_url, headers)
		}
		Err(error) => {
			error!(%error, "failed to proxy Docker registry request");
			response_with_text(
				StatusCode::BAD_GATEWAY,
				format!("failed to proxy Docker registry request: {error}\n"),
			)
		}
	}
}

struct DockerManifestContext<'a> {
	state: &'a AppState,
	docker_base_url: &'a Url,
	repository: NexusRepository,
	headers: &'a HeaderMap,
	requester_login: Option<&'a str>,
	scanner_kind: ArtifactScannerKind,
}

async fn authorize_docker_manifest(
	context: DockerManifestContext<'_>,
	manifest_request: DockerManifestRequest,
	uri: Uri,
) -> Response<Body> {
	match authorize_docker_manifest_inner(context, &manifest_request, &uri)
		.await
	{
		Ok(response) => response,
		Err(response) => *response,
	}
}

async fn authorize_docker_manifest_inner(
	context: DockerManifestContext<'_>,
	manifest_request: &DockerManifestRequest,
	uri: &Uri,
) -> Result<Response<Body>, Box<Response<Body>>> {
	let prefetched = match fetch_docker_manifest(
		context.state,
		context.docker_base_url,
		uri,
		context.headers,
	)
	.await
	{
		Ok(DockerManifestFetch::Complete(prefetched)) => prefetched,
		Ok(DockerManifestFetch::Forward(response)) => {
			return Ok(response);
		}
		Err(error) => {
			let target = docker_reference_target(manifest_request);
			return docker_manifest_fetch_failure(
				context.state,
				context.docker_base_url,
				uri,
				context.headers,
				&target,
				format!("manifest request failed: {error}"),
			)
			.await;
		}
	};

	match docker_manifest_kind(&prefetched.headers) {
		DockerManifestKind::Index => return Ok(prefetched.into_response()),
		DockerManifestKind::Manifest => {}
		DockerManifestKind::Unknown => {
			let target = docker_reference_target(manifest_request);
			return docker_manifest_failure(
				context.state,
				&target,
				"Docker manifest media type is not supported".to_owned(),
				prefetched,
			);
		}
	}
	if docker_manifest_is_attestation(&prefetched.bytes) {
		return Ok(prefetched.into_response());
	}

	let Some(digest) = docker_manifest_digest(
		&prefetched.headers,
		&manifest_request.reference,
	) else {
		let target = docker_reference_target(manifest_request);
		return docker_manifest_failure(
			context.state,
			&target,
			"Docker manifest digest could not be resolved".to_owned(),
			prefetched,
		);
	};
	let target = docker_digest_target(&manifest_request.image_name, &digest);
	let cache_key = docker_cache_key(
		&context.repository.name,
		&manifest_request.image_name,
		&digest,
	);

	match context.state.cache.get(&cache_key).await {
		Ok(Some(scan)) => {
			let active_policy = context.state.active_policy();
			let policy_context = active_policy.context_for(
				&context.repository.name,
				&context.repository.format,
			);
			handle_policy_evaluation(
				context.state,
				&policy_context,
				&target,
				active_policy.evaluator.evaluate_with_context(
					&policy_context,
					&target,
					scan.vulnerabilities,
				),
				context.requester_login,
			)
			.await?;
			return Ok(prefetched.into_response());
		}
		Ok(None) => {}
		Err(error) => {
			error!(%error, target = %target.display_name(), "cache lookup failed");
		}
	}

	let permit = match context
		.state
		.artifact_scanner_semaphore
		.clone()
		.acquire_owned()
		.await
	{
		Ok(permit) => permit,
		Err(error) => {
			return docker_manifest_failure(
				context.state,
				&target,
				format!("scanner concurrency limiter failed: {error}"),
				prefetched,
			);
		}
	};

	let auth_config = match docker_auth_config(
		context.state,
		context.docker_base_url,
	)
	.await
	{
		Ok(auth_config) => auth_config,
		Err(error) => {
			drop(permit);
			return docker_manifest_failure(
				context.state,
				&target,
				format!("failed to create Docker scanner auth config: {error}"),
				prefetched,
			);
		}
	};
	let image_ref = match docker_image_ref(
		context.docker_base_url,
		&manifest_request.image_name,
		&digest,
	) {
		Ok(image_ref) => image_ref,
		Err(error) => {
			drop(permit);
			return docker_manifest_failure(
				context.state,
				&target,
				format!("failed to build scanner image reference: {error}"),
				prefetched,
			);
		}
	};

	let scanner =
		external_scanner_for_kind(&context.state.config, context.scanner_kind);
	let vulnerabilities = match scanner
		.scan_image(
			&target,
			&image_ref,
			auth_config.as_ref().map(TempDir::path),
			context.docker_base_url.scheme() == "http",
		)
		.await
	{
		Ok(vulnerabilities) => vulnerabilities,
		Err(error) => {
			drop(permit);
			return docker_manifest_failure(
				context.state,
				&target,
				format!("scanner failed: {error}"),
				prefetched,
			);
		}
	};
	drop(permit);

	put_cache(
		context.state,
		cache_key,
		CachedScan::new(vulnerabilities.clone()),
		&target,
	)
	.await;
	let active_policy = context.state.active_policy();
	let policy_context = active_policy
		.context_for(&context.repository.name, &context.repository.format);
	handle_policy_evaluation(
		context.state,
		&policy_context,
		&target,
		active_policy.evaluator.evaluate_with_context(
			&policy_context,
			&target,
			vulnerabilities,
		),
		context.requester_login,
	)
	.await?;

	Ok(prefetched.into_response())
}

enum DockerManifestFetch {
	Complete(BufferedNexusResponse),
	Forward(Response<Body>),
}

struct BufferedNexusResponse {
	status: StatusCode,
	headers: HeaderMap,
	bytes: Vec<u8>,
}

impl BufferedNexusResponse {
	fn into_response(self) -> Response<Body> {
		let mut builder = Response::builder().status(self.status);
		for (name, value) in &self.headers {
			builder = builder.header(name, value);
		}

		builder
			.body(Body::from(self.bytes))
			.expect("buffered Nexus response is valid")
	}
}

async fn fetch_docker_manifest(
	state: &AppState,
	docker_base_url: &Url,
	uri: &Uri,
	headers: &HeaderMap,
) -> anyhow::Result<DockerManifestFetch> {
	let nexus_url = build_nexus_url(docker_base_url, uri);
	let request =
		copy_request_headers(state.http_client.get(nexus_url), headers, false);
	let response = request
		.send()
		.await
		.context("Nexus Docker manifest request failed")?;
	let status = StatusCode::from_u16(response.status().as_u16())
		.context("invalid Nexus Docker status code")?;

	if status != StatusCode::OK {
		return response_from_nexus(response)
			.map(|response| {
				rewrite_docker_auth_challenge(
					response,
					docker_base_url,
					headers,
				)
			})
			.map(DockerManifestFetch::Forward);
	}

	let headers = response_headers(response.headers());
	let bytes = response
		.bytes()
		.await
		.context("failed to read Docker manifest bytes")?
		.to_vec();

	Ok(DockerManifestFetch::Complete(BufferedNexusResponse {
		status,
		headers,
		bytes,
	}))
}

async fn docker_manifest_fetch_failure(
	state: &AppState,
	docker_base_url: &Url,
	uri: &Uri,
	headers: &HeaderMap,
	target: &ScanTarget,
	reason: String,
) -> Result<Response<Body>, Box<Response<Body>>> {
	error!(target = %target.display_name(), reason, "Docker manifest request failed");

	if !state.config.fail_open {
		return Err(Box::new(docker_failure_response(target, &reason)));
	}

	warn!(
		target = %target.display_name(),
		"allowing Docker manifest because fail_open=true"
	);
	forward_request_to_base(
		state,
		docker_base_url,
		Method::GET,
		uri.clone(),
		headers,
		Body::empty(),
	)
	.await
	.map(|response| {
		rewrite_docker_auth_challenge(response, docker_base_url, headers)
	})
	.map_err(|error| {
		Box::new(response_with_text(
			StatusCode::BAD_GATEWAY,
			format!("failed to proxy Docker registry request: {error}\n"),
		))
	})
}

fn rewrite_docker_auth_challenge(
	mut response: Response<Body>,
	docker_base_url: &Url,
	request_headers: &HeaderMap,
) -> Response<Body> {
	let Some(proxy_origin) = docker_proxy_origin(request_headers) else {
		return response;
	};
	let Ok(internal_realm) = docker_base_url.join("/v2/token") else {
		return response;
	};
	let Some(challenge) = response
		.headers()
		.get(WWW_AUTHENTICATE)
		.and_then(|value| value.to_str().ok())
	else {
		return response;
	};

	let internal_realm = format!("realm=\"{internal_realm}\"");
	let proxy_realm = format!("realm=\"{proxy_origin}/v2/token\"");
	if !challenge.contains(&internal_realm) {
		return response;
	}
	let rewritten = challenge.replace(&internal_realm, &proxy_realm);
	if let Ok(value) = HeaderValue::from_str(&rewritten) {
		response.headers_mut().insert(WWW_AUTHENTICATE, value);
	}
	response
}

fn docker_proxy_origin(headers: &HeaderMap) -> Option<String> {
	let host = first_forwarded_header(headers, "x-forwarded-host")
		.or_else(|| first_forwarded_header(headers, HOST.as_str()))?;
	let proto = first_forwarded_header(headers, "x-forwarded-proto")
		.filter(|value| {
			value.eq_ignore_ascii_case("http")
				|| value.eq_ignore_ascii_case("https")
		})
		.unwrap_or("http");
	Some(format!("{proto}://{host}"))
}

fn first_forwarded_header<'a>(
	headers: &'a HeaderMap,
	name: &str,
) -> Option<&'a str> {
	headers
		.get(name)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.split(',').next())
		.map(str::trim)
		.filter(|value| !value.is_empty() && !value.contains('/'))
}

fn docker_manifest_failure(
	state: &AppState,
	target: &ScanTarget,
	reason: String,
	prefetched: BufferedNexusResponse,
) -> Result<Response<Body>, Box<Response<Body>>> {
	error!(target = %target.display_name(), reason, "Docker manifest scan failed");

	if state.config.fail_open {
		warn!(
			target = %target.display_name(),
			"allowing Docker manifest because fail_open=true"
		);
		return Ok(prefetched.into_response());
	}

	Err(Box::new(docker_failure_response(target, &reason)))
}

fn docker_failure_response(
	target: &ScanTarget,
	reason: &str,
) -> Response<Body> {
	response_with_text(
		StatusCode::SERVICE_UNAVAILABLE,
		format!(
			"Docker image scan failed and fail_open=false\n\nTarget: {}\nReason: {reason}\n",
			target.display_name()
		),
	)
}

fn docker_repository_and_scanner(
	state: &AppState,
) -> Result<Option<(NexusRepository, ArtifactScannerKind)>, String> {
	let repository_name = state
		.config
		.docker_repository_name
		.as_deref()
		.ok_or_else(|| "Docker repository name is not configured".to_owned())?;
	let repository = state
		.repository_catalog()
		.get(repository_name)
		.ok_or_else(|| {
			format!(
				"configured Docker repository {repository_name} is missing from the catalog"
			)
		})?;
	if normalize_repository_format(&repository.format) != "docker" {
		return Err(format!(
			"configured Docker repository {repository_name} has format {}, expected docker",
			repository.format
		));
	}

	Ok(state
		.config
		.artifact_scanner_for_format("docker")
		.map(|scanner| (repository, scanner)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerManifestRequest {
	image_name: String,
	reference: String,
}

fn parse_manifest_request_path(path: &str) -> Option<DockerManifestRequest> {
	let rest = path.strip_prefix("/v2/")?;
	let (name, reference) = rest.rsplit_once("/manifests/")?;
	if name.is_empty() || reference.is_empty() {
		return None;
	}

	Some(DockerManifestRequest {
		image_name: percent_decode_str(name).decode_utf8_lossy().into_owned(),
		reference: percent_decode_str(reference)
			.decode_utf8_lossy()
			.into_owned(),
	})
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerManifestKind {
	Manifest,
	Index,
	Unknown,
}

fn docker_manifest_kind(headers: &HeaderMap) -> DockerManifestKind {
	let Some(content_type) = headers
		.get(CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
	else {
		return DockerManifestKind::Unknown;
	};
	let content_type = content_type
		.split(';')
		.next()
		.unwrap_or_default()
		.trim()
		.to_ascii_lowercase();

	match content_type.as_str() {
		DOCKER_MANIFEST_V2 | OCI_IMAGE_MANIFEST_V1 => {
			DockerManifestKind::Manifest
		}
		DOCKER_MANIFEST_LIST_V2 | OCI_IMAGE_INDEX_V1 => {
			DockerManifestKind::Index
		}
		_ => DockerManifestKind::Unknown,
	}
}

fn docker_manifest_is_attestation(bytes: &[u8]) -> bool {
	#[derive(serde::Deserialize)]
	struct Manifest {
		#[serde(default)]
		layers: Vec<Layer>,
	}

	#[derive(serde::Deserialize)]
	struct Layer {
		#[serde(rename = "mediaType")]
		media_type: Option<String>,
	}

	let Ok(manifest) = serde_json::from_slice::<Manifest>(bytes) else {
		return false;
	};
	!manifest.layers.is_empty()
		&& manifest.layers.iter().all(|layer| {
			matches!(
				layer.media_type.as_deref(),
				Some("application/vnd.in-toto+json")
					| Some("application/vnd.dsse.envelope.v1+json")
			)
		})
}

fn docker_manifest_digest(
	headers: &HeaderMap,
	reference: &str,
) -> Option<String> {
	let digest_header = HeaderName::from_static("docker-content-digest");
	headers
		.get(digest_header)
		.and_then(|value| value.to_str().ok())
		.map(str::trim)
		.filter(|value| is_digest_reference(value))
		.map(str::to_owned)
		.or_else(|| {
			is_digest_reference(reference).then(|| reference.to_owned())
		})
}

fn is_digest_reference(value: &str) -> bool {
	let Some((algorithm, digest)) = value.split_once(':') else {
		return false;
	};

	!algorithm.is_empty() && !digest.is_empty()
}

fn docker_digest_target(image_name: &str, digest: &str) -> ScanTarget {
	ScanTarget::Artifact(ArtifactTarget::with_digest(
		"docker",
		format!("{image_name}@{digest}"),
		digest.to_owned(),
	))
}

fn docker_reference_target(request: &DockerManifestRequest) -> ScanTarget {
	ScanTarget::Artifact(ArtifactTarget::new(
		"docker",
		format!("{}:{}", request.image_name, request.reference),
	))
}

fn docker_cache_key(
	repository_name: &str,
	image_name: &str,
	digest: &str,
) -> CacheKey {
	CacheKey::from_parts(
		"docker",
		format!("{repository_name}/{image_name}@{digest}"),
		None::<String>,
	)
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
	let config = json!({
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

fn docker_image_ref(
	docker_base_url: &Url,
	image_name: &str,
	digest: &str,
) -> anyhow::Result<String> {
	Ok(format!(
		"{}/{image_name}@{digest}",
		docker_registry_authority(docker_base_url)?
	))
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

fn docker_registry_base_url(state: &AppState) -> Url {
	Url::parse(
		state
			.config
			.docker_registry_base_url
			.as_deref()
			.expect("Docker registry base URL is configured"),
	)
	.expect("Docker registry base URL was validated during configuration")
}

fn normalize_repository_format(format: &str) -> String {
	format
		.chars()
		.filter(|character| character.is_ascii_alphanumeric())
		.flat_map(char::to_lowercase)
		.collect()
}

fn unsupported_response() -> Response<Body> {
	let body = json!({
		"errors": [
			{
				"code": "UNSUPPORTED",
				"message": "The operation is unsupported."
			}
		]
	});

	Response::builder()
		.status(StatusCode::METHOD_NOT_ALLOWED)
		.header(CONTENT_TYPE, "application/json")
		.header("Allow", "GET, HEAD")
		.body(Body::from(serde_json::to_vec(&body).expect("valid JSON")))
		.expect("Docker unsupported response is valid")
}
