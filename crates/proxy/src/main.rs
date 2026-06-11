mod classifier;

use std::env;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CONNECTION, CONTENT_TYPE, HOST, TRANSFER_ENCODING};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use classifier::{RequestClassification, classify_request};
use futures_util::StreamExt;
use nexus_sec_proxy_cache::{CacheKey, CachedScan, MokaScanCache, ScanCache};
use nexus_sec_proxy_config::{
	AppConfig, ArtifactScannerKind, UnsupportedTargetPolicy,
};
use nexus_sec_proxy_security::{
	BlockReport, ExternalScanner, ExternalScannerKind, OsvClient,
	PolicyContext, PolicyEvaluation, PolicyEvaluator, PolicyOutcome,
	ScanTarget, SecurityError, VulnerabilitySource,
};
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
	policy_context: PolicyContext,
	evaluator: PolicyEvaluator,
}

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
	let evaluator = PolicyEvaluator::from_policy_set(config.policy_set.clone());
	let policy_context = config
		.policy_set
		.context(&config.repository_name, &config.repository_format);
	let state = Arc::new(AppState {
		config: Arc::new(config),
		upstream_base_url,
		http_client,
		cache,
		osv,
		artifact_scanner,
		artifact_scanner_semaphore,
		policy_context,
		evaluator,
	});

	info!(
		bind_addr = %bind_addr,
		upstream_base_url = %state.config.upstream_base_url,
		repository_name = %state.config.repository_name,
		repository_format = %state.config.repository_format,
		team = state.policy_context.team.as_deref().unwrap_or(""),
		osv_ecosystem = ?state.config.osv_ecosystem,
		osv_api_url = %state.config.osv_api_url,
		policy_file = ?state.config.policy_file,
		fail_open = state.config.fail_open,
		unsupported_target_policy = ?state.config.unsupported_target_policy,
		artifact_scanner = ?state.config.artifact_scanner,
		artifact_scanner_command = %state.config.artifact_scanner_command,
		cache_max_capacity = state.config.cache_max_capacity,
		"starting nexus security proxy"
	);

	let app = Router::new()
		.route("/healthz", get(healthz))
		.fallback(proxy_handler)
		.with_state(state);
	let listener = tokio::net::TcpListener::bind(bind_addr)
		.await
		.with_context(|| format!("failed to bind {bind_addr}"))?;

	axum::serve(listener, app)
		.with_graceful_shutdown(shutdown_signal())
		.await
		.context("server failed")?;

	Ok(())
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

async fn proxy_handler(
	State(state): State<Arc<AppState>>,
	request: Request<Body>,
) -> Response<Body> {
	let method = request.method().clone();
	let uri = request.uri().clone();

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
			return handle_policy_evaluation(
				state,
				&target,
				state.evaluator.evaluate_with_context(
					&state.policy_context,
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

	let decision = match state.osv.vulnerabilities(&target).await {
		Ok(vulnerabilities) => {
			put_cache(
				state,
				cache_key,
				CachedScan::new(vulnerabilities.clone()),
				&target,
			)
			.await;
			state.evaluator.evaluate_with_context(
				&state.policy_context,
				&target,
				vulnerabilities,
			)
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

	handle_policy_evaluation(state, &target, decision)
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
			let evaluation = state.evaluator.evaluate_with_context(
				&state.policy_context,
				&target,
				scan.vulnerabilities,
			);

			match handle_policy_evaluation(state, &target, evaluation) {
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

	let decision = match scanner
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
			state.evaluator.evaluate_with_context(
				&state.policy_context,
				&target,
				vulnerabilities,
			)
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

	match handle_policy_evaluation(state, &target, decision) {
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
			Err(Box::new(response_with_text(
				StatusCode::FORBIDDEN,
				report.to_plain_text(),
			)))
		}
	}
}

fn handle_policy_evaluation(
	state: &AppState,
	target: &ScanTarget,
	evaluation: PolicyEvaluation,
) -> Result<(), Box<Response<Body>>> {
	audit_policy_evaluation(state, target, &evaluation);

	match evaluation.outcome {
		PolicyOutcome::Allowed | PolicyOutcome::ReportOnly(_) => Ok(()),
		PolicyOutcome::Blocked(report) => Err(Box::new(response_with_text(
			StatusCode::FORBIDDEN,
			report.to_plain_text(),
		))),
	}
}

fn audit_policy_evaluation(
	state: &AppState,
	target: &ScanTarget,
	evaluation: &PolicyEvaluation,
) {
	let context = &state.policy_context;
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
}
