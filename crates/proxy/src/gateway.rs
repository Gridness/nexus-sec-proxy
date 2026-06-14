use std::sync::Arc;

use anyhow::Context;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONNECTION, HOST, TRANSFER_ENCODING};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nexus_sec_proxy_security::ScanTarget;
use tracing::error;
use url::Url;

use crate::admin::{admin_disabled, admin_unknown};
use crate::catalog::parse_repository_path;
use crate::classifier::{
	ClassificationContext, RequestClassification, classify_path,
};
use crate::responses::{response_with_text, unknown_repository_response};
use crate::scan::{authorize_package_target, handle_unsupported_target};
use crate::state::AppState;

pub(crate) async fn proxy_handler(
	State(state): State<Arc<AppState>>,
	request: Request<Body>,
) -> Response<Body> {
	let (parts, body) = request.into_parts();
	let method = parts.method;
	let uri = parts.uri;
	let headers = parts.headers;
	let requester_login = basic_auth_username(&headers);

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
						requester_login.as_deref(),
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
						requester_login.as_deref(),
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

pub(crate) fn basic_auth_username(headers: &HeaderMap) -> Option<String> {
	let header = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
	let mut parts = header.split_ascii_whitespace();
	let scheme = parts.next()?;
	let credentials = parts.next()?;
	if parts.next().is_some() {
		return None;
	}
	if !scheme.eq_ignore_ascii_case("Basic") {
		return None;
	}

	let decoded = STANDARD.decode(credentials).ok()?;
	let decoded = String::from_utf8(decoded).ok()?;
	let (username, _) = decoded.split_once(':')?;
	if username.is_empty() {
		return None;
	}

	Some(username.to_owned())
}
