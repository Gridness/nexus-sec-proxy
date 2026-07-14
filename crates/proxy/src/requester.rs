#[cfg(feature = "yandex-messenger")]
use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, Uri};
#[cfg(feature = "yandex-messenger")]
use axum::http::{Response, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
#[cfg(feature = "yandex-messenger")]
use tracing::{error, warn};

#[cfg(feature = "yandex-messenger")]
use crate::gateway::{build_nexus_url, response_from_nexus};
#[cfg(feature = "yandex-messenger")]
use crate::responses::response_with_text;
#[cfg(feature = "yandex-messenger")]
use crate::state::AppState;

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "yandex-messenger"), allow(dead_code))]
pub(crate) enum Requester {
	Basic {
		user_id: Option<String>,
		authorization: HeaderValue,
		uri: Uri,
	},
	DockerBearer {
		user_id: String,
	},
}

impl Requester {
	pub(crate) fn basic(uri: &Uri, headers: &HeaderMap) -> Option<Self> {
		let authorization = headers.get(AUTHORIZATION)?.clone();
		let header = authorization.to_str().ok()?.trim();
		let scheme = header.split_ascii_whitespace().next()?;
		if !scheme.eq_ignore_ascii_case("Basic") {
			return None;
		}

		Some(Self::Basic {
			user_id: basic_auth_username(headers),
			authorization,
			uri: uri.clone(),
		})
	}

	pub(crate) fn docker_bearer(headers: &HeaderMap) -> Option<Self> {
		let header = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
		let mut parts = header.split_ascii_whitespace();
		if !parts.next()?.eq_ignore_ascii_case("Bearer") {
			return None;
		}
		let token = parts.next()?;
		if parts.next().is_some() {
			return None;
		}
		let payload = token.split('.').nth(1)?;
		let decoded = URL_SAFE_NO_PAD
			.decode(payload)
			.or_else(|_| URL_SAFE.decode(payload))
			.ok()?;
		#[derive(Deserialize)]
		struct Claims {
			sub: String,
		}
		let claims: Claims = serde_json::from_slice(&decoded).ok()?;
		let user_id = claims.sub.trim();
		if user_id.is_empty() {
			return None;
		}

		Some(Self::DockerBearer {
			user_id: user_id.to_owned(),
		})
	}
}

pub(crate) fn basic_auth_username(headers: &HeaderMap) -> Option<String> {
	let header = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
	let mut parts = header.split_ascii_whitespace();
	let scheme = parts.next()?;
	let credentials = parts.next()?;
	if parts.next().is_some() || !scheme.eq_ignore_ascii_case("Basic") {
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

#[cfg(feature = "yandex-messenger")]
pub(crate) async fn messenger_recipient(
	state: &AppState,
	requester: Option<&Requester>,
) -> Result<Option<String>, Box<Response<Body>>> {
	if state.yandex_messenger.is_none() {
		return Ok(None);
	}
	let Some(requester) = requester else {
		return Ok(None);
	};

	let user_id = match requester {
		Requester::Basic {
			user_id,
			authorization,
			uri,
		} => {
			let nexus_url = build_nexus_url(&state.nexus_base_url, uri);
			let response = state
				.http_client
				.head(nexus_url)
				.header(AUTHORIZATION, authorization)
				.send()
				.await
				.map_err(|error| {
					error!(%error, "Nexus requester verification failed");
					Box::new(response_with_text(
						StatusCode::SERVICE_UNAVAILABLE,
						"Request could not be verified by Nexus\n",
					))
				})?;
			let status = StatusCode::from_u16(response.status().as_u16())
				.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
			if matches!(
				status,
				StatusCode::UNAUTHORIZED
					| StatusCode::FORBIDDEN
					| StatusCode::NOT_FOUND
			) {
				return Err(Box::new(
					response_from_nexus(response).unwrap_or_else(|error| {
						error!(%error, "failed to return Nexus verification response");
						response_with_text(
							StatusCode::SERVICE_UNAVAILABLE,
							"Request could not be verified by Nexus\n",
						)
					}),
				));
			}
			if !status.is_success() {
				error!(%status, "Nexus requester verification returned an unexpected status");
				return Err(Box::new(response_with_text(
					StatusCode::SERVICE_UNAVAILABLE,
					"Request could not be verified by Nexus\n",
				)));
			}

			let Some(user_id) = user_id.as_deref() else {
				warn!(
					"verified Basic request did not contain a usable Nexus user ID"
				);
				return Ok(None);
			};
			user_id
		}
		Requester::DockerBearer { user_id } => user_id,
	};

	Ok(resolve_nexus_email(state, user_id).await)
}

#[cfg(feature = "yandex-messenger")]
async fn resolve_nexus_email(
	state: &AppState,
	user_id: &str,
) -> Option<String> {
	#[derive(Deserialize)]
	#[serde(rename_all = "camelCase")]
	struct NexusUser {
		user_id: String,
		email_address: String,
		status: String,
	}

	let (Some(username), Some(password)) = (
		state.config.nexus_username.as_deref(),
		state.config.nexus_password.as_deref(),
	) else {
		error!("Nexus service credentials are missing");
		return None;
	};
	let mut url = state.nexus_base_url.clone();
	let base_path = state.nexus_base_url.path().trim_end_matches('/');
	url.set_path(&format!("{base_path}/service/rest/v1/security/users"));
	url.set_query(None);
	url.query_pairs_mut().append_pair("userId", user_id);
	let response = match state
		.http_client
		.get(url)
		.basic_auth(username, Some(password))
		.send()
		.await
	{
		Ok(response) => response,
		Err(error) => {
			error!(%error, "Nexus recipient lookup failed");
			return None;
		}
	};
	if !response.status().is_success() {
		warn!(status = %response.status(), "Nexus recipient lookup was rejected");
		return None;
	}
	let users = match response.json::<Vec<NexusUser>>().await {
		Ok(users) => users,
		Err(error) => {
			error!(%error, "Nexus recipient lookup returned invalid JSON");
			return None;
		}
	};
	let mut matches = users.into_iter().filter(|user| {
		user.user_id == user_id && user.status.eq_ignore_ascii_case("active")
	});
	let Some(user) = matches.next() else {
		warn!(
			user_id,
			"Nexus recipient lookup found no active exact match"
		);
		return None;
	};
	if matches.next().is_some() {
		warn!(user_id, "Nexus recipient lookup was ambiguous");
		return None;
	}
	let email = user.email_address.trim();
	let valid = email
		.split_once('@')
		.is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
		&& !email.chars().any(char::is_whitespace);
	if !valid {
		warn!(user_id, "Nexus recipient has no usable email address");
		return None;
	}

	Some(email.to_owned())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn extracts_subject_only_from_a_bearer_jwt() {
		let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
		let mut headers = HeaderMap::new();
		headers.insert(
			AUTHORIZATION,
			format!("Bearer e30.{payload}.signature").parse().unwrap(),
		);

		assert!(matches!(
			Requester::docker_bearer(&headers),
			Some(Requester::DockerBearer { user_id }) if user_id == "alice"
		));

		headers.insert(AUTHORIZATION, "Bearer opaque".parse().unwrap());
		assert!(Requester::docker_bearer(&headers).is_none());
	}
}
