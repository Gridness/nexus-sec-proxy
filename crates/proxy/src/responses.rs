use axum::Json;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ErrorResponse {
	error: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	details: Option<String>,
}
pub(crate) fn json_error(
	status: StatusCode,
	error: impl Into<String>,
	details: Option<String>,
) -> Response<Body> {
	(
		status,
		Json(ErrorResponse {
			error: error.into(),
			details,
		}),
	)
		.into_response()
}
pub(crate) fn response_with_text(
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

pub(crate) fn unknown_repository_response(repository: &str) -> Response<Body> {
	response_with_text(
		StatusCode::FORBIDDEN,
		format!(
			"Repository blocked by nexus-sec-proxy\n\nRepository: {repository}\nReason: repository is not present in the Nexus catalog\n"
		),
	)
}
