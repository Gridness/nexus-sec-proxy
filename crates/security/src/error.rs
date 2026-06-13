use std::time::Duration;

use reqwest::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
	#[error("scanner request failed: {0}")]
	Request(String),
	#[error("scanner returned {status}: {body}")]
	UnexpectedStatus { status: StatusCode, body: String },
	#[error("invalid scanner response: {0}")]
	InvalidResponse(String),
	#[error("invalid package reference: {0}")]
	InvalidPackageReference(String),
	#[error("unsupported scan target: {0}")]
	UnsupportedTarget(String),
	#[error("external scanner timed out after {0:?}")]
	ScannerTimeout(Duration),
	#[error("external scanner exited with {status}: {stderr}")]
	ScannerFailed { status: String, stderr: String },
}
