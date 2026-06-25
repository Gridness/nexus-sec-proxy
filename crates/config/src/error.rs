use nexus_sec_proxy_security::{PolicySetError, SeverityParseError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
	#[error("invalid socket address in {name}: {value}")]
	InvalidSocketAddr {
		name: &'static str,
		value: String,
		#[source]
		source: std::net::AddrParseError,
	},
	#[error("invalid boolean in {name}: {value}")]
	InvalidBool {
		name: &'static str,
		value: String,
		#[source]
		source: std::str::ParseBoolError,
	},
	#[error("invalid severity in {name}: {value}")]
	InvalidSeverity {
		name: &'static str,
		value: String,
		#[source]
		source: SeverityParseError,
	},
	#[error("invalid unsigned integer in {name}: {value}")]
	InvalidUnsignedInt {
		name: &'static str,
		value: String,
		#[source]
		source: std::num::ParseIntError,
	},
	#[error("invalid unsupported target policy in {name}: {value}")]
	InvalidUnsupportedTargetPolicy { name: &'static str, value: String },
	#[error("invalid artifact scanner in {name}: {value}")]
	InvalidArtifactScanner { name: &'static str, value: String },
	#[error("invalid OSV ecosystem override in {name}: {value}")]
	InvalidOsvEcosystemOverride { name: &'static str, value: String },
	#[error("invalid Trust base URL in {name}: {value} ({reason})")]
	InvalidTrustBaseUrl {
		name: &'static str,
		value: String,
		reason: String,
	},
	#[error("{name} must be at least {minimum}, got {value}")]
	ValueBelowMinimum {
		name: &'static str,
		value: u64,
		minimum: u64,
	},
	#[error("missing required environment variable: {name}")]
	MissingRequired { name: &'static str },
	#[error("failed to read policy file {path}")]
	PolicyFileRead {
		path: String,
		#[source]
		source: std::io::Error,
	},
	#[error("invalid policy file {path}")]
	PolicyFileParse {
		path: String,
		#[source]
		source: PolicySetError,
	},
}
