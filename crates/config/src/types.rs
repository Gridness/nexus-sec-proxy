use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedTargetPolicy {
	#[default]
	Allow,
	Block,
}

impl FromStr for UnsupportedTargetPolicy {
	type Err = ();

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value.trim().to_ascii_lowercase().as_str() {
			"allow" | "pass" | "pass-through" | "passthrough" => {
				Ok(Self::Allow)
			}
			"block" | "deny" => Ok(Self::Block),
			_ => Err(()),
		}
	}
}

#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactScannerKind {
	#[default]
	Disabled,
	Trivy,
	Grype,
}

impl FromStr for ArtifactScannerKind {
	type Err = ();

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value.trim().to_ascii_lowercase().as_str() {
			"disabled" | "none" | "off" => Ok(Self::Disabled),
			"trivy" => Ok(Self::Trivy),
			"grype" => Ok(Self::Grype),
			_ => Err(()),
		}
	}
}
