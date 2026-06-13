use async_trait::async_trait;

use crate::{ScanTarget, SecurityError, Vulnerability};

use super::ScanDecision;

#[async_trait]
pub trait VulnerabilitySource: Send + Sync {
	async fn vulnerabilities(
		&self,
		target: &ScanTarget,
	) -> Result<Vec<Vulnerability>, SecurityError>;
}

pub trait VulnerabilityEvaluator: Send + Sync {
	fn evaluate(
		&self,
		target: &ScanTarget,
		vulnerabilities: Vec<Vulnerability>,
	) -> ScanDecision;
}
