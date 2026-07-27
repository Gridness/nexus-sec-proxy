use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::{BlockReport, PolicyContext, Severity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustReport {
	pub id: Uuid,
	pub created_at: String,
	pub requester: Option<String>,
	pub context: PolicyContext,
	pub block: BlockReport,
	pub severity_counts: SeverityCounts,
}

impl TrustReport {
	#[must_use]
	pub fn new(context: PolicyContext, block: BlockReport) -> Self {
		let severity_counts =
			SeverityCounts::from_vulnerabilities(&block.vulnerabilities);
		let now = OffsetDateTime::now_utc();
		let created_at = now
			.format(&Rfc3339)
			.unwrap_or_else(|_| now.unix_timestamp().to_string());

		Self {
			id: Uuid::new_v4(),
			created_at,
			requester: None,
			context,
			block,
			severity_counts,
		}
	}

	#[must_use]
	pub fn with_requester(mut self, requester: impl Into<String>) -> Self {
		self.requester = Some(requester.into());
		self
	}
}

#[derive(
	Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct SeverityCounts {
	pub total: usize,
	pub critical: usize,
	pub high: usize,
	pub medium: usize,
	pub low: usize,
	pub unknown: usize,
}

impl SeverityCounts {
	#[must_use]
	pub fn from_vulnerabilities(
		vulnerabilities: &[crate::Vulnerability],
	) -> Self {
		let mut counts = Self {
			total: vulnerabilities.len(),
			..Self::default()
		};

		for vulnerability in vulnerabilities {
			match vulnerability.severity {
				Some(Severity::Critical) => counts.critical += 1,
				Some(Severity::High) => counts.high += 1,
				Some(Severity::Medium) => counts.medium += 1,
				Some(Severity::Low) => counts.low += 1,
				None => counts.unknown += 1,
			}
		}

		counts
	}
}
