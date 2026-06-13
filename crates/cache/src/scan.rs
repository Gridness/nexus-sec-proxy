use nexus_sec_proxy_security::Vulnerability;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedScan {
	pub vulnerabilities: Vec<Vulnerability>,
}

impl CachedScan {
	#[must_use]
	pub fn new(vulnerabilities: Vec<Vulnerability>) -> Self {
		Self { vulnerabilities }
	}

	#[must_use]
	pub fn empty() -> Self {
		Self {
			vulnerabilities: Vec::new(),
		}
	}

	#[must_use]
	pub fn has_vulnerabilities(&self) -> bool {
		!self.vulnerabilities.is_empty()
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStats {
	pub clean_entry_count: u64,
	pub vulnerable_entry_count: u64,
	pub total_entry_count: u64,
}
