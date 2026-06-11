use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use nexus_sec_proxy_security::Vulnerability;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
	#[error("cache backend failed: {0}")]
	Backend(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
	pub namespace: String,
	pub identifier: String,
	pub version: Option<String>,
}

impl CacheKey {
	#[must_use]
	pub fn new(
		namespace: impl Into<String>,
		identifier: impl Into<String>,
		version: impl Into<String>,
	) -> Self {
		Self::from_parts(namespace, identifier, Some(version))
	}

	#[must_use]
	pub fn from_parts(
		namespace: impl Into<String>,
		identifier: impl Into<String>,
		version: Option<impl Into<String>>,
	) -> Self {
		Self {
			namespace: namespace.into(),
			identifier: identifier.into(),
			version: version.map(Into::into),
		}
	}
}

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

#[derive(Debug, Clone)]
pub struct MokaScanCache {
	clean: Cache<CacheKey, CachedScan>,
	vulnerable: Cache<CacheKey, CachedScan>,
}

impl MokaScanCache {
	#[must_use]
	pub fn new(
		max_capacity: u64,
		allowed_ttl: Duration,
		blocked_ttl: Duration,
	) -> Self {
		Self {
			clean: Cache::builder()
				.max_capacity(max_capacity)
				.time_to_live(allowed_ttl)
				.build(),
			vulnerable: Cache::builder()
				.max_capacity(max_capacity)
				.time_to_live(blocked_ttl)
				.build(),
		}
	}

	#[must_use]
	pub fn len(&self) -> u64 {
		self.clean.entry_count() + self.vulnerable.entry_count()
	}

	#[must_use]
	pub async fn stats(&self) -> CacheStats {
		self.clean.run_pending_tasks().await;
		self.vulnerable.run_pending_tasks().await;

		let clean_entry_count = self.clean.entry_count();
		let vulnerable_entry_count = self.vulnerable.entry_count();

		CacheStats {
			clean_entry_count,
			vulnerable_entry_count,
			total_entry_count: clean_entry_count + vulnerable_entry_count,
		}
	}

	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}
}

#[async_trait]
pub trait ScanCache: Send + Sync {
	async fn get(
		&self,
		key: &CacheKey,
	) -> Result<Option<CachedScan>, CacheError>;

	async fn put(
		&self,
		key: CacheKey,
		scan: CachedScan,
	) -> Result<(), CacheError>;

	async fn invalidate(&self, key: &CacheKey) -> Result<(), CacheError>;

	async fn stats(&self) -> Result<CacheStats, CacheError>;
}

#[async_trait]
impl ScanCache for MokaScanCache {
	async fn get(
		&self,
		key: &CacheKey,
	) -> Result<Option<CachedScan>, CacheError> {
		if let Some(scan) = self.vulnerable.get(key).await {
			Ok(Some(scan))
		} else {
			Ok(self.clean.get(key).await)
		}
	}

	async fn put(
		&self,
		key: CacheKey,
		scan: CachedScan,
	) -> Result<(), CacheError> {
		if scan.has_vulnerabilities() {
			self.clean.invalidate(&key).await;
			self.vulnerable.insert(key, scan).await;
		} else {
			self.vulnerable.invalidate(&key).await;
			self.clean.insert(key, scan).await;
		}
		Ok(())
	}

	async fn invalidate(&self, key: &CacheKey) -> Result<(), CacheError> {
		self.clean.invalidate(key).await;
		self.vulnerable.invalidate(key).await;
		Ok(())
	}

	async fn stats(&self) -> Result<CacheStats, CacheError> {
		Ok(MokaScanCache::stats(self).await)
	}
}

#[cfg(test)]
mod tests {
	use nexus_sec_proxy_security::{
		PackageCoordinate, PolicyContext, PolicyEvaluator, PolicyOutcome,
		ScanTarget, SecurityPolicy, Severity, VulnerabilityLimits,
	};

	use super::*;

	#[tokio::test]
	async fn stores_and_reads_empty_scan() {
		let cache = MokaScanCache::new(
			100,
			Duration::from_secs(60),
			Duration::from_secs(60),
		);
		let key = CacheKey::new("Maven", "Maven/org.example:demo", "1.0.0");

		cache.put(key.clone(), CachedScan::empty()).await.unwrap();

		assert_eq!(cache.get(&key).await.unwrap(), Some(CachedScan::empty()));
	}

	#[tokio::test]
	async fn invalidates_scan() {
		let cache = MokaScanCache::new(
			100,
			Duration::from_secs(60),
			Duration::from_secs(60),
		);
		let key = CacheKey::new("npm", "npm/left-pad", "1.0.0");

		cache.put(key.clone(), CachedScan::empty()).await.unwrap();
		cache.invalidate(&key).await.unwrap();

		assert_eq!(cache.get(&key).await.unwrap(), None);
	}

	#[tokio::test]
	async fn reports_clean_vulnerable_and_total_entry_counts() {
		let cache = MokaScanCache::new(
			100,
			Duration::from_secs(60),
			Duration::from_secs(60),
		);
		let safe_key = CacheKey::new("npm", "npm/safe", "1.0.0");
		let vulnerable_key = CacheKey::new("npm", "npm/vulnerable", "1.0.0");

		cache
			.put(safe_key.clone(), CachedScan::empty())
			.await
			.unwrap();
		cache
			.put(
				vulnerable_key.clone(),
				CachedScan::new(vec![vulnerability("CVE-1")]),
			)
			.await
			.unwrap();

		assert_eq!(
			cache.stats().await,
			CacheStats {
				clean_entry_count: 1,
				vulnerable_entry_count: 1,
				total_entry_count: 2,
			}
		);

		cache
			.put(safe_key, CachedScan::new(vec![vulnerability("CVE-2")]))
			.await
			.unwrap();

		assert_eq!(
			cache.stats().await,
			CacheStats {
				clean_entry_count: 0,
				vulnerable_entry_count: 2,
				total_entry_count: 2,
			}
		);
	}

	#[tokio::test]
	async fn expires_using_vulnerability_presence_ttl() {
		let cache = MokaScanCache::new(
			100,
			Duration::from_millis(50),
			Duration::from_secs(60),
		);
		let allowed_key = CacheKey::new("npm", "npm/safe", "1.0.0");
		let blocked_key = CacheKey::new("npm", "npm/blocked", "1.0.0");

		cache
			.put(allowed_key.clone(), CachedScan::empty())
			.await
			.unwrap();
		cache
			.put(
				blocked_key.clone(),
				CachedScan::new(vec![vulnerability("CVE-1")]),
			)
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(75)).await;

		assert_eq!(cache.get(&allowed_key).await.unwrap(), None);
		assert!(cache.get(&blocked_key).await.unwrap().is_some());
	}

	#[tokio::test]
	async fn cached_vulnerabilities_are_re_evaluated_under_current_policy() {
		let cache = MokaScanCache::new(
			100,
			Duration::from_secs(60),
			Duration::from_secs(60),
		);
		let key = CacheKey::new("npm", "npm/left-pad", "1.0.0");
		let target = ScanTarget::Package(PackageCoordinate::new(
			"npm", "left-pad", "1.0.0",
		));
		let context = PolicyContext::new("default", "npm", None::<String>);

		cache
			.put(
				key.clone(),
				CachedScan::new(vec![vulnerability_with_severity(
					"CVE-1",
					Severity::High,
				)]),
			)
			.await
			.unwrap();

		let cached = cache.get(&key).await.unwrap().unwrap();
		let strict = PolicyEvaluator::default().evaluate_with_context(
			&context,
			&target,
			cached.vulnerabilities.clone(),
		);
		let lenient = PolicyEvaluator::new(SecurityPolicy::new(
			Severity::Critical,
			std::iter::empty::<&str>(),
			VulnerabilityLimits::default(),
		))
		.evaluate_with_context(&context, &target, cached.vulnerabilities);

		assert!(strict.is_blocked());
		assert!(matches!(lenient.outcome, PolicyOutcome::Allowed));
	}

	fn vulnerability(id: &str) -> Vulnerability {
		Vulnerability {
			id: id.to_owned(),
			aliases: Vec::new(),
			summary: None,
			details: None,
			severity: None,
			references: Vec::new(),
		}
	}

	fn vulnerability_with_severity(
		id: &str,
		severity: Severity,
	) -> Vulnerability {
		Vulnerability {
			id: id.to_owned(),
			aliases: Vec::new(),
			summary: None,
			details: None,
			severity: Some(severity),
			references: Vec::new(),
		}
	}
}
