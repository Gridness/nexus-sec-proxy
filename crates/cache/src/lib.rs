use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
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
pub enum CachedDecision {
	Allowed,
	Blocked {
		vulnerability_ids: Vec<String>,
		body: String,
	},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedScan {
	pub decision: CachedDecision,
}

impl CachedScan {
	#[must_use]
	pub fn allowed() -> Self {
		Self {
			decision: CachedDecision::Allowed,
		}
	}

	#[must_use]
	pub fn blocked(
		vulnerability_ids: Vec<String>,
		body: impl Into<String>,
	) -> Self {
		Self {
			decision: CachedDecision::Blocked {
				vulnerability_ids,
				body: body.into(),
			},
		}
	}

	#[must_use]
	pub fn is_blocked(&self) -> bool {
		matches!(self.decision, CachedDecision::Blocked { .. })
	}
}

#[derive(Debug, Clone)]
pub struct MokaScanCache {
	allowed: Cache<CacheKey, CachedScan>,
	blocked: Cache<CacheKey, CachedScan>,
}

impl MokaScanCache {
	#[must_use]
	pub fn new(
		max_capacity: u64,
		allowed_ttl: Duration,
		blocked_ttl: Duration,
	) -> Self {
		Self {
			allowed: Cache::builder()
				.max_capacity(max_capacity)
				.time_to_live(allowed_ttl)
				.build(),
			blocked: Cache::builder()
				.max_capacity(max_capacity)
				.time_to_live(blocked_ttl)
				.build(),
		}
	}

	#[must_use]
	pub fn len(&self) -> u64 {
		self.allowed.entry_count() + self.blocked.entry_count()
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
}

#[async_trait]
impl ScanCache for MokaScanCache {
	async fn get(
		&self,
		key: &CacheKey,
	) -> Result<Option<CachedScan>, CacheError> {
		if let Some(scan) = self.blocked.get(key).await {
			Ok(Some(scan))
		} else {
			Ok(self.allowed.get(key).await)
		}
	}

	async fn put(
		&self,
		key: CacheKey,
		scan: CachedScan,
	) -> Result<(), CacheError> {
		if scan.is_blocked() {
			self.allowed.invalidate(&key).await;
			self.blocked.insert(key, scan).await;
		} else {
			self.blocked.invalidate(&key).await;
			self.allowed.insert(key, scan).await;
		}
		Ok(())
	}

	async fn invalidate(&self, key: &CacheKey) -> Result<(), CacheError> {
		self.allowed.invalidate(key).await;
		self.blocked.invalidate(key).await;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn stores_and_reads_allowed_scan() {
		let cache = MokaScanCache::new(
			100,
			Duration::from_secs(60),
			Duration::from_secs(60),
		);
		let key = CacheKey::new("Maven", "Maven/org.example:demo", "1.0.0");

		cache.put(key.clone(), CachedScan::allowed()).await.unwrap();

		assert_eq!(cache.get(&key).await.unwrap(), Some(CachedScan::allowed()));
	}

	#[tokio::test]
	async fn invalidates_scan() {
		let cache = MokaScanCache::new(
			100,
			Duration::from_secs(60),
			Duration::from_secs(60),
		);
		let key = CacheKey::new("npm", "npm/left-pad", "1.0.0");

		cache.put(key.clone(), CachedScan::allowed()).await.unwrap();
		cache.invalidate(&key).await.unwrap();

		assert_eq!(cache.get(&key).await.unwrap(), None);
	}

	#[tokio::test]
	async fn expires_using_decision_specific_ttl() {
		let cache = MokaScanCache::new(
			100,
			Duration::from_millis(50),
			Duration::from_secs(60),
		);
		let allowed_key = CacheKey::new("npm", "npm/safe", "1.0.0");
		let blocked_key = CacheKey::new("npm", "npm/blocked", "1.0.0");

		cache
			.put(allowed_key.clone(), CachedScan::allowed())
			.await
			.unwrap();
		cache
			.put(
				blocked_key.clone(),
				CachedScan::blocked(vec!["CVE-1".to_owned()], "blocked"),
			)
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(75)).await;

		assert_eq!(cache.get(&allowed_key).await.unwrap(), None);
		assert!(cache.get(&blocked_key).await.unwrap().is_some());
	}
}
