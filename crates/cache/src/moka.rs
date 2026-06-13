use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;

use crate::{CacheError, CacheKey, CacheStats, CachedScan};

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
