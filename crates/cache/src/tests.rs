use nexus_sec_proxy_security::{
	PackageCoordinate, PolicyContext, PolicyEvaluator, PolicyOutcome,
	ScanTarget, SecurityPolicy, Severity, VulnerabilityLimits,
};

use super::*;
use nexus_sec_proxy_security::Vulnerability;
use std::time::Duration;

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
	let target =
		ScanTarget::Package(PackageCoordinate::new("npm", "left-pad", "1.0.0"));
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

fn vulnerability_with_severity(id: &str, severity: Severity) -> Vulnerability {
	Vulnerability {
		id: id.to_owned(),
		aliases: Vec::new(),
		summary: None,
		details: None,
		severity: Some(severity),
		references: Vec::new(),
	}
}
