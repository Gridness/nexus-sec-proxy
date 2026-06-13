use super::*;
use crate::external::{parse_grype_output, parse_trivy_output};
use crate::osv::severity_from_text_or_score;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[test]
fn default_policy_blocks_high_and_critical_only() {
	let target = package_target();
	let evaluator = PolicyEvaluator::default();

	let medium_decision = evaluator
		.evaluate(&target, vec![vulnerability("CVE-1", Severity::Medium, [])]);
	let high_decision = evaluator
		.evaluate(&target, vec![vulnerability("CVE-2", Severity::High, [])]);
	let critical_decision = evaluator.evaluate(
		&target,
		vec![vulnerability("CVE-3", Severity::Critical, [])],
	);

	assert_eq!(medium_decision, ScanDecision::Allowed);
	assert!(high_decision.is_blocked());
	assert!(critical_decision.is_blocked());
}

#[test]
fn allowlist_matches_aliases_case_insensitively() {
	let target = package_target();
	let policy = SecurityPolicy::new(
		Severity::High,
		[" cve-2026-0001 "],
		VulnerabilityLimits::default(),
	);
	let evaluator = PolicyEvaluator::new(policy);

	let decision = evaluator.evaluate(
		&target,
		vec![vulnerability(
			"GHSA-0000",
			Severity::Critical,
			["CVE-2026-0001"],
		)],
	);

	assert_eq!(decision, ScanDecision::Allowed);
}

#[test]
fn per_severity_limit_blocks_when_count_is_exceeded() {
	let target = package_target();
	let policy = SecurityPolicy::new(
		Severity::Critical,
		std::iter::empty::<&str>(),
		VulnerabilityLimits {
			medium: Some(1),
			..VulnerabilityLimits::default()
		},
	);
	let evaluator = PolicyEvaluator::new(policy);

	let decision = evaluator.evaluate(
		&target,
		vec![
			vulnerability("CVE-1", Severity::Medium, []),
			vulnerability("CVE-2", Severity::Medium, []),
		],
	);

	assert!(decision.is_blocked());
}

#[test]
fn total_limit_is_applied_after_allowlist() {
	let target = package_target();
	let policy = SecurityPolicy::new(
		Severity::Low,
		["CVE-1"],
		VulnerabilityLimits {
			total: Some(1),
			low: Some(10),
			..VulnerabilityLimits::default()
		},
	);
	let evaluator = PolicyEvaluator::new(policy);

	let decision = evaluator.evaluate(
		&target,
		vec![
			vulnerability("CVE-1", Severity::Low, []),
			vulnerability("CVE-2", Severity::Low, []),
			vulnerability("CVE-3", Severity::Low, []),
		],
	);

	assert!(decision.is_blocked());
}

#[test]
fn parses_policy_toml_with_repository_team_mapping() {
	let policy_set = PolicySet::from_toml_str(
		r#"
		[default_policy]
		minimum_blocking_severity = "critical"
		mode = "report_only"
		max_total_vulnerabilities = 3

		[repositories."npm-internal"]
		team = "Web"

		[[policies]]
		id = "npm-web"
		repositories = [" npm-internal "]
		formats = ["NPM"]
		teams = ["web"]
		minimum_blocking_severity = "medium"
		mode = "enforce"
		max_medium_vulnerabilities = 0

		[[exceptions]]
		id = "SEC-001"
		owner = "security"
		ticket = "SEC-1"
		reason = "accepted during rollout"
		expires_at = "2099-01-01T00:00:00Z"
		vulnerability_ids = [" cve-2026-0001 "]
		packages = ["left-pad"]
		versions = ["1.0.0"]
		"#,
	)
	.unwrap();

	let context = policy_set.context("NPM-INTERNAL", "npm");
	let selected = policy_set.select_policy(&context);

	assert_eq!(context.team.as_deref(), Some("web"));
	assert_eq!(selected.id, "npm-web");
	assert_eq!(selected.policy.minimum_blocking_severity, Severity::Medium);
	assert_eq!(selected.policy.limits.medium, Some(0));
	assert_eq!(policy_set.exceptions[0].vulnerability_ids.len(), 1);
}

#[test]
fn rejects_unknown_policy_file_fields() {
	let error = PolicySet::from_toml_str(
		r#"
		[default_policy]
		minimum_blocking_severity = "HIGH"
		unexpected = true
		"#,
	)
	.unwrap_err();

	assert!(matches!(error, PolicySetError::Parse(_)));
}

#[test]
fn rejects_exception_without_required_metadata() {
	let error = PolicySet::from_toml_str(
		r#"
		[default_policy]
		minimum_blocking_severity = "HIGH"

		[[exceptions]]
		id = "SEC-001"
		ticket = "SEC-1"
		reason = "accepted during rollout"
		expires_at = "2099-01-01T00:00:00Z"
		vulnerability_ids = ["CVE-2026-0001"]
		"#,
	)
	.unwrap_err();

	assert!(matches!(error, PolicySetError::Parse(_)));
}

#[test]
fn rejects_duplicate_policy_and_exception_ids() {
	let duplicate_policy = PolicySet::from_toml_str(
		r#"
		[default_policy]
		id = "base"

		[[policies]]
		id = "Team"

		[[policies]]
		id = " team "
		"#,
	)
	.unwrap_err();
	assert!(matches!(
		duplicate_policy,
		PolicySetError::DuplicatePolicyId { .. }
	));

	let duplicate_exception = PolicySet::from_toml_str(
		r#"
		[default_policy]
		minimum_blocking_severity = "HIGH"

		[[exceptions]]
		id = "SEC-001"
		owner = "security"
		ticket = "SEC-1"
		reason = "accepted"
		expires_at = "2099-01-01T00:00:00Z"
		vulnerability_ids = ["CVE-2026-0001"]

		[[exceptions]]
		id = "sec-001"
		owner = "security"
		ticket = "SEC-2"
		reason = "accepted"
		expires_at = "2099-01-01T00:00:00Z"
		vulnerability_ids = ["CVE-2026-0002"]
		"#,
	)
	.unwrap_err();
	assert!(matches!(
		duplicate_exception,
		PolicySetError::DuplicateExceptionId { .. }
	));
}

#[test]
fn policy_selection_uses_first_matching_scope_then_default() {
	let policy_set = PolicySet::from_toml_str(
		r#"
		[default_policy]
		id = "fallback"
		minimum_blocking_severity = "critical"

		[[policies]]
		id = "first"
		repositories = ["repo-a"]
		formats = ["npm"]
		minimum_blocking_severity = "medium"

		[[policies]]
		id = "second"
		repositories = ["repo-a"]
		formats = ["npm"]
		minimum_blocking_severity = "low"
		"#,
	)
	.unwrap();

	let matching = PolicyContext::new("repo-a", "NPM", None::<String>);
	let fallback = PolicyContext::new("repo-b", "npm", None::<String>);

	assert_eq!(policy_set.select_policy(&matching).id, "first");
	assert_eq!(policy_set.select_policy(&fallback).id, "fallback");
}

#[test]
fn active_exception_matches_alias_package_and_version() {
	let target = package_target();
	let policy_set = PolicySet::from_toml_str(
		r#"
		[default_policy]
		minimum_blocking_severity = "HIGH"

		[[exceptions]]
		id = "SEC-001"
		owner = "security"
		ticket = "SEC-1"
		reason = "accepted during rollout"
		expires_at = "2099-01-01T00:00:00Z"
		vulnerability_ids = ["CVE-2026-0001"]
		packages = ["left-pad"]
		versions = ["1.0.0"]
		"#,
	)
	.unwrap();
	let evaluator = PolicyEvaluator::from_policy_set(policy_set);
	let context = PolicyContext::new("default", "npm", None::<String>);

	let evaluation = evaluator.evaluate_at(
		&context,
		&target,
		vec![vulnerability(
			"GHSA-0000",
			Severity::Critical,
			["cve-2026-0001"],
		)],
		at("2026-06-11T00:00:00Z"),
	);

	assert!(matches!(evaluation.outcome, PolicyOutcome::Allowed));
	assert_eq!(evaluation.applied_exceptions.len(), 1);
	assert!(evaluation.expired_exceptions.is_empty());
}

#[test]
fn expired_exception_is_reported_but_does_not_suppress() {
	let target = package_target();
	let policy_set = PolicySet::from_toml_str(
		r#"
		[default_policy]
		minimum_blocking_severity = "HIGH"

		[[exceptions]]
		id = "SEC-001"
		owner = "security"
		ticket = "SEC-1"
		reason = "accepted during rollout"
		expires_at = "2026-01-01T00:00:00Z"
		vulnerability_ids = ["CVE-2026-0001"]
		packages = ["left-pad"]
		versions = ["1.0.0"]
		"#,
	)
	.unwrap();
	let evaluator = PolicyEvaluator::from_policy_set(policy_set);
	let context = PolicyContext::new("default", "npm", None::<String>);

	let evaluation = evaluator.evaluate_at(
		&context,
		&target,
		vec![vulnerability("CVE-2026-0001", Severity::High, [])],
		at("2026-06-11T00:00:00Z"),
	);

	assert!(matches!(evaluation.outcome, PolicyOutcome::Blocked(_)));
	assert!(evaluation.applied_exceptions.is_empty());
	assert_eq!(evaluation.expired_exceptions.len(), 1);
}

#[test]
fn report_only_policy_returns_report_only_violation() {
	let target = package_target();
	let policy_set = PolicySet::from_toml_str(
		r#"
		[default_policy]
		id = "fallback"
		minimum_blocking_severity = "HIGH"
		mode = "report_only"
		"#,
	)
	.unwrap();
	let evaluator = PolicyEvaluator::from_policy_set(policy_set);
	let context = PolicyContext::new("default", "npm", None::<String>);

	let evaluation = evaluator.evaluate_at(
		&context,
		&target,
		vec![vulnerability("CVE-2026-0001", Severity::High, [])],
		at("2026-06-11T00:00:00Z"),
	);

	match evaluation.outcome {
		PolicyOutcome::ReportOnly(report) => {
			assert_eq!(report.policy_id.as_deref(), Some("fallback"));
			assert!(report.to_plain_text().contains("Policy: fallback"));
		}
		other => panic!("unexpected outcome: {other:?}"),
	}
}

#[test]
fn block_report_includes_references() {
	let report = BlockReport {
		target: package_target(),
		reason: "test".to_owned(),
		policy_id: None,
		policy_violations: vec![PolicyViolation {
			reason: "critical limit exceeded".to_owned(),
		}],
		vulnerabilities: vec![Vulnerability {
			id: "CVE-2026-0001".to_owned(),
			aliases: vec!["GHSA-0001".to_owned()],
			summary: Some("bad package".to_owned()),
			details: None,
			severity: Some(Severity::Critical),
			references: vec![Reference {
				url: "https://osv.dev/vulnerability/CVE-2026-0001".to_owned(),
				kind: Some("WEB".to_owned()),
			}],
		}],
	};

	let body = report.to_plain_text();

	assert!(body.contains("CVE-2026-0001"));
	assert!(body.contains("https://osv.dev/vulnerability/CVE-2026-0001"));
}

#[test]
fn parses_severity_names_and_scores() {
	assert_eq!("critical".parse::<Severity>(), Ok(Severity::Critical));
	assert_eq!("moderate".parse::<Severity>(), Ok(Severity::Medium));
	assert_eq!(severity_from_text_or_score("9.8"), Some(Severity::Critical));
	assert!("unknown".parse::<Severity>().is_err());
}

#[test]
fn package_coordinate_supports_purl_identity() {
	let package = ScanTarget::Package(PackageCoordinate::from_purl(
		"pypi",
		"pkg:pypi/jinja2@3.1.4",
		None::<&str>,
	));

	assert_eq!(package.cache_namespace(), "pypi");
	assert_eq!(package.cache_identifier(), "pkg:pypi/jinja2@3.1.4");
	assert_eq!(package.cache_version(), None);
}

#[test]
fn maps_known_nexus_formats_to_osv_ecosystems() {
	assert_eq!(default_osv_ecosystem_for_format("maven2"), Some("Maven"));
	assert_eq!(default_osv_ecosystem_for_format("PyPI"), Some("PyPI"));
	assert_eq!(
		default_osv_ecosystem_for_format("rust / cargo"),
		Some("crates.io")
	);
	assert_eq!(default_osv_ecosystem_for_format("docker"), None);
}

#[test]
fn parses_trivy_json_output() {
	let target = artifact_target();
	let output = br#"{
		"Results": [{
			"Target": "artifact.tar",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2026-0001",
				"PkgName": "openssl",
				"InstalledVersion": "1.0.0",
				"Title": "openssl issue",
				"Description": "bad crypto",
				"Severity": "CRITICAL",
				"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-0001",
				"References": ["https://example.invalid/CVE-2026-0001"]
			}]
		}]
	}"#;

	let vulnerabilities = parse_trivy_output(&target, output).unwrap();

	assert_eq!(vulnerabilities.len(), 1);
	assert_eq!(vulnerabilities[0].id, "CVE-2026-0001");
	assert_eq!(vulnerabilities[0].severity, Some(Severity::Critical));
	assert_eq!(vulnerabilities[0].references.len(), 2);
}

#[test]
fn parses_grype_json_output() {
	let target = artifact_target();
	let output = br#"{
		"matches": [{
			"vulnerability": {
				"id": "GHSA-0000",
				"severity": "High",
				"description": "bad library",
				"urls": ["https://github.com/advisories/GHSA-0000"],
				"aliases": [{"id": "CVE-2026-0002"}]
			},
			"relatedVulnerabilities": [{"id": "CVE-2026-0003"}],
			"artifact": {
				"name": "demo",
				"version": "1.0.0"
			}
		}]
	}"#;

	let vulnerabilities = parse_grype_output(&target, output).unwrap();

	assert_eq!(vulnerabilities.len(), 1);
	assert_eq!(vulnerabilities[0].id, "GHSA-0000");
	assert_eq!(vulnerabilities[0].severity, Some(Severity::High));
	assert!(
		vulnerabilities[0]
			.aliases
			.contains(&"CVE-2026-0002".to_owned())
	);
	assert!(
		vulnerabilities[0]
			.aliases
			.contains(&"CVE-2026-0003".to_owned())
	);
}

fn package_target() -> ScanTarget {
	ScanTarget::Package(PackageCoordinate::new("npm", "left-pad", "1.0.0"))
}

fn artifact_target() -> ScanTarget {
	ScanTarget::Artifact(ArtifactTarget::new("raw", "/artifact.tar"))
}

fn at(value: &str) -> OffsetDateTime {
	OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

fn vulnerability<const N: usize>(
	id: &str,
	severity: Severity,
	aliases: [&str; N],
) -> Vulnerability {
	Vulnerability {
		id: id.to_owned(),
		aliases: aliases.into_iter().map(str::to_owned).collect(),
		summary: None,
		details: None,
		severity: Some(severity),
		references: Vec::new(),
	}
}
