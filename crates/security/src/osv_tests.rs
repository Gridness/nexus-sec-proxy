use pretty_assertions::assert_eq;

use super::*;

#[test]
fn maps_component_and_fixed_range_events() {
	let vulnerability: OsvVulnerability =
		serde_json::from_value(serde_json::json!({
			"id": "GHSA-0000-0000-0000",
			"aliases": ["CVE-2026-0001"],
			"summary": "bad package",
			"details": "details",
			"database_specific": {"severity": "HIGH"},
			"affected": [{
				"package": {"name": "left-pad", "ecosystem": "npm"},
				"ranges": [{
					"type": "SEMVER",
					"events": [
						{"introduced": "0"},
						{"fixed": " 1.0.1 "},
						{"fixed": "1.0.1"},
						{"fixed": "2.0.0"}
					]
				}]
			}, {
				"package": {"name": "other", "ecosystem": "npm"},
				"ranges": [{"events": [{"fixed": "99.0.0"}]}]
			}]
		}))
		.unwrap();
	let package = PackageCoordinate::new("npm", "left-pad", "1.0.0");

	assert_eq!(
		vulnerability.into_vulnerability(&package),
		Vulnerability {
			id: "GHSA-0000-0000-0000".to_owned(),
			aliases: vec!["CVE-2026-0001".to_owned()],
			summary: Some("bad package".to_owned()),
			details: Some("details".to_owned()),
			severity: Some(Severity::High),
			references: Vec::new(),
			component_name: Some("left-pad".to_owned()),
			component_version: Some("1.0.0".to_owned()),
			fixed_versions: vec!["1.0.1".to_owned(), "2.0.0".to_owned()],
		}
	);
}
