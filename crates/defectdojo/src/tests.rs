use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use nexus_sec_proxy_security::{
	BlockReport, PackageCoordinate, PolicyContext, PolicyViolation, Reference,
	ScanTarget, Severity, TrustReport, Vulnerability,
};
use pretty_assertions::assert_eq;
use serde_json::json;

use super::*;

#[derive(Clone, Default)]
struct CapturedRequest(Arc<Mutex<Option<(HeaderMap, String)>>>);

async fn capture_import(
	State(captured): State<CapturedRequest>,
	headers: HeaderMap,
	body: Body,
) -> impl IntoResponse {
	let body = to_bytes(body, usize::MAX).await.unwrap();
	*captured.0.lock().unwrap() =
		Some((headers, String::from_utf8(body.to_vec()).unwrap()));
	(StatusCode::CREATED, axum::Json(json!({"test_id": 42})))
}

async fn rejected_import() -> impl IntoResponse {
	(StatusCode::FORBIDDEN, "no permission")
}

async fn malformed_import() -> impl IntoResponse {
	(StatusCode::CREATED, axum::Json(json!({"message": "done"})))
}

async fn slow_import() -> impl IntoResponse {
	tokio::time::sleep(Duration::from_millis(100)).await;
	(StatusCode::CREATED, axum::Json(json!({"test_id": 1})))
}

#[test]
fn maps_vulnerabilities_and_policy_findings() {
	let first = report();
	let second = report();
	let first_json = serde_json::to_value(GenericReport::from(&first)).unwrap();
	let second_json =
		serde_json::to_value(GenericReport::from(&second)).unwrap();
	let finding = &first_json["findings"][0];

	assert_eq!(first_json["type"], REPORT_TYPE);
	assert_eq!(finding["severity"], "Critical");
	assert_eq!(finding["cve"], "CVE-2026-0001");
	assert_eq!(finding["component_name"], "openssl");
	assert_eq!(finding["component_version"], "1.0.0");
	assert_eq!(finding["fix_available"], true);
	assert_eq!(finding["fix_version"], "1.0.1, 1.1.0");
	assert_eq!(
		finding["mitigation"],
		"Upgrade openssl to a fixed version: 1.0.1, 1.1.0"
	);
	assert_eq!(
		finding["unique_id_from_tool"],
		second_json["findings"][0]["unique_id_from_tool"]
	);
	assert!(finding["description"].as_str().unwrap().contains("alice"));

	let policy = TrustReport::new(
		PolicyContext::new("raw-proxy", "raw", None::<String>),
		BlockReport::unsupported(
			ScanTarget::Package(PackageCoordinate::new(
				"npm", "left-pad", "1.0.0",
			)),
			"unsupported",
		),
	);
	let policy_json =
		serde_json::to_value(GenericReport::from(&policy)).unwrap();

	assert_eq!(policy_json["findings"][0]["severity"], "Info");
	assert_eq!(
		policy_json["findings"][0]["vuln_id_from_tool"],
		"NEXUS-SEC-PROXY-POLICY"
	);
}

#[tokio::test]
async fn submits_the_synchronous_multipart_contract_and_returns_test_url() {
	let captured = CapturedRequest::default();
	let base_url = spawn_server(
		Router::new()
			.route("/api/v2/import-scan/", post(capture_import))
			.with_state(captured.clone()),
	)
	.await;
	let client = client(base_url.clone(), Duration::from_secs(1));

	let created = client.submit(&report()).await.unwrap();

	assert_eq!(created.url, format!("{base_url}test/42"));
	let (headers, body) = captured.0.lock().unwrap().clone().unwrap();
	assert_eq!(headers["authorization"], "Token token");
	assert!(
		headers["content-type"]
			.to_str()
			.unwrap()
			.starts_with("multipart/form-data; boundary=")
	);
	for expected in [
		"name=\"scan_type\"",
		"Generic Findings Import",
		"name=\"engagement\"",
		"17",
		"name=\"background_import\"",
		"false",
		"name=\"minimum_severity\"",
		"Info",
		"name=\"active\"",
		"true",
		"name=\"verified\"",
		"name=\"skip_duplicates\"",
		"nexus-sec-proxy.json",
		"unique_id_from_tool",
	] {
		assert!(
			body.contains(expected),
			"missing multipart value {expected}"
		);
	}
	assert_eq!(
		client.status(),
		DefectDojoStatus {
			submitted: 1,
			failed: 0,
			last_success_at: client.status().last_success_at,
			last_failure_at: None,
			last_failure_category: None,
		}
	);
}

#[tokio::test]
async fn records_rejection_malformed_response_and_timeout() {
	let rejected_url = spawn_server(
		Router::new().route("/api/v2/import-scan/", post(rejected_import)),
	)
	.await;
	let rejected = client(rejected_url, Duration::from_secs(1));
	assert!(matches!(
		rejected.submit(&report()).await,
		Err(DefectDojoError::Rejected {
			status: StatusCode::FORBIDDEN,
			..
		})
	));
	assert_eq!(
		rejected.status().last_failure_category.as_deref(),
		Some("rejected")
	);

	let malformed_url = spawn_server(
		Router::new().route("/api/v2/import-scan/", post(malformed_import)),
	)
	.await;
	let malformed = client(malformed_url, Duration::from_secs(1));
	assert!(matches!(
		malformed.submit(&report()).await,
		Err(DefectDojoError::MissingTestId)
	));
	assert_eq!(
		malformed.status().last_failure_category.as_deref(),
		Some("invalid_response")
	);

	let timeout_url = spawn_server(
		Router::new().route("/api/v2/import-scan/", post(slow_import)),
	)
	.await;
	let timeout = client(timeout_url, Duration::from_millis(10));
	assert!(matches!(
		timeout.submit(&report()).await,
		Err(DefectDojoError::Request(_))
	));
	assert_eq!(
		timeout.status().last_failure_category.as_deref(),
		Some("timeout")
	);
}

fn report() -> TrustReport {
	TrustReport::new(
		PolicyContext::new("docker-proxy", "docker", Some("platform")),
		BlockReport {
			target: ScanTarget::Package(PackageCoordinate::new(
				"npm", "left-pad", "1.0.0",
			)),
			reason: "policy violated".to_owned(),
			policy_id: Some("strict".to_owned()),
			policy_violations: vec![PolicyViolation {
				reason: "critical limit exceeded".to_owned(),
			}],
			vulnerabilities: vec![Vulnerability {
				id: "GHSA-0000-0000-0000".to_owned(),
				aliases: vec!["cve-2026-0001".to_owned()],
				summary: Some("Bad crypto".to_owned()),
				details: Some("Details".to_owned()),
				severity: Some(Severity::Critical),
				references: vec![Reference {
					url: "https://example.invalid/advisory".to_owned(),
					kind: Some("WEB".to_owned()),
				}],
				component_name: Some("openssl".to_owned()),
				component_version: Some("1.0.0".to_owned()),
				fixed_versions: vec!["1.0.1".to_owned(), "1.1.0".to_owned()],
			}],
		},
	)
	.with_requester("alice")
}

fn client(base_url: Url, timeout: Duration) -> DefectDojoClient {
	let http_client =
		reqwest::Client::builder().timeout(timeout).build().unwrap();
	DefectDojoClient::new(
		DefectDojoConfig::new(base_url, "token", NonZeroU64::new(17).unwrap()),
		http_client,
	)
}

async fn spawn_server(app: Router) -> Url {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});
	Url::parse(&format!("http://{address}/")).unwrap()
}
