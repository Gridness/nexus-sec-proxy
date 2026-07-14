use std::fmt::Write as _;
use std::io;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::header::{
	CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, PRAGMA,
	REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{Response, StatusCode};
use nexus_sec_proxy_security::{
	BlockReport, PolicyContext, Reference, Severity, Vulnerability,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use url::Url;
use uuid::{Uuid, Version};

use crate::state::AppState;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone)]
pub(crate) struct ReportStore {
	directory: Arc<PathBuf>,
	base_url: Arc<str>,
	retention: Duration,
	last_cleanup: Arc<Mutex<Instant>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatedReport {
	pub(crate) url: String,
}

impl ReportStore {
	pub(crate) async fn initialize(
		directory: impl Into<PathBuf>,
		base_url: impl Into<String>,
		retention_days: u64,
	) -> io::Result<Self> {
		let store = Self {
			directory: Arc::new(directory.into()),
			base_url: Arc::from(base_url.into()),
			retention: Duration::from_secs(
				retention_days.saturating_mul(24 * 60 * 60),
			),
			last_cleanup: Arc::new(Mutex::new(Instant::now())),
		};

		tokio::fs::create_dir_all(&*store.directory).await?;
		store.verify_writable().await?;
		store.cleanup_expired().await?;
		*store.last_cleanup.lock().await = Instant::now();

		Ok(store)
	}

	pub(crate) async fn create(
		&self,
		context: &PolicyContext,
		report: &BlockReport,
	) -> io::Result<CreatedReport> {
		self.cleanup_if_due().await?;

		let id = Uuid::new_v4();
		let timestamp = OffsetDateTime::now_utc()
			.format(&Rfc3339)
			.unwrap_or_else(|_| {
				OffsetDateTime::now_utc().unix_timestamp().to_string()
			});
		let html = render_report(&timestamp, context, report);
		let final_path = self.report_path(id);
		let temporary_path = self.directory.join(format!(".{id}.html.tmp"));

		let write_result = async {
			let mut file = tokio::fs::OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(&temporary_path)
				.await?;
			file.write_all(html.as_bytes()).await?;
			file.sync_all().await?;
			drop(file);
			tokio::fs::rename(&temporary_path, &final_path).await
		}
		.await;

		if let Err(error) = write_result {
			let _ = tokio::fs::remove_file(&temporary_path).await;
			return Err(error);
		}

		Ok(CreatedReport {
			url: format!(
				"{}/trust/reports/{id}",
				self.base_url.trim_end_matches('/')
			),
		})
	}

	pub(crate) async fn read(&self, id: &str) -> io::Result<Option<Vec<u8>>> {
		let Some(id) = valid_report_id(id) else {
			return Ok(None);
		};
		let path = self.report_path(id);
		let metadata = match tokio::fs::metadata(&path).await {
			Ok(metadata) => metadata,
			Err(error) if error.kind() == io::ErrorKind::NotFound => {
				return Ok(None);
			}
			Err(error) => return Err(error),
		};

		if !metadata.is_file()
			|| is_expired(metadata.modified()?, self.retention)
		{
			if metadata.is_file() {
				let _ = tokio::fs::remove_file(path).await;
			}
			return Ok(None);
		}

		match tokio::fs::read(path).await {
			Ok(contents) => Ok(Some(contents)),
			Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(error),
		}
	}

	pub(crate) async fn verify_writable(&self) -> io::Result<()> {
		let probe = self
			.directory
			.join(format!(".write-test-{}", Uuid::new_v4()));
		let result = async {
			let mut file = tokio::fs::OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(&probe)
				.await?;
			file.write_all(b"ok").await?;
			file.sync_all().await?;
			drop(file);
			tokio::fs::remove_file(&probe).await
		}
		.await;

		if result.is_err() {
			let _ = tokio::fs::remove_file(probe).await;
		}

		result
	}

	async fn cleanup_if_due(&self) -> io::Result<()> {
		let mut last_cleanup = self.last_cleanup.lock().await;
		if last_cleanup.elapsed() < CLEANUP_INTERVAL {
			return Ok(());
		}

		self.cleanup_expired().await?;
		*last_cleanup = Instant::now();
		Ok(())
	}

	async fn cleanup_expired(&self) -> io::Result<()> {
		let mut entries = tokio::fs::read_dir(&*self.directory).await?;
		while let Some(entry) = entries.next_entry().await? {
			let metadata = match entry.metadata().await {
				Ok(metadata) => metadata,
				Err(error) if error.kind() == io::ErrorKind::NotFound => {
					continue;
				}
				Err(error) => return Err(error),
			};
			if metadata.is_file()
				&& is_expired(metadata.modified()?, self.retention)
			{
				match tokio::fs::remove_file(entry.path()).await {
					Ok(()) => {}
					Err(error) if error.kind() == io::ErrorKind::NotFound => {}
					Err(error) => return Err(error),
				}
			}
		}

		Ok(())
	}

	fn report_path(&self, id: Uuid) -> PathBuf {
		self.directory.join(format!("{id}.html"))
	}

	#[cfg(test)]
	pub(crate) fn directory(&self) -> &Path {
		&self.directory
	}

	#[cfg(test)]
	pub(crate) fn for_test(
		directory: impl Into<PathBuf>,
		base_url: impl Into<String>,
		retention_days: u64,
	) -> Self {
		Self {
			directory: Arc::new(directory.into()),
			base_url: Arc::from(base_url.into()),
			retention: Duration::from_secs(retention_days * 24 * 60 * 60),
			last_cleanup: Arc::new(Mutex::new(Instant::now())),
		}
	}
}

pub(crate) async fn serve_report(
	State(state): State<Arc<AppState>>,
	AxumPath(id): AxumPath<String>,
) -> Response<Body> {
	let response = match state.report_store.read(&id).await {
		Ok(Some(contents)) => Response::builder()
			.status(StatusCode::OK)
			.header(CONTENT_TYPE, "text/html; charset=utf-8")
			.body(Body::from(contents))
			.expect("static Trust report response is valid"),
		Ok(None) => Response::builder()
			.status(StatusCode::NOT_FOUND)
			.header(CONTENT_TYPE, "text/plain; charset=utf-8")
			.body(Body::from("Trust report not found\n"))
			.expect("static Trust not-found response is valid"),
		Err(error) => {
			tracing::error!(%error, report_id = %id, "Trust report read failed");
			Response::builder()
				.status(StatusCode::SERVICE_UNAVAILABLE)
				.header(CONTENT_TYPE, "text/plain; charset=utf-8")
				.body(Body::from("Trust report is temporarily unavailable\n"))
				.expect("static Trust unavailable response is valid")
		}
	};

	with_security_headers(response)
}

fn with_security_headers(mut response: Response<Body>) -> Response<Body> {
	let headers = response.headers_mut();
	headers.insert(
		CACHE_CONTROL,
		"no-store, no-cache, must-revalidate, max-age=0"
			.parse()
			.expect("static header is valid"),
	);
	headers.insert(PRAGMA, "no-cache".parse().expect("static header is valid"));
	headers.insert(
		X_CONTENT_TYPE_OPTIONS,
		"nosniff".parse().expect("static header is valid"),
	);
	headers.insert(
		REFERRER_POLICY,
		"no-referrer".parse().expect("static header is valid"),
	);
	headers.insert(
		X_FRAME_OPTIONS,
		"DENY".parse().expect("static header is valid"),
	);
	headers.insert(
		axum::http::HeaderName::from_static("x-robots-tag"),
		"noindex, nofollow, noarchive"
			.parse()
			.expect("static header is valid"),
	);
	headers.insert(
		CONTENT_SECURITY_POLICY,
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
			.parse()
			.expect("static header is valid"),
	);
	response
}

fn valid_report_id(id: &str) -> Option<Uuid> {
	let parsed = Uuid::parse_str(id).ok()?;

	(parsed.get_version() == Some(Version::Random)
		&& parsed.hyphenated().to_string() == id)
		.then_some(parsed)
}

fn is_expired(modified: SystemTime, retention: Duration) -> bool {
	SystemTime::now()
		.duration_since(modified)
		.is_ok_and(|age| age >= retention)
}

fn render_report(
	timestamp: &str,
	context: &PolicyContext,
	report: &BlockReport,
) -> String {
	let counts = SeverityCounts::from_vulnerabilities(&report.vulnerabilities);
	let mut html = String::with_capacity(12_000);
	html.push_str(
		r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Trust — Block report</title>
<style>
:root{color-scheme:light dark;--bg:#f5f7fa;--panel:#fff;--text:#172033;--muted:#5f6b7a;--line:#d9e0e8;--accent:#2855d9;--danger:#b42318;--chip:#eef2f7}
@media(prefers-color-scheme:dark){:root{--bg:#0f1420;--panel:#171e2c;--text:#edf2f8;--muted:#a9b4c3;--line:#303a4c;--accent:#86a5ff;--danger:#ff8a80;--chip:#222c3d}}
:root[data-theme="light"]{color-scheme:light;--bg:#f5f7fa;--panel:#fff;--text:#172033;--muted:#5f6b7a;--line:#d9e0e8;--accent:#2855d9;--danger:#b42318;--chip:#eef2f7}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0f1420;--panel:#171e2c;--text:#edf2f8;--muted:#a9b4c3;--line:#303a4c;--accent:#86a5ff;--danger:#ff8a80;--chip:#222c3d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.55}a{color:var(--accent);overflow-wrap:anywhere}header{border-bottom:1px solid var(--line);background:var(--panel)}.header-inner,main{width:min(1120px,calc(100% - 32px));margin:auto}.header-inner{min-height:72px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:10px;font-size:1.25rem;font-weight:750}.brand svg{width:30px;height:30px;color:var(--accent)}button{border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text);padding:8px 11px;cursor:pointer}main{padding:32px 0 56px}h1{font-size:clamp(1.75rem,4vw,2.5rem);line-height:1.15;margin:0 0 8px}.lede{color:var(--muted);margin:0 0 28px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin-top:20px;box-shadow:0 8px 24px rgba(15,23,42,.05)}h2{font-size:1.15rem;margin:0 0 16px}.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.fact dt{font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}.fact dd{margin:3px 0 0;overflow-wrap:anywhere}.reason{color:var(--danger);font-weight:650}.counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}.count{background:var(--chip);border-radius:10px;padding:14px}.count strong{display:block;font-size:1.5rem}.count span{color:var(--muted);font-size:.85rem}.violations{margin:0;padding-left:22px}.violations li+li{margin-top:6px}details{border:1px solid var(--line);border-radius:10px;background:var(--panel)}details+details{margin-top:10px}summary{cursor:pointer;padding:14px 16px;font-weight:650}.vulnerability{border-top:1px solid var(--line);padding:16px}.vulnerability dl{display:grid;grid-template-columns:minmax(90px,140px) 1fr;gap:8px 14px;margin:0}.vulnerability dt{color:var(--muted)}.vulnerability dd{margin:0;overflow-wrap:anywhere}.description{white-space:pre-wrap}.empty{color:var(--muted);margin:0}.references{margin:0;padding-left:20px}.references li+li{margin-top:5px}@media(max-width:560px){.header-inner,main{width:min(100% - 20px,1120px)}main{padding-top:22px}.panel{padding:16px}.vulnerability dl{grid-template-columns:1fr;gap:2px}.vulnerability dd+dt{margin-top:9px}}
</style>
<script>(()=>{try{const t=localStorage.getItem("trust-theme");if(t==="light"||t==="dark")document.documentElement.dataset.theme=t}catch{}})()</script>
</head>
<body>
<header><div class="header-inner"><div class="brand">
<svg viewBox="0 0 32 32" role="img" aria-label="Shield with lock"><path fill="currentColor" d="M16 2 4.5 6.2v8.7c0 7.1 4.8 12.7 11.5 15.1 6.7-2.4 11.5-8 11.5-15.1V6.2L16 2Zm0 3.2 8.5 3.1v6.6c0 5.4-3.4 9.9-8.5 12.1-5.1-2.2-8.5-6.7-8.5-12.1V8.3L16 5.2Z"/><path fill="currentColor" d="M12 15v-2a4 4 0 0 1 8 0v2h1v7H11v-7h1Zm2 0h4v-2a2 2 0 1 0-4 0v2Z"/></svg>
<span>Trust</span></div><button id="theme-toggle" type="button" aria-label="Toggle color theme" aria-pressed="false">Theme</button></div></header>
<main><h1>Download blocked</h1><p class="lede">This report explains the enforced security decision.</p>
<section class="panel" aria-labelledby="decision-heading"><h2 id="decision-heading">Decision</h2><dl class="facts">"#,
	);
	fact(&mut html, "Blocked at", timestamp);
	fact(&mut html, "Target", &report.target.display_name());
	fact(&mut html, "Repository", &context.repository);
	fact(&mut html, "Format", &context.format);
	fact(
		&mut html,
		"Team",
		context.team.as_deref().unwrap_or("Not assigned"),
	);
	fact(
		&mut html,
		"Policy",
		report
			.policy_id
			.as_deref()
			.unwrap_or("Unsupported target policy"),
	);
	html.push_str("</dl><p class=\"reason\">");
	escape_into(&mut html, &report.reason);
	html.push_str("</p></section>");

	html.push_str(
		"<section class=\"panel\" aria-labelledby=\"severity-heading\"><h2 id=\"severity-heading\">Severity counts</h2><div class=\"counts\">",
	);
	count(&mut html, "Total", counts.total);
	count(&mut html, "Critical", counts.critical);
	count(&mut html, "High", counts.high);
	count(&mut html, "Medium", counts.medium);
	count(&mut html, "Low", counts.low);
	count(&mut html, "Unknown", counts.unknown);
	html.push_str("</div></section>");

	html.push_str(
		"<section class=\"panel\" aria-labelledby=\"violations-heading\"><h2 id=\"violations-heading\">Policy violations</h2>",
	);
	if report.policy_violations.is_empty() {
		html.push_str(
			"<p class=\"empty\">No policy violation details were provided.</p>",
		);
	} else {
		html.push_str("<ul class=\"violations\">");
		for violation in &report.policy_violations {
			html.push_str("<li>");
			escape_into(&mut html, &violation.reason);
			html.push_str("</li>");
		}
		html.push_str("</ul>");
	}
	html.push_str("</section>");

	html.push_str(
		"<section class=\"panel\" aria-labelledby=\"vulnerabilities-heading\"><h2 id=\"vulnerabilities-heading\">Block-relevant vulnerabilities</h2>",
	);
	if report.vulnerabilities.is_empty() {
		html.push_str(
			"<p class=\"empty\">No vulnerabilities are associated with this block.</p>",
		);
	} else {
		for vulnerability in &report.vulnerabilities {
			vulnerability_details(&mut html, vulnerability);
		}
	}
	html.push_str(
		r#"</section></main>
<script>(()=>{const b=document.getElementById("theme-toggle");const root=document.documentElement;const current=()=>root.dataset.theme||(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light");const sync=()=>{const d=current();b.setAttribute("aria-pressed",String(d==="dark"));b.textContent=d==="dark"?"Light theme":"Dark theme"};b.addEventListener("click",()=>{const next=current()==="dark"?"light":"dark";root.dataset.theme=next;try{localStorage.setItem("trust-theme",next)}catch{}sync()});sync()})()</script>
</body>
</html>
"#,
	);

	html
}

fn fact(html: &mut String, label: &str, value: &str) {
	html.push_str("<div class=\"fact\"><dt>");
	escape_into(html, label);
	html.push_str("</dt><dd>");
	escape_into(html, value);
	html.push_str("</dd></div>");
}

fn count(html: &mut String, label: &str, value: usize) {
	let _ = write!(html, "<div class=\"count\"><strong>{value}</strong><span>");
	escape_into(html, label);
	html.push_str("</span></div>");
}

fn vulnerability_details(html: &mut String, vulnerability: &Vulnerability) {
	let severity = vulnerability.severity.map_or("UNKNOWN", Severity::as_str);
	html.push_str("<details><summary>");
	escape_into(html, &vulnerability.id);
	html.push_str(" · ");
	escape_into(html, severity);
	html.push_str("</summary><div class=\"vulnerability\"><dl>");
	fact_row(html, "ID", &vulnerability.id);
	fact_row(html, "Severity", severity);
	let aliases = vulnerability.aliases.join(", ");
	fact_row(
		html,
		"Aliases",
		if aliases.is_empty() { "None" } else { &aliases },
	);
	fact_row(
		html,
		"Summary",
		vulnerability.summary.as_deref().unwrap_or("Not provided"),
	);
	html.push_str("<dt>Description</dt><dd class=\"description\">");
	escape_into(
		html,
		vulnerability
			.details
			.as_deref()
			.unwrap_or("No full description provided."),
	);
	html.push_str("</dd><dt>References</dt><dd>");
	if vulnerability.references.is_empty() {
		html.push_str("None");
	} else {
		html.push_str("<ul class=\"references\">");
		for reference in &vulnerability.references {
			reference_link(html, reference);
		}
		html.push_str("</ul>");
	}
	html.push_str("</dd></dl></div></details>");
}

fn fact_row(html: &mut String, label: &str, value: &str) {
	html.push_str("<dt>");
	escape_into(html, label);
	html.push_str("</dt><dd>");
	escape_into(html, value);
	html.push_str("</dd>");
}

fn reference_link(html: &mut String, reference: &Reference) {
	html.push_str("<li>");
	if let Ok(url) = Url::parse(&reference.url)
		&& matches!(url.scheme(), "http" | "https")
	{
		html.push_str("<a href=\"");
		escape_into(html, &reference.url);
		html.push_str("\" rel=\"noopener noreferrer\">");
		escape_into(html, &reference.url);
		html.push_str("</a>");
	} else {
		escape_into(html, &reference.url);
	}
	if let Some(kind) = reference.kind.as_deref() {
		html.push_str(" (");
		escape_into(html, kind);
		html.push(')');
	}
	html.push_str("</li>");
}

fn escape_into(output: &mut String, value: &str) {
	for character in value.chars() {
		match character {
			'&' => output.push_str("&amp;"),
			'<' => output.push_str("&lt;"),
			'>' => output.push_str("&gt;"),
			'"' => output.push_str("&quot;"),
			'\'' => output.push_str("&#39;"),
			_ => output.push(character),
		}
	}
}

#[derive(Debug, Default, PartialEq, Eq)]
struct SeverityCounts {
	total: usize,
	critical: usize,
	high: usize,
	medium: usize,
	low: usize,
	unknown: usize,
}

impl SeverityCounts {
	fn from_vulnerabilities(vulnerabilities: &[Vulnerability]) -> Self {
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

#[cfg(test)]
mod tests {
	use super::*;
	use nexus_sec_proxy_security::{
		PackageCoordinate, PolicyViolation, ScanTarget,
	};

	fn report() -> BlockReport {
		BlockReport {
			target: ScanTarget::Package(PackageCoordinate::new(
				"npm",
				"<package>",
				"1.0.0",
			)),
			reason: "blocked <now>".to_owned(),
			policy_id: Some("default".to_owned()),
			policy_violations: vec![PolicyViolation {
				reason: "unsafe & blocked".to_owned(),
			}],
			vulnerabilities: vec![
				Vulnerability {
					id: "CVE-1<script>".to_owned(),
					aliases: vec!["GHSA-1".to_owned()],
					summary: Some("summary <unsafe>".to_owned()),
					details: Some("full & detailed".to_owned()),
					severity: Some(Severity::Critical),
					references: vec![
						Reference {
							url: "https://example.invalid/?a=1&b=2".to_owned(),
							kind: Some("WEB".to_owned()),
						},
						Reference {
							url: "javascript:alert(1)".to_owned(),
							kind: None,
						},
					],
				},
				Vulnerability {
					id: "UNKNOWN-1".to_owned(),
					aliases: Vec::new(),
					summary: None,
					details: None,
					severity: None,
					references: Vec::new(),
				},
			],
		}
	}

	#[test]
	fn renders_complete_safe_responsive_report() {
		let context = PolicyContext::new("npm-proxy", "npm", Some("platform"));
		let html = render_report("2026-06-25T00:00:00Z", &context, &report());

		assert!(html.contains("Shield with lock"));
		assert!(html.contains("<span>Trust</span>"));
		assert!(html.contains("prefers-color-scheme:dark"));
		assert!(html.contains("localStorage.setItem"));
		assert!(html.contains("<details>"));
		assert!(html.contains("full &amp; detailed"));
		assert!(html.contains("CVE-1&lt;script&gt;"));
		assert!(!html.contains("CVE-1<script>"));
		assert!(html.contains("href=\"https://example.invalid/?a=1&amp;b=2\""));
		assert!(!html.contains("href=\"javascript:"));
		assert!(html.contains("javascript:alert(1)"));
		assert!(html.contains("<strong>2</strong><span>Total"));
		assert!(html.contains("<strong>1</strong><span>Critical"));
		assert!(html.contains("<strong>1</strong><span>Unknown"));
	}

	#[test]
	fn only_accepts_canonical_v4_ids() {
		let id = Uuid::new_v4();
		assert_eq!(valid_report_id(&id.to_string()), Some(id));
		assert_eq!(valid_report_id(&id.to_string().to_uppercase()), None);
		assert_eq!(valid_report_id("../etc/passwd"), None);
		assert_eq!(valid_report_id(&Uuid::nil().to_string()), None);
	}

	#[test]
	fn counts_every_severity_including_unknown() {
		let vulnerabilities = [
			Some(Severity::Critical),
			Some(Severity::High),
			Some(Severity::Medium),
			Some(Severity::Low),
			None,
		]
		.into_iter()
		.enumerate()
		.map(|(index, severity)| Vulnerability {
			id: format!("VULN-{index}"),
			aliases: Vec::new(),
			summary: None,
			details: None,
			severity,
			references: Vec::new(),
		})
		.collect::<Vec<_>>();

		assert_eq!(
			SeverityCounts::from_vulnerabilities(&vulnerabilities),
			SeverityCounts {
				total: 5,
				critical: 1,
				high: 1,
				medium: 1,
				low: 1,
				unknown: 1,
			}
		);
	}

	#[tokio::test]
	async fn creates_unique_reports_and_rejects_missing_ids() {
		let directory = tempfile::tempdir().unwrap();
		let store = ReportStore::initialize(
			directory.path(),
			"https://trust.example.invalid/root",
			30,
		)
		.await
		.unwrap();
		let context = PolicyContext::new("npm-proxy", "npm", None::<String>);

		let first = store.create(&context, &report()).await.unwrap();
		let second = store.create(&context, &report()).await.unwrap();

		assert_ne!(first.url, second.url);
		let first_id = first.url.rsplit('/').next().unwrap();
		let contents = store.read(first_id).await.unwrap().unwrap();
		assert!(String::from_utf8(contents).unwrap().contains("npm-proxy"));
		assert!(store.read("invalid").await.unwrap().is_none());
		assert_eq!(std::fs::read_dir(store.directory()).unwrap().count(), 2);
	}

	#[tokio::test]
	async fn expired_reports_are_removed_at_startup_and_on_read() {
		let startup_directory = tempfile::tempdir().unwrap();
		let stale_path = startup_directory
			.path()
			.join(format!("{}.html", Uuid::new_v4()));
		std::fs::write(&stale_path, "stale").unwrap();

		let store = ReportStore::initialize(
			startup_directory.path(),
			"https://trust.example.invalid",
			0,
		)
		.await
		.unwrap();
		assert!(!stale_path.exists());

		let context = PolicyContext::new("npm-proxy", "npm", None::<String>);
		let created = store.create(&context, &report()).await.unwrap();
		let id = created.url.rsplit('/').next().unwrap();
		assert!(store.read(id).await.unwrap().is_none());
		assert_eq!(std::fs::read_dir(store.directory()).unwrap().count(), 0);
	}

	#[tokio::test]
	async fn initialization_fails_when_report_path_is_not_a_directory() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("reports");
		std::fs::write(&path, "not a directory").unwrap();

		let error =
			ReportStore::initialize(path, "https://trust.example.invalid", 30)
				.await
				.unwrap_err();

		assert!(matches!(
			error.kind(),
			io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory
		));
	}
}
