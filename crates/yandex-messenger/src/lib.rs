use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use reqwest::header::AUTHORIZATION;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

pub const DEFAULT_API_URL: &str = "https://botapi.messenger.yandex.net";

const SEND_TEXT_PATH: &str = "/bot/v1/messages/sendText/";
const MAX_TEXT_CHARS: usize = 6000;
const QUEUE_CAPACITY: usize = 256;
const MAX_SEND_ATTEMPTS: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YandexMessengerConfig {
	pub token: String,
	pub template_file: PathBuf,
	pub api_url: String,
}

impl YandexMessengerConfig {
	#[must_use]
	pub fn new(
		token: impl Into<String>,
		template_file: impl Into<PathBuf>,
		api_url: impl Into<String>,
	) -> Self {
		Self {
			token: token.into(),
			template_file: template_file.into(),
			api_url: api_url.into(),
		}
	}
}

#[derive(Debug, Clone)]
pub struct YandexMessengerNotifier {
	sender: mpsc::Sender<WorkerCommand>,
	status: Arc<DeliveryStatus>,
	worker: Arc<Mutex<Option<JoinHandle<()>>>>,
}

#[derive(Debug)]
struct DeliveryWorker {
	http_client: reqwest::Client,
	token: Arc<str>,
	api_url: Arc<str>,
	template_loader: TemplateLoader,
	payload_sequence: Arc<AtomicU64>,
	status: Arc<DeliveryStatus>,
}

#[derive(Debug)]
enum WorkerCommand {
	Notification(BlockNotification),
	Shutdown,
}

#[derive(Debug, Default)]
struct DeliveryStatus {
	sent: AtomicU64,
	retried: AtomicU64,
	failed: AtomicU64,
	skipped: std::sync::Mutex<BTreeMap<String, u64>>,
	last: std::sync::Mutex<LastDelivery>,
}

#[derive(Debug, Default)]
struct LastDelivery {
	last_success_at: Option<String>,
	last_failure_at: Option<String>,
	last_failure_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct YandexMessengerStatus {
	pub sent: u64,
	pub retried: u64,
	pub failed: u64,
	pub skipped_by_reason: BTreeMap<String, u64>,
	pub last_success_at: Option<String>,
	pub last_failure_at: Option<String>,
	pub last_failure_category: Option<String>,
}

impl YandexMessengerNotifier {
	#[must_use]
	pub fn new(
		config: YandexMessengerConfig,
		http_client: reqwest::Client,
	) -> Self {
		let status = Arc::new(DeliveryStatus::default());
		let worker = DeliveryWorker {
			http_client,
			token: Arc::from(config.token),
			api_url: Arc::from(config.api_url),
			template_loader: TemplateLoader::new(config.template_file),
			payload_sequence: Arc::new(AtomicU64::new(1)),
			status: Arc::clone(&status),
		};
		let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
		let worker = tokio::spawn(worker.run(receiver));

		Self {
			sender,
			status,
			worker: Arc::new(Mutex::new(Some(worker))),
		}
	}

	pub fn notify_blocked(&self, notification: BlockNotification) {
		match self
			.sender
			.try_send(WorkerCommand::Notification(notification))
		{
			Ok(()) => {}
			Err(mpsc::error::TrySendError::Full(_)) => {
				self.record_skipped("queue_full");
				warn!("Yandex Messenger queue is full; notification dropped");
			}
			Err(mpsc::error::TrySendError::Closed(_)) => {
				self.record_skipped("worker_closed");
				warn!(
					"Yandex Messenger worker is closed; notification dropped"
				);
			}
		}
	}

	pub fn record_skipped(&self, reason: &'static str) {
		let mut skipped = self
			.status
			.skipped
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		*skipped.entry(reason.to_owned()).or_default() += 1;
	}

	#[must_use]
	pub fn status(&self) -> YandexMessengerStatus {
		let skipped_by_reason = self
			.status
			.skipped
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.clone();
		let last = self
			.status
			.last
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);

		YandexMessengerStatus {
			sent: self.status.sent.load(Ordering::Relaxed),
			retried: self.status.retried.load(Ordering::Relaxed),
			failed: self.status.failed.load(Ordering::Relaxed),
			skipped_by_reason,
			last_success_at: last.last_success_at.clone(),
			last_failure_at: last.last_failure_at.clone(),
			last_failure_category: last.last_failure_category.clone(),
		}
	}

	pub async fn shutdown(&self, timeout: Duration) {
		if tokio::time::timeout(
			timeout,
			self.sender.send(WorkerCommand::Shutdown),
		)
		.await
		.is_err()
		{
			warn!("Yandex Messenger shutdown signal timed out");
			if let Some(worker) = self.worker.lock().await.take() {
				worker.abort();
				let _ = worker.await;
			}
			return;
		}
		let Some(mut worker) = self.worker.lock().await.take() else {
			return;
		};
		if tokio::time::timeout(timeout, &mut worker).await.is_err() {
			warn!("Yandex Messenger queue drain timed out");
			worker.abort();
			let _ = worker.await;
		}
	}
}

pub async fn validate_config(
	config: &YandexMessengerConfig,
) -> anyhow::Result<()> {
	if config.token.is_empty() {
		anyhow::bail!("Yandex Messenger token is empty");
	}
	let url = reqwest::Url::parse(&config.api_url)
		.context("invalid Yandex Messenger API URL")?;
	if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
		anyhow::bail!(
			"Yandex Messenger API URL must be an HTTP(S) URL with a host"
		);
	}
	let template = tokio::fs::read_to_string(&config.template_file)
		.await
		.with_context(|| {
			format!(
				"failed to read Yandex Messenger template {}",
				config.template_file.display()
			)
		})?;
	if template.is_empty() {
		anyhow::bail!("Yandex Messenger template is empty");
	}

	Ok(())
}

impl DeliveryWorker {
	async fn run(self, mut receiver: mpsc::Receiver<WorkerCommand>) {
		while let Some(command) = receiver.recv().await {
			match command {
				WorkerCommand::Notification(notification) => {
					self.deliver(notification).await;
				}
				WorkerCommand::Shutdown => break,
			}
		}
	}

	async fn deliver(&self, notification: BlockNotification) {
		let timestamp = now_rfc3339();
		let template_context = notification.template_context(timestamp);
		let Some(text) = self.template_loader.render(&template_context).await
		else {
			self.record_failure("template_unavailable");
			return;
		};
		if text.is_empty() {
			self.record_failure("template_empty");
			return;
		}

		let request = SendTextRequest {
			login: notification.login,
			text: truncate_text(text, &notification.report_url),
			payload_id: self.next_payload_id(),
		};
		for attempt in 1..=MAX_SEND_ATTEMPTS {
			match self.send_attempt(&request).await {
				Ok(()) => {
					self.status.sent.fetch_add(1, Ordering::Relaxed);
					let mut last = self
						.status
						.last
						.lock()
						.unwrap_or_else(std::sync::PoisonError::into_inner);
					last.last_success_at = Some(now_rfc3339());
					info!(attempt, "Yandex Messenger notification sent");
					return;
				}
				Err(failure)
					if failure.transient && attempt < MAX_SEND_ATTEMPTS =>
				{
					self.status.retried.fetch_add(1, Ordering::Relaxed);
					warn!(
						attempt,
						category = failure.category,
						"transient Yandex Messenger delivery failure; retrying"
					);
					tokio::time::sleep(Duration::from_millis(100 * attempt))
						.await;
				}
				Err(failure) => {
					self.record_failure(failure.category);
					error!(
						attempt,
						category = failure.category,
						"Yandex Messenger notification failed"
					);
					return;
				}
			}
		}
	}

	async fn send_attempt(
		&self,
		request: &SendTextRequest,
	) -> Result<(), SendFailure> {
		let response = self
			.http_client
			.post(self.send_text_url())
			.header(AUTHORIZATION, format!("OAuth {}", self.token))
			.json(request)
			.send()
			.await
			.map_err(|_| SendFailure::transient("network"))?;
		let status = response.status();
		if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
			return Err(SendFailure::transient("rate_limited"));
		}
		if status.is_server_error() {
			return Err(SendFailure::transient("server_error"));
		}
		if !status.is_success() {
			return Err(SendFailure::permanent("rejected"));
		}
		let body = response
			.bytes()
			.await
			.map_err(|_| SendFailure::transient("network"))?;
		let value = serde_json::from_slice::<serde_json::Value>(&body)
			.map_err(|_| SendFailure::permanent("invalid_response"))?;
		if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
			return Err(SendFailure::permanent("api_error"));
		}

		Ok(())
	}

	fn send_text_url(&self) -> String {
		format!("{}{}", self.api_url.trim_end_matches('/'), SEND_TEXT_PATH)
	}

	fn next_payload_id(&self) -> String {
		let sequence = self.payload_sequence.fetch_add(1, Ordering::Relaxed);
		let nanos = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_nanos();

		format!("nexus-sec-proxy-{nanos}-{sequence}")
	}

	fn record_failure(&self, category: &'static str) {
		self.status.failed.fetch_add(1, Ordering::Relaxed);
		let mut last = self
			.status
			.last
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		last.last_failure_at = Some(now_rfc3339());
		last.last_failure_category = Some(category.to_owned());
	}
}

#[derive(Debug)]
struct SendFailure {
	transient: bool,
	category: &'static str,
}

impl SendFailure {
	fn transient(category: &'static str) -> Self {
		Self {
			transient: true,
			category,
		}
	}

	fn permanent(category: &'static str) -> Self {
		Self {
			transient: false,
			category,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockNotification {
	pub login: String,
	pub repository: String,
	pub format: String,
	pub target: String,
	pub reason: String,
	pub policy_id: Option<String>,
	pub vulnerability_ids: Vec<String>,
	pub report_url: String,
}

impl BlockNotification {
	#[must_use]
	pub fn template_context(&self, timestamp: String) -> TemplateContext {
		TemplateContext {
			user: self.login.clone(),
			repository: self.repository.clone(),
			format: self.format.clone(),
			target: self.target.clone(),
			reason: self.reason.clone(),
			policy_id: self.policy_id.clone().unwrap_or_default(),
			vulnerability_ids: self.vulnerability_ids.join(","),
			report_url: self.report_url.clone(),
			timestamp,
		}
	}
}

#[derive(Debug, Clone)]
pub struct TemplateLoader {
	path: Arc<PathBuf>,
	state: Arc<Mutex<TemplateState>>,
}

impl TemplateLoader {
	#[must_use]
	pub fn new(path: impl Into<PathBuf>) -> Self {
		Self {
			path: Arc::new(path.into()),
			state: Arc::new(Mutex::new(TemplateState::default())),
		}
	}

	pub async fn render(&self, context: &TemplateContext) -> Option<String> {
		let template = self.current_template().await?;
		let contains_report_url = template.contains("{report_url}");
		let mut rendered = render_template(&template, context);

		if !contains_report_url {
			if !rendered.ends_with('\n') && !rendered.is_empty() {
				rendered.push('\n');
			}
			rendered.push_str("Report: ");
			rendered.push_str(&context.report_url);
		}

		Some(rendered)
	}

	async fn current_template(&self) -> Option<String> {
		let metadata = match tokio::fs::metadata(&*self.path).await {
			Ok(metadata) => metadata,
			Err(error) => {
				debug!(
					error = %error,
					template_file = %self.path.display(),
					"yandex messenger template metadata read failed"
				);
				let state = self.state.lock().await;
				return state.template.clone();
			}
		};
		let modified = metadata.modified().ok();
		let mut state = self.state.lock().await;
		let unchanged = state.template.is_some()
			&& modified.is_some()
			&& state.modified == modified;

		if unchanged {
			return state.template.clone();
		}

		match tokio::fs::read_to_string(&*self.path).await {
			Ok(template) => {
				state.modified = modified;
				state.template = Some(template.clone());
				Some(template)
			}
			Err(error) => {
				debug!(
					error = %error,
					template_file = %self.path.display(),
					"yandex messenger template reload failed"
				);
				state.template.clone()
			}
		}
	}
}

#[derive(Debug, Clone, Default)]
struct TemplateState {
	modified: Option<SystemTime>,
	template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateContext {
	pub user: String,
	pub repository: String,
	pub format: String,
	pub target: String,
	pub reason: String,
	pub policy_id: String,
	pub vulnerability_ids: String,
	pub report_url: String,
	pub timestamp: String,
}

#[must_use]
pub fn render_template(template: &str, context: &TemplateContext) -> String {
	let mut rendered = String::with_capacity(template.len());
	let mut rest = template;

	while let Some(open) = rest.find('{') {
		rendered.push_str(&rest[..open]);
		let after_open = &rest[open + 1..];
		let Some(close) = after_open.find('}') else {
			rendered.push_str(&rest[open..]);
			return rendered;
		};
		let key = &after_open[..close];
		match placeholder_value(key, context) {
			Some(value) => rendered.push_str(value),
			None => {
				rendered.push('{');
				rendered.push_str(key);
				rendered.push('}');
			}
		}
		rest = &after_open[close + 1..];
	}

	rendered.push_str(rest);
	rendered
}

fn placeholder_value<'a>(
	key: &str,
	context: &'a TemplateContext,
) -> Option<&'a str> {
	match key {
		"user" => Some(&context.user),
		"repository" => Some(&context.repository),
		"format" => Some(&context.format),
		"target" => Some(&context.target),
		"reason" => Some(&context.reason),
		"policy_id" => Some(&context.policy_id),
		"vulnerability_ids" => Some(&context.vulnerability_ids),
		"report_url" => Some(&context.report_url),
		"timestamp" => Some(&context.timestamp),
		_ => None,
	}
}

fn truncate_text(text: String, report_url: &str) -> String {
	if text.chars().count() <= MAX_TEXT_CHARS {
		return text;
	}

	let suffix = format!("\nReport: {report_url}");
	let suffix_chars = suffix.chars().count();
	if suffix_chars >= MAX_TEXT_CHARS {
		return suffix.chars().take(MAX_TEXT_CHARS).collect();
	}

	let prefix_chars = MAX_TEXT_CHARS - suffix_chars;
	let mut truncated = text.chars().take(prefix_chars).collect::<String>();
	truncated.push_str(&suffix);
	truncated
}

fn now_rfc3339() -> String {
	OffsetDateTime::now_utc()
		.format(&Rfc3339)
		.unwrap_or_else(|error| {
			debug!(%error, "failed to format Yandex Messenger timestamp");
			OffsetDateTime::now_utc().unix_timestamp().to_string()
		})
}

#[derive(Debug, Serialize)]
struct SendTextRequest {
	login: String,
	text: String,
	payload_id: String,
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;

	#[test]
	fn renders_known_template_placeholders_and_leaves_unknown_unchanged() {
		let context = template_context();
		let rendered = render_template(
			"{user}/{repository}/{format}/{target}/{reason}/{policy_id}/{vulnerability_ids}/{report_url}/{timestamp}/{unknown}",
			&context,
		);

		assert_eq!(
			rendered,
			"alice/npm-proxy/npm/npm:left-pad@1.0.0/blocked/default/CVE-1,CVE-2/https://trust.example.invalid/trust/reports/123/2026-06-11T00:00:00Z/{unknown}"
		);
	}

	#[tokio::test]
	async fn template_loader_reloads_and_keeps_last_valid_template() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("message.txt");
		std::fs::write(&path, "blocked {user}").unwrap();
		let loader = TemplateLoader::new(&path);
		let context = template_context();

		assert_eq!(
			loader.render(&context).await.as_deref(),
			Some(
				"blocked alice\nReport: https://trust.example.invalid/trust/reports/123"
			)
		);

		tokio::time::sleep(Duration::from_millis(5)).await;
		std::fs::write(&path, "blocked {repository}").unwrap();
		assert_eq!(
			loader.render(&context).await.as_deref(),
			Some(
				"blocked npm-proxy\nReport: https://trust.example.invalid/trust/reports/123"
			)
		);

		tokio::time::sleep(Duration::from_millis(5)).await;
		std::fs::remove_file(&path).unwrap();
		std::fs::create_dir(&path).unwrap();
		assert_eq!(
			loader.render(&context).await.as_deref(),
			Some(
				"blocked npm-proxy\nReport: https://trust.example.invalid/trust/reports/123"
			)
		);
	}

	#[tokio::test]
	async fn template_can_place_report_url_explicitly() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("message.txt");
		std::fs::write(&path, "Open {report_url} for {user}").unwrap();
		let loader = TemplateLoader::new(path);

		assert_eq!(
			loader.render(&template_context()).await.as_deref(),
			Some(
				"Open https://trust.example.invalid/trust/reports/123 for alice"
			)
		);
	}

	#[test]
	fn oversized_text_always_keeps_complete_report_url() {
		let report_url = "https://trust.example.invalid/trust/reports/123";
		let text = format!("{} {report_url}", "x".repeat(MAX_TEXT_CHARS * 2));

		let truncated = truncate_text(text, report_url);

		assert_eq!(truncated.chars().count(), MAX_TEXT_CHARS);
		assert!(truncated.ends_with(&format!("Report: {report_url}")));
	}

	#[tokio::test]
	async fn template_loader_returns_none_without_a_valid_template() {
		let dir = tempfile::tempdir().unwrap();
		let loader = TemplateLoader::new(dir.path().join("missing.txt"));

		assert_eq!(loader.render(&template_context()).await, None);
	}

	fn template_context() -> TemplateContext {
		TemplateContext {
			user: "alice".to_owned(),
			repository: "npm-proxy".to_owned(),
			format: "npm".to_owned(),
			target: "npm:left-pad@1.0.0".to_owned(),
			reason: "blocked".to_owned(),
			policy_id: "default".to_owned(),
			vulnerability_ids: "CVE-1,CVE-2".to_owned(),
			report_url: "https://trust.example.invalid/trust/reports/123"
				.to_owned(),
			timestamp: "2026-06-11T00:00:00Z".to_owned(),
		}
	}
}
