use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use reqwest::header::AUTHORIZATION;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tracing::debug;

pub const DEFAULT_API_URL: &str = "https://botapi.messenger.yandex.net";

const SEND_TEXT_PATH: &str = "/bot/v1/messages/sendText/";
const MAX_TEXT_CHARS: usize = 6000;

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
	http_client: reqwest::Client,
	token: Arc<str>,
	api_url: Arc<str>,
	template_loader: TemplateLoader,
	payload_sequence: Arc<AtomicU64>,
}

impl YandexMessengerNotifier {
	#[must_use]
	pub fn new(
		config: YandexMessengerConfig,
		http_client: reqwest::Client,
	) -> Self {
		Self {
			http_client,
			token: Arc::from(config.token),
			api_url: Arc::from(config.api_url),
			template_loader: TemplateLoader::new(config.template_file),
			payload_sequence: Arc::new(AtomicU64::new(1)),
		}
	}

	pub fn notify_blocked(&self, notification: BlockNotification) {
		let notifier = self.clone();
		let Ok(handle) = Handle::try_current() else {
			debug!(
				"yandex messenger notification skipped without tokio runtime"
			);
			return;
		};

		handle.spawn(async move {
			if let Err(error) = notifier.send_blocked(notification).await {
				debug!(%error, "yandex messenger notification failed");
			}
		});
	}

	async fn send_blocked(
		&self,
		notification: BlockNotification,
	) -> anyhow::Result<()> {
		let timestamp = now_rfc3339();
		let template_context = notification.template_context(timestamp);
		let Some(text) = self.template_loader.render(&template_context).await
		else {
			return Ok(());
		};
		if text.is_empty() {
			return Ok(());
		}

		let request = SendTextRequest {
			login: notification.login,
			text: truncate_text(text),
			payload_id: self.next_payload_id(),
		};
		let response = self
			.http_client
			.post(self.send_text_url())
			.header(AUTHORIZATION, format!("OAuth {}", self.token))
			.json(&request)
			.send()
			.await
			.context("Yandex Messenger sendText request failed")?;
		let status = response.status();
		let body = response
			.bytes()
			.await
			.context("Yandex Messenger response body read failed")?;

		if !status.is_success() {
			bail!("Yandex Messenger returned {status}");
		}

		if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
			if value.get("ok").and_then(serde_json::Value::as_bool)
				== Some(false)
			{
				bail!("Yandex Messenger returned ok=false");
			}
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

		Some(render_template(&template, context))
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
		"timestamp" => Some(&context.timestamp),
		_ => None,
	}
}

fn truncate_text(text: String) -> String {
	if text.chars().count() <= MAX_TEXT_CHARS {
		return text;
	}

	text.chars().take(MAX_TEXT_CHARS).collect()
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
			"{user}/{repository}/{format}/{target}/{reason}/{policy_id}/{vulnerability_ids}/{timestamp}/{unknown}",
			&context,
		);

		assert_eq!(
			rendered,
			"alice/npm-proxy/npm/npm:left-pad@1.0.0/blocked/default/CVE-1,CVE-2/2026-06-11T00:00:00Z/{unknown}"
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
			Some("blocked alice")
		);

		tokio::time::sleep(Duration::from_millis(5)).await;
		std::fs::write(&path, "blocked {repository}").unwrap();
		assert_eq!(
			loader.render(&context).await.as_deref(),
			Some("blocked npm-proxy")
		);

		tokio::time::sleep(Duration::from_millis(5)).await;
		std::fs::remove_file(&path).unwrap();
		std::fs::create_dir(&path).unwrap();
		assert_eq!(
			loader.render(&context).await.as_deref(),
			Some("blocked npm-proxy")
		);
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
			timestamp: "2026-06-11T00:00:00Z".to_owned(),
		}
	}
}
