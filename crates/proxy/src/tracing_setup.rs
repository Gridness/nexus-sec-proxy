use std::env;

pub(crate) fn init_tracing(json: bool) {
	let filter = tracing_subscriber::EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| "nexus_sec_proxy=info,tower_http=info".into());

	if json {
		tracing_subscriber::fmt()
			.json()
			.with_env_filter(filter)
			.init();
	} else {
		tracing_subscriber::fmt().with_env_filter(filter).init();
	}
}

pub(crate) fn env_log_json() -> bool {
	env::var("NEXUS_SEC_PROXY_LOG_JSON")
		.ok()
		.and_then(|value| value.parse().ok())
		.unwrap_or(false)
}
