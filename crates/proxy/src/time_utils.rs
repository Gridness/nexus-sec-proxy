use std::time::{Duration, SystemTime};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::error;

pub(crate) fn now_rfc3339() -> String {
	format_offset_datetime(OffsetDateTime::now_utc())
}

pub(crate) fn format_system_time(time: SystemTime) -> String {
	format_offset_datetime(OffsetDateTime::from(time))
}

fn format_offset_datetime(time: OffsetDateTime) -> String {
	time.format(&Rfc3339).unwrap_or_else(|error| {
		error!(%error, "failed to format RFC3339 timestamp");
		time.unix_timestamp().to_string()
	})
}
pub(crate) fn system_time_age_seconds(time: SystemTime) -> u64 {
	SystemTime::now()
		.duration_since(time)
		.unwrap_or(Duration::ZERO)
		.as_secs()
}
