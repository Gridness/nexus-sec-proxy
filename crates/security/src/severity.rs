use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
	Low,
	Medium,
	High,
	Critical,
}

impl Severity {
	#[must_use]
	pub fn all() -> [Self; 4] {
		[Self::Low, Self::Medium, Self::High, Self::Critical]
	}

	#[must_use]
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Low => "LOW",
			Self::Medium => "MEDIUM",
			Self::High => "HIGH",
			Self::Critical => "CRITICAL",
		}
	}
}

impl fmt::Display for Severity {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(self.as_str())
	}
}

impl FromStr for Severity {
	type Err = SeverityParseError;

	fn from_str(input: &str) -> Result<Self, Self::Err> {
		match input.trim().to_ascii_uppercase().as_str() {
			"LOW" => Ok(Self::Low),
			"MEDIUM" | "MODERATE" => Ok(Self::Medium),
			"HIGH" => Ok(Self::High),
			"CRITICAL" => Ok(Self::Critical),
			_ => Err(SeverityParseError {
				input: input.to_owned(),
			}),
		}
	}
}

impl<'de> Deserialize<'de> for Severity {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct SeverityVisitor;

		impl<'de> Visitor<'de> for SeverityVisitor {
			type Value = Severity;

			fn expecting(
				&self,
				formatter: &mut fmt::Formatter<'_>,
			) -> fmt::Result {
				formatter.write_str(
					"a severity such as LOW, MEDIUM, HIGH, or CRITICAL",
				)
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				value.parse().map_err(E::custom)
			}
		}

		deserializer.deserialize_str(SeverityVisitor)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid severity: {input}")]
pub struct SeverityParseError {
	input: String,
}
