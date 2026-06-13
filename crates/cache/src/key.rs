use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
	pub namespace: String,
	pub identifier: String,
	pub version: Option<String>,
}

impl CacheKey {
	#[must_use]
	pub fn new(
		namespace: impl Into<String>,
		identifier: impl Into<String>,
		version: impl Into<String>,
	) -> Self {
		Self::from_parts(namespace, identifier, Some(version))
	}

	#[must_use]
	pub fn from_parts(
		namespace: impl Into<String>,
		identifier: impl Into<String>,
		version: Option<impl Into<String>>,
	) -> Self {
		Self {
			namespace: namespace.into(),
			identifier: identifier.into(),
			version: version.map(Into::into),
		}
	}
}
