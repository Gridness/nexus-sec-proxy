use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
	#[error("cache backend failed: {0}")]
	Backend(String),
}
