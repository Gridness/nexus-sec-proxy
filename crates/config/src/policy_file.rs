use std::fs;

use nexus_sec_proxy_security::{PolicySet, PolicySetError, SecurityPolicy};

use crate::ConfigError;
use crate::env::security_policy_env;

pub fn load_policy_file(path: &str) -> Result<PolicySet, ConfigError> {
	let content = fs::read_to_string(path).map_err(|source| {
		ConfigError::PolicyFileRead {
			path: path.to_owned(),
			source,
		}
	})?;

	parse_policy_toml(&content).map_err(|source| ConfigError::PolicyFileParse {
		path: path.to_owned(),
		source,
	})
}

pub fn parse_policy_toml(input: &str) -> Result<PolicySet, PolicySetError> {
	PolicySet::from_toml_str(input)
}

pub(crate) fn load_policy(
	lookup: &mut impl FnMut(&'static str) -> Option<String>,
	policy_file: Option<&str>,
) -> Result<(SecurityPolicy, PolicySet), ConfigError> {
	if let Some(path) = policy_file {
		let policy_set = load_policy_file(path)?;
		let security_policy = policy_set.default_policy.policy.clone();

		Ok((security_policy, policy_set))
	} else {
		let security_policy = security_policy_env(lookup)?;
		let policy_set = PolicySet::from_legacy_policy(security_policy.clone());

		Ok((security_policy, policy_set))
	}
}
