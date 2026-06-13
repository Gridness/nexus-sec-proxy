use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageCoordinate {
	pub source_format: String,
	pub identity: PackageIdentity,
	pub version: Option<String>,
}

impl PackageCoordinate {
	#[must_use]
	pub fn new(
		ecosystem: impl Into<String>,
		name: impl Into<String>,
		version: impl Into<String>,
	) -> Self {
		Self::from_osv(ecosystem, name, version)
	}

	#[must_use]
	pub fn from_osv(
		ecosystem: impl Into<String>,
		name: impl Into<String>,
		version: impl Into<String>,
	) -> Self {
		let ecosystem = ecosystem.into();

		Self {
			source_format: ecosystem.clone(),
			identity: PackageIdentity::Osv {
				ecosystem,
				name: name.into(),
			},
			version: Some(version.into()),
		}
	}

	#[must_use]
	pub fn from_purl(
		source_format: impl Into<String>,
		purl: impl Into<String>,
		version: Option<impl Into<String>>,
	) -> Self {
		Self {
			source_format: source_format.into(),
			identity: PackageIdentity::Purl { purl: purl.into() },
			version: version.map(Into::into),
		}
	}

	#[must_use]
	pub fn from_git_commit(commit: impl Into<String>) -> Self {
		Self {
			source_format: "git".to_owned(),
			identity: PackageIdentity::GitCommit {
				commit: commit.into(),
			},
			version: None,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PackageIdentity {
	Osv { ecosystem: String, name: String },
	Purl { purl: String },
	GitCommit { commit: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactTarget {
	pub source_format: String,
	pub uri: String,
	pub digest: Option<String>,
}

impl ArtifactTarget {
	#[must_use]
	pub fn new(
		source_format: impl Into<String>,
		uri: impl Into<String>,
	) -> Self {
		Self {
			source_format: source_format.into(),
			uri: uri.into(),
			digest: None,
		}
	}

	#[must_use]
	pub fn with_digest(
		source_format: impl Into<String>,
		uri: impl Into<String>,
		digest: impl Into<String>,
	) -> Self {
		Self {
			source_format: source_format.into(),
			uri: uri.into(),
			digest: Some(digest.into()),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanTarget {
	Package(PackageCoordinate),
	Artifact(ArtifactTarget),
}

impl ScanTarget {
	#[must_use]
	pub fn cache_namespace(&self) -> &str {
		match self {
			Self::Package(package) => &package.source_format,
			Self::Artifact(artifact) => &artifact.source_format,
		}
	}

	#[must_use]
	pub fn cache_identifier(&self) -> String {
		match self {
			Self::Package(package) => match &package.identity {
				PackageIdentity::Osv { ecosystem, name } => {
					format!("{ecosystem}/{name}")
				}
				PackageIdentity::Purl { purl } => purl.clone(),
				PackageIdentity::GitCommit { commit } => commit.clone(),
			},
			Self::Artifact(artifact) => artifact
				.digest
				.clone()
				.unwrap_or_else(|| artifact.uri.clone()),
		}
	}

	#[must_use]
	pub fn cache_version(&self) -> Option<&str> {
		match self {
			Self::Package(package) => package.version.as_deref(),
			Self::Artifact(_) => None,
		}
	}

	#[must_use]
	pub fn display_name(&self) -> String {
		match self {
			Self::Package(package) => match &package.identity {
				PackageIdentity::Osv { ecosystem, name } => {
					match package.version.as_deref() {
						Some(version) => {
							format!("{ecosystem}:{name}@{version}")
						}
						None => format!("{ecosystem}:{name}"),
					}
				}
				PackageIdentity::Purl { purl } => purl.clone(),
				PackageIdentity::GitCommit { commit } => {
					format!("git commit {commit}")
				}
			},
			Self::Artifact(artifact) => match artifact.digest.as_deref() {
				Some(digest) => {
					format!("{} artifact {}", artifact.source_format, digest)
				}
				None => {
					format!(
						"{} artifact {}",
						artifact.source_format, artifact.uri
					)
				}
			},
		}
	}
}

#[must_use]
pub fn default_osv_ecosystem_for_format(
	repository_format: &str,
) -> Option<&'static str> {
	match normalize_repository_format(repository_format).as_str() {
		"alpine" => Some("Alpine"),
		"apk" => Some("Alpine"),
		"cran" | "r" => Some("R"),
		"cargo" | "rust" | "rustcargo" => Some("crates.io"),
		"composer" | "phpcomposer" => Some("Packagist"),
		"debian" => Some("Debian GNU/Linux"),
		"go" | "golang" => Some("Go"),
		"maven" | "maven2" => Some("Maven"),
		"npm" | "node" => Some("npm"),
		"nuget" => Some("NuGet"),
		"packagist" => Some("Packagist"),
		"pub" | "flutter" | "dart" => Some("Pub"),
		"pypi" | "python" => Some("PyPI"),
		"rockylinux" | "rocky" => Some("Rocky Linux"),
		"rubygems" | "gem" | "ruby" => Some("RubyGems"),
		"swift" => Some("SwiftURL"),
		"ubuntu" => Some("Ubuntu OS"),
		_ => None,
	}
}

fn normalize_repository_format(repository_format: &str) -> String {
	repository_format
		.chars()
		.filter(|character| character.is_ascii_alphanumeric())
		.flat_map(char::to_lowercase)
		.collect()
}
