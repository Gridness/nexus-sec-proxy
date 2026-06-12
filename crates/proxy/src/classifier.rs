use axum::http::Method;
#[cfg(test)]
use axum::http::Uri;
#[cfg(test)]
use nexus_sec_proxy_config::AppConfig;
use nexus_sec_proxy_security::{
	ArtifactTarget, PackageCoordinate, ScanTarget,
	default_osv_ecosystem_for_format,
};
use percent_encoding::percent_decode_str;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestClassification {
	ProxyOnly,
	Scan(ScanTarget),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationContext {
	pub repository_format: String,
	pub osv_ecosystem: Option<String>,
}

impl ClassificationContext {
	pub fn new(
		repository_format: impl Into<String>,
		osv_ecosystem: Option<String>,
	) -> Self {
		Self {
			repository_format: repository_format.into(),
			osv_ecosystem,
		}
	}

	#[cfg(test)]
	pub fn from_config(config: &AppConfig) -> Self {
		Self::new(
			config.repository_format.clone(),
			config.osv_ecosystem.clone(),
		)
	}
}

#[cfg(test)]
pub fn classify_request(
	config: &AppConfig,
	method: &Method,
	uri: &Uri,
) -> RequestClassification {
	classify_path(
		&ClassificationContext::from_config(config),
		method,
		uri.path(),
	)
}

pub fn classify_path(
	context: &ClassificationContext,
	method: &Method,
	path: &str,
) -> RequestClassification {
	if method != Method::GET && method != Method::HEAD {
		return RequestClassification::ProxyOnly;
	}

	let segments = decoded_segments(path);
	let format = normalize_format(&context.repository_format);

	let target = match format.as_str() {
		"alpine" => classify_alpine(context, path, &segments),
		"ansible" => classify_dash_archive_optional_package(
			context,
			path,
			&segments,
			&[".tar.gz", ".tgz"],
			None,
		),
		"apt" | "debian" | "ubuntu" => classify_apt(context, path, &segments),
		"bower" => classify_dash_archive_optional_package(
			context,
			path,
			&segments,
			&[".zip", ".tar.gz", ".tgz"],
			None,
		),
		"cocoapods" | "pod" | "pods" => classify_dash_archive_optional_package(
			context,
			path,
			&segments,
			&[".zip", ".tar.gz", ".tgz"],
			None,
		),
		"composer" | "phpcomposer" => {
			classify_composer(context, path, &segments)
		}
		"conan" => classify_dash_archive_optional_package(
			context,
			path,
			&segments,
			&[".tgz", ".tar.gz", ".zip"],
			None,
		),
		"conda" => classify_conda(context, path, &segments),
		"maven" | "maven2" => classify_maven(context, &segments),
		"npm" => classify_npm(context, &segments),
		"pypi" | "python" => classify_pypi(context, &segments),
		"nuget" => classify_nuget(context, &segments),
		"cargo" | "rust" | "rustcargo" => classify_cargo(context, &segments),
		"rubygems" | "gem" | "ruby" => classify_rubygems(context, &segments),
		"go" | "golang" => classify_go(context, &segments),
		"docker" => classify_docker(context, path, &segments),
		"gitlfs" => classify_git_lfs(context, path, &segments),
		"helm" => classify_dash_archive_optional_package(
			context,
			path,
			&segments,
			&[".tgz", ".tar.gz"],
			None,
		),
		"huggingface" | "huggingfacehub" | "hf" => {
			classify_generic_artifact(context, path, &segments)
		}
		"p2" | "eclipsep2" => classify_p2(context, path, &segments),
		"pub" | "flutter" | "dart" => classify_pub(context, &segments),
		"r" | "cran" => classify_r(context, &segments),
		"raw" => classify_generic_artifact(context, path, &segments),
		"swift" => classify_swift(context, path, &segments),
		"terraform" => classify_terraform(context, path, &segments),
		"yum" | "rpm" => classify_yum(context, path, &segments),
		_ => classify_generic_artifact(context, path, &segments),
	};

	target
		.map(RequestClassification::Scan)
		.unwrap_or(RequestClassification::ProxyOnly)
}

fn classify_alpine(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;
	if !file.ends_with(".apk") {
		return None;
	}

	let stem = file.strip_suffix(".apk")?;
	let (name_and_version, release) = stem.rsplit_once('-')?;
	let (name, version) = name_and_version.rsplit_once('-')?;

	Some(package_or_artifact_target(
		context,
		path,
		Some("Alpine"),
		name.to_owned(),
		format!("{version}-{release}"),
	))
}

fn classify_apt(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;
	if !file.ends_with(".deb") {
		return None;
	}

	let stem = file.strip_suffix(".deb")?;
	let (name_and_version, _architecture) = stem.rsplit_once('_')?;
	let (name, version) = name_and_version.rsplit_once('_')?;

	Some(package_or_artifact_target(
		context,
		path,
		default_linux_ecosystem(context),
		name.to_owned(),
		version.to_owned(),
	))
}

fn classify_composer(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;

	if file.ends_with(".json") {
		return None;
	}

	if let Some((name, version)) = package_version_from_path(segments) {
		return Some(package_or_artifact_target(
			context,
			path,
			Some("Packagist"),
			name,
			version,
		));
	}

	classify_dash_archive_optional_package(
		context,
		path,
		segments,
		&[".zip", ".tar.gz", ".tgz"],
		Some("Packagist"),
	)
}

fn classify_conda(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;
	let stem = file
		.strip_suffix(".tar.bz2")
		.or_else(|| file.strip_suffix(".conda"))?;
	let (name_and_version, _build) = stem.rsplit_once('-')?;
	let (name, version) = name_and_version.rsplit_once('-')?;

	Some(package_or_artifact_target(
		context,
		path,
		None,
		name.to_owned(),
		version.to_owned(),
	))
}

fn classify_maven(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	if segments.len() < 4 {
		return None;
	}

	let file = segments.last()?;
	if is_sidecar(file) || file == "maven-metadata.xml" {
		return None;
	}

	let version = segments.get(segments.len().checked_sub(2)?)?;
	let artifact_id = segments.get(segments.len().checked_sub(3)?)?;
	let group = segments[..segments.len() - 3].join(".");

	if group.is_empty() || !file.contains(version) {
		return None;
	}

	Some(package_target(
		context,
		"Maven",
		format!("{group}:{artifact_id}"),
		version.clone(),
	))
}

fn classify_npm(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;

	if !file.ends_with(".tgz") {
		return None;
	}

	let (package_name, tarball_name) = if segments.len() >= 4
		&& segments
			.first()
			.is_some_and(|segment| segment.starts_with('@'))
		&& segments.get(2).is_some_and(|segment| segment == "-")
	{
		(
			format!("{}/{}", segments.first()?, segments.get(1)?),
			segments.get(1)?.as_str(),
		)
	} else if segments.len() >= 3
		&& segments.get(1).is_some_and(|segment| segment == "-")
	{
		(segments.first()?.clone(), segments.first()?.as_str())
	} else {
		return None;
	};

	let version = strip_archive_suffix(file, &[".tgz"])
		.and_then(|stem| stem.strip_prefix(&format!("{tarball_name}-")))
		.or_else(|| {
			strip_archive_suffix(file, &[".tgz"]).and_then(|stem| {
				stem.rsplit_once('-').map(|(_, version)| version)
			})
		})?;

	Some(package_target(
		context,
		"npm",
		package_name,
		version.to_owned(),
	))
}

fn classify_pypi(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;

	if let Some(stem) = file.strip_suffix(".whl") {
		let mut parts = stem.split('-');
		let name = normalize_pypi_name(parts.next()?);
		let version = parts.next()?.to_owned();

		return Some(package_target(context, "PyPI", name, version));
	}

	let stem = strip_archive_suffix(file, &[".tar.gz", ".zip", ".tgz"])?;
	let (name, version) = stem.rsplit_once('-')?;

	Some(package_target(
		context,
		"PyPI",
		normalize_pypi_name(name),
		version.to_owned(),
	))
}

fn classify_nuget(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	let container_index = segments
		.iter()
		.position(|segment| segment.eq_ignore_ascii_case("v3-flatcontainer"))?;
	let name = segments.get(container_index + 1)?;
	let version = segments.get(container_index + 2)?;
	let file = segments.last()?;

	if !file.ends_with(".nupkg") {
		return None;
	}

	Some(package_target(
		context,
		"NuGet",
		name.clone(),
		version.clone(),
	))
}

fn classify_cargo(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	let crates_index = segments
		.windows(3)
		.position(|window| window == ["api", "v1", "crates"])?;
	let name = segments.get(crates_index + 3)?;
	let version = segments.get(crates_index + 4)?;

	if segments
		.get(crates_index + 5)
		.is_none_or(|segment| segment != "download")
	{
		return None;
	}

	Some(package_target(
		context,
		"crates.io",
		name.clone(),
		version.clone(),
	))
}

fn classify_rubygems(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	if segments.first().is_none_or(|segment| segment != "gems") {
		return None;
	}

	let stem = segments.last()?.strip_suffix(".gem")?;
	let (name, version) = stem.rsplit_once('-')?;

	Some(package_target(
		context,
		"RubyGems",
		name.to_owned(),
		version.to_owned(),
	))
}

fn classify_go(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	let version_marker = segments.iter().position(|segment| segment == "@v")?;
	let module = segments[..version_marker].join("/");
	let version = segments
		.get(version_marker + 1)?
		.strip_suffix(".zip")
		.or_else(|| segments.get(version_marker + 1)?.strip_suffix(".mod"))
		.or_else(|| segments.get(version_marker + 1)?.strip_suffix(".info"))?;

	if module.is_empty() {
		return None;
	}

	Some(package_target(context, "Go", module, version.to_owned()))
}

fn classify_git_lfs(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	if let Some(index) =
		segments.iter().position(|segment| segment == "objects")
		&& let Some(digest) = segments.get(index + 1)
	{
		return Some(ScanTarget::Artifact(ArtifactTarget::with_digest(
			&context.repository_format,
			path,
			digest.clone(),
		)));
	}

	classify_generic_artifact(context, path, segments)
}

fn classify_docker(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	if segments.first().is_none_or(|segment| segment != "v2") {
		return None;
	}

	if let Some(index) = segments.iter().position(|segment| segment == "blobs")
	{
		let digest = segments.get(index + 1)?;

		return Some(ScanTarget::Artifact(ArtifactTarget::with_digest(
			&context.repository_format,
			path,
			digest.clone(),
		)));
	}

	if segments.iter().any(|segment| segment == "manifests") {
		return Some(ScanTarget::Artifact(ArtifactTarget::new(
			&context.repository_format,
			path,
		)));
	}

	None
}

fn classify_p2(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;

	if file == "content.xml"
		|| file == "artifacts.xml"
		|| file.ends_with(".xml.xz")
		|| file.ends_with(".xml.gz")
	{
		return None;
	}

	let stem = strip_archive_suffix(file, &[".jar", ".zip"])?;
	let (name, version) = stem.rsplit_once('_')?;

	Some(package_or_artifact_target(
		context,
		path,
		None,
		name.to_owned(),
		version.to_owned(),
	))
}

fn classify_pub(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	let packages_index =
		segments.iter().position(|segment| segment == "packages")?;
	let name = segments.get(packages_index + 1)?;
	let versions_marker = segments.get(packages_index + 2)?;
	if versions_marker != "versions" {
		return None;
	}

	let version = strip_archive_suffix(
		segments.get(packages_index + 3)?,
		&[".tar.gz", ".tgz", ".zip"],
	)?;

	Some(package_target(
		context,
		"Pub",
		name.clone(),
		version.to_owned(),
	))
}

fn classify_r(
	context: &ClassificationContext,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;
	let stem = strip_archive_suffix(file, &[".tar.gz", ".tgz", ".zip"])?;
	let (name, version) = stem.rsplit_once('_')?;

	Some(package_target(
		context,
		"R",
		name.to_owned(),
		version.to_owned(),
	))
}

fn classify_swift(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;
	let version = strip_archive_suffix(file, &[".zip", ".tar.gz", ".tgz"])
		.or_else(|| semantic_version_like(file))?;

	let name = if segments.len() >= 3 {
		format!(
			"{}/{}",
			segments.get(segments.len() - 3)?,
			segments.get(segments.len() - 2)?
		)
	} else if segments.len() >= 2 {
		segments.get(segments.len() - 2)?.clone()
	} else {
		return None;
	};

	Some(package_or_artifact_target(
		context,
		path,
		Some("SwiftURL"),
		name,
		version.to_owned(),
	))
}

fn classify_terraform(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	if let Some(index) =
		segments.iter().position(|segment| segment == "providers")
		&& segments.len() > index + 5
	{
		let namespace = segments.get(index + 1)?;
		let provider_type = segments.get(index + 2)?;
		let version = segments.get(index + 3)?;

		return Some(package_or_artifact_target(
			context,
			path,
			None,
			format!("{namespace}/{provider_type}"),
			version.clone(),
		));
	}

	if let Some(index) =
		segments.iter().position(|segment| segment == "modules")
		&& segments.len() > index + 5
	{
		let namespace = segments.get(index + 1)?;
		let name = segments.get(index + 2)?;
		let provider = segments.get(index + 3)?;
		let version = segments.get(index + 4)?;

		return Some(package_or_artifact_target(
			context,
			path,
			None,
			format!("{namespace}/{name}/{provider}"),
			version.clone(),
		));
	}

	classify_generic_artifact(context, path, segments)
}

fn classify_yum(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;
	if !file.ends_with(".rpm") {
		return None;
	}

	let stem = file.strip_suffix(".rpm")?;
	let without_arch = stem.rsplit_once('.').map_or(stem, |(stem, _arch)| stem);
	let (name_and_version, release) = without_arch.rsplit_once('-')?;
	let (name, version) = name_and_version.rsplit_once('-')?;

	Some(package_or_artifact_target(
		context,
		path,
		default_linux_ecosystem(context),
		name.to_owned(),
		format!("{version}-{release}"),
	))
}

fn classify_generic_artifact(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;

	if is_probable_artifact(file) {
		Some(ScanTarget::Artifact(ArtifactTarget::new(
			&context.repository_format,
			path,
		)))
	} else {
		None
	}
}

fn classify_dash_archive_optional_package(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
	suffixes: &[&str],
	default_ecosystem: Option<&str>,
) -> Option<ScanTarget> {
	let file = segments.last()?;
	let stem = strip_archive_suffix(file, suffixes)?;
	let (name, version) = stem.rsplit_once('-')?;

	Some(package_or_artifact_target(
		context,
		path,
		default_ecosystem,
		name.to_owned(),
		version.to_owned(),
	))
}

fn package_target(
	context: &ClassificationContext,
	default_ecosystem: &str,
	name: String,
	version: String,
) -> ScanTarget {
	let ecosystem = context
		.osv_ecosystem
		.clone()
		.or_else(|| {
			default_osv_ecosystem_for_format(&context.repository_format)
				.map(str::to_owned)
		})
		.unwrap_or_else(|| default_ecosystem.to_owned());

	ScanTarget::Package(PackageCoordinate::from_osv(ecosystem, name, version))
}

fn package_or_artifact_target(
	context: &ClassificationContext,
	path: &str,
	default_ecosystem: Option<&str>,
	name: String,
	version: String,
) -> ScanTarget {
	let ecosystem = context
		.osv_ecosystem
		.clone()
		.or_else(|| {
			default_osv_ecosystem_for_format(&context.repository_format)
				.map(str::to_owned)
		})
		.or_else(|| default_ecosystem.map(str::to_owned));

	if let Some(ecosystem) = ecosystem {
		ScanTarget::Package(PackageCoordinate::from_osv(
			ecosystem, name, version,
		))
	} else {
		ScanTarget::Artifact(ArtifactTarget::new(
			&context.repository_format,
			path,
		))
	}
}

fn default_linux_ecosystem(
	context: &ClassificationContext,
) -> Option<&'static str> {
	match normalize_format(&context.repository_format).as_str() {
		"debian" => Some("Debian GNU/Linux"),
		"ubuntu" => Some("Ubuntu OS"),
		"almalinux" => Some("AlmaLinux"),
		"rockylinux" | "rocky" => Some("Rocky Linux"),
		_ => None,
	}
}

fn package_version_from_path(segments: &[String]) -> Option<(String, String)> {
	for window in segments.windows(3) {
		let first = window.first()?;
		let second = window.get(1)?;
		let third = window.get(2)?;

		if semantic_version_like(third).is_some() {
			return Some((format!("{first}/{second}"), third.clone()));
		}
	}

	None
}

fn decoded_segments(path: &str) -> Vec<String> {
	path.trim_start_matches('/')
		.split('/')
		.filter(|segment| !segment.is_empty())
		.map(|segment| percent_decode_str(segment).decode_utf8_lossy().into())
		.collect()
}

fn normalize_format(format: &str) -> String {
	format
		.chars()
		.filter(|character| character.is_ascii_alphanumeric())
		.flat_map(char::to_lowercase)
		.collect()
}

fn strip_archive_suffix<'a>(
	file: &'a str,
	suffixes: &[&str],
) -> Option<&'a str> {
	suffixes.iter().find_map(|suffix| file.strip_suffix(suffix))
}

fn normalize_pypi_name(name: &str) -> String {
	name.replace(['_', '.'], "-").to_ascii_lowercase()
}

fn semantic_version_like(value: &str) -> Option<&str> {
	value
		.chars()
		.next()
		.is_some_and(|character| character.is_ascii_digit())
		.then_some(value)
}

fn is_sidecar(file: &str) -> bool {
	[".asc", ".md5", ".sha1", ".sha256", ".sha512", ".sig"]
		.iter()
		.any(|suffix| file.ends_with(suffix))
}

fn is_probable_artifact(file: &str) -> bool {
	[
		".aar", ".apk", ".crate", ".deb", ".egg", ".gem", ".gz", ".jar",
		".conda", ".nupkg", ".pom", ".rpm", ".tar", ".tar.bz2", ".tgz", ".war",
		".whl", ".zip",
	]
	.iter()
	.any(|suffix| file.ends_with(suffix))
		&& !is_sidecar(file)
}

#[cfg(test)]
mod tests {
	use axum::http::Uri;
	use nexus_sec_proxy_config::{
		AppConfig, ArtifactScannerKind, UnsupportedTargetPolicy,
	};
	use nexus_sec_proxy_security::{
		PackageIdentity, PolicySet, SecurityPolicy,
	};

	use super::*;

	#[test]
	fn classifies_maven_artifact() {
		let config = config("maven2", Some("Maven"));
		let uri = uri("/com/example/demo/1.2.3/demo-1.2.3.jar");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "Maven", "com.example:demo", "1.2.3");
	}

	#[test]
	fn classifies_stripped_nexus_repository_path() {
		let context = ClassificationContext::new("maven2", None);

		let classification = classify_path(
			&context,
			&Method::GET,
			"/com/example/demo/1.2.3/demo-1.2.3.jar",
		);

		assert_package(classification, "Maven", "com.example:demo", "1.2.3");
	}

	#[test]
	fn classifies_scoped_npm_tarball() {
		let config = config("npm", Some("npm"));
		let uri = uri("/@scope/pkg/-/pkg-1.2.3.tgz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "npm", "@scope/pkg", "1.2.3");
	}

	#[test]
	fn classifies_pypi_wheel() {
		let config = config("pypi", Some("PyPI"));
		let uri = uri("/packages/aa/bb/My_Pkg-1.2.3-py3-none-any.whl");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "PyPI", "my-pkg", "1.2.3");
	}

	#[test]
	fn classifies_nuget_flat_container_download() {
		let config = config("nuget", Some("NuGet"));
		let uri = uri(
			"/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
		);

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "NuGet", "newtonsoft.json", "13.0.3");
	}

	#[test]
	fn classifies_docker_blob_as_artifact() {
		let config = config("docker", None);
		let uri = uri("/v2/library/alpine/blobs/sha256:abc123");

		let classification = classify_request(&config, &Method::GET, &uri);

		match classification {
			RequestClassification::Scan(ScanTarget::Artifact(artifact)) => {
				assert_eq!(artifact.source_format, "docker");
				assert_eq!(artifact.digest.as_deref(), Some("sha256:abc123"));
			}
			other => panic!("unexpected classification: {other:?}"),
		}
	}

	#[test]
	fn classifies_alpine_apk() {
		let config = config("alpine", None);
		let uri = uri("/v3.19/main/x86_64/musl-1.2.4-r0.apk");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "Alpine", "musl", "1.2.4-r0");
	}

	#[test]
	fn apt_deb_without_os_override_is_artifact() {
		let config = config("apt", None);
		let uri = uri("/pool/main/o/openssl/openssl_3.0.2-0ubuntu1_amd64.deb");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_artifact(classification, "apt", None);
	}

	#[test]
	fn apt_deb_with_ubuntu_override_is_package() {
		let config = config("apt", Some("Ubuntu OS"));
		let uri = uri("/pool/main/o/openssl/openssl_3.0.2-0ubuntu1_amd64.deb");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(
			classification,
			"Ubuntu OS",
			"openssl",
			"3.0.2-0ubuntu1",
		);
	}

	#[test]
	fn yum_rpm_with_rocky_override_is_package() {
		let config = config("yum", Some("Rocky Linux"));
		let uri =
			uri("/BaseOS/x86_64/os/Packages/openssl-3.0.7-28.el9.x86_64.rpm");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(
			classification,
			"Rocky Linux",
			"openssl",
			"3.0.7-28.el9",
		);
	}

	#[test]
	fn classifies_composer_package_when_version_is_in_path() {
		let config = config("composer", None);
		let uri = uri("/dist/monolog/monolog/3.5.0/archive.zip");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "Packagist", "monolog/monolog", "3.5.0");
	}

	#[test]
	fn classifies_pub_package_archive() {
		let config = config("pub", None);
		let uri = uri("/api/packages/http/versions/1.2.0.tar.gz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "Pub", "http", "1.2.0");
	}

	#[test]
	fn classifies_r_package_archive() {
		let config = config("r", None);
		let uri = uri("/src/contrib/dplyr_1.1.4.tar.gz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "R", "dplyr", "1.1.4");
	}

	#[test]
	fn classifies_swift_package_archive() {
		let config = config("swift", None);
		let uri = uri("/apple/swift-log/1.5.3.zip");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_package(classification, "SwiftURL", "apple/swift-log", "1.5.3");
	}

	#[test]
	fn terraform_provider_without_override_is_artifact() {
		let config = config("terraform", None);
		let uri =
			uri("/v1/providers/hashicorp/aws/5.30.0/download/linux/amd64");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_artifact(classification, "terraform", None);
	}

	#[test]
	fn helm_chart_without_override_is_artifact() {
		let config = config("helm", None);
		let uri = uri("/charts/nginx-15.4.4.tgz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_artifact(classification, "helm", None);
	}

	#[test]
	fn conda_package_without_override_is_artifact() {
		let config = config("conda", None);
		let uri = uri("/linux-64/openssl-3.0.12-h7f8727e_0.conda");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_artifact(classification, "conda", None);
	}

	#[test]
	fn p2_plugin_without_override_is_artifact() {
		let config = config("p2", None);
		let uri = uri("/plugins/org.example.demo_1.2.3.jar");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_artifact(classification, "p2", None);
	}

	#[test]
	fn git_lfs_object_uses_digest_as_artifact_identifier() {
		let config = config("git-lfs", None);
		let uri = uri("/objects/sha256:abcdef");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_artifact(classification, "git-lfs", Some("sha256:abcdef"));
	}

	#[test]
	fn ansible_collection_without_override_is_artifact() {
		let config = config("ansible", None);
		let uri = uri("/downloads/community-general-8.0.0.tar.gz");

		let classification = classify_request(&config, &Method::GET, &uri);

		assert_artifact(classification, "ansible", None);
	}

	#[test]
	fn sidecar_checksum_is_proxy_only() {
		let config = config("maven2", Some("Maven"));
		let uri = uri("/com/example/demo/1.2.3/demo-1.2.3.jar.sha1");

		assert_eq!(
			classify_request(&config, &Method::GET, &uri),
			RequestClassification::ProxyOnly
		);
	}

	fn config(format: &str, ecosystem: Option<&str>) -> AppConfig {
		AppConfig {
			bind_addr: "127.0.0.1:3000".parse().unwrap(),
			nexus_base_url: "https://repo.example.invalid".to_owned(),
			upstream_base_url: "https://repo.example.invalid".to_owned(),
			repository_name: "default".to_owned(),
			repository_format: format.to_owned(),
			osv_ecosystem: ecosystem.map(str::to_owned),
			osv_ecosystem_overrides: Default::default(),
			nexus_username: None,
			nexus_password: None,
			osv_api_url: "https://api.osv.dev/v1/query".to_owned(),
			policy_file: None,
			admin_token: None,
			log_json: false,
			fail_open: true,
			unsupported_target_policy: UnsupportedTargetPolicy::Allow,
			cache_allowed_ttl_secs: 86_400,
			cache_blocked_ttl_secs: 3_600,
			cache_max_capacity: 100,
			request_timeout_secs: 30,
			artifact_scanner: ArtifactScannerKind::Disabled,
			artifact_scanner_command: String::new(),
			artifact_scanner_skip_db_update: true,
			artifact_scanner_offline: true,
			artifact_scanner_timeout_secs: 300,
			artifact_scan_max_bytes: 512 * 1024 * 1024,
			artifact_scanner_concurrency: 2,
			artifact_tmp_dir: None,
			security_policy: SecurityPolicy::default(),
			policy_set: PolicySet::default(),
		}
	}

	fn uri(path: &str) -> Uri {
		path.parse().unwrap()
	}

	fn assert_package(
		classification: RequestClassification,
		ecosystem: &str,
		name: &str,
		version: &str,
	) {
		match classification {
			RequestClassification::Scan(ScanTarget::Package(package)) => {
				assert_eq!(package.version.as_deref(), Some(version));
				assert_eq!(
					package.identity,
					PackageIdentity::Osv {
						ecosystem: ecosystem.to_owned(),
						name: name.to_owned(),
					}
				);
			}
			other => panic!("unexpected classification: {other:?}"),
		}
	}

	fn assert_artifact(
		classification: RequestClassification,
		source_format: &str,
		digest: Option<&str>,
	) {
		match classification {
			RequestClassification::Scan(ScanTarget::Artifact(artifact)) => {
				assert_eq!(artifact.source_format, source_format);
				assert_eq!(artifact.digest.as_deref(), digest);
			}
			other => panic!("unexpected classification: {other:?}"),
		}
	}
}
