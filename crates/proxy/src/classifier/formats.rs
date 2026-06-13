use nexus_sec_proxy_security::{ArtifactTarget, ScanTarget};

use super::{
	ClassificationContext, default_linux_ecosystem, is_probable_artifact,
	is_sidecar, normalize_pypi_name, package_or_artifact_target,
	package_target, package_version_from_path, semantic_version_like,
	strip_archive_suffix,
};

pub(super) fn classify_alpine(
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

pub(super) fn classify_apt(
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

pub(super) fn classify_composer(
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

pub(super) fn classify_conda(
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

pub(super) fn classify_maven(
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

pub(super) fn classify_npm(
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

pub(super) fn classify_pypi(
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

pub(super) fn classify_nuget(
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

pub(super) fn classify_cargo(
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

pub(super) fn classify_rubygems(
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

pub(super) fn classify_go(
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

pub(super) fn classify_git_lfs(
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

pub(super) fn classify_docker(
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

pub(super) fn classify_p2(
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

pub(super) fn classify_pub(
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

pub(super) fn classify_r(
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

pub(super) fn classify_swift(
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

pub(super) fn classify_terraform(
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

pub(super) fn classify_yum(
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

pub(super) fn classify_generic_artifact(
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

pub(super) fn classify_dash_archive_optional_package(
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
