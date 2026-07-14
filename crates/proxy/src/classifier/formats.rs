use nexus_sec_proxy_security::{ArtifactTarget, ScanTarget};

use super::{ClassificationContext, package_target, strip_archive_suffix};

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

pub(super) fn classify_docker(
	_context: &ClassificationContext,
	_path: &str,
	_segments: &[String],
) -> Option<ScanTarget> {
	None
}

pub(super) fn classify_helm(
	context: &ClassificationContext,
	path: &str,
	segments: &[String],
) -> Option<ScanTarget> {
	let file = segments.last()?;
	if !file.ends_with(".tgz") && !file.ends_with(".tar.gz") {
		return None;
	}

	Some(ScanTarget::Artifact(ArtifactTarget::new(
		&context.repository_format,
		path,
	)))
}

fn is_sidecar(file: &str) -> bool {
	[".asc", ".md5", ".sha1", ".sha256", ".sha512", ".sig"]
		.iter()
		.any(|suffix| file.ends_with(suffix))
}

fn normalize_pypi_name(name: &str) -> String {
	name.replace(['_', '.'], "-").to_ascii_lowercase()
}
