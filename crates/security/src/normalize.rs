pub(crate) fn normalize_vulnerability_id(id: &str) -> Option<String> {
	let normalized = id.trim().to_ascii_uppercase();

	(!normalized.is_empty()).then_some(normalized)
}

pub(crate) fn normalize_match_value(value: &str) -> Option<String> {
	let normalized = value.trim().to_ascii_lowercase();

	(!normalized.is_empty()).then_some(normalized)
}

pub(crate) fn normalize_context_value(
	value: impl Into<String>,
	default: &str,
) -> String {
	normalize_match_value(&value.into()).unwrap_or_else(|| default.to_owned())
}

pub(crate) fn normalized_selector_list(values: Vec<String>) -> Vec<String> {
	let mut normalized = values
		.into_iter()
		.filter_map(|value| normalize_match_value(&value))
		.collect::<Vec<_>>();

	normalized.sort();
	normalized.dedup();
	normalized
}

pub(crate) fn matches_case_insensitive_selector(
	selectors: &[String],
	value: Option<&str>,
) -> bool {
	if selectors.is_empty() {
		return true;
	}

	value.and_then(normalize_match_value).is_some_and(|value| {
		selectors.iter().any(|selector| selector == &value)
	})
}
