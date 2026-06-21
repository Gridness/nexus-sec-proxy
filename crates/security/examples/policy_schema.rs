fn main() -> Result<(), Box<dyn std::error::Error>> {
	let schema = nexus_sec_proxy_security::policy_toml_schema();
	println!("{}", serde_json::to_string_pretty(&schema)?);
	Ok(())
}
