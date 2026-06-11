# Nexus Security Proxy

`nexus-sec-proxy` is a Nexus-facing upstream proxy. Configure a Nexus OSS
proxy repository to use this service as its remote URL; this service then talks
to the real upstream registry.

Request flow:

1. Nexus requests metadata or an artifact from this service.
2. Metadata and sidecar files are proxied through.
3. Artifact downloads are classified into a scan target.
4. Supported package targets are checked through OSV and the local policy.
5. Blocked packages return `403 Forbidden` with plain-text details and
   vulnerability references.
6. Allowed packages are streamed from upstream to Nexus.

## Run

```bash
NEXUS_SEC_PROXY_UPSTREAM_BASE_URL=https://repo1.maven.org/maven2 \
NEXUS_SEC_PROXY_REPOSITORY_FORMAT=maven2 \
cargo run -p nexus-sec-proxy
```

Health check:

```bash
curl http://127.0.0.1:3000/healthz
```

## Core Configuration

Required:

```bash
NEXUS_SEC_PROXY_UPSTREAM_BASE_URL=https://real-upstream.example
```

Common:

```bash
NEXUS_SEC_PROXY_BIND_ADDR=127.0.0.1:3000
NEXUS_SEC_PROXY_REPOSITORY_NAME=maven-central
NEXUS_SEC_PROXY_REPOSITORY_FORMAT=maven2
NEXUS_SEC_PROXY_OSV_ECOSYSTEM=Maven
NEXUS_SEC_PROXY_OSV_API_URL=https://api.osv.dev/v1/query
NEXUS_SEC_PROXY_POLICY_FILE=/etc/nexus-sec-proxy/policy.toml
NEXUS_SEC_PROXY_LOG_JSON=false
NEXUS_SEC_PROXY_FAIL_OPEN=true
NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY=allow
```

Policy:

```bash
NEXUS_SEC_PROXY_MINIMUM_BLOCKING_SEVERITY=HIGH
NEXUS_SEC_PROXY_ALLOWED_VULNERABILITY_IDS=CVE-2026-0001,GHSA-xxxx
NEXUS_SEC_PROXY_MAX_TOTAL_VULNERABILITIES=5
NEXUS_SEC_PROXY_MAX_LOW_VULNERABILITIES=10
NEXUS_SEC_PROXY_MAX_MEDIUM_VULNERABILITIES=2
NEXUS_SEC_PROXY_MAX_HIGH_VULNERABILITIES=0
NEXUS_SEC_PROXY_MAX_CRITICAL_VULNERABILITIES=0
```

The legacy policy env vars above are used only when
`NEXUS_SEC_PROXY_POLICY_FILE` is unset. A policy file supports repository,
format, and team scoped rules, report-only mode, and expiring exceptions:

```toml
[default_policy]
id = "default"
minimum_blocking_severity = "HIGH"
mode = "enforce"

[repositories."npm-internal"]
team = "web"

[[policies]]
id = "web-npm"
repositories = ["npm-internal"]
formats = ["npm"]
teams = ["web"]
minimum_blocking_severity = "MEDIUM"
mode = "report_only"
max_critical_vulnerabilities = 0

[[exceptions]]
id = "SEC-1234"
owner = "security"
ticket = "SEC-1234"
reason = "temporary rollout exception"
expires_at = "2026-12-31T23:59:59Z"
vulnerability_ids = ["CVE-2026-0001", "GHSA-xxxx"]
repositories = ["npm-internal"]
formats = ["npm"]
teams = ["web"]
packages = ["left-pad"]
versions = ["1.0.0"]
```

`[[policies]]` entries are checked in file order; the first matching scope
wins. Omitted scope arrays act as wildcards. `mode = "report_only"` proxies
the artifact but emits a structured audit event for the violation.

Cache:

```bash
NEXUS_SEC_PROXY_CACHE_ALLOWED_TTL_SECS=86400
NEXUS_SEC_PROXY_CACHE_BLOCKED_TTL_SECS=3600
NEXUS_SEC_PROXY_CACHE_MAX_CAPACITY=100000
NEXUS_SEC_PROXY_REQUEST_TIMEOUT_SECS=30
```

Artifact scanning:

```bash
NEXUS_SEC_PROXY_ARTIFACT_SCANNER=trivy
NEXUS_SEC_PROXY_ARTIFACT_SCANNER_COMMAND=trivy
NEXUS_SEC_PROXY_ARTIFACT_SCANNER_SKIP_DB_UPDATE=true
NEXUS_SEC_PROXY_ARTIFACT_SCANNER_OFFLINE=true
NEXUS_SEC_PROXY_ARTIFACT_SCANNER_TIMEOUT_SECS=300
NEXUS_SEC_PROXY_ARTIFACT_SCAN_MAX_BYTES=536870912
NEXUS_SEC_PROXY_ARTIFACT_SCANNER_CONCURRENCY=2
NEXUS_SEC_PROXY_ARTIFACT_TMP_DIR=/var/tmp/nexus-sec-proxy
NEXUS_SEC_PROXY_SCANNER_DB_UPDATE_INTERVAL_SECS=21600
NEXUS_SEC_PROXY_SCANNER_DB_RETRY_INTERVAL_SECS=300
TRIVY_CACHE_DIR=/var/cache/trivy
GRYPE_DB_CACHE_DIR=/var/cache/grype/db
```

`NEXUS_SEC_PROXY_ARTIFACT_SCANNER` supports `disabled`, `trivy`, and
`grype`. The scanner executable must exist in the runtime image or host PATH.
In Docker Compose, the `scanner-db-updater` sidecar refreshes the Trivy and
Grype vulnerability databases on startup and every 6 hours by default. The
proxy still keeps request-path scans offline with
`NEXUS_SEC_PROXY_ARTIFACT_SCANNER_SKIP_DB_UPDATE=true` and
`NEXUS_SEC_PROXY_ARTIFACT_SCANNER_OFFLINE=true`, so stale or missing scanner
databases are logged by the scanner path but do not make `/healthz` fail.

To explicitly prewarm scanner databases, run:

```bash
docker compose run --rm scanner-db-updater once
```

With Trivy this service invokes filesystem scans with JSON output,
vulnerability scanning only, quiet mode, offline mode, and DB update skipping.
With Grype this service invokes JSON output against the prefetched artifact
path.

## Current Format Handling

Coordinate scans are implemented by default for:

- Alpine
- Cargo / Rust
- Composer / Packagist, when the package version is present in the path
- Go proxy-style downloads
- Maven
- npm
- NuGet
- Pub / Flutter / Dart
- PyPI
- R / CRAN
- RubyGems
- Swift

These formats are parsed as package coordinates only when you provide
`NEXUS_SEC_PROXY_OSV_ECOSYSTEM`, because the repository format alone does not
identify the operating system or package database precisely enough:

- APT / Debian / Ubuntu
- Yum / RPM

These formats are classified as artifact targets by default:

- Ansible Galaxy collections
- Bower
- CocoaPods
- Conan
- Conda
- Docker manifests and blobs
- Git LFS objects
- Helm charts
- Hugging Face assets
- Eclipse p2
- Raw repositories
- Terraform modules/providers
- unknown binary archives

Artifact targets are prefetched to temporary storage and scanned before any
bytes are sent to Nexus when `NEXUS_SEC_PROXY_ARTIFACT_SCANNER` is `trivy` or
`grype`. If artifact scanning is disabled, those targets are controlled by
`NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY`.
