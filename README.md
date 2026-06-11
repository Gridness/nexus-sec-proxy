# Nexus Security Proxy

`nexus-sec-proxy` is a Nexus-facing upstream proxy. Configure a Nexus OSS
proxy repository to use this service as its remote URL; this service then talks
to the real upstream registry.

Request flow:

1. Nexus requests metadata or an artifact from this service.
2. Metadata and sidecar files are proxied through.
3. Artifact downloads are classified into a scan target.
4. Supported package targets are checked through OSV and the active policy.
5. Artifact targets can be prefetched and scanned by Trivy or Grype.
6. Vulnerability results are cached, then re-evaluated against the active
   policy for each request.
7. Blocked packages return `403 Forbidden` with plain-text details and
   vulnerability references.
8. Report-only violations are logged but streamed from upstream to Nexus.
9. Allowed packages are streamed from upstream to Nexus.

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
NEXUS_SEC_PROXY_ADMIN_TOKEN=
NEXUS_SEC_PROXY_LOG_JSON=false
NEXUS_SEC_PROXY_FAIL_OPEN=true
NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY=allow
```

Configuration notes:

- `NEXUS_SEC_PROXY_UPSTREAM_BASE_URL` is required. The legacy name
  `NEXUS_SEC_PROXY_UPSTREAM_REGISTRY` is still accepted as a fallback.
- `NEXUS_SEC_PROXY_REPOSITORY_NAME` identifies this Nexus repository for
  policy matching. The default is `default`.
- `NEXUS_SEC_PROXY_REPOSITORY_FORMAT` drives request classification. The
  default is `generic`.
- `NEXUS_SEC_PROXY_OSV_ECOSYSTEM` overrides the ecosystem sent to OSV. If it
  is unset, known repository formats such as `maven2`, `npm`, and `pypi` are
  mapped automatically.
- `NEXUS_SEC_PROXY_ADMIN_TOKEN` enables `/admin` and `/admin/api/*` when set
  to a non-empty value. Admin API requests must include
  `Authorization: Bearer <token>`. When it is unset or empty, admin routes are
  disabled and `/admin*` paths are not proxied upstream.
- `NEXUS_SEC_PROXY_FAIL_OPEN=true` allows downloads when OSV or the configured
  artifact scanner fails. Set it to `false` to return `503 Service Unavailable`
  on scanner failures.
- `NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY=allow` allows targets that cannot
  be scanned. Set it to `block` to deny unsupported targets.
- `NEXUS_SEC_PROXY_LOG_JSON=true` enables JSON tracing output for machine
  parsing and audit ingestion.

## Policy Configuration

There are two policy configuration modes.

### Legacy Env Policy

When `NEXUS_SEC_PROXY_POLICY_FILE` is unset, the proxy builds a single default
policy from environment variables:

```bash
NEXUS_SEC_PROXY_MINIMUM_BLOCKING_SEVERITY=HIGH
NEXUS_SEC_PROXY_ALLOWED_VULNERABILITY_IDS=CVE-2026-0001,GHSA-xxxx
NEXUS_SEC_PROXY_MAX_TOTAL_VULNERABILITIES=5
NEXUS_SEC_PROXY_MAX_LOW_VULNERABILITIES=10
NEXUS_SEC_PROXY_MAX_MEDIUM_VULNERABILITIES=2
NEXUS_SEC_PROXY_MAX_HIGH_VULNERABILITIES=0
NEXUS_SEC_PROXY_MAX_CRITICAL_VULNERABILITIES=0
```

`NEXUS_SEC_PROXY_MINIMUM_SEVERITY` is still accepted as a legacy fallback for
`NEXUS_SEC_PROXY_MINIMUM_BLOCKING_SEVERITY`.

`NEXUS_SEC_PROXY_ALLOWED_VULNERABILITY_IDS` is a comma-separated allowlist. It
matches the primary vulnerability ID and aliases case-insensitively. Limits are
applied after allowlisted IDs are removed.

### TOML Policy File

When `NEXUS_SEC_PROXY_POLICY_FILE` is set, the policy file is loaded at
startup and the legacy policy env vars above are ignored. The active policy can
also be reloaded through the admin API. Policy files support:

- repository, format, and team scoped policies
- first-match policy selection
- `enforce` and `report_only` modes
- structured exceptions with owners, tickets, reasons, expiry timestamps, and
  optional target scopes
- case-insensitive matching for repositories, formats, teams, and
  vulnerability IDs
- exact normalized package and version matching for exception target scopes

Example:

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

Policy file rules:

- `[default_policy]` is required and is used when no `[[policies]]` scope
  matches.
- `[repositories."<repo-name>"] team = "<team>"` maps a repository to one team.
  The current repository comes from `NEXUS_SEC_PROXY_REPOSITORY_NAME`.
- `[[policies]]` entries are checked in file order. The first matching scope
  wins.
- Omitted scope arrays are wildcards.
- Policy scope fields are `repositories`, `formats`, and `teams`.
- Policy threshold fields match the legacy env names without the
  `NEXUS_SEC_PROXY_` prefix: `minimum_blocking_severity`,
  `allowed_vulnerability_ids`, `max_total_vulnerabilities`,
  `max_low_vulnerabilities`, `max_medium_vulnerabilities`,
  `max_high_vulnerabilities`, and `max_critical_vulnerabilities`.
- `mode = "enforce"` blocks violations with `403 Forbidden`.
- `mode = "report_only"` logs the would-block report and proxies the request.
- Unknown TOML fields are rejected at startup.
- Invalid reload attempts are rejected and leave the active policy unchanged.
- Only the policy file is live-reloadable. Network, scanner, cache sizing, and
  upstream settings require a restart.

Exception rules:

- Each `[[exceptions]]` entry requires `id`, `owner`, `ticket`, `reason`,
  `expires_at`, and `vulnerability_ids`.
- `expires_at` must be RFC3339, for example `2026-12-31T23:59:59Z`.
- `vulnerability_ids` match primary IDs and aliases.
- Optional exception scopes are `repositories`, `formats`, `teams`,
  `packages`, and `versions`.
- Active matching exceptions suppress matching vulnerabilities before severity
  and count limits are evaluated.
- Expired matching exceptions are ignored for enforcement but logged as audit
  events.

Blocked responses include the selected policy ID:

```text
Package blocked by nexus-sec-proxy

Target: npm:left-pad@1.0.0
Reason: vulnerability policy was violated
Policy: web-npm
```

## Admin API and UI

The admin surface is disabled by default. Set a non-empty
`NEXUS_SEC_PROXY_ADMIN_TOKEN` to enable it:

```bash
NEXUS_SEC_PROXY_ADMIN_TOKEN=change-me
```

All admin API requests require:

```text
Authorization: Bearer <token>
```

`GET /admin` serves a small built-in HTML dashboard. The page contains no
embedded operational data; it prompts for the token and then calls the JSON
API from the browser.

Read-only endpoints:

- `GET /admin/api/status` returns uptime, immutable config, active policy
  generation/source, cache summary, and scanner summary.
- `GET /admin/api/policy` returns the active policy set, current policy
  context, and selected policy ID.
- `GET /admin/api/cache` returns clean, vulnerable, and total cache entry
  counts plus configured TTLs and capacity.
- `GET /admin/api/scanner` returns scanner config, available scanner permits,
  and best-effort Trivy/Grype DB file age from `TRIVY_CACHE_DIR` and
  `GRYPE_DB_CACHE_DIR`.
- `GET /admin/api/decisions?limit=N` returns recent blocked and report-only
  decisions, newest first. `limit` is clamped to `1..=100`.

Policy operations:

- `POST /admin/api/policy/reload` reloads `NEXUS_SEC_PROXY_POLICY_FILE`,
  validates it, and atomically swaps the active policy only on success. It
  returns `409 Conflict` when no policy file is configured and `422
  Unprocessable Entity` when the file is invalid.
- `POST /admin/api/policy/validate` validates TOML supplied in the request body
  without reading from disk:

```bash
curl -sS \
  -H "Authorization: Bearer ${NEXUS_SEC_PROXY_ADMIN_TOKEN}" \
  http://127.0.0.1:3000/admin/api/status

curl -sS -X POST \
  -H "Authorization: Bearer ${NEXUS_SEC_PROXY_ADMIN_TOKEN}" \
  http://127.0.0.1:3000/admin/api/policy/reload

curl -sS -X POST \
  -H "Authorization: Bearer ${NEXUS_SEC_PROXY_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"policy_toml":"[default_policy]\nid=\"default\"\nminimum_blocking_severity=\"HIGH\"\n","repository_name":"npm-internal","repository_format":"npm"}' \
  http://127.0.0.1:3000/admin/api/policy/validate
```

No cache flush is needed after policy reloads. The cache stores raw
vulnerability lists and every request evaluates those raw results against the
current active policy snapshot.

In Docker Compose, `NEXUS_SEC_PROXY_ADMIN_TOKEN` is wired with an empty default,
so existing deployments keep the admin surface disabled until the variable is
set explicitly.

## Audit Logging

The proxy emits structured `tracing` events for policy outcomes. Use
`NEXUS_SEC_PROXY_LOG_JSON=true` when these logs need to be consumed by SIEM or
log pipelines.

Audit event names:

- `policy_blocked`
- `policy_report_only_violation`
- `policy_exception_applied`
- `policy_exception_expired_match`

Each event includes repository, format, team, policy ID, mode, target display
name, vulnerability IDs, and exception metadata when present: exception ID,
owner, ticket, reason, and expiry.

## Cache

```bash
NEXUS_SEC_PROXY_CACHE_ALLOWED_TTL_SECS=86400
NEXUS_SEC_PROXY_CACHE_BLOCKED_TTL_SECS=3600
NEXUS_SEC_PROXY_CACHE_MAX_CAPACITY=100000
NEXUS_SEC_PROXY_REQUEST_TIMEOUT_SECS=30
```

The cache stores raw vulnerability lists, not final allow/block decisions. Empty
scan results use `NEXUS_SEC_PROXY_CACHE_ALLOWED_TTL_SECS`; non-empty scan
results use `NEXUS_SEC_PROXY_CACHE_BLOCKED_TTL_SECS`. Cached vulnerability
lists are re-evaluated on every request so policy modes, scoped rules, and
exception expiry do not leak across repositories or teams.

## Artifact Scanning

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
