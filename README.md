# Nexus Security Proxy

`nexus-sec-proxy` is a front-of-Nexus security proxy. Point package managers at
this service using normal Nexus URLs, for example
`http://proxy:3000/repository/maven-central/...`. The proxy discovers Nexus
repositories, checks package downloads before contacting Nexus, and forwards
allowed traffic to Nexus.

Request flow:

1. Clients request Nexus paths through this service.
2. `/repository/{repo}/...` requests are matched against the Nexus repository
   catalog from `GET /service/rest/v1/repositories`.
3. Unknown repositories fail closed before Nexus.
4. Metadata, sidecars, UI, REST, auth/token flows, and non-download paths pass
   through.
5. `GET` and `HEAD` package downloads are classified from the stripped
   repository path and checked through OSV plus the active policy.
6. Enforced blocks create a self-contained Trust report and return
   `403 Forbidden` with its secret URL before Nexus receives the request.
7. Report-only and allowed package requests are forwarded to Nexus.
8. Artifact-only targets are not prefetched from Nexus. They are controlled by
   `NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY`: `block` denies them before
   Nexus; `allow` forwards them without artifact scanning.

## Run

```bash
NEXUS_SEC_PROXY_NEXUS_BASE_URL=http://127.0.0.1:8081 \
NEXUS_SEC_PROXY_TRUST_BASE_URL=http://127.0.0.1:3000 \
cargo run -p nexus-sec-proxy
```

Health check:

```bash
curl http://127.0.0.1:3000/healthz
```

## E2E Environment

Bootstrap the local Docker-based e2e environment:

```bash
scripts/bootstrap-e2e.sh
```

The script uses `e2e.compose.yaml`, starts Nexus first, waits for a non-empty
Nexus repository catalog, primes scanner database volumes, starts the scanner
DB updater and proxy, verifies `http://127.0.0.1:3000/healthz`, requests a
known vulnerable Maven package, and fetches the Trust page linked by its 403
response.
It enables the proxy admin UI with the default bearer token
`e2e-admin-token` unless `NEXUS_SEC_PROXY_E2E_ADMIN_TOKEN` or
`NEXUS_SEC_PROXY_ADMIN_TOKEN` is set. When the environment is ready, the script
prints the proxy admin URL, bearer token, and any Nexus test credentials it had
to use or could discover.

## Core Configuration

Required:

```bash
NEXUS_SEC_PROXY_NEXUS_BASE_URL=http://nexus:8081
NEXUS_SEC_PROXY_TRUST_BASE_URL=https://proxy.example.com
```

Common:

```bash
NEXUS_SEC_PROXY_BIND_ADDR=127.0.0.1:3000
NEXUS_SEC_PROXY_NEXUS_USERNAME=
NEXUS_SEC_PROXY_NEXUS_PASSWORD=
NEXUS_SEC_PROXY_REPOSITORY_REFRESH_INTERVAL_SECS=60
NEXUS_SEC_PROXY_OSV_ECOSYSTEM_OVERRIDES=apt-proxy=Ubuntu OS,yum-proxy=Rocky Linux
NEXUS_SEC_PROXY_OSV_API_URL=https://api.osv.dev/v1/query
NEXUS_SEC_PROXY_POLICY_FILE=/etc/nexus-sec-proxy/policy.toml
NEXUS_SEC_PROXY_ADMIN_TOKEN=
NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN=
NEXUS_SEC_PROXY_YANDEX_MESSENGER_TEMPLATE_FILE=
NEXUS_SEC_PROXY_YANDEX_MESSENGER_API_URL=https://botapi.messenger.yandex.net
NEXUS_SEC_PROXY_YANDEX_MESSENGER_ENABLED=
NEXUS_SEC_PROXY_TRUST_REPORT_DIR=/var/lib/nexus-sec-proxy/trust-reports
NEXUS_SEC_PROXY_TRUST_REPORT_RETENTION_DAYS=30
NEXUS_SEC_PROXY_LOG_JSON=false
NEXUS_SEC_PROXY_FAIL_OPEN=true
NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY=allow
```

Configuration notes:

- `NEXUS_SEC_PROXY_NEXUS_BASE_URL` is the preferred Nexus URL. The old
  `NEXUS_SEC_PROXY_UPSTREAM_BASE_URL` and `NEXUS_SEC_PROXY_UPSTREAM_REGISTRY`
  names are accepted as compatibility fallbacks.
- `NEXUS_SEC_PROXY_NEXUS_USERNAME` and
  `NEXUS_SEC_PROXY_NEXUS_PASSWORD` are used only for repository catalog
  discovery.
- `NEXUS_SEC_PROXY_REPOSITORY_REFRESH_INTERVAL_SECS` refreshes the repository
  catalog independently in each proxy replica. The default is `60`; set it to
  `0` to disable automatic refresh. Failed refreshes keep the last valid
  catalog.
- Repository names and formats come from Nexus. Legacy
  `NEXUS_SEC_PROXY_REPOSITORY_NAME`, `NEXUS_SEC_PROXY_REPOSITORY_FORMAT`, and
  `NEXUS_SEC_PROXY_OSV_ECOSYSTEM` are still parsed for compatibility helpers,
  but catalog-discovered traffic uses per-request repository data.
- `NEXUS_SEC_PROXY_OSV_ECOSYSTEM_OVERRIDES` maps repository names to OSV
  ecosystems for formats where the Nexus format is ambiguous.
- `NEXUS_SEC_PROXY_ADMIN_TOKEN` enables `/admin` and `/admin/api/*` when set
  to a non-empty value. Admin API requests must include
  `Authorization: Bearer <token>`.
- Yandex Messenger notifications are enabled by default only when both
  `NEXUS_SEC_PROXY_YANDEX_MESSENGER_TOKEN` and
  `NEXUS_SEC_PROXY_YANDEX_MESSENGER_TEMPLATE_FILE` are set. Set
  `NEXUS_SEC_PROXY_YANDEX_MESSENGER_ENABLED=false` to force them off. Binaries
  built with `--no-default-features` accept these variables but never send
  Messenger notifications.
- `NEXUS_SEC_PROXY_TRUST_BASE_URL` is the public HTTP(S) origin or base path
  used in report links. Query strings and fragments are rejected.
- `NEXUS_SEC_PROXY_TRUST_REPORT_DIR` must be writable. Startup fails if the
  directory cannot be created and tested. Runtime write failures deny the
  download with `503 Service Unavailable`.
- Trust reports expire after
  `NEXUS_SEC_PROXY_TRUST_REPORT_RETENTION_DAYS` (minimum `1`, default `30`).
  Replicas on different hosts must mount the same external shared filesystem
  at the configured report directory.
- `NEXUS_SEC_PROXY_FAIL_OPEN=true` allows downloads when OSV fails. Set it to
  `false` to return `503 Service Unavailable` on scanner failures.
- `NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY=allow` allows targets that cannot
  be checked before Nexus. Set it to `block` to deny them before Nexus.
- The initial repository catalog load is mandatory. A load failure or empty
  catalog fails startup.

## Policy Configuration

When `NEXUS_SEC_PROXY_POLICY_FILE` is unset, the proxy builds one default
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

When `NEXUS_SEC_PROXY_POLICY_FILE` is set, the TOML file is loaded at startup
and can be reloaded through the admin API. Policy files support repository,
format, and team scoped policies; first-match policy selection; `enforce` and
`report_only` modes; and structured exceptions.

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

Policy notes:

- `[default_policy]` is required and is used when no scoped policy matches.
- `[repositories."<repo-name>"] team = "<team>"` maps a Nexus repository name
  to a team.
- `[[policies]]` entries are checked in file order.
- Omitted scope arrays are wildcards.
- Policy scope fields are `repositories`, `formats`, and `teams`.
- `mode = "enforce"` blocks violations with `403 Forbidden`.
- `mode = "report_only"` logs the would-block report and forwards the request.
- Unknown TOML fields are rejected.
- Policy reload swaps the active policy only after successful validation.

The policy TOML JSON Schema for editor and tooling support is checked in at
`schemas/policy.schema.json`. Regenerate it after policy input changes with:

```bash
cargo run -p nexus-sec-proxy-security --features policy-schema --example policy_schema > schemas/policy.schema.json
```

## Admin API and UI

Set a non-empty `NEXUS_SEC_PROXY_ADMIN_TOKEN` to enable the admin surface:

```bash
NEXUS_SEC_PROXY_ADMIN_TOKEN=change-me
```

Read-only endpoints:

- `GET /admin` serves a small built-in dashboard.
- `GET /admin/api/status` returns uptime, immutable config, active policy
  generation/source, repository catalog status, cache summary, and scanner
  summary.
- `GET /admin/api/policy` returns the active policy set and policy generation.
- `GET /admin/api/repositories` returns the loaded Nexus repository catalog.
- `GET /admin/api/cache` returns cache counts plus configured TTLs and
  capacity.
- `GET /admin/api/scanner` returns scanner config and best-effort local DB
  file age.
- `GET /admin/api/decisions?limit=N` returns recent blocked and report-only
  decisions, newest first. Blocked decisions include `report_url`; report-only
  decisions use `null`.

Operations:

- `POST /admin/api/policy/reload` reloads `NEXUS_SEC_PROXY_POLICY_FILE`.
- `POST /admin/api/policy/validate` validates TOML supplied in the request
  body and can preview policy selection for a supplied repository and format.
- `POST /admin/api/repositories/reload` reloads the Nexus repository catalog.

Examples:

```bash
curl -sS \
  -H "Authorization: Bearer ${NEXUS_SEC_PROXY_ADMIN_TOKEN}" \
  http://127.0.0.1:3000/admin/api/status

curl -sS -X POST \
  -H "Authorization: Bearer ${NEXUS_SEC_PROXY_ADMIN_TOKEN}" \
  http://127.0.0.1:3000/admin/api/repositories/reload
```

## Audit Logging

Use `NEXUS_SEC_PROXY_LOG_JSON=true` for JSON tracing output.

Audit event names:

- `policy_blocked`
- `policy_report_only_violation`
- `policy_exception_applied`
- `policy_exception_expired_match`

Each event includes repository, format, team, policy ID, mode, target display
name, vulnerability IDs, and exception metadata when present.
`policy_blocked` also includes `report_url`.

## Trust Reports

Every enforced policy or unsupported-target block creates a new UUID v4 report
at `GET /trust/reports/{uuid}`. The route does not use admin authentication:
possession of the unguessable URL grants access until retention expiry.
Responses disable caching and send restrictive browser security headers.

Reports contain the block context, policy violations, severity counts, and only
the vulnerabilities relevant to the block. Scanner-provided text is escaped;
only HTTP and HTTPS references become links. Report-only decisions do not
create Trust pages. Repeated blocks from cache receive distinct URLs.

## Yandex Messenger Notifications

Default builds include Yandex Messenger support through the
`yandex-messenger` Cargo feature. To compile the proxy without this integration:

```bash
cargo build -p nexus-sec-proxy --no-default-features
```

When the feature is not compiled in, Yandex Messenger environment variables are
still accepted for configuration compatibility but notifications are ignored.

When configured, enforced `403 Forbidden` block decisions trigger a best-effort
Yandex Messenger private message. The proxy uses the incoming Basic Auth
username as the Messenger `login`; requests without Basic Auth still block as
usual but do not notify. Notification failures do not change the client-visible
403 response body.

The template file is checked on every blocked notification and reloaded when
its modification time changes. If reload fails, the last valid template remains
active. Supported placeholders:

```text
{user}
{repository}
{format}
{target}
{reason}
{policy_id}
{vulnerability_ids}
{report_url}
{timestamp}
```

Unknown placeholders are left unchanged. If `{report_url}` is omitted, the
notifier appends `Report: <url>`. Message truncation always reserves room for
the complete report URL.

## Cache

```bash
NEXUS_SEC_PROXY_CACHE_ALLOWED_TTL_SECS=86400
NEXUS_SEC_PROXY_CACHE_BLOCKED_TTL_SECS=3600
NEXUS_SEC_PROXY_CACHE_MAX_CAPACITY=100000
NEXUS_SEC_PROXY_REQUEST_TIMEOUT_SECS=30
```

The cache stores raw vulnerability lists, not final allow/block decisions.
Cached vulnerability lists are re-evaluated on every request so policy reloads,
repository scopes, team scopes, and exception expiry do not leak across
repositories.

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

These formats need `NEXUS_SEC_PROXY_OSV_ECOSYSTEM_OVERRIDES` when the Nexus
repository format alone does not identify the operating system or package
database precisely enough:

- APT / Debian / Ubuntu
- Yum / RPM

These formats are classified as artifact targets by default and are controlled
by `NEXUS_SEC_PROXY_UNSUPPORTED_TARGET_POLICY`:

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
