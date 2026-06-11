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
NEXUS_SEC_PROXY_REPOSITORY_FORMAT=maven2
NEXUS_SEC_PROXY_OSV_ECOSYSTEM=Maven
NEXUS_SEC_PROXY_OSV_API_URL=https://api.osv.dev/v1/query
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
```

`NEXUS_SEC_PROXY_ARTIFACT_SCANNER` supports `disabled`, `trivy`, and
`grype`. The scanner executable must exist in the runtime image or host PATH.
For production, prewarm and persist scanner vulnerability databases out of band
and keep `NEXUS_SEC_PROXY_ARTIFACT_SCANNER_SKIP_DB_UPDATE=true` on request
paths. With Trivy this service invokes filesystem scans with JSON output,
vulnerability scanning only, quiet mode, optional offline mode, and optional DB
update skipping. With Grype this service invokes JSON output against the
prefetched artifact path.

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
