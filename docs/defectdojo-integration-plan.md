# DefectDojo integration plan

## Outcome

When the default `defectdojo` Cargo feature is compiled and
`NEXUS_SEC_PROXY_DEFECTDOJO_ENABLED=true`, each enforced block creates one
complete DefectDojo Test in a configured Engagement. That Test replaces the
local HTML Trust Report. The denied response and any Yandex notification link
to the Test.

When runtime activation is false, the existing local report flow remains
unchanged. A binary built without the feature must reject runtime activation
at startup.

The governing decisions are recorded in
[ADR 0010](adr/0010-defectdojo-can-own-trust-reports.md),
[ADR 0011](adr/0011-defectdojo-has-build-and-runtime-activation.md), and
[ADR 0012](adr/0012-defectdojo-health-is-request-scoped.md).

## Deliberate non-goals

- SARIF export.
- Requester IP collection or forwarded-header trust.
- DefectDojo reports for `report_only` decisions.
- Importing allowlisted, excepted, or otherwise non-blocking findings.
- Dynamic Product or Engagement creation.
- Automatic retries, queues, outboxes, or deletion jobs.
- A generic report-sink trait or support for another reporting product.
- DefectDojo 2.x or Pro-only APIs.
- A live DefectDojo dependency in startup, `/healthz`, or CI.

## Deployment contract

The standard binary and image compile both optional integrations by default:

```toml
default = ["defectdojo", "yandex-messenger"]
```

Runtime activation uses:

| Variable | Requirement |
| --- | --- |
| `NEXUS_SEC_PROXY_DEFECTDOJO_ENABLED` | Defaults to `false` |
| `NEXUS_SEC_PROXY_DEFECTDOJO_URL` | Required when enabled; HTTPS except loopback tests |
| `NEXUS_SEC_PROXY_DEFECTDOJO_TOKEN` | API token; mutually exclusive with the token file |
| `NEXUS_SEC_PROXY_DEFECTDOJO_TOKEN_FILE` | Docker-secret-friendly token source |
| `NEXUS_SEC_PROXY_DEFECTDOJO_ENGAGEMENT_ID` | Required positive ID of an existing Engagement |

The existing request timeout bounds the synchronous API call; no second
DefectDojo timeout setting is needed. Local Trust Report directory, base URL,
and retention settings are ignored while DefectDojo is active and retain
their current validation in local mode.

The DefectDojo Open Source 3.x deployment must:

1. Pre-create the Reporting Engagement.
2. Grant the API token permission to import a scan into that Engagement.
3. Configure the generated
   `Nexus Security Proxy Scan (Generic Findings Import)` Test Type to use the
   `Unique ID From Tool` deduplication algorithm.
4. Expose API and UI from the configured base URL.

The operator guide will include the corresponding Open Source deduplication
setting and require it to be checked against the deployed 3.x release.

## Report data contract

Create one report envelope before persistence so local HTML, DefectDojo,
audit, decisions, and Yandex use the same UUID and UTC timestamp. The envelope
contains:

- report UUID and RFC 3339 timestamp;
- repository, artifact format, target, team, policy, reason, and violations;
- severity counts and only the vulnerabilities responsible for the block;
- verified Nexus Requester ID, or an explicit unavailable value;
- vulnerability ID, aliases, summary, details, severity, references, affected
  component/version, and scanner-reported fixed versions.

Basic credentials still require the exact Nexus `HEAD` verification described
by ADR 0003 before a report is created. Docker requests reuse the successful
manifest response. Requester verification must be separated from Yandex email
lookup so it also runs when Yandex is disabled. A client-asserted username and
all forwarding headers are excluded.

Extend the security vulnerability model only with the scanner facts required
for reporting:

```text
component_name: optional string
component_version: optional string
fixed_versions: list of strings
```

OSV fixed range events and Trivy package, installed version, and fixed version
fields populate them. Fixed versions are trimmed and deduplicated. Mitigation
is derived only when fixed versions exist, for example “Upgrade X to a fixed
version: Y”; otherwise it remains unknown. Local HTML displays the same
Requester and mitigation content.

## DefectDojo mapping

Use `POST /api/v2/import-scan/` with `scan_type=Generic Findings Import`, an
in-memory Generic Findings JSON file, `background_import=false`,
`minimum_severity=Info`, `active=true`, `verified=true`,
`skip_duplicates=false`, and the configured Engagement. Every call creates a
new Test; `reimport-scan` is not used.

The JSON file has top-level type `Nexus Security Proxy`. Each vulnerability
maps to one Finding:

| DefectDojo field | Source |
| --- | --- |
| `title` | Primary vulnerability ID and target |
| `severity` | Normalized scanner severity; unknown becomes `Info` |
| `description` | Summary, details, report context, violations, Requester, timestamp, and report UUID |
| `vuln_id_from_tool` | Primary scanner vulnerability ID |
| `unique_id_from_tool` | UUIDv5 of repository, target cache identity, and primary vulnerability ID |
| `cve` | First normalized CVE from the primary ID or aliases |
| `references` | Scanner references plus missing CVE record links |
| `component_name` / `component_version` | Scanner component data, falling back to the target |
| `mitigation` / `fix_available` / `fix_version` | Scanner-reported fixed versions only |
| `tags` | Repository, artifact format, team, policy, and report UUID |

Using the existing UUID dependency's v5 support keeps deduplication identities
short and deterministic without adding a hashing crate. Repeated blocked
requests create distinct Tests while matching vulnerability Findings
deduplicate as the same remediation work.

An unsupported-target block imports one `Info` Policy Finding. Its unique ID
includes the report UUID because it represents that occurrence, not a
scanner-identified vulnerability.

The client accepts success only after the synchronous response identifies the
created Test. It returns the UI URL formed from that Test ID. A non-success
status, malformed response, or timeout fails report creation.

## Runtime behavior

Use one concrete proxy-side enum:

```text
ReportBackend
├── Local(ReportStore)
└── DefectDojo(DefectDojoClient)  [feature-gated]
```

No trait or factory is needed. Startup constructs exactly one backend. The
local `/trust/reports/{id}` route and writable-directory health check are
installed only for the local backend.

The existing central enforced-block path persists the report before audit,
decision response, and notification:

1. Verify the Requester when the request shape requires it.
2. Build the shared report envelope.
3. Persist once through the selected backend.
4. Record the audit event and decision with the returned authoritative URL.
5. Send the best-effort Yandex notification.
6. Return the denial containing the same URL.

DefectDojo gets one bounded attempt. Failure leaves the artifact denied,
returns `503`, records failure observability, and sends no Yandex notification.
It does not fall back to local storage because that would create a second
authority.

`/healthz` performs no DefectDojo request. Admin status and structured logs
show whether the integration is available and enabled, submission and failure
counts, and the latest success/failure time and failure category. The token
must never appear in configuration serialization, status, or logs.

## Review-sized implementation stages

Land each stage separately and keep its non-mechanical diff below 500 lines.
Split a stage again if its actual diff crosses that limit.

### 1. Preserve complete report facts

- Add component and fixed-version fields to the security vulnerability model.
- Parse OSV and Trivy remediation facts with focused parser tests.
- Introduce the shared report envelope and one timestamp/UUID at the block
  boundary.
- Decouple Nexus Requester verification from Yandex recipient lookup.
- Add Requester and mitigation to local HTML.

Primary crates: `nexus-sec-proxy-security`, `nexus-sec-proxy`.

### 2. Add the concrete DefectDojo client crate

- Add workspace crate `nexus-sec-proxy-defectdojo`.
- Enable reqwest multipart and UUIDv5 through existing workspace dependencies.
- Serialize Generic Findings, send the import, parse the Test ID, construct the
  Test URL, and expose delivery status.
- Add mock-HTTP contract tests for multipart fields, authorization, report
  mapping, success, rejection, malformed response, and timeout.

The crate gets a small public API for configuration, submission, and status;
it does not define a reporting abstraction.

### 3. Select the report backend

- Add feature and runtime configuration validation.
- Add the concrete `ReportBackend` enum to proxy state.
- Route the central block flow through the selected backend.
- Conditionally serve local reports and run local-storage health checks.
- Add proxy tests for success, failure, repeated blocks, unsupported targets,
  `report_only`, requester verification, Yandex links, and featureless startup.

New feature-specific tests belong in sibling test modules instead of growing
the existing large proxy test file.

### 4. Package and document it

- Compile DefectDojo into the standard Docker image while preserving build args
  for all four Yandex/DefectDojo feature combinations.
- Add compose and `.env.example` settings without enabling runtime integration.
- Document Open Source 3.x setup, Engagement ownership, deduplication, secrets,
  failure behavior, and migration from local reports.
- Extend CI to cover default features, no features, Yandex-only, and
  DefectDojo-only builds/tests. Do not start a full DefectDojo stack.

## Verification

For each implementation stage, run the affected package tests with
`just test -p ...`. The minimum final matrix is:

```sh
just test -p nexus-sec-proxy-security
just test -p nexus-sec-proxy-config
just test -p nexus-sec-proxy-defectdojo
just test -p nexus-sec-proxy
just test -p nexus-sec-proxy --no-default-features
just test -p nexus-sec-proxy --no-default-features --features yandex-messenger
just test -p nexus-sec-proxy --no-default-features --features defectdojo
```

Before each large Rust stage, run scoped `just fix -p ...`. Because security
and proxy are shared crates, ask before the final workspace-wide `just test`.
After tests, run the required `just fmt` and do not rerun tests solely because
of formatting.

The feature is complete when:

- the default image contains both integrations but still uses local reports by
  default;
- enabled DefectDojo blocks create one complete Test and link it everywhere;
- repeated blocks create separate Tests with stable vulnerability identities;
- report-only and accepted findings never reach DefectDojo;
- unsupported targets create one informational Policy Finding;
- factual mitigation and verified Requester data appear in both backends;
- DefectDojo failure returns `503` without fallback or notification;
- `/healthz` stays independent of DefectDojo availability;
- activation without the compiled feature fails startup;
- requester IP and unverified forwarding identity are absent.

## References

- [DefectDojo API v2](https://docs.defectdojo.com/automation/api/api-v2-docs/)
- [Generic Findings Import](https://docs.defectdojo.com/supported_tools/parsers/file/generic/)
- [Finding deduplication](https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/)
- [Open Source deduplication tuning](https://docs.defectdojo.com/triage_findings/finding_deduplication/os__deduplication_tuning/)
