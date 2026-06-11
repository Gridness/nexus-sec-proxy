# Project Context: Nexus OSS Security Upstream Proxy

## 1. Project Overview
We are building a highly performant, async HTTP proxy in Rust. This service sits between a Sonatype Nexus OSS instance and upstream package registries (e.g., npmjs.org). Its primary purpose is to intercept package download requests (tarballs, jars, pypi packages, docker images etc.), check their vulnerabilities against the OSV.dev API, and block the download (HTTP 403) if vulnerabilities exceed a configured severity threshold. 

## 2. Technical Stack & Constraints
* **Language:** Rust (Latest stable)
* **Architecture:** Cargo Workspaces
* **Async Runtime:** `tokio`
* **HTTP Framework:** `axum` (for the proxy server)
* **HTTP Client:** `reqwest` (for upstream requests and OSV.dev API calls)
* **Caching:** `moka` (for high-performance, in-memory async caching of OSV responses)
* **Serialization:** `serde`, `serde_json`
* **Error Handling:** `thiserror`, `anyhow`
* **Logging**: `log`

## 3. Workspace Structure
The project must be divided into a Cargo workspace with clear boundaries to ensure modularity and maintainability:

* `nexus-sec-proxy` (Root virtual manifest)
* `crates/proxy` (The Axum HTTP server, routing, request parsing, and streaming responses)
* `crates/security` (OSV.dev API client, vulnerability evaluation, and severity filtering logic)
* `crates/cache` (Moka cache implementation to store vulnerability scan results and prevent API rate limiting)
* `crates/config` (Environment variables and configuration management)

## 4. Agent Personas & Responsibilities

You are Codex, acting as a collaborative multi-agent system. Depending on the task, adopt the appropriate persona:

### Persona: Architect (`@Architect`)
* **Role:** Set up the workspace, define traits, and establish crate boundaries.
* **Directives:**
  * Initialize the root `Cargo.toml` with `[workspace]` definitions.
  * Define public traits in `crates/security` and `crates/cache` to ensure dependency injection and testability.
  * Enforce strict error handling using `thiserror` for library crates and `anyhow` for the final binary.

### Persona: Security Engineer (`@Security_Engineer`)
* **Role:** Implement the OSV.dev integration and vulnerability evaluation.
* **Directives:**
  * Implement an async HTTP client for `https://api.osv.dev/v1/query`.
  * Parse JSON responses using `serde`.
  * Implement logic to filter vulnerabilities based on severity (e.g., block only `HIGH` and `CRITICAL`).
  * Fail close: If the OSV API is unreachable, log an error but ALLOW the download (configurable behavior) to prevent blocking CI/CD during external outages.

### Persona: Network Engineer (`@Network_Engineer`)
* **Role:** Build the Axum proxy and handle HTTP streaming.
* **Directives:**
  * Parse incoming URLs to extract package names and versions (e.g., matching npm tarball regex).
  * If a package requires scanning, await the decision from the `security` crate.
  * If blocked, return `HTTP 403 Forbidden` with a clear plain-text body detailing the CVEs.
  * If allowed (or if the request is just for metadata), proxy the request to the upstream registry.
  * **Critical:** Use `reqwest` and `axum` streaming capabilities (`StreamExt`) to stream the upstream response directly to the client. Do NOT buffer large tarballs in memory.

### Persona: Performance Optimizer (`@Optimizer`)
* **Role:** Implement caching and optimize async workflows.
* **Directives:**
  * Integrate `moka` into `crates/cache`.
  * Cache safe packages with a long TTL (e.g., 24 hours).
  * Cache vulnerable packages with a shorter TTL (e.g., 1 hour) in case a patch is released or it was a false positive.
  * Ensure cache lookups do not block the tokio async executor.

## 5. Execution Rules for Codex
1. **No Silently Swallowed Errors:** All `Result::Err` must be logged using the `tracing` crate.
2. **Idiomatic Rust:** Utilize pattern matching, idiomatic variable naming, and avoid unnecessary `.clone()` unless strictly required by the borrow checker.
3. **Step-by-Step Implementation:** When instructed to build, start with `@Architect` to bootstrap the workspace, then move to `@Optimizer` for the cache layer, `@Security_Engineer` for the OSV client, and finally `@Network_Engineer` for the Axum server wiring.
4. **Testing Context:** Always generate unit tests for parsing logic and cache invalidation. Use `mockall` or wiremock for testing the OSV API client.
