# nexus-sec-proxy

## Naming conventions & coding standards

In the crates directory where nexus-sec-proxy Rust code lives:

- All crates sit under crates subdirectory.
- Crate names start with `nexus-sec-proxy-`. For example, the `core` folder crate should be named `nexus-sec-proxy-core`.
- Keep all project dependencies in workspace's `Cargo.toml`. Reference workspace dependencies inside crates.
- When using format! and you can inline variables into {}, always do that.
- Always collapse if statements per https://rust-lang.github.io/rust-clippy/master/index.html#collapsible_if
Always inline format! args when possible per https://rust-lang.github.io/rust-clippy/master/index.html#uninlined_format_args
- Use method references over closures when possible per https://rust-lang.github.io/rust-clippy/master/index.html#redundant_closure_for_method_calls
- Avoid bool or ambiguous Option parameters that force callers to write hard-to-read code such as `foo(false)` or `bar(None)`. Prefer enums, named methods, newtypes, or other idiomatic Rust API shapes when they keep the callsite self-documenting.
- When possible, make match statements exhaustive and avoid wildcard arms.
- Newly added traits should include doc comments that explain their role and how implementations are expected to use them.
- Discourage both `#[async_trait]` and `#[allow(async_fn_in_trait)]` in Rust traits.
  - Prefer native RPITIT trait methods with explicit Send bounds on the returned future.
  - Preferred trait shape: `fn foo(&self, ...) -> impl std::future::Future<Output = T> + Send;Preferred trait shape: fn foo(&self, ...) -> impl std::future::Future<Output = T> + Send;`
  - Implementations may still use `async fn foo(&self, ...) -> T` when they satisfy that contract.
  - Do not use `#[allow(async_fn_in_trait)]` as a shortcut around spelling the future contract explicitly.
- When writing tests, prefer comparing the equality of entire objects over fields one by one.
- Do not add tests for values that are statically defined.
- Do not add negative tests for logic that was removed.
- Prefer private modules and explicitly exported public crate API.
- Avoid large modules:
  - Prefer adding new modules instead of growing existing ones.
  - Target Rust modules under 500 LoC, excluding tests.
  - If a file exceeds roughly 800 LoC, add new functionality in a new module instead of extending the existing file unless there is a strong documented reason not to.
  - When extracting code from a large module, move the related tests and module/type docs toward the new implementation so the invariants stay close to the code that owns them.
- When running Rust commands (e.g. just fix or just test) be patient with the command and never try to kill them using the PID. Rust lock can make the execution slow, this is expected.

Run `just fmt` (in the `crates` directory) automatically after you have finished making code changes anywhere in this repository; do not ask for approval to run it. Additionally, run the tests:

1. Do not run `cargo test` directly. Use `just test` so test execution follows the repo defaults.
2. Run the test for the specific project that was changed. For example, if changes were made in `crates/nexus-sec-proxy-cli`, run `just test -p nexus-sec-proxy-cli`.
3. Once those pass, if any changes were made in common, core, or protocol, run the complete test suite with `just test`. Avoid `--all-features` for routine local runs because it expands the build matrix and can significantly increase `target/` disk usage; use it only when you specifically need full feature coverage. project-specific or individual tests can be run without asking the user, but do ask the user before running the complete test suite.

Before initializing a large change to `crates`, run `just fix -p <project>` (in `crates` directory) to fix any linter issues in the code. Prefer scoping with `-p` to avoid slow workspace‑wide Clippy builds; only run just fix without `-p` if you changed shared crates. Do not re-run tests after running `fix` or `fmt`.

## Code review rules

### Crate API surface

Keep crate API surfaces as small as possible. Avoid proliferating test-only helpers.

### Breaking changes

Search for breaking changes in external integration surfaces:

- Wiki static website serving
- CLI parameters
- configuration loading

### Test authoring guidance

If unit tests are needed, put them in a dedicated test file (*_tests.rs). Avoid test-only functions in the main implementation.

Check whether there are existing helpers to make tests more streamlined and readable.

### Change size guidance (800 lines)

Unless the change is mechanical the total number of changed lines should not exceed 800 lines. For complex logic changes the size should be under 500 lines.

If the change is larger, explore whether it can be split into reviewable stages and identify the smallest coherent stage to land first. Base the staging suggestion on the actual diff, dependencies, and affected call sites.

## Commands

See and use [justfile](./justfile).

## Tests

### Test module organization

- When adding a new test module, define its contents in a separate sibling file rather than inline in the implementation file.
- Use an explicit `#[path = "..._tests.rs"]` attribute so the test filename is descriptive and easy to locate:
```rust
#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
```
- This applies only when introducing a new test module. Do not move or rewrite existing inline `#[cfg(test)] mod tests { ... }` modules solely to follow this convention.

### Benchmarks

cargo benchmarks can be run with `just bench`, use the divan crate to write new ones.

Use `just bench-smoke` to dry-run the benchmark for a single iteration to ensure it works.

### Test assertions

- Tests should use pretty_assertions::assert_eq for clearer diffs. Import this at the top of the test module if it isn't already.
- Prefer deep equals comparisons whenever possible. Perform assert_eq!() on entire objects, rather than individual fields.
- Avoid mutating process environment in tests; prefer passing environment-derived flags or dependencies from above.

## Platform support

Tests and features must support Linux, macOS and Windows unless feature is explicitly OS-specific.
