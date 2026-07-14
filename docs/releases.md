# Releases

Releases are zero-touch after the repository settings below are configured.
Merge a pull request to `main`; do not create release tags or edit versions by
hand.

## Version policy

`[workspace.package].version` in `Cargo.toml` is authoritative. Release Please
updates it, deployment examples, `CHANGELOG.md`, and its version-state files in
a small automated pull request. The release workflow then refreshes
`Cargo.lock`; workspace crates inherit the root version through Cargo.

The `simple` Release Please strategy is intentional: its Rust updater cannot
handle Cargo's `version.workspace = true` inheritance ([upstream issue #2111](https://github.com/googleapis/release-please/issues/2111)).
The workflow verifies `.release-please-version`, the release manifest, and
Cargo metadata all contain the same version.

Pull request titles must follow Conventional Commits. Release-worthy changes
are classified as follows:

- `feat` increments the minor version.
- `fix`, `perf`, and `build` increment the patch version.
- A breaking change increments the minor version while the project is below
  `1.0.0`, then the major version.
- `docs`, `test`, `ci`, `chore`, and non-breaking `refactor` changes do not
  create a release.

The highest required increment wins. The first release is `v0.1.0` and includes
the existing product history. Product-impacting changes appear in the
changelog; hidden maintenance commits remain visible through comparison links.

## Publication order

The release workflow starts only after the exact `main` CI commit succeeds. It
then:

1. Creates or updates the Release Please PR.
2. Allows only version, lockfile, manifest, and changelog changes; verifies
   locked Cargo metadata and version agreement.
3. Builds the candidate and runs the ephemeral Nexus/proxy e2e check, including
   a vulnerable Maven block and reachable Trust report.
4. Squash-merges the release PR.
5. Builds exact `linux/amd64` and `linux/arm64` proxy and updater images with
   SPDX SBOMs and GitHub-signed provenance.
6. Reports all HIGH/CRITICAL findings and blocks fixable HIGH/CRITICAL findings.
7. Verifies both architectures and publishes `X.Y`, `X`, and `latest` aliases.
8. Creates the `vX.Y.Z` tag and GitHub release last.

The exact image tags are:

```text
ghcr.io/gridness/nexus-sec-proxy:X.Y.Z
ghcr.io/gridness/nexus-sec-proxy-scanner-db-updater:X.Y.Z
```

The workflow is serialized. A stale run exits before changing release state,
and a rerun resumes a merged `autorelease: pending` PR. Exact image publication
and alias creation are safe to repeat. No workflow performs a deployment.

## One-time GitHub settings

Configure these once in repository settings:

1. Under **Actions → General → Workflow permissions**, allow read and write
   permissions and enable **Allow GitHub Actions to create and approve pull
   requests**.
2. Allow squash merges, disable merge commits and rebase merges, and use the PR
   title as the default squash commit title. The conventional PR title then
   becomes the commit Release Please evaluates.
3. Keep `main` protected by required pull requests. If required status checks
   are added later, allow the release workflow to merge its narrowly validated
   Release Please PR because `GITHUB_TOKEN`-created PRs do not start another CI
   run.
4. After the GHCR packages first exist, make them public if production hosts
   should pull without `docker login`; otherwise grant those hosts package read
   access.

Dependabot opens weekly GitHub Actions and Cargo updates with conventional
titles. Those PRs deliberately follow the normal review and CI path and are not
auto-merged.
