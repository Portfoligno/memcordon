# CI architecture

GitHub Actions selects events, runners, permissions, caches, artifacts, and the
credential boundary. The non-publishable memcordon-ci Rust package performs all
sequencing with typed argument vectors and monotonic subprocess deadlines.

Local credential-free entry points include:

    cargo run --locked --package memcordon-ci -- suite policy
    cargo run --locked --package memcordon-ci -- suite quality
    cargo run --locked --package memcordon-ci -- suite native

The production packages support Rust 1.85 and the MSRV suite selects those
packages explicitly. The non-publishable `memcordon-ci` tool requires Rust 1.88
and is bootstrapped in CI with the pinned stable toolchain. Consequently,
workspace-wide Cargo commands such as `cargo test --workspace` are intentionally
unsupported on Rust 1.85; use the package-selected MSRV suite for that contract.

Public CI uses fixed Linux x64/arm64, macOS arm64/x64, and Windows x64 runners.
Deep CI and Backend Certification run on every unfiltered branch or tag push and
support inputless manual dispatch; neither workflow runs on a schedule.
Repository policy requires those exact trigger sets. Deep CI cancels an older
in-progress same-ref run, while Backend Certification preserves the in-progress
same-ref run so its evidence can complete.

Dependabot checks the root and independent fuzz Cargo workspaces separately each
week, with open pull request limits of five and three respectively. It also
checks GitHub Actions weekly with an open pull request limit of three. Repository
policy enforces that exact dependency-surface matrix.

Hard cgroup and Job Object certification uses the exact standard GitHub-hosted
labels `ubuntu-24.04` and `windows-2025`. Each certification job receives a
fresh VM, performs runtime qualification, runs every required scenario, and
fails rather than treating an unavailable hard backend as a passing skip. Linux
uses root only inside the typed CI driver to establish a systemd delegation and
runs qualification as the unprivileged runner user; the workflow itself remains
credential-free and read-only.

In certification schema 2, `runner_class: "ephemeral-certified"` means a fresh
standard GitHub-hosted job VM selected by an exact policy-validated label, with
`runner_provider`, `runner_label`, runtime evidence, and exact per-test results
validated for that run. It is not advance certification of a rolling runner
image. A cache miss affects speed only. Toolchains are installed rather than
cached; Cargo sources and the `target/ci/bootstrap` and `target/ci/backend`
compilation outputs use separate complete keys. Reports and credentials are
never cached, and every runtime qualification and scenario runs on every job.

Release phases derive source identity from Git and GitHub event metadata, never
from a custom project environment variable. The closed `oidc-only` credential
policy accepts exactly two step-local variable names in `release.yml`:
`GITHUB_TOKEN` for GitHub staging/finalization and a registry-specific provider
input for each crates.io publication slot. Each slot obtains a fresh short-lived
token from the pinned crates.io trusted-publishing action, passes it in memory to
the paired typed Cargo credential provider, and fails closed if acquisition or
publication fails. No job names a GitHub Environment, so execution requires no
environment approval or environment OIDC claim. Repository policy rejects any
named GitHub Environment.

The crates.io trusted-publisher identity is owner `Portfoligno`, repository
`memcordon`, and workflow `release.yml`. Repository policy enforces the exact
three unconditional OIDC pairs, rejects stored credentials and transition
inputs, and prevents publication credentials from being passed through action
inputs, command arguments, caches, artifacts, or reports.
