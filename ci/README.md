# CI architecture

GitHub Actions selects events, runners, permissions, caches, artifacts, and the
credential boundary. The non-publishable memcordon-ci Rust package performs all
sequencing with typed argument vectors and monotonic subprocess deadlines.

Local credential-free entry points include:

    cargo run --locked --package memcordon-ci -- suite policy
    cargo run --locked --package memcordon-ci -- suite quality
    cargo run --locked --package memcordon-ci -- suite native

Public CI uses fixed Linux x64/arm64, macOS arm64/x64, and Windows x64 runners.
Deep CI and Backend Certification run on every unfiltered branch or tag push and
support inputless manual dispatch; neither workflow runs on a schedule.
Repository policy requires those exact trigger sets. Deep CI cancels an older
in-progress same-ref run, while Backend Certification preserves the in-progress
same-ref run so its evidence can complete.

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

Release phases derive source identity and the typed credential path from Git and
GitHub event metadata, never from a custom project environment variable. The
first-release transition accepts exactly two step-local variables in
`release.yml`: `GITHUB_TOKEN` for GitHub staging/finalization and
`CARGO_REGISTRY_TOKEN` for each selected crates.io publication slot. A protected
tag push selects the temporary repository Actions secret; a same-tag manual
dispatch may deliberately select that path or OIDC fallback. The fallback is
rejected until every configured crate name exists. No job names a GitHub
Environment, so execution requires no environment approval or environment OIDC
claim. Repository policy rejects any named GitHub Environment.

After the first-tag OIDC reconciliation, the required cleanup changes the closed
credential policy to `oidc-only`, removes the stored secret and transition input,
and promotes the three OIDC pairs to the sole unconditional publication path.
The crates.io trusted-publisher identity is owner, repository, and workflow.
Repository policy enforces exact transition and steady-state shapes and prevents
the stored-token path from surviving into a later version.
