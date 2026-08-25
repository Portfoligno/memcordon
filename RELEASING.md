# Releasing MemCordon

Use this runbook to publish the three MemCordon crates and their matching GitHub
Release through the OIDC-only workflow. The release is complete only when the
public crates, assets, checksums, publication report, and credential-free
verification all agree.

The `memcordon` crate installs both `memcordon` and
`memcordon-sealed-agent`; there is no fourth crate or trusted-publisher slot.
Linux and Windows native archives contain those two binaries plus
`runtime-manifest.json`. macOS archives contain only the CLI and mark the
sealed runtime not applicable. Release schema 3, native asset report schema 2,
and publication report schema 2 bind that exact inventory.

Repository architecture, validation suites, and backend certification are
described in [MAINTAINERS.md](MAINTAINERS.md). Record user-visible changes in
[CHANGELOG.md](CHANGELOG.md).

## Prerequisites

- Use an authorized release-maintainer account and confirm each crates.io
  trusted publisher names owner `Portfoligno`, repository `memcordon`, and
  workflow `release.yml`.
- Start from a clean checkout of the intended release commit after every public
  CI check has passed.
- Confirm the fixed `ubuntu-24.04`, `windows-2025`, and Windows ARM64 native
  jobs are available. A skipped scenario or failed runtime qualification
  blocks release.
- Confirm the intended version has not been published and its tag does not
  exist. Never move or reuse a published tag or version.

## 1. Create the release commit

Prepare a reviewed pull request that replaces the workspace development version
with the exact SemVer release, updates exact internal dependency requirements,
updates `Cargo.lock` and `fuzz/Cargo.lock`, and moves user-visible changes into
one dated changelog section. Push the release commit without a tag and require
its CI, Deep CI, and Backend Certification workflows to pass. CI runs the
repository policy, quality, MSRV, and supply-chain suites on that exact commit.

From the release commit, create the public crate archives locally:

```console
cargo package --locked --no-verify \
  --package memcordon-core \
  --package memcordon-platform \
  --package memcordon
```

Inspect each archive under `target/package/` and require every public CI check
on the release commit to pass. These are pre-tag checks; tag-triggered release
certification has not run yet. This step is complete when CI and archive
inspection pass and the package graph, lockfiles, generated help, documentation,
README rendering, and archive contents agree. Correct the release commit and
repeat its CI and archive checks if they do not; do not defer a failure to the
tag-triggered workflow.

For the normalized `memcordon` archive, require `autobins = false`,
exactly the CLI and sealed agent as default-install binaries, feature-gated test
fixtures, the complete binary-private agent source tree, and no public agent
library target.

## 2. Verify immutable inputs

Record the exact release commit, confirm the checkout is clean, and inspect the
workflow bytes at that commit:

```console
release_commit=$(git rev-parse HEAD)
printf '%s\n' "$release_commit"
git status --short
git show "${release_commit}:.github/workflows/release.yml"
```

`git status --short` must produce no output. Keep the printed commit for tag
creation and incident reconciliation. Release eligibility is bound to the tag
and that exact commit, not branch ancestry or workflow files on another branch.

## 3. Create and push the tag

After all reversible checks pass, an authorized maintainer creates an annotated,
protected SemVer tag, such as `1.2.3`, on the recorded commit and pushes only
that tag. Release tags do not use a `v` prefix. Tag push is the first
irreversible publication action: stop before it if any input is incomplete.
Post-tag certification evidence cannot exist yet and is not a prerequisite for
creating the tag.

From the verified release commit, substitute the release version once and push
only that tag:

```console
release_version=1.2.3
test "$(git rev-parse HEAD)" = "$release_commit"
git tag --annotate "$release_version" \
  --message "Release $release_version" "$release_commit"
git push origin "refs/tags/$release_version"
```

## 4. Monitor publication

The workflow validates tag and workflow provenance, package contents, native
assets, Miri, fuzzing, and certified backends before it can publish. It then
stages a GitHub draft, publishes at most one crate per credential slot in
dependency order, verifies public package content, uploads the deterministic
publication report and native assets, publishes the GitHub Release, and runs
credential-free public verification. Do not finalize the release manually.

Native verification checks exact archive members, runtime-manifest identity,
component order/modes/digests, CLI and agent versions, agent package inspection,
and Linux or Windows sealed-provider installation from the bundled agent. Public Cargo
verification installs the released `memcordon` crate into a fresh root,
requires exactly both runtime binaries, and exercises the same version and
inspection checks.

Linux cgroup v2 and Windows Job Object certification runs on fresh
GitHub-hosted VMs with the exact labels `ubuntu-24.04`, `windows-2025`, and the
workflow's Windows ARM64 runner. Windows backend, package, channel-parity, and
post-public Cargo/native smoke gates are required on their matching architecture.
Those jobs retain only `contents: read`, receive no release credentials, and
must pass runtime qualification and every hard-backend scenario with zero skips
before assembly. In schema 2, `ephemeral-certified` binds evidence to that
hosted run's provider, fixed label, tagged commit, runtime checks, and passed
test inventory; an image or capability regression blocks the release.

Find and watch the run for the exact tag:

```console
gh run list --workflow release.yml --branch "$release_version" --event push
gh run watch RUN_ID --exit-status
```

Stop on any failed, cancelled, timed-out, or skipped required job. Preserve the
tag and public state, inspect that run's logs and artifacts, and use the
reconciliation procedure after correcting only recoverable external state.
Never replace the tag or publish a crate or asset manually.

## 5. Reconcile a partial release

Rerun partial publication by manually dispatching the workflow from the same
existing protected tag and supplying the exact tag. Public registry and release
state are authoritative. Identical public crates/assets are accepted;
conflicting same-version content fails permanently. Never move or reuse a
published tag or version. Yanking is an explicit incident-response decision.

Dispatch and watch reconciliation with:

```console
gh workflow run release.yml --ref "$release_version" --field tag="$release_version"
gh run list --workflow release.yml --branch "$release_version" --event workflow_dispatch
gh run watch RUN_ID --exit-status
```

Before dispatch, restore `release_version` and `release_commit` from the release
record if this is a new shell, then verify the remote tag still names that
commit:

```console
git fetch origin "refs/tags/$release_version"
test "$(git rev-parse 'FETCH_HEAD^{commit}')" = "$release_commit"
```

Stop permanently for conflicting same-version registry content, a moved or
mismatched tag, mismatched workflow provenance, or a non-identical GitHub
asset. For transient service failures or an interrupted run, preserve the tag
and rerun the same dispatch; the workflow reconciles identical public state and
continues from the first missing publication step.

## Publication security invariants

- The publish job must retain `id-token: write`. Each of the three
  dependency-ordered publication slots acquires its own short-lived capability
  from the pinned crates.io action.
- The paired publication step passes that capability in memory through the
  typed Cargo credential provider. The provider accepts only Cargo protocol
  version 1 `get` requests for a crates.io publish operation whose crate name,
  version, and checksum match the selected preassembled artifact. Its response
  is non-cacheable and operation-dependent.
- The isolated Cargo configuration contains only the provider executable and
  artifact identity. The capability must never be passed as an argument,
  written by `cargo login`, persisted, cached, uploaded, or logged. A missing
  capability, identity mismatch, or publication failure blocks finalization.
- Each publication step must define its own exact, isolated `CARGO_HOME`; Rust
  release tooling neither defines nor reinjects it or the registry capability.
  The non-secret provider configuration is supplied as a typed `--config PATH`
  argument. Publication homes and credentials are never cached.
- No repository, organization, or GitHub Environment secret may replace
  trusted publishing. Release tags must use the closed `oidc-only` policy.
- No workflow job uses a named GitHub Environment. Tag controls, exact
  provenance checks, and serialized publication remain the authorization
  boundary; there is no environment approval, secret, or environment-bound
  OIDC claim.

## Completion

A release is complete only when every crate is publicly visible with verified
content, every native asset and checksum is attached to the published GitHub
Release, the deterministic publication report succeeds, and the final
credential-free verification passes. The public registry and GitHub release are
the observable state; a draft alone is not completion. The exact tag-triggered
or reconciliation run must also finish successfully, including every runtime
qualification and required certification scenario with zero skips.

## Post-release maintenance

Start the next development version with the `-dev` suffix, update exact internal
requirements and both lockfiles, and leave future user-visible changes outside
dated release sections until the next release. No credential cleanup is needed:
OIDC capabilities are short-lived, isolated per slot, and never persisted.
