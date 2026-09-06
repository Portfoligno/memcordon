# Releasing MemCordon

Use this runbook to publish the four MemCordon crates and their matching GitHub
Release through the temporary OIDC-first new-crate fallback. The release is
complete only when the public crates, assets, checksums, publication report,
and credential-free verification all agree.

The published crates, in publication order, are `memcordon-core`,
`memcordon-platform`, `memcordon-windows-launch-core`, and `memcordon`. Every
publication slot always attempts crates.io Trusted Publishing first; only the
exact crates.io new-crate rejection, rechecked against public registry
topology, can select the narrowly scoped fallback token for that one attempt.
The `memcordon` crate installs four default binaries: `memcordon`,
`memcordon-sealed-agent`, `memcordon-target-desktop-bootstrap`, and
`memcordon-session-broker`. Linux native archives contain the CLI and sealed
agent; Windows archives contain all four binaries. Each archive includes
`runtime-manifest.json`. macOS archives contain only the CLI and mark the sealed
runtime not applicable. Release schema 3, native asset report schema 2, and
publication report schema 2 bind that exact inventory.

Repository architecture, validation suites, and backend certification are
described in [MAINTAINERS.md](MAINTAINERS.md). Record user-visible changes in
[CHANGELOG.md](CHANGELOG.md).

## Prerequisites

- Use an authorized release-maintainer account and confirm the trusted
  publishers for `memcordon-core`, `memcordon-platform`, and `memcordon` name
  owner `Portfoligno`, repository `memcordon`, and workflow `release.yml`.
- The bounded fallback targets stable `0.5.2`. Immediately before tagging,
  determine which configured crate names are still absent from crates.io and
  create the narrowest shortest-lived token with only `publish-new` authority
  scoped to exactly those names. Store it only as repository Actions secret
  `MEMCORDON_CRATES_IO_NEW_CRATE_FALLBACK`. Do not use an organization secret,
  GitHub Environment, wildcard or all-crate authority, `publish-update`,
  yank, or owner-management authority.
- Start from a clean checkout of the intended release commit after every public
  CI check has passed.
- Confirm the fixed `ubuntu-24.04`, `windows-2025`, and Windows ARM64 native
  jobs are available. A skipped scenario or failed runtime qualification
  blocks release.
- Confirm the intended version has not been published and its tag does not
  exist. Never move or reuse a published tag or version.
- Never reuse or move `0.5.2-rc.11`. Its yanked core and platform versions are
  immutable registry state; this transition uses the new stable `0.5.2`
  version.

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
  --package memcordon-windows-launch-core \
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
exactly the four default-install binaries listed above, feature-gated test
fixtures, the complete binary-private agent source tree, and no public agent
library target. The publication order in `ci/release.toml` must match the
deterministic dependency order derived from Cargo metadata by repository policy
and release preflight.

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
requires exactly the four default binaries, and exercises the same version and
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
existing protected tag and supplying the exact tag. Public registry and
release state are authoritative. Identical public
crates/assets are accepted; conflicting same-version content fails permanently.
A yanked target version is rejected rather than unyanked automatically. Never
move or reuse a published tag or version. Yanking is an explicit
incident-response decision.

Dispatch and watch reconciliation with:

```console
gh workflow run release.yml --ref "$release_version" \
  --field tag="$release_version"
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

Every publication slot begins with a fresh OIDC attempt. If crates.io rejects
that attempt with the exact Trusted Publishing new-crate diagnostic, a
credential-free authorizer rechecks that the exact target version and the
crate name are both absent before the narrowly scoped token is mapped into the
standard Cargo variable for exactly one retry of the same artifact. A crate
whose name already exists never receives the fallback token; later slots reset
to OIDC.

## Publication security invariants

- The publish job must retain `id-token: write`. Existing crate identities use
  short-lived capabilities from the pinned crates.io action. The generic
  fallback policy keeps exactly four publication positions, each of which
  attempts OIDC first; no crate name or slot is mapped to a credential source.
- The typed Cargo credential provider accepts only Cargo protocol version 1
  `get` requests for crates.io read and publish operations whose provider argv,
  credential origin, publication slot, crate name, version, and checksum match
  the selected preassembled artifact. Publish requests must additionally carry
  the exact Cargo crate, version, and archive checksum fields. Every response
  is non-cacheable and operation-dependent. The fallback origin answers an
  index-read only after fresh same-run evidence of the exact OIDC rejection,
  absent crate name, absent exact version, and authorization matches that
  bound artifact; the read does not consume the one-shot attempt. Only the
  exact publish `get` records the actual token attempt.
- The isolated Cargo configuration contains only the provider executable and
  artifact identity. The capability must never be passed as an argument,
  written by `cargo login`, persisted, cached, uploaded, or logged. A missing
  capability, identity mismatch, or publication failure blocks finalization.
- Each publication step must define its own exact, isolated `CARGO_HOME`; Rust
  release tooling neither defines nor reinjects it or the registry capability.
  The non-secret provider configuration is supplied as a typed `--config PATH`
  argument. Publication homes and credentials are never cached.
- The only stored credential permitted during fallback `0.5.2` is the exact
  repository Actions secret named above, mapped only to the standard
  `CARGO_REGISTRIES_CRATES_IO_TOKEN` variable in the token-fallback step. The
  legacy `CARGO_REGISTRY_TOKEN` interface, organization secrets, GitHub
  Environments, credential-bearing caches/artifacts, command arguments, and
  logs remain forbidden.
- Publication attempts write credential-free slot evidence under
  `target/ci/publication-evidence/`; the aggregate file is uploaded as a
  diagnostic artifact and never enters the immutable publication report. It
  contains no capability value or credential-origin secret.
- No workflow job uses a named GitHub Environment. Tag controls, exact
  provenance checks, and serialized publication remain the authorization
  boundary; there is no environment approval or environment-bound OIDC claim.

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
dated release sections until the next release.

Before creating any later release tag, complete the fallback cleanup in order:
confirm all four crate names and exact `0.5.2` versions are publicly unyanked;
configure and audit the trusted publisher for every configured crate,
especially each name that was created through fallback; run one successful
same-tag dispatch after deleting the secret so every OIDC acquisition step
succeeds against already-public state; revoke the crates.io fallback token;
delete `MEMCORDON_CRATES_IO_NEW_CRATE_FALLBACK`; and merge reviewed policy that
returns to `oidc-only`, removes the fallback profile and token-fallback steps,
and restores four unconditional OIDC pairs. Only after that cleanup passes
repository policy may tag creation resume.
