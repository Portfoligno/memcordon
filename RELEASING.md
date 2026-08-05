# Releasing MemCordon

Repository architecture, validation suites, and backend certification are
described in [MAINTAINERS.md](MAINTAINERS.md). Record user-visible changes in
[CHANGELOG.md](CHANGELOG.md).

This guide describes the OIDC-only release process used after the initial
`0.1.3` publication. The immutable `0.1.3` tag retains the historical workflow
that published the first release; the post-release credential cleanup does not
rewrite that tag.

Prepare a release in a reviewed pull request: replace the workspace development
version with the exact SemVer release, update exact internal dependency
requirements and Cargo.lock, add a dated changelog section, and pass every
public CI check. An authorized release maintainer then creates an immutable
protected SemVer tag, such as `1.2.3`, on that exact commit. Release tags do not
use a `v` prefix.

Release eligibility is bound to the immutable exact tag and tagged commit, not
to branch ancestry or to workflow files on any branch. The release workflow
validates the remote tag identity, event/tag/version/workflow provenance at the
tagged commit, package graph/content, native assets, Miri, fuzzing, and certified
backends. It stages a GitHub draft, publishes at most one crate per credential
slot in dependency order, verifies public package content, uploads a
deterministic publication report, publishes the GitHub Release, and performs a
credential-free public verification.

Linux cgroup v2 and Windows Job Object certification runs on fresh standard
GitHub-hosted VMs selected by the exact labels `ubuntu-24.04` and
`windows-2025`. Those jobs retain only `contents: read`, do not receive release
credentials, and must pass per-run runtime qualification and every exact
hard-backend scenario with zero skips before assembly can start. In schema 2,
`ephemeral-certified` is evidence about that exact hosted job run: the report
also binds the provider, fixed label, tagged commit, runtime checks, and passed
test inventory. A rolling hosted image is never considered certified in
advance; an image or capability regression blocks the release.

For a release created with the OIDC-only workflow, rerun partial
publication by manually dispatching that workflow from the same existing
protected tag and supplying the exact tag. Public registry and release state are
authoritative. Identical public crates/assets are accepted; conflicting
same-version content fails permanently. Never move or reuse a published tag or
version. Yanking is an explicit incident-response decision. Release `0.1.3` is
already complete and its historical credential path is retired, so it is not an
OIDC-only reconciliation target.

Independently audit each crates.io trusted publisher before release with owner
`Portfoligno`, repository `memcordon`, and workflow `release.yml`. The publish job
must retain `id-token: write`; each of the three dependency-ordered publication
slots acquires its own short-lived capability from the pinned crates.io action.
The paired publication step passes that capability in memory through the typed
Cargo credential provider. The provider accepts only Cargo protocol version 1
`get` requests for a crates.io publish operation whose crate name, version, and
checksum match the selected preassembled artifact; its response is non-cacheable
and operation-dependent. The isolated Cargo configuration contains only the
provider executable and that artifact identity. The capability must never be
passed on an argument, written by `cargo login`, persisted, cached, uploaded, or
logged. Any missing OIDC capability, identity mismatch, or failed publication
blocks finalization.

Each publication step also defines its own exact, isolated `CARGO_HOME`; Rust
release tooling neither defines nor reinjects it or the registry capability.
The non-secret credential-provider configuration is supplied to Cargo as a
typed `--config PATH` argument. Publication homes and credentials are never
cached.

The retired first-release singular Cargo registry-token credential is revoked,
and no repository, organization, or GitHub Environment secret may replace
trusted publishing. Do not configure or pass the retired variable
operationally; the CI driver scrubs it from subprocess environments. The
immutable `0.1.3` tag retains its historical workflow bytes, while every later
release tag must use the closed `oidc-only` policy.

No workflow job uses a named GitHub Environment. Release execution therefore
has no environment approval, environment secret, or environment-bound OIDC
claim; tag controls, exact provenance checks, and serialized publication remain
the release authorization boundary.
