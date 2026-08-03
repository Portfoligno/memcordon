# Releasing MemCordon

Prepare a release in a reviewed pull request: replace the workspace development
version with the exact SemVer release, update exact internal dependency
requirements and Cargo.lock, add a dated changelog section, and pass every
public CI check. An authorized release maintainer then creates an immutable
protected SemVer tag, such as `0.1.0`, on that exact commit. Release tags do not
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

Rerun a partially completed release by manually dispatching the workflow from
the same existing protected tag and supplying that exact tag. Public registry
and release state are authoritative. Identical public crates/assets are
accepted; conflicting same-version content fails permanently. Never move or
reuse a published tag or version. Yanking is an explicit incident-response
decision.

Independently audit each crates.io trusted publisher before release with owner
`Portfoligno`, repository `memcordon`, and workflow `release.yml`. The publish job
must retain `id-token: write`; each of the three dependency-ordered publication
slots acquires its own short-lived capability from the pinned crates.io action.
The paired publication step passes that capability in memory through the typed
Cargo credential provider; the isolated Cargo configuration contains only the
provider executable and the selected artifact identity. The capability must
never be passed on an argument, written by `cargo login`, persisted, cached,
uploaded, or logged. Any missing OIDC capability or failed publication blocks
finalization.

The retired first-release credential is revoked and no repository,
organization, or GitHub Environment secret may replace trusted publishing. The
immutable first tag retains its historical workflow bytes, while every current
and future tag uses the closed `oidc-only` policy.

No workflow job uses a named GitHub Environment. Release execution therefore
has no environment approval, environment secret, or environment-bound OIDC
claim; tag controls, exact provenance checks, and serialized publication remain
the release authorization boundary.
