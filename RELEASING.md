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

Rerun a partially completed first release by manually dispatching the workflow
from the same existing protected tag, supplying that exact tag and deliberately
selecting `stored-token` or `oidc-fallback`. Public registry and release state are
authoritative. Identical public crates/assets are accepted; conflicting
same-version content fails permanently. OIDC fallback is prohibited until every
configured crate name exists, and a failed stored-token slot never switches
credentials automatically. Never move or reuse a published tag or version.
Yanking is an explicit incident-response decision.

For the first publication only, create the narrowest, shortest-lived crates.io
token that can create the three intended crate names and store it as the
repository Actions secret `CARGO_REGISTRY_TOKEN`. Do not store it at organization
scope or in a GitHub Environment. The protected first-tag run injects it only
into each selected publication step. It must never be passed on an argument,
written by `cargo login`, copied to another variable, cached, uploaded, or
printed.

After all three names exist, configure and independently audit each crates.io
trusted publisher with owner `Portfoligno`, repository `memcordon`, workflow
`release.yml`. Exercise the exact same first tag once in `oidc-fallback` mode and
require complete public reconciliation. Before another release tag is created,
freeze tag creation, revoke the API token, delete the repository Actions secret,
and merge the reviewed cleanup that changes
`ci/release.toml` to `oidc-only`, removes `first_release_version` and the dispatch
choice, deletes every stored-token slot, and makes the three OIDC slots
unconditional. Verify the repository has no crates.io token secret before
release tags resume. The immutable first tag retains historical workflow bytes,
but the credential is revoked and every later tag is OIDC-only.

No workflow job uses a named GitHub Environment. Release execution therefore
has no environment approval, environment secret, or environment-bound OIDC
claim; tag controls, exact provenance checks, and serialized publication remain
the release authorization boundary.
