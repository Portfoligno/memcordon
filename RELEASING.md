# Releasing MemCordon

The Rust release workflow selects an existing unsigned annotated tag and prepares
the exact public crate and native archive bytes for that commit. Source, package,
native-test and installed-consumer checks gate preparation and publication.
Installed workload permission is checked separately through live authentication
and native resource checks, with local administrator grants for contract-bound
launches.

The selected distribution keeps four public crates and six native targets.
Source-controlled distribution configuration selects actual packages, features,
and archive members. Ordinary build and test failures stop preparation. Passing
release checks does not grant installed workloads permission to launch.

Release maintenance starts from a clean reviewed commit with a canonical release
version, exact internal dependency versions, updated lockfiles, and user-visible
changes in CHANGELOG.md. A maintainer-approved unsigned annotated tag identifies
that commit. Tags and already published versions must not be moved or overwritten.

Preparation must package each public crate once, retain those exact bytes for
native consumer tests, and assemble the actual archives, manifest, notes, and
checksums. Installed tests must exercise the selected artifacts on their matching
native targets and distinguish unavailable hosts from passing tests.

Publication uses a narrow writer for prepared bytes after build and test processes
have finished. It reconciles each remote output as absent, matching, conflicting,
or unknown, preserving actual partial results. Unknown remote state is never
absence; conflicts never cause automatic overwrite, retagging, deletion, or yanking.
Credentials belong only to the service operations that need them and are excluded
from build subprocesses, caches, logs, and artifacts.

A completed release requires verified public crate bytes and GitHub assets for the
selected tag.

## Tag and workflow operations

Build the ordinary CI driver with the pinned toolchain in `ci/toolchains.toml`.
From the reviewed release commit, run these separate operations:

```console
target/ci/release/memcordon-ci release prepare-tag --version 0.5.0
target/ci/release/memcordon-ci release create-tag
target/ci/release/memcordon-ci release push-tag
```

Use the actual release version instead of the example. Preparation records the
full commit and exact tag reference without creating either a tag or a release.
Creation produces an unsigned annotated tag and verifies its local object.
Push transfers only that recorded tag without force. A failed or ambiguous push
must be reconciled against the same object and reference before another effect.

The workflow fans out from source selection to packages, source checks, both Miri
halves, both Fuzz halves and six native producers. Each installed consumer uses its
own target's archive and the exact packaged crates. Windows native and Cargo
channels run on separate fresh hosts; Linux and macOS channels complete teardown
before the next channel starts. Assembly waits for every required successful leaf.
The credentialed publisher consumes the prepared bytes and publication executable
without a checkout, Cargo build or compilation cache.

Prepared output includes `manifest.json`, checksums, release notes and
`compatibility.json`; each native archive includes `package.json` and its actual
runtime manifest. These describe measured members, selected features, protocol
versions and supported report formats. They are byte-integrity and compatibility
metadata, not permission objects.

## Partial publication and recovery

`release inspect` performs remote readback of prepared crate and GitHub asset
bytes. `release publish` publishes only absent outputs, verifies matching outputs,
and retains separate conflict or unknown outcomes. Publication is serial; bounded
anonymous reads share one deadline and throttle budget.

For a failed run, `release reconcile-tag` observes the recorded tag and reports the
actual workflow state. `--dispatch --mode reprepare` requests a fresh run at that
same tag. `--mode use-original` additionally requires the exact original run,
prepared-artifact and publication-tool artifact IDs. Recovery verifies their source,
names, bytes and producer association before using them. Expired or unverifiable
artifacts require repreparation.

The source-controlled `public_consumer` distribution option selects a final registry
consumer. It checks all four exposed crate archives, compiles a downstream program
against the published versions, installs the published CLI and executes success
and deadline cases with native status and complete-retirement checks.

## Required status migration

Branch protection should require the ordinary CI jobs and the selected stress/Mac
assessment jobs. Those assessments fail when a selected phase is missing, failed,
duplicated or reports another source or architecture. Keep branch-protection
requirements aligned with the current workflow job names. Repository status
administration is a maintainer operation; editing workflow files does not update
branch protection automatically.

Performance forms remain serial or combined by default. `ci/performance.toml` can
select bounded split forms only from the required comparative measurements.
Missing measurements keep the complete default execution. Unknown cache inputs
disable compiled reuse and allow an ordinary build; the first CI driver build may
be cold. Reports, installed state and prepared package bytes are not build caches.
