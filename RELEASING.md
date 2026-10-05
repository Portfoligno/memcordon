# Releasing MemCordon

The Rust release workflow prepares exact public crate and native archive bytes
from branch candidates or an existing unsigned annotated release tag. Only tagged
preparation can be published. Source, package, native-test and installed-consumer
checks gate preparation and publication.
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

Every branch push runs the same release preparation jobs on the exact event
commit, including all six native producers, architecture-local installed
consumers and fresh-runner assembly. Manual candidate dispatch selects
`preparation-mode: candidate` with no tag or recovery IDs. Candidate output uses
`memcordon.prepared-candidate` under `.release/prepared-candidate`; it cannot be
published or used for publication-only recovery. Candidate notes record an exact
version section, `Unreleased`, or unavailable notes. The real tag run still
requires exact release notes and independently prepares its own payloads.

Required artifacts use immutable provider IDs and names containing the producing
run and attempt. Rerun consumers may reuse an earlier producer's returned ID;
they never resolve a name pattern or overwrite an uncertain upload. Tagged
assembly uploads its completed prepared bundle and the unchanged executable
archive it used together. Recovery accepts only a pair associated with the same
successful final assembly attempt. Candidate artifacts have seven-day retention;
tagged artifacts retain the repository's configured release retention. Expired
bytes require tagged repreparation.

Normal publication and publication-only recovery have separate tag-only writer
jobs. Original-artifact validation runs first in a read-only job. Writers receive
only the selected tool and prepared bytes, with no compilation or executable
cache restore. Old tags continue to use their own workflow and artifact format.

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
same tag. `--mode publication-only` additionally requires the exact original run,
prepared-artifact and publication-tool artifact IDs. Recovery verifies their source,
names, bytes and producer association before using them. Expired or unverifiable
artifacts require repreparation.

The source-controlled `public_consumer` distribution option selects a final registry
consumer. It checks all four exposed crate archives, compiles a downstream program
against the published versions, installs the published CLI and executes success
and deadline cases with native status and complete-retirement checks.

## Required status migration

On nondeleted branch pushes and tags matching Release's literal
`[0-9]+.[0-9]+.[0-9]+*` trigger, Release owns common source checks, optimized native
tests, Miri/fuzz smoke, standard backends and selected distributable preparation.
Ordinary CI retains all six debug-native cells; Deep CI retains complete stress
and assessment; Native backend tests retains both private Linux architectures and
the explicit Windows sealed payloads and native/Cargo installed channels. The
public distribution currently selects only the CLI with no runtime features, so
its installed consumers do not replace these optional runtime checks. Branch and
matching-tag preparation remain separate real executions.

PR and merge-group checks retain ordinary CI's full existing selection on their
actual merge source. Explicit CI, Deep and Native backend dispatches retain their
full standalone work; tags outside Release's trigger keep Deep and Native backend
common checks. Ref deletion schedules no work for the deleted ref. Do not disable
those workflows or combine their concurrency groups. A failing owner should be
rerun directly; an explicit standalone dispatch remains available for diagnostics.

Before suppression reaches a protected branch, confirm that Release is enabled
and its branch candidate path really executes, then inventory required checks and
dashboards through maintainer settings. Branch readiness must use actual Release
preparation completion plus retained debug, stress and optional checks required by
development policy. Keep ordinary CI checks required for PR/merge-group events;
do not require a Release-only check absent on fork PRs. A skipped job's successful
display is not executed coverage and cannot hide a failed or canceled owner.
Editing workflow files does not update branch protection automatically; no live
settings migration or successful representative event run is implied here.

The complete macOS suite validates current native and acceptance phase reports
locally before reporting completion. Standalone macOS assessment remains for
manual and uncovered-tag runs, including failed selected phases. Both validators
reject missing, failed, skipped or wrong-source/architecture results. Release
retains the actual phase diagnostics without treating them as publication grants.

At the serial macOS layout, the job conditions suppress 18 duplicate runner
executions on covered branch pushes and 12 on matching tags. These are structural
counts, not measured time or cost savings. Measure actual started jobs, queues,
phase timings and failed/unavailable coverage on representative events before
claiming an observed reduction. Rollback restores affected standalone conditions
and policy expectations while retaining local macOS assertions and cache role
separation.

Performance forms remain serial or combined by default. `ci/performance.toml` can
select a bounded stress split as an explicit scheduling choice. Both selected
phases retain their full coverage and budgets; optional comparative measurements
must be honest when supplied. Other performance forms retain their existing
measurement requirements. CI debug-native and Release optimized-native caches use
separate `native-debug` and `native-release` purposes, with actual native argument
recipes and selected product inputs in their identities. Unknown cache inputs
disable compiled reuse and allow an ordinary build; the first CI driver build may
be cold. Reports, installed state and prepared package bytes are not build caches.

Combined stress keeps its 120-minute envelope. Native release production admits
30, 25, 15 and 60-minute sequential child ceilings inside a 180-minute planning
envelope, with one original operation deadline. Product deadlines remain strict.
Preparation jobs retain bounded execution/deadline/installed diagnostics with
best-effort uploads. Missing final evidence remains incomplete; a retained report
does not change a failed or cancelled workflow outcome.
