# Releasing MemCordon

The Rust release workflow prepares exact public crate and native archive bytes
from branch candidates or an existing unsigned annotated release tag. Only tagged
preparation can be published. Source, package, native-test and installed-consumer
checks gate preparation. Mandatory runner-local HTTP rehearsal follows assembly
and gates publication.
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

Assembly is followed by `Release rehearsal` for both candidates and tagged
preparation. Selection builds the separate unpublished
`memcordon-release-rehearsal` helper beside the driver; its single-executable
archive does not change the original publication-tool archive or product packages.
The job downloads exact input and publisher IDs, then runs the original publisher
process against disposable file-backed loopback HTTP fixtures. It compiles and
installs nothing. Candidates retain `candidate.json` and their selected notes
disposition; unavailable notes use an explicitly labeled fixture placeholder.
Candidate bytes never become a tagged envelope or a production publication input.

Rehearsal checks actual requests, committed bodies, exposed-byte readback,
interruption, fresh-process retry and observed child retirement. Its reports are
bounded diagnostics under `.release/rehearsal-results`, uploaded best-effort for
seven days; they are never consumed by the publisher or installed with MemCordon.
No certificate, staging controller, enrollment or new publication authority is
required. Rehearsal has no production credentials and addresses only owned
numeric-loopback fixtures. It does not establish live account access, OIDC, TLS or
provider availability; real publication still authenticates and reconciles its
actual destinations.

For an already assembled local input, run the built helper with the publisher
which belongs to that input:

```console
./target/ci/release/memcordon-release-rehearsal run --publisher target/ci/release/memcordon-ci --input .release/prepared-candidate --report-dir .release/rehearsal-results
```

Use the exact prepared or original recovery pair for tagged input. The input and
publisher remain immutable; reports and fixture state occupy separate directories.
The helper reserves minute 49 for ending case work and minute 50 for settlement,
inside each job's 60-minute envelope. These are planning bounds, not measured
performance. A failed or canceled rehearsal blocks its publisher even if optional
diagnostics cannot be retained.

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

Publication-only recovery also requires this invocation's fresh `Release recovery
rehearsal`. Both it and `recovery-publish` download the validated original
prepared/tool IDs from the original run. The current helper coordinates the test
but runs the original publication executable; it never substitutes a newly built
publisher. An old executable without the hidden rehearsal interface fails
compatibility explicitly. Reprepare at the same supported tag when necessary;
do not move historical tags or treat their older workflow as retroactively tested.
Matching destination bytes can be adopted without a local progress receipt;
uncertain/conflicting state stops without automatic deletion, overwrite or yanking.

The live writer has a single 20-minute operation allowance inside its existing
30-minute job. Each registry-visibility slot remains capped at 300 seconds and the
remaining shared allowance. Exhaustion may leave actual partial publication;
recover from the same original bytes instead of extending the deadline or claiming
rollback. Local fixture cleanup is separate from remote publication effects.

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

Keep `Release rehearsal` and `Release recovery rehearsal` names stable. Inventory
required-check settings administratively before relying on them: candidates use
the normal gate, while publication-only recovery uses the separate original-pair
gate. A skipped sibling is not executed rehearsal. If the new test infrastructure
fails, pause publication and fix it; removing its success dependency is a separate
maintainer policy decision, never an automatic fallback. No required-check setting
change or hosted rehearsal outcome is implied by the source change.

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
