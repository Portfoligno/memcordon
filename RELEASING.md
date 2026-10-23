# Releasing MemCordon

The Rust release workflow prepares exact public crate and native archive bytes
from branch candidates or an existing unsigned annotated release tag. Only tagged
preparation can be published. Source, package, native-test and installed-consumer
checks gate final preparation. Mandatory runner-local HTTP rehearsal starts from
early assembled payloads and must pass before final preparation and publication.
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

## Failure scheduling and compilation reuse

Selection checks formatting before compiling the main driver, then validates the
selected source, configuration and notes. Quality compilation/documentation, MSRV,
supply-chain checks, packages, shard tests, rehearsal-helper compilation and native
producers start from their own prerequisites. The same-run Linux driver archive
is reused only on compatible runners. Publication-only recovery keeps the original
prepared bytes and original publisher; current selection metadata is still passed
to public consumers.

`assemble-payload` assembles native/package inputs without waiting for independent
consumer checks. Rehearsal runs those actual bytes while consumers finish. Only
the final `assemble` job, after all required checks and rehearsal pass, copies the
unchanged input and publisher archive into the recoverable artifact pair. Early
assembled input is never a publication-only recovery artifact. Four macOS
installed jobs separately execute native and Cargo channels on both architectures;
Linux/Windows candidate and public readiness coverage remains required.

Native Cargo execution stops scheduling test executables after a failure by
default. Local `suite native --failure-mode collect-all` retains diagnostic
execution and still returns failure. Applicable suite and target commands expose
the same typed failure choice. Cache-producing matrices use `fail-fast: false`
so an unrelated failed shard does not cancel another runner's retention. This
does not change local stop-after-failure into collect-all. Deep CI
manual runs default to `collect-all`; CI and Release default to
`stop-after-failure`. Native and publication jobs retain their own
cleanup and original deadlines. Publication's shared concurrency group never
cancels an active publisher.

Independent compiler lanes use separate target directories and share a maximum
of four Cargo workers, falling back to serial work on one CPU. Rehearsal accepts
`--jobs 1` or `--jobs 2` (default two); each case owns its listener, store and
ordered fault/recovery sequence. Failure stops new admissions and active owners
settle before the final result. A bounded first-failure notice is reported before
peer settlement and cache copies; it does not claim that cleanup finished.
Stress packages and lifecycle use separate jobs; cold
lifecycle compilation precedes its existing 35-minute seeded execution allowance.

Cache V4 separates downloaded source data, Cargo index metadata, installed tools,
tool compilation and workspace compilation. Keys describe relevant content and
compiler/native compatibility; commit identity is diagnostic metadata, not a
dependency cache invalidator. Every restored compiled output is prepared before
use, including exact hits, and Cargo re-evaluates current inputs. Identity-bearing
local packages are rebuilt. Fresh consumer homes receive only current downloaded
source data, never old configuration, credentials, compiled output or success
reports. Settled consumer builds may export eligible third-party downloads back
to the shared store; selected public package images stay fresh. Native debug's
auxiliary `target/debug` and `target/release` profiles have a separate cache role,
with package cleanup that preserves driver and report siblings. Unknown
compatibility runs clean. Saves require a settled owner and
unchanged requested context; a cache hit never skips actual selected tests.

Local compilation and bounded structural/process tests do not qualify all six
native architectures, cold Windows/macOS hosts, real full-catalogue release
rehearsal or healthy/failing Actions timings. Those acceptance runs belong in CI;
no elapsed-time improvement is claimed before measurement. If concurrency fails
native acceptance, select one-worker rehearsal or serial compilation while
retaining coverage. Unavailable current cache compatibility takes the ordinary
clean build path. If early routing fails, restore late assembly ordering without bypassing
rehearsal or accepting incomplete recovery artifacts.

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

The workflow fans out from source selection to packages, source checks, four Miri
quarters, four Fuzz quarters and six native producers. Legacy local half and full
suites retain their original selection. Each installed consumer uses its
own target's archive and the exact packaged crates. Windows native and Cargo
channels run on separate fresh hosts; Linux and macOS channels complete teardown
before the next channel starts. Assembly waits for every required successful leaf.
The credentialed publisher consumes the prepared bytes and publication executable
without a checkout, Cargo build or compilation cache.

Selection retains source, package, version, policy and release-note checks without
restoring or fetching the complete Workspace download family. Each real consumer
still acquires its own required sources. Cache saves use the selected failure-mode
branch's actual settlement and acquisition outputs.

Action transfers remain serial until the pinned actions and full workflow parser
pass a controlled runner trial of background/wait/parallel support. The paused CI
loop supplies no such execution evidence. A future rollout must cap concurrent
cache transfers at two and target downloads at three, join before output use or
sanitation, and preserve exact artifact IDs and disjoint destinations. No hosted
timing or queue improvement is claimed by local workflow tests. Existing Backend
host-mutating operations retain their original owner and do not expose unsupported
collect-all dispatch behavior.

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

`ci/performance.toml` selects the existing bounded preparation, quality and stress
overlap, and the standalone macOS split as source-controlled scheduling choices.
Selected phases retain full coverage and budgets; optional comparative
measurements must be honest when supplied. CI debug-native and Release optimized-native caches use
separate `native-debug` and `native-release` purposes, with actual native argument
recipes and selected product inputs in their identities. Unknown cache inputs
disable compiled reuse and allow an ordinary build; the first CI driver build may
be cold. Reports, installed state and prepared package bytes are not build caches.

Combined stress keeps its existing work envelope. Native Release production
keeps the product's 30-minute cap, native compile caps of 25 minutes (other),
40 (macOS) or 60 (Windows), native execution's 15-minute cap and the backend's
60-minute cap, all clipped to one original operation deadline. Compiler work
overlaps only where the inherited allocation permits; a one-worker host runs
serially. Generated job ceilings include actual cache/action overhead separately.
Preparation jobs retain bounded execution/deadline/installed diagnostics with
best-effort uploads. Missing final evidence remains incomplete; a retained report
does not change a failed or cancelled workflow outcome.

The four workflow files are generated from
`tools/memcordon-ci/src/workflow_definitions/`. Edit those Rust definitions and
their finite command/action adapters, then run `memcordon-ci ci workflows --write`.
CI runs `ci workflows --check`; it never rewrites its checkout to hide drift.
Keep events, native matrices, permissions, artifact pairing, rehearsal and
tag/recovery publication prerequisites in the platform graph.

Compiler/Clippy, documentation, audit and deny are separate required leaves.
They start from the same actual source selection, without dependencies on one
another. The ordinary CI leaves keep their existing non-push event selection;
Release preparation leaves each need only `select`. The combined local quality
and supply-chain commands remain available and call the shared implementations.

| Workflow | Job keys | Actual check labels |
| --- | --- | --- |
| CI | `quality`, `quality-docs` | `quality / check and Clippy`, `quality / documentation` |
| CI | `supply-chain-audit`, `supply-chain-deny` | `Supply chain / audit`, `Supply chain / deny` |
| Release | `source-checks`, `source-docs` | `Source check and Clippy`, `Source documentation` |
| Release | `supply-chain-audit`, `supply-chain-deny` | `Supply chain / audit`, `Supply chain / deny` |

Map every actual required check consumer to both new leaves. The former quality
label alone no longer includes documentation, and the former combined security
label does not stand for audit and deny. Assembly requires all Release leaves;
failed, canceled or skipped required work cannot be replaced by a cached result.
Repository settings were not inspected or changed by this source migration.

Native Release compilation retains the existing product/native overlap, then
offers each eligible compiler partition before native execution, backend checks
and packaging. The later required phase validates selected source and actual
product bytes; restoring compiler data never proves that a test passed. A local
same-job boot-relative handoff and the original wall deadline jointly preserve
the original 140-minute work and 155-minute cleanup intervals across cache
actions. Missing or mismatched handoffs fail resume instead of granting new time.
The complete local build command remains a composition of the same phases.

Job ceilings are computed from reviewed finite step branches, including driver
bootstrap, acquisition, immutable transfers and five minutes of setup/teardown
slack. Shared operation time is counted once; sequential Actions time remains
additional. Generation rejects missing bounds, arithmetic overflow or a plan
beyond the runner limit. These ceilings are planning limits, not measurements.
Previously implicit production estimates are now explicit Actions run-step
guards: macOS deadline 75 minutes, standalone macOS phases 120, Linux private
195, working Windows preparation 150 and each working Windows installed channel
135. These are newly enforced outer
workflow limits, not preexisting Rust operation clocks. Individual child
timeouts, test scenarios and iterations remain unchanged; the guards do not
guarantee that every sequential child can consume its maximum allowance.
Linux private certification separates actual package/native payload production
from installed-channel and observer execution. Each architecture has its own
required producer and immutable artifact id. The producer retains the complete
original native operation on one host; its 190-minute Actions guard is a new
planning limit. Runtime retains its 195-minute guard and performs the unchanged
workspace fetch, installed cases and observer cases. Transferred native and
Cargo payloads must match the current working source and distribution; the
fresh driver additionally has a source, host and same-run byte manifest. Native
clock and completion records are excluded from this transfer.
The standalone macOS layout selects the existing native/acceptance split on
separate runners. Its combined local/Release callback stays sequential; no
fabricated speedup samples authorize either layout.

Finite `ci segment` operations retain eligible source and compiler work before
returning the original failure. Completed compilation transfers and partial
seeds have distinct namespaces and validated inboxes. Neither a restored image
nor a transfer manifest means that the current tests, native readiness or
rehearsal passed. Optional cache context/transfer time is bounded separately from
the original production deadlines; unavailable cache reuse takes the source path.

`ci/driver-bootstrap.toml` enables executable reuse on all six supported native
hosts, subject to current input/image compatibility and owned-byte checks.
Current-source cold builds and adoption remain available. No historical cache
test approval is required to use compatible outputs. A failed first cold build
has no Rust supervisor to retain a safe partial driver target. Publication and
rehearsal continue to use their selected immutable prepared artifacts; the
publication-tool producer actually compiles current source.

Portable ordering/allocation tests and a linked timer test establish only their
executed scope. Native Linux/macOS/Windows cancellation, reader retirement and
clock handoff acceptance and representative event execution require their actual
environments.
No hosted acceptance, cache persistence or performance improvement follows from
the generated graph or an action's successful conclusion alone.

Release also requires the six `readiness-tools-{host}` preparation phases for
`linux-x64`, `linux-arm64`, `macos-x64`, `macos-arm64`, `windows-x64` and
`windows-arm64`. These phases compile the existing readiness helper and its
current-source driver on the selected native host. Native and installed jobs
consume their exact same-run immutable artifact IDs; candidate and installed
jobs still require their native test producer to succeed. These artifacts
contain only selected program bytes and their checked identity, never native
operation clocks or prepared test results. The original native work clock
starts on the native runner and remains there through required retirement.
This preparation boundary does not change executable cache enablement.

`CI source formatting`, `Release source formatting` and `Release source policy`
are independent required source checks. Release final assembly depends on its
format and policy owners. Required-status configuration that relied on CI quality
also needs the new formatting check before relying on compiler-only quality.
Workflow edits do not update repository rulesets.

Selection uses the freshly compiled current-source driver for parity, selected
inputs and publication-tool preparation before optional adoption/export. Policy
and planners run before their own retention tails; source verification runs
before full source acquisition. Separate audit and deny leaves retain one live
session through their actual check and only then offer settled outputs.

Branch supersession uses separate workflow/event/ref lanes. Cancellation stops
new ordinary diagnostic/reporting work and lookup probes. Finite cleanup of
already-owned resources and eligible cache saves remain best effort within the
runner lifetime; a save never changes a failed or canceled workload result.

Release fuzz now requires the actual `fuzz-setup` producer (`Release fuzz setup`)
before each unchanged quarter compiles and executes. A setup failure makes the
selected shard fail its required admission step. The setup artifact binds the
selected checkout, toolchain, native host and exact workflow run and attempt;
it carries the current program and pinned fuzz tool, never a passed-test claim.

Standalone Linux private checks use `private-linux-prepare-x64` and
`private-linux-prepare-arm64`, followed by the corresponding required runtime
jobs `private-linux` and `private-linux-arm64`. Preparation runs the original
native compilation and validation on one host, then transfers byte-validated
native/Cargo payloads and the current program. Runtime verifies its own source,
distribution and exact immutable artifact before the installed and observer
cases. Native clock records stay in preparation. Maintainers must include the
new preparation statuses wherever the corresponding runtime checks are required;
these workflow edits do not modify protected-branch settings.
