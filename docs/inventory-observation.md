# Inventory observations and experiments

The Windows and Linux native scanners retain full declared roots and validate opened file
identity, read contents, post-read metadata, and reopened path identity. Its
ordered pipeline documents failure precedence in [inventory-pipeline.md](inventory-pipeline.md).
A failure remains a failure; comparison tests must validate that contract and
the documented DFS precedence rather than assume timing-dependent legacy error
text is invariant. No timing improvement or RC11 speedup is established here.

## Observation contract

`inventory_progress` exposes a shared cancellation token, operation spans, task
transitions and dependency metadata. Task events carry task, parent, logical
ordinal, state and monotonic time; speculative preparation has no invented DFS
ordinal. Offered, started, ready, received and consumed are distinct. Queue and
ready residence, coordinator waits, directory enumeration/sort, open/precheck,
identity, read/hash, postcheck/reopen, root draining and joins are observable.

Before a potentially blocking operation, its actor publishes numeric operation,
task and start time with an atomic generation protocol. Readers either obtain a
coherent active tuple or explicitly mark it incoherent. Bulk actor-owned counters
publish at outer span/task boundaries and one-second checkpoints; each snapshot
includes publication time. Thus a blocked syscall can have fresh active state and
stale counters. A snapshot is a vector of actor publications, not a globally
simultaneous instant. In-flight durations are not silently added to completed
duration counters. Inclusive and exclusive nested-span arrays are separate;
sum exclusive spans for operation accounting, never inclusive nested spans.
Worker idle and task-other time are separate from named operation envelopes.
Cumulative operation time across threads is not elapsed wall time.

File attempted/completed/validated/committed counters and committed manifest
bytes have explicit `file_counters_scope: windows_linux_native_pipeline`. Generic
source and other platform scans retain operation/read counters and full manifests but
do not claim native identity-validation counters. Returned read bytes include
work that can subsequently fail validation and must not be used as committed
manifest bytes. `root_complete` describes one root, not complete context or
parent admission. Only successful parent supervision can admit the final context.

There are at most 32 registered actor slots, 64 live task ledger entries and a
256-event tail per observer; terminal tasks reconcile online and release their
entries. Actor/root path samples are truncated to 256 Unicode characters and are
diagnostic samples, not content identities. No unbounded path intern table or
finished-task log is retained. Manifest and directory traversal memory still
scale with input size. Observation overhead is not yet qualified: numeric stores,
clock reads, sampling and writer costs remain real work and require paired
instrumented/uninstrumented Windows comparisons before an overhead claim.

`--observation-dir` selects asynchronous JSON snapshots independently of stderr.
The writer queue holds at most eight records of at most 64 KiB, alternating two
files. Saturation, oversized records or write failures increase loss accounting;
final acknowledgement waits at most 100 ms. The human-output queue is separately
bounded at 16 messages. Writers may remain blocked in OS I/O until the enclosing
process terminates; inventory threads do not wait indefinitely on them. Alternating
files can contain a truncated latest write after a crash: consumers must parse
each separately and retain the newest valid sequence. Absence of a final record
means incomplete/unknown, never success.

The seed writes synchronized `run-start.json`, `phase-start.json` and
`phase-end.json`, each capped at 64 KiB, before/after supervised work. A run-start
record survives an interrupted bootstrap; phase sequence numbers disambiguate an
old phase-end record. At most 64 run directories are retained per report base;
exhaustion fails explicitly until evidence is archived. CI uploads only these
journals and the two inventory snapshots, with 14-day artifact retention. Product
candidate manifests and parent admission records are not diagnostic uploads.
Complete product manifests remain input-sized; diagnostic bounds do not claim
to cap compiler outputs or the operating system's caches.

Windows supervision also retains `phase-process-usage.json` for the owned child
process. It records charged user/kernel CPU time and logical I/O operations and
transfer bytes, with elapsed sample positions and query durations. The history
keeps a first sample and at most 16 recent samples at a one-second cadence;
individual API failures and unsupported platforms are explicit. Sampling stops
at the deadline or observed termination, and never renews the child budget.
The parent persists the authoritative phase outcome before the bounded history,
independently of the scanner's ability to write a final snapshot. Optional
diagnostic write failures use a separate `phase-process-usage-error.json` record
when it can be written; they never rewrite the authoritative outcome. A missing
record is missing evidence, not zero resource use or permission to publish a
cache.

These counters cover the child process, not its descendants. CPU time can help
separate charged execution from elapsed waiting; logical I/O is not physical
disk traffic and does not attribute waits to storage, cache misses, filesystem
filters or a particular security product. Samples are diagnostics only: they
neither change admission nor establish a throughput improvement. Windows kernel
profiling remains a separate qualification path when these counters cannot
distinguish the cause.

The Windows ARM64 loader CI entry opts into `ci-native-fingerprint --output PATH
--trace-inventory true`. The bootstrap parent records the same prepare child
with the existing `ci/inventory.wprp` recipe; it does not run a second inventory.
Its 48 MiB memory buffers retain a rolling window. Parent supervision still
enforces the 1,800-second child budget and records its authoritative outcome
before trace export. Trace setup, save, or cleanup failures are diagnostic
failures and cannot replace that outcome or authorize cache publication.

Recording uses a newly created, owned virtual disk with actual capacity at most
512 MiB for WPR output, temporary files, and command logs. It formats only a
volume verified to belong to that disk, temporarily assigns an unused drive
letter for the documented formatter operand, removes that owned assignment
after formatting, and detaches
the disk after recording. Each WPR command uses a 30-second containment budget.
Retained command logs are limited to 64 KiB each; truncation is recorded. Only a
complete bounded export is published as `inventory-trace.etl`; working disk
images and partial exports are excluded from artifact upload and caches.

`phase-trace.json` identifies the owned session, recipe and WPR binary digests,
command outcomes, export identity, and collection or cleanup failures. Unavailable
permissions, APIs, or formatting are explicit unavailable evidence. Inspect
collector status and the ETL for event loss before attributing a wait. A missing
or truncated status log cannot establish complete coverage. CPU/context-switch,
file/disk I/O and FilterManager events can distinguish some scheduling and I/O
causes; the presence of a filter alone does not prove that it caused the delay.
Recording itself changes workload overhead, so timings from this mode are
diagnostic observations rather than an uninstrumented performance benchmark.

## Finite comparisons

Invoke the compiled controller directly:

```text
memcordon-ci inventory-scan --request request.json --report-dir observation
memcordon-ci inventory-benchmark --plan plan.json --output comparison
memcordon-ci inventory-profile --plan profile-plan.json --output capture
```

`request.json` is a strict schema-1 object with nonempty `profile` and
`corpus_identity`, `roots` (1–128 absolute paths), and `audits` (0–16). Use the
same materialized immutable roots for current/baseline comparisons. The corpus
label is supplied provenance; it is not itself verification. Initial full
manifests and each audit have separate phase records. A failed/partial scan has
no valid comparison identity. The report must be outside measured roots.

`plan.json` has `schema: 1`, the `request`, `variants` (1–8 objects with `name`,
absolute `binary`, and lowercase SHA-256 `sha256`), finite `order` (1–64 variant
indices), `child_budget_seconds` (1–1800), and `instance_provenance`. The runner
checks binary digests before and after execution, executes precisely that order,
retains failed observations, and compares complete root identities. It does not
retry failed trials. Each child has bounded output capture (4 MiB); JSON requests
are capped at 1 MiB. Streamed manifest artifacts share a 64 MiB budget per scan;
exhaustion is a failed experiment, not truncated success. With at most 64 planned
observations, manifest storage is at most 4 GiB, separate from bounded logs,
snapshot slots and small phase/comparison records. There is no hidden unbounded
trial loop. Individual variants must implement the same scan CLI; an older
binary lacking it fails explicitly and needs a reviewed baseline adapter/build.

Plan AB and BA orders on equivalent fresh instances, or prespecify a finite
reversed-order schedule on one instance. Preserve image, volume, input and binary
identities, Defender/minifilter configuration, power state and machine provenance
externally. Initial and audit timing must remain separate. Same-machine repeated
scans, matching digests or a VM image do not prove equivalent page cache,
standby-list, minifilter, firmware or storage-controller cache state. The result
therefore explicitly reports `cache_equivalence: not_established`. Digest equality
can reject correctness regressions; completed phase distributions can select
pipeline variants. Neither establishes a timeout change by itself.

## Windows trace capture

`profile-plan.json` has `schema: 1`, `scanner` and `wpr` variant objects, the same
`request`, absolute `trace_directory`, and `child_budget_seconds` (1–1800).
The checked-in `ci/inventory.wprp` is digest-bound to the compiled controller.
Capture uses typed WPR arguments and an exclusively reserved instance name;
failed or ambiguous starts and failed stops attempt cancellation of only that
instance. Up to 64 instance reservations are retained for investigation. Each
WPR command has a 30-second limit and 64 KiB output capture. Collector/status
failure remains failure even when an ETL was saved.

The profile requests CPU sampling, context switches, process/image, disk/file
events and FilterManager events with 48 MiB configured memory buffers. This is a
rolling memory trace, not a claim of complete event history. WPR status and the
raw ETL must be examined for lost events and provider coverage. A dedicated
local volume of **actual capacity at most 512 MiB**, at least 96 MiB available,
and distinct volume identity from workspace and measured inputs is required for
ETL/temp export. Caller quota alone is insufficient. The directory must be
empty. Both export and WPR temporary files use that bounded volume; unsupported
volume APIs fail admission. Separate collector memory, subprocess capture,
snapshot IPC, benchmark manifests and export-volume limits are intentional.

ETL digest/size, WPR status, instance identity and scan outcome are retained.
Windows Performance Analyzer can distinguish CPU saturation, disk latency,
enumeration/open/check costs and overlapping work; FilterManager events require
runtime interpretation and do not by themselves prove Defender causality.
Successful capture does not set `runtime_qualified`: real Windows qualification
must exercise x64/ARM64 file replacement, drift and cancellation tests; WPR
profile/provider acceptance; mount aliases; full export volume; interrupted
start/stop and surviving-child cleanup; and digest-equivalent finite comparisons.
Cross-compilation checks Rust signatures, not Windows runtime behavior. Non-Windows
profiling explicitly reports that no WPR session was started.

The existing 1800-second per-child deadline is preserved. Progress is evidence,
not an exemption: returned bytes, validated/committed files and advancing DFS
work are meaningful progress; heartbeats alone show liveness. Deadline expiry,
nonzero exit, spawn/status failure and unknown termination remain distinct
failures. The five-second termination observation window does not admit late
success. Existing job ceilings remain the final resource envelope. Pipeline,
input-profile and deadline policy changes require their own correctness and
Windows qualification evidence; the staged-profile production gate stays closed.

The ARM64 loader CI job opts into `ci-native-fingerprint --trace-inventory true`.
Before fingerprint setup, it runs `ci-native-fingerprint --qualify-trace-volume`.
This separate, fail-closed qualification uses the production provisioning and
formatter capture code in a contained helper with the existing 30-second command
budget and five-second termination observation. It verifies NTFS plus a tiny
write/sync/read/remove operation and requires successful cleanup. It performs no
inventory or WPR recording and cannot publish a build context or cache admission.
Its parent completion is retained in `phase-volume-qualification-parent.json`;
worker phase records and formatter streams use the ordinary bounded upload.
This runtime check qualifies formatting on the actual Windows runner; it does
not establish WPR provider acceptance or complete tracing coverage.

The formatter receives a documented drive-letter-colon operand. Windows creates
that temporary mapping only when the letter is unused; no occupied assignment
is deleted or replaced. The mapped volume's disk and exact partition extent are
checked before formatting and before removing the assignment. A GUID path
accepted by native volume APIs is not assumed to be accepted by format.com.

This records the same prepare child, without a second scan or deadline extension.
A contained recorder sibling owns a fresh 512 MiB virtual disk, its verified
single-partition mount, and the WPR instance. Native disk operations execute only
inside that helper: the parent limits readiness to 30 seconds and export/cleanup
to 120 seconds, with the existing five-second termination observation allowance.
Readiness and finish markers contain the parent's random instance identity and
are published complete with no-clobber hard links. The original prepare result
and admission are recorded independently before trace export.

WPR uses 48 MiB rolling memory buffers; its export, temporary files and live logs
share the bounded virtual disk. Only a complete ETL (with size and SHA-256) and
at most 64 KiB per command log are retained outside it. Truncation and collector
status failures are explicit. Trace JSON, ETL and logs are uploaded as diagnostic
artifacts and excluded from managed cache inputs. Provisioning or recording
failure preserves the authoritative workload result.

On ambiguous start or export failure, the parent terminates the recorder job and
attempts bounded cancellation of only its previously generated WPR identity.
Observed helper termination closes the non-permanent disk attachment. A failed
native detach/cancel or unobserved termination is reported as unknown cleanup;
no successful cleanup or complete trace is inferred. A killed helper can leave
an excluded backing image or mount directory, bounded by the disk capacity, or
a temporary drive assignment whose cleanup was not observed.
Abrupt loss of the supervising runner can also prevent the final WPR cancellation;
runner teardown remains the outer cleanup authority. These are Windows runtime
qualification requirements, not guarantees established by cross-compilation.

Formatter startup failures retain the complete supervision outcome (including
exit code), native error kind/code and verified-volume stage context. Before the
volume is formatted, stdout and stderr use concurrent pipe readers: each keeps
at most 64 KiB and drains excess, with byte counts, truncation and read/retention
errors recorded in `phase-trace.json`. Prefixes are saved as
`inventory-wpr-format-stdout.log` and `inventory-wpr-format-stderr.log`. Reader
joins execute only inside the contained recorder, so the parent's unchanged
startup deadline also bounds stalled collection. Missing or truncated output
never implies successful formatting or recording.
