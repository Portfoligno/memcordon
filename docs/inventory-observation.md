# Inventory observations and experiments

The Windows native scanner retains full declared roots and validates opened file
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
bytes have explicit `file_counters_scope: windows_native_pipeline`. Generic
source/non-Windows scans retain operation/read counters and full manifests but
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
