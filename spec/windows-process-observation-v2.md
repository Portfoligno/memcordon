# Windows process observation V2

Windows Job membership and cleanup authority are native Job facts. The process
observation field in a terminal receipt is a bounded sample, not a complete
ledger of every process that ever joined the Job. A workload must never be
rejected merely because its cumulative process count exceeds the sample.

The service-owned policy reserves at most 256 KiB for a Job PID snapshot and
24 KiB for retained sample entries. An observation tick makes at most two Job
snapshot queries and 64 identity queries, with ticks at least 100 ms apart.
The encoded observation field has a 128 KiB limit. Its policy, counters,
omission reasons, entries, root identity and optional native Job accounting are
separately typed. Sample entries are keyed by PID
and creation time; equal PID with a different creation time is a distinct
identity. Old entries may be evicted. The decoder refuses entry K+1 before
allocating it, where K is computed from the service policy and entry size.

Snapshot byte exhaustion, retry exhaustion, query-budget exhaustion, sample
eviction and optional sample-allocation failure are explicit omissions. They
do not turn successful native containment into a failure. Native query or
authentication errors that are not one of those expected omission conditions
remain real monitor failures and enter the proof-producing retirement path.
Counters saturate explicitly. Native Job accounting preserves the raw `u32`
total and active values; a lower later total records a regression instead of
being interpreted as an exact distinct-process count.

The root identity is separate from the evictable sample. Historical observations
may carry a separately typed qualification membership witness; the current
launcher freezes its observation without that witness. Sample entries do not
authorize child creation or release. Missing sample entries cannot weaken the
launcher's native suspended-target checks, Job-wide cleanup or restart-safety
requirements.

Terminal receipt V2 distinguishes observed `Execution` from
`RecoveredClosure`. Only `Execution` has observed child PID, outcome, duration,
authorization offset and native boundary detail. `RecoveredClosure` contains
the typed original failure or an explicit unavailable reason; it does not
invent a child exit, elapsed time, peak usage or live-native mechanism
attestation. Both kinds require a separately bound retirement proof. Frontend
delivery evidence is added only after exact terminal authority and retirement
confirmation have been validated; it is not part of the provider-issued
receipt.

Current installed consumers run `sampling-population` and
`guardian-loss-after-release` on each selected native Windows architecture and
native-bundle/Cargo-package channel. The population case independently holds
the root and 256 child identities and requires a deadline result with complete
retirement. The guardian-loss case requires the original monitor failure and
complete retirement. Execution, bounded output collection, workload cleanup and
package cleanup are checked separately. Release assembly waits for successful
selected native and installed jobs; their results do not authorize installed
workloads. See [installed-provider acceptance](windows-causal-diagnostics-acceptance.md)
for the current consumer boundary. Source-level boot simulation cannot establish
behavior across an actual host reboot.
