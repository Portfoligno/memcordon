# macOS native launch V1

This contract describes the macOS standard watchdog launch path implemented in
`crates/memcordon-platform/src/macos_launch.rs` and
`crates/memcordon-platform/src/macos_watchdog.rs`.
Acknowledged startup and bounded cleanup ownership improve supervision; they
do not turn sampled process discovery into hard memory enforcement or sealed
containment. No new workload profile or administrator grant is introduced.

## Native invocation and startup order

The caller supplies the MemCordon helper executable explicitly. Helpers start
through native `posix_spawn` with separate native arguments, environment entries
and file actions. Target replacement uses Rust's native argv-preserving `exec`.
There is no shell command construction or post-fork Rust `pre_exec` callback.
The guardian has private standard streams; the launcher preserves the target
streams and closes its private protocol endpoint across successful exec.

The parent requires this order before reporting a successful launch:

1. Reserve native child ownership and spawn the guardian; receive `Ready`.
2. Spawn the launcher in a fresh process group, still gated; receive `Ready`.
3. Send the guardian `Bind { group }`; it observes the root identity and returns
   the matching `Armed { group }` acknowledgment.
4. Check guardian liveness and register a kernel process-event witness for the
   owned, unreaped launcher before sending `Release`.
5. Require both close-on-exec protocol closure and a `NOTE_EXEC` event from the
   registered `EVFILT_PROC` witness. EOF or launcher exit alone is insufficient.

A returned exec error carries its native errno in `Failure { errno }`.
Malformed, premature, duplicate, mismatched, or missing acknowledgments fail
startup. A ready helper, a bound group, and confirmed target exec are separate
observations. None proves that the workload completed successfully.

## Private framing

Each private socket frame has a u16 big-endian length followed by at most 256
JSON bytes. The strict frame contains `version` (1), a run correlation value,
and `message`; messages use the closed `kind` vocabulary `Ready`, `Bind`,
`Armed`, `Release`, `Disarm`, `Retired`, and `Failure`. The run value binds the
two private channels to this invocation; it is not a policy grant or signature.

Zero or oversized frames, unknown fields, wrong versions/correlation values,
partial frames and invalid transition messages are rejected. Nonblocking
transfers retain their absolute deadline through interrupted and fragmented
reads/writes. The private protocol is not a public executable-control API.

## Deadline origin and cleanup

The attempt's monotonic clock begins before helper setup. The parent startup
window is at most five seconds and is shortened by the configured attempt or
remaining supervision deadline. Setup, ready/bind/arm exchange and exec
confirmation consume that original budget. Monitoring does not restart the
clock after launch. A separate bounded cleanup budget remains subject to the
outer supervision deadline where applicable.

The guardian independently observes its private parent lease and samples known
members. Lease loss triggers emergency cleanup of the bound process group and
observed identities. Ordinary completion uses `Disarm`/`Retired` plus explicit
helper reaping. Lost acknowledgments or an expired cleanup budget retain an
incomplete or unknown result; they cannot be converted into successful cleanup.

The guardian ignores `SIGHUP` before announcing readiness. An orphaned stopped
process group receives the kernel's `SIGHUP`/`SIGCONT` pair when its parent dies;
the guardian must survive that pair to service its death lease. This disposition
is confined to the guardian and does not change the target's signal handling.

Process identity is checked before acting on sampled members. Holding the
unreaped owned root preserves its identity while guardian cleanup remains
outstanding. Descendants that escape before observation can still evade sampled
discovery. This mechanism does not claim comprehensive descendant custody,
isolation from credential/session changes, or a certified sealed boundary.

## Bounded runtime ownership

The runtime has 256 owned-child slots per process, reserved before native spawn.
These slots account helpers and unresolved reaping obligations, not 256
guaranteed concurrent workloads. A dropped unresolved child transfers its
existing slot to the permanent reaper without allocation or blocking. A slot
is not reusable until its owned wait obligation ends. Root reaping respects an
outstanding guardian dependency. Exhaustion rejects new native admission.

Potentially blocking inspection/spawn work uses one runtime-owned inspector
worker and one queued request per process. A busy or unavailable queue rejects
submission. The caller waits only through its absolute deadline; a stalled
native operation remains owned by that worker, and no replacement thread is
created to bypass the bound. This bounds waiting and admission resources; it
does not promise cancellation of an uninterruptible native operation. A late
spawn result retains its child ownership and reaping obligation.

## Startup failure observations

`Error`, top-level `ExecutionErrorReport`, and `SupervisionErrorRecord` carry
optional `native_startup: NativeStartupDiagnosticV1`. Absence serializes exactly
as before. Its own `schema_version` is 1; execution report schema 9 is unchanged.
Strict older consumers may reject the additional failure field. Compatibility
does not imply acceptance by an independently strict older decoder.

The diagnostic retains requested/canonical helper paths using `NativeArgument`,
optional device/inode/size identity and optional digest, observed cwd, typed
phase and operation, native errno, guardian/launcher PIDs, readiness, release
and exec-confirmation facts. Unavailable metadata stays optional. The current
native capture records filesystem identity when available and does not claim
an independently authenticated helper digest when none was measured.

Cleanup has explicit `complete`, `incomplete`, or `unknown` state and separately
retained typed cleanup errors. The enclosing original error code, message and
errno remain the primary cause. Validation rejects impossible readiness/exec
ordering, invalid native path representations, and contradictions with the
enclosing release/cleanup observations. Diagnostics are not restart authority.
These path-bearing failure records may contain private filesystem information;
they are distinct from the closed public Windows causal projection.

## Explicit doctor execution probe

Ordinary `memcordon doctor --json` remains schema 6 and does not execute a target.
`memcordon doctor --probe-execution --json` explicitly runs the macOS native
helper and internal probe target with a five-second deadline. It emits a
separate envelope:

```text
kind: doctor-execution-probe
schema_version: 1
doctor: ordinary schema-6 DoctorReport
execution: supported, helper_ready, target_exec_confirmed, target_exit,
           cleanup_complete, failure
```

The probe succeeds only when the requested doctor requirement is met, helper
readiness and target exec are confirmed, target exit is zero, and observed
cleanup is complete. Unsupported platforms or failed predicates return 125.
The probe does not establish hard enforcement, sealed qualification, permission
for an arbitrary workload, or compatibility of required TCP operations.

## Evidence and release boundary

Portable model tests check framing, diagnostic closure and report consistency.
Native launch tests exercise actual helpers, process events, failure paths,
cleanup ownership and deadline behavior. Each result applies to the source,
architecture and invocation actually tested; neither layer substitutes for the
other.

CI may build and install the candidate distribution into an isolated package
root and run native tests through that installed image. Such a result validates
the candidate package path. It is not an approved published provider release,
a consumer artifact pin, a new grant, or downstream workload qualification.
Release and consumer acceptance require their own provenance and native
evidence. The existing two-profile catalogue remains unchanged.
