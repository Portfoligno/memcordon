# macOS native launch contract

This document keeps its original path for existing links. The current private
guardian framing is revision 2; execution reports are schema 10 and plan reports
are schema 9. Revision 1 reports remain historical observations and must not be
upgraded by inventing authorization, custody, or clock evidence.

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

1. Snapshot the caller envelope, reserve native child ownership and spawn the
   guardian; receive `Hello`.
2. Send the guardian the immutable continuous-clock work deadline, grace and
   explicit installed-image capability. Its reserved spawn owner creates the
   launcher as the guardian's native child in a fresh process group, still gated.
3. Bind the root identity and restore the caller's signal dispositions and limits in the
   launcher before the guardian acknowledges readiness and group ownership.
4. Check guardian liveness and register a kernel process-event witness for the
   owned, unreaped launcher before sending `Release`.
5. Require both close-on-exec protocol closure and a `NOTE_EXEC` event from the
   registered `EVFILT_PROC` witness. EOF or launcher exit alone is insufficient.

A returned exec error carries its native errno in `Failure { errno }`.
Malformed, premature, duplicate, mismatched, or missing acknowledgments fail
startup. A ready helper, a bound group, and confirmed target exec are separate
observations. None proves that the workload completed successfully.

Before queueing native creation, the caller owns duplicates of each intended
non-close-on-exec descriptor, an open cwd directory, the calling thread's signal
mask, ignored signal dispositions, and resource limits. A separate private
capture owner performs cwd acquisition and descriptor enumeration under the
original continuous deadline; the calling thread supplies its own signal mask
and ignored-disposition snapshot, captured before supervisor handlers replace
the intercepted actions. The capture worker never rediscovers those dispositions
from the supervisor's handlers. Native exec resets caught handlers to defaults;
host handler pointers are not transferred to another executable.
A timed-out capture remains in that single reserved slot until it settles.
A separate private
datagram transfers the descriptors and cwd with `SCM_RIGHTS`. Its strict manifest
binds the run, version, descriptor count and distinct destination numbers;
missing, truncated, duplicate or mismatched entries fail before authorization.
Closed standard descriptors are represented by their absence. Received sources
are promoted above every destination and private launch endpoints are kept out
of that destination range. Only the launcher installs target-facing mappings.
The guardian and inspection helpers have private standard streams, and temporary
owned copies close when native creation settles. Source open-file descriptions
are never changed to nonblocking mode.

Darwin provides no supported atomic read-only umask query. The target preserves
the kernel-inherited umask captured when the guardian is created; MemCordon never
temporarily changes the embedding process's umask to inspect it. Concurrent host
umask changes before that native creation boundary therefore select the inherited
value. Owned descriptors and cwd remain stable across later host close/reuse or
cwd changes, while resource-limit restoration fails closed if the fresh child
cannot restore the captured limits.

## Signal ownership and startup interruption

The CLI establishes one owned execution context before bounded helper lookup and
retains it through all attempts. The context restores complete original signal
actions explicitly before returning a successful library result. Owned mode
requires exclusive management of intercepted process-wide dispositions and
cooperative quiescence between sessions; it cannot synchronize arbitrary host
libraries calling `sigaction`. Embedders that manage their own signals use an
owned caller snapshot and host-managed cancellation instead of installing a
second supervisor handler set. Host-managed contexts change no global signal
actions and retain the original caller-thread mask for target execution.
Each cancellation handle belongs to one run; cloned handles only route signals
to that run. Finishing or dropping a context does not make its handle reusable.
A fresh handle may already be cancelled before its first context is established.

Interruption is sticky for the entire run. Cancellation published before atomic
frontend admission prevents submission of a release request. This ordering is
defined at frontend publication, not the physical instant a key is pressed or a
signal is sent. A blocked or undispatched signal has not yet been published.
Admission commitment alone does not prove guardian release or target execution.

Before any release bytes can be exposed, cancellation can retain `not-issued`.
After possible exposure with no authoritative receipt, release remains `unknown`;
cleanup must not manufacture complete runtime retirement to serialize it.
Confirmed release retains `issued`, including whether exec was witnessed.
Interrupted startup may have no PID or a prepared launcher PID and does not
invent a child exit code. Only authoritative release counts as confirmed target
authorization. Every observed interruption vetoes restart, including when a
higher-priority deadline or memory event is the terminal outcome.

Signals delivered to the frontend interrupt supervision even when the target
inherits an ignored disposition for that signal. The ordinary sampled-watchdog
and undiscovered-descendant limitations remain unchanged. Execution schema 10,
runtime evidence V1 and private framing V2 retain their existing meanings.

## Private framing

Each private socket frame has a u16 big-endian length followed by at most 4096
JSON bytes. The strict frame contains `version` (2), a run correlation value,
and `message`; the closed vocabulary additionally carries configuration,
signal restoration, authorization and root-exit observations. The run value binds the
two private channels to this invocation; it is not a policy grant or signature.

Zero or oversized frames, unknown fields, wrong versions/correlation values,
partial frames and invalid transition messages are rejected. Nonblocking
transfers retain their absolute deadline through interrupted and fragmented
reads/writes. The private protocol is not a public executable-control API.

## Deadline origin and cleanup

The Darwin continuous clock begins before helper resolution and counts system
sleep. The guardian services an expired timer on its next scheduling opportunity
after resume. The parent startup
window is at most five seconds and is shortened by the configured attempt or
remaining supervision deadline. Setup, ready/bind/arm exchange and exec
confirmation consume that original budget. Monitoring does not restart the
clock after launch. Work expiry anchors the applicable limit grace, then a
separate three-second retirement reserve and one-second result-delivery reserve.
Late detection consumes those original reserves instead of renewing them.

The guardian's finite kqueue loop independently services deadlines and its private
parent lease. Normal and emergency inspection use separate owned native helpers;
neither can occupy the guardian's deadline loop. Lease loss triggers emergency cleanup of the bound process group and
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

Native creation uses a reserved owner, separately from ordinary sampling.
Guardian inspection has independent normal and emergency native processes with
bounded framed results. A busy or unavailable lane rejects submission; it does
not create replacement workers to bypass the reservation. Outstanding frontend
inspection also prevents claiming complete native retirement. This bounds
waiting and admission resources, while leaving uninterruptible native operations
explicitly unresolved. A late spawn retains child custody and cannot release
target execution after cancellation.

Final report/diagnostic output runs in a separate writer with a bounded payload
and delivery deadline. A prepared report may identify that writer, but cannot
certify its own persistence or the writer's later reap. The independent oracle
records observed helper birth identities and checks retirement outside MemCordon.

## Startup failure observations

`Error`, top-level `ExecutionErrorReport`, and `SupervisionErrorRecord` carry
optional `native_startup: NativeStartupDiagnosticV1`. Absence serializes exactly
as before. Its own `schema_version` is 1; execution reports now use schema 10.
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
