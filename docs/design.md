# MemCordon (`memcordon`): Design Specification for a Cross-Platform Workload Memory Limiter

**Status:** Proposed design  
**Date:** 2026-07-29  
**Project name:** MemCordon  
**Cargo package:** `memcordon`  
**Binary name:** `memcordon` during parallel adoption; an optional `memlimit` compatibility alias may be shipped later  
**Primary implementation language:** Rust  
**Audience:** implementers, reviewers, maintainers, packagers, and users who need a reliable local safeguard around memory-hungry commands

> **Name rationale:** A cordon establishes a clear boundary around a workload without implying that every backend is a complete security sandbox. Registry and trademark availability must still be verified before publication.

---

## 1. Executive summary

`memcordon` is a replacement design for a process memory wrapper that treats the launched command and all of its descendants as one **workload**. It addresses lifecycle, status propagation, containment, accounting, performance, and observability shortcomings identified in the existing `memlimit` implementation.

The key design decision is to stop pretending that one portable polling algorithm can provide the same guarantee on every operating system. `memcordon` therefore exposes two enforcement classes:

1. **Kernel-backed enforcement** on platforms with an appropriate workload primitive:
   - Linux: cgroup v2.
   - Windows: Job Objects.
2. **Best-effort watchdog enforcement** where no comparable public aggregate primitive is available:
   - macOS: process group plus descendant discovery and sampled physical-footprint accounting.
   - Other Unix systems: a clearly labeled, platform-specific sampled fallback where implemented.

The package always reports the selected backend, enforcement class, and metric. A caller can require kernel-backed enforcement and fail closed rather than silently accepting a weaker fallback.

The direct child is always tracked through an owned child handle or native process handle. Its liveness is never inferred from whether a PID appears in a process table. Every post-spawn path attempts to terminate as required, reap the direct child exactly once, clean up the workload container, and return a documented outcome.

The default scope is the entire workload. There is no ordinary `--children` switch because descendants are not an optional afterthought: they are the unit being limited.

---

## 2. Source basis and motivating defect

This design is based on:

- The current `shadyfennec/memlimit` repository and its documented behavior.
- A static review of its process lifecycle, memory accounting, termination, arithmetic, diagnostics, and tests.
- A user-provided defect report for `memlimit 0.1.0` on macOS arm64.
- Official operating-system and Rust documentation listed in [References](#30-references).

The supplied defect report establishes this concrete failure in `--children` mode on macOS arm64:

```console
memlimit --children 8589934592 /usr/bin/true
```

The wrapped command exits immediately, but the wrapper remains running, the child appears as `<defunct>`, and no wrapper exit status is returned until interruption. The report also reproduces the same symptom with a real Hell check. Its requested acceptance behavior is incorporated verbatim in spirit: a short-lived successful or failing child must be reaped, leave no zombie, cause the wrapper to exit within a bounded interval, and produce the documented status.

The source-level design rule derived from that report is stronger:

> **Process-table presence must never be the authority for direct-child liveness.**

On Unix, an exited but unreaped child can remain visible as a zombie. The wrapper must call `try_wait`, `waitpid(..., WNOHANG)`, or an equivalent native operation during the monitoring loop and must perform a final blocking reap during cleanup.

---

## 3. Problem statement

A memory-limiting command wrapper must solve several independent problems correctly:

1. Launch the target without leaving an uncontained startup window.
2. Define which processes belong to the workload.
3. Define what “memory” means on the current platform.
4. Enforce or observe the configured limit.
5. Detect direct-child exit without creating zombies.
6. Terminate every contained process when policy requires it.
7. Preserve or deliberately map exit outcomes.
8. Survive races among child exit, descendant creation, limit events, user interruption, and monitor failure.
9. Avoid becoming a substantial source of CPU or memory overhead itself.
10. Tell the user exactly which guarantees were and were not provided.

The original one-loop process-table polling model conflates these concerns. `memcordon` separates them into a platform-neutral state machine and platform-specific containment backends.

---

## 4. Goals

### 4.1 Functional goals

`memcordon` shall:

- Reap the direct child promptly on every supported platform.
- Return promptly when a short-lived child exits.
- Preserve a normal direct-child exit code.
- Return a dedicated nonzero status when the workload hits its memory limit.
- Treat the launched command and descendants as one workload by default.
- Terminate the complete contained workload after a limit event.
- Prevent the user command from running before required containment setup is complete.
- Use the strongest practical platform mechanism available.
- Offer a mode that requires kernel-backed enforcement and fails closed if it cannot be established.
- Use explicit, platform-accurate metric names.
- Put wrapper diagnostics on stderr only.
- Produce an optional versioned machine-readable report.
- Bound watchdog polling and avoid full-speed busy loops.
- Use checked or saturating arithmetic and `u64` byte counts end to end.
- Handle spawn, monitor, wait, and termination failures without panicking.
- Clean up remaining descendants when the direct command ends, unless the user explicitly selects workload-lifetime semantics.

### 4.2 Reliability goals

The implementation shall maintain these invariants:

1. After a target has been spawned, ownership of its direct-child handle is retained until reaped.
2. No normal control path drops an unreaped direct child.
3. Cleanup operations are idempotent and safe to retry.
4. Once a limit event is conclusively observed, a later child exit cannot convert the outcome to success.
5. A monitoring failure after launch fails closed by default: terminate the workload, reap the direct child, and return a wrapper error.
6. The child’s stdout and stderr remain its own unless the caller explicitly requests capture.
7. The wrapper never emits ordinary diagnostics to stdout.

### 4.3 Product-truthfulness goals

The package shall not:

- Describe sampled monitoring as a hard limit.
- Describe RSS, physical footprint, cgroup memory, and Windows commit as if they were interchangeable.
- Claim that process groups are an inescapable security boundary.
- silently downgrade `--enforcement hard` to watchdog mode.
- claim that a configured byte value can never be exceeded by even one byte.

---

## 5. Non-goals

Version 1 is not intended to be:

- A general-purpose security sandbox.
- A replacement for containers, virtual machines, seccomp, Landlock, Windows App Containers, or macOS sandboxing.
- A portable definition of one universally comparable “actual memory” metric.
- A tool for attaching a limit to an arbitrary already-running process tree.
- A distributed or multi-host resource manager.
- A CPU, I/O, network, GPU, or filesystem limiter, although the architecture should allow additional resource policies later.
- A guarantee against a malicious same-user workload that can attack the wrapper, its control socket, its cgroup delegation, or host service manager.

The primary threat is accidental or buggy resource exhaustion by a locally launched workload. Kernel-backed backends also provide meaningful containment against ordinary descendant creation, but that does not turn the package into a complete hostile-code boundary.

---

## 6. Terminology

| Term | Meaning |
|---|---|
| **Direct child** | The command process launched by `memcordon`, after the internal launcher has `exec`-replaced itself where applicable. |
| **Workload** | The direct child plus every process contained by the selected backend. |
| **Backend** | Platform-specific implementation of spawning, containment, accounting, event observation, termination, and cleanup. |
| **Kernel-backed** | The operating system itself applies a workload-wide resource restriction, even if the wrapper is delayed. |
| **Watchdog** | The wrapper samples usage and reacts after observing a threshold crossing. |
| **Metric** | The platform quantity being limited or sampled, such as cgroup memory, job commit, physical footprint, or RSS. |
| **Limit event** | Conclusive backend evidence that the workload reached or attempted to cross the configured limit. |
| **Container** | In this document, a generic workload-containment object such as a cgroup or Job Object; it does not necessarily mean an OCI container. |
| **Reap** | Collect the terminated direct child’s exit status so it does not remain a zombie. |
| **Fail closed** | On wrapper uncertainty after launch, terminate the workload rather than allow it to continue unmonitored. |

---

## 7. User-facing command model

### 7.1 Primary command

```text
memcordon run [OPTIONS] -- COMMAND [ARG...]
```

The `--` separator is recommended and required when command arguments could be mistaken for wrapper flags.

### 7.2 Core options

```text
--memory <SIZE>                 Required workload memory limit
--enforcement <auto|hard|watchdog>
                                Default: auto
--lifetime <command|workload>   Default: command
--metric <native|physical-footprint|rss|virtual>
                                Default: native; availability is backend-specific
--poll-interval <DURATION>      Watchdog sampling interval; default: 50ms
--signal-grace <DURATION>       Grace after forwarded user termination; default: 2s
--limit-grace <DURATION>        Grace after a memory event; default: 0s
--swap <SIZE|unlimited|host>    Linux cgroup swap policy; default described below
--report <none|text|json>
--report-file <PATH>            Required for durable JSON in automation
--quiet                         Suppress nonessential informational output
--no-backend-warning            Suppress the one-line watchdog downgrade warning
```

### 7.3 Inspection and maintenance commands

```text
memcordon probe [--json]
memcordon explain [--enforcement MODE] [--memory SIZE]
memcordon cleanup [--dry-run]
memcordon version --verbose
```

- `probe` reports available backends, permissions, metrics, and reasons a backend is unavailable.
- `explain` resolves the effective policy without launching a workload.
- `cleanup` removes stale package-owned Linux cgroups after validating ownership and emptiness. It must not kill arbitrary cgroups by name alone.
- `version --verbose` includes build target, enabled backend features, report-schema version, and dependency/license metadata.

### 7.4 Examples

Run with the strongest available backend:

```console
memcordon run --memory 8GiB -- hell --check automation/hell-automation-checks.hell
```

Require kernel-backed enforcement:

```console
memcordon run --enforcement hard --memory 8GiB -- cargo test --workspace
```

Use an explicit macOS watchdog policy:

```console
memcordon run \
  --enforcement watchdog \
  --metric physical-footprint \
  --memory 8GiB \
  --poll-interval 50ms \
  -- ./local-check
```

Write a machine-readable result without mixing it into child output:

```console
memcordon run \
  --memory 8GiB \
  --report json \
  --report-file ./memcordon-result.json \
  -- ./build.sh
```

Inspect guarantees before running:

```console
memcordon probe
```

Example macOS output:

```text
selected backend: macos-watchdog
class: watchdog
metric: physical-footprint-sum
whole-workload hard limit: unavailable
startup containment: process group established before target exec
child reaping: native waitpid/kqueue
known limitation: a descendant that creates a new session before discovery may escape
```

---

## 8. Defaults and policy decisions

### 8.1 Workload scope is always the default

There is no ordinary `--children` option. All strong backends contain descendants automatically. Watchdog backends discover and track descendants as part of their basic contract.

A future expert-only direct-process mode may be added, but it must not be the default and must be named explicitly, such as `--scope direct-process`.

### 8.2 Enforcement selection

- `auto`: choose the strongest available backend.
  - Linux with usable cgroup v2: kernel-backed.
  - Windows with usable Job Objects: kernel-backed.
  - macOS: watchdog.
  - If `auto` selects watchdog, print a one-line warning to stderr unless explicitly suppressed.
- `hard`: require a kernel-backed workload limit. If setup cannot be completed before target execution, do not launch the target and return a setup error.
- `watchdog`: deliberately use sampled enforcement, even if a strong backend exists. This is useful for backend comparison and diagnostics, not the recommended production setting.

### 8.3 Workload lifetime

`--lifetime command` is the default:

- The direct child’s exit ends the command contract.
- Any descendants still present in the backend container are terminated during cleanup.
- The wrapper returns the direct child outcome unless a prior limit, monitor, or user-interruption event has higher precedence.

`--lifetime workload` means:

- The direct child is reaped as soon as it exits.
- The wrapper remains until the contained workload is empty.
- The returned child status remains the direct child’s status.
- A configurable maximum drain time should be added before this mode leaves experimental status.

This explicit choice prevents daemonized or background descendants from escaping merely because the original command exited.

### 8.4 Limit response

Memory exhaustion is a host-protection event. The default `--limit-grace` is therefore `0s`: forcefully terminate the complete workload as soon as a conclusive limit event is observed.

A nonzero grace is permitted for cooperative applications, but the backend’s kernel cap remains in force during the grace period where available. Watchdog mode warns that additional overshoot is possible during any grace period.

### 8.5 Monitor failure

There is no fail-open mode in version 1.

If monitoring or accounting fails after target launch:

1. Record a monitor error.
2. Terminate the workload using the strongest available method.
3. Reap the direct child.
4. Clean up containment state.
5. Return wrapper status `125`.

A future fail-open option would need an unmistakable name and would not be accepted by `--enforcement hard`.

---

## 9. Byte-size and duration syntax

### 9.1 Memory sizes

Accepted examples:

```text
4096B
512KiB
8GiB
1.5GiB
8000MB
```

Rules:

- Bare numbers are bytes for compatibility, but documentation always shows a unit.
- Decimal units: `KB`, `MB`, `GB`, `TB`, `PB`, `EB`, powers of 1000.
- Binary units: `KiB`, `MiB`, `GiB`, `TiB`, `PiB`, `EiB`, powers of 1024.
- Ambiguous suffixes such as `8G` are rejected.
- Parsing uses decimal integer/rational arithmetic, not floating-point arithmetic.
- The final value is a `u64` byte count.
- Fractional values are rounded up to the next byte so the configured limit is never silently lower due to truncation.
- Overflow is a typed parse error.
- `--memory 0` is rejected.
- `unlimited` is accepted only for options whose contract allows it, such as Linux swap.

### 9.2 Durations

Accepted examples:

```text
10ms
250ms
2s
1.5s
1m
```

Watchdog intervals below `10ms` are rejected by default because they are likely to create excessive monitor overhead. An experimental build may permit lower values behind an explicit unsafe-performance option.

---

## 10. Memory semantics

A new implementation must define the metric before defining enforcement. The default metric is `native`, meaning the backend’s most appropriate workload-wide quantity, not a claim of cross-platform equivalence.

### 10.1 Capability matrix

| Platform/backend | Enforcement class | Native metric | Descendant membership | Main qualification |
|---|---|---|---|---|
| Linux cgroup v2 | Kernel-backed | cgroup memory charge from `memory.current`; cap via `memory.max` | Kernel-maintained cgroup hierarchy | `memory.max` may be exceeded temporarily in documented circumstances; swap is separate. |
| Windows Job Object | Kernel-backed | Job-wide committed memory | Child processes join the job by default when breakaway is not allowed | Commit is not resident physical memory; exceeding the cap denies further commit and the wrapper then terminates the job. |
| macOS watchdog | Sampled | Sum of per-process physical footprint | Process group plus sampled/sticky descendant set | No public cgroup-equivalent aggregate hard cap; short bursts and early session escape can be missed. |
| Generic Unix watchdog | Sampled | Explicit RSS or platform-specific resident metric | Process group plus sampled descendants | Semantics and strength depend on the platform implementation. |

### 10.2 Linux native metric

The Linux backend reports:

- `memory.current`: current cgroup memory usage, including descendants.
- `memory.peak`: peak cgroup usage where available.
- `memory.events`: limit and OOM event counters.
- Optional `memory.swap.current` and `memory.swap.peak` where available.

The report metric name is `linux-cgroup-memory`.

The configured `--memory` value is written to `memory.max`. The package documents that the kernel may temporarily report usage above that value under certain circumstances. “Kernel-backed” means the operating system performs reclaim, allocation control, and cgroup OOM handling independently of wrapper scheduling; it does not mean mathematical zero-overshoot.

#### Linux swap policy

Swap is a separate resource in cgroup v2. Version 1 uses this default:

- `--swap 0` when `--enforcement hard` or when `auto` selects Linux cgroup v2.

This default prevents a workload from moving a large anonymous footprint into swap and continuing to expand beyond the intended workstation-protection budget. Users who need swap can set an explicit cgroup swap allowance, `unlimited`, or `host` to leave the inherited host policy unchanged.

If the resolved policy requires an explicit swap cap but the cgroup swap controller is unavailable, `--enforcement hard` and Linux `auto` fail before target execution. The user may deliberately select `--swap host` to accept host-inherited swap behavior. No swap-policy weakening is silent.

The resolved policy is always shown by `explain` and recorded in the report.

### 10.3 Windows native metric

The Windows backend uses Job Object **committed memory** and reports the metric as `windows-job-commit`.

This is not working set and not directly comparable to Linux cgroup memory or macOS physical footprint. A process that attempts to commit memory beyond the job-wide cap receives an allocation failure from the operating system. `memcordon` also observes a job memory notification and terminates the complete job so the wrapper retains “stop the workload at the limit” behavior rather than merely denying additional allocation.

To make limit notification reliable without materially lowering the user’s cap:

1. Set the enforceable `JOB_OBJECT_LIMIT_JOB_MEMORY` value to the requested limit.
2. Set a guaranteed notification threshold one native page below the cap, or to the lowest valid threshold for very small limits.
3. On notification, record a limit event and call `TerminateJobObject`.
4. Query `PeakJobMemoryUsed` for the final report.

The package must describe the one-page notification margin in `explain` and in the JSON report.

### 10.4 macOS native watchdog metric

The preferred macOS metric is `physical-footprint-sum`:

- Enumerate workload process IDs through public process-information APIs available in the macOS SDK.
- Query each known process using `proc_pid_rusage` and a supported `RUSAGE_INFO_*` version.
- Use `ri_phys_footprint` where available.
- Fall back to a resident-size field only when physical footprint is unavailable, and record that fallback explicitly.
- Charge each process ID once; do not count threads as separate processes.
- Add values with saturating arithmetic.

The sum remains a sampled approximation. Per-process physical-footprint accounting is more meaningful on macOS than an undocumented claim of “actual memory,” but summing process values is still not a universal measure of exclusive ownership. The report must retain the exact metric name and backend version.

### 10.5 RSS mode

`--metric rss` is allowed only in watchdog mode. It means a sum of process resident-set measurements as provided by the platform collector. Documentation warns that:

- Shared pages may be represented in multiple processes.
- Swapped-out memory is not resident.
- Kernel counters may be delayed or approximate.

### 10.6 Virtual mode

`--metric virtual` is an expert-only watchdog metric. It is never described as physical consumption and is rejected by kernel-backed mode unless a future backend offers a precise native address-space policy.

The compatibility layer may accept the old `--virtual` spelling, but it prints a warning and maps to `--enforcement watchdog --metric virtual`.

---

## 11. Exit-status contract

The wrapper exposes a deliberate outcome model rather than deriving success from an absent ordinary child exit code.

### 11.1 Wrapper exit codes

A direct child’s normal exit code is returned unchanged when the wrapper platform can represent it. On Unix this is the ordinary `0–255` shell range. The wrapper itself uses these conventional statuses:

| Exit code | Wrapper-generated meaning |
|---:|---|
| `124` | Workload memory limit reached or attempted. |
| `125` | Wrapper/backend/monitor failure after policy resolution or launch. |
| `126` | Command was found but could not be executed. |
| `127` | Command was not found. |
| `2` | CLI usage or configuration error before launch. |
| `128 + signal` | Unix direct child or wrapper terminated by a signal, when no higher-precedence limit or monitor outcome exists. |

A direct child can itself return any reserved value, including `124`, `125`, `126`, or `127`; shell exit codes alone therefore cannot encode perfect provenance. Automation that must distinguish child-generated and wrapper-generated outcomes uses the JSON report.

On Windows, the report records the full native 32-bit child exit status. The wrapper returns the platform-native value when the runtime and shell preserve it; otherwise it uses the documented compatibility mapping and records the lossless value in JSON.

### 11.2 Outcome precedence

Highest to lowest:

1. Confirmed memory-limit event.
2. Wrapper monitor/backend failure after launch.
3. User-requested wrapper termination.
4. Direct child signal termination.
5. Direct child normal exit.

Examples:

- If a cgroup memory event occurs and the child exits with `0` during cleanup, the wrapper returns `124`.
- If the direct child exits `7` before any limit event, the wrapper returns `7`.
- If Ctrl-C is received before a memory event, the wrapper forwards/terminates according to policy and returns `130` on Unix.
- If sampling fails in watchdog mode, the wrapper kills the workload and returns `125`, even if the child then exits normally.

### 11.3 Raw outcome model

```rust
pub enum RunOutcome {
    Exited {
        child: ChildTermination,
        peak: Option<Bytes>,
    },
    LimitExceeded {
        limit: Bytes,
        observed: Option<Bytes>,
        peak: Option<Bytes>,
        evidence: LimitEvidence,
        child_after_termination: Option<ChildTermination>,
    },
    Interrupted {
        signal: Interruption,
        child_after_termination: Option<ChildTermination>,
    },
    MonitorFailed {
        error: MonitorError,
        child_after_termination: Option<ChildTermination>,
    },
}
```

`ChildTermination` distinguishes normal exit, Unix signal, Windows native status, and unavailable status. No `None => success` conversion exists.

---

## 12. Output and reporting

### 12.1 Stream ownership

- Child stdin, stdout, and stderr are inherited by default.
- All wrapper text diagnostics go to stderr.
- The wrapper writes nothing to stdout unless the user explicitly selects a report destination there.
- Text emitted after a limit is concise and single-line by default.

Example:

```text
memcordon: memory limit exceeded; backend=linux-cgroup-v2 metric=linux-cgroup-memory limit=8.00GiB peak=8.03GiB exit=124
```

### 12.2 JSON report

The report is versioned independently of the executable.

Illustrative schema:

```json
{
  "schema_version": 1,
  "tool": {
    "name": "memcordon",
    "version": "0.1.0"
  },
  "command": {
    "program": "hell",
    "args": ["--check", "automation/hell-automation-checks.hell"],
    "pid": 27913
  },
  "policy": {
    "requested_enforcement": "auto",
    "effective_enforcement": "watchdog",
    "memory_limit_bytes": 8589934592,
    "swap_limit_bytes": null,
    "lifetime": "command",
    "poll_interval_ms": 50
  },
  "backend": {
    "name": "macos-watchdog",
    "class": "watchdog",
    "metric": "physical-footprint-sum",
    "hard_limit": false,
    "limitations": [
      "sampled accounting",
      "descendant may escape by creating a new session before discovery"
    ]
  },
  "result": {
    "outcome": "child-exited",
    "wrapper_exit_code": 0,
    "child": {
      "kind": "exit-code",
      "code": 0
    },
    "limit_evidence": null,
    "peak_bytes": 12345344,
    "duration_ms": 17
  },
  "cleanup": {
    "direct_child_reaped": true,
    "workload_empty": true,
    "forced_termination": false,
    "errors": []
  }
}
```

### 12.3 Atomic report writes

For a file report:

1. Write to a sibling temporary file.
2. Flush and close.
3. Rename atomically where supported.
4. If a required report cannot be written, return `125` after preserving the workload outcome in stderr.

A `--report-optional` flag may allow the child outcome to win over report failure, but required reporting is the safer automation default.

---

## 13. Architecture overview

### 13.1 Layering

```text
+-----------------------------------------------------------+
| CLI: parsing, policy resolution, diagnostics, exit mapping |
+-----------------------------------------------------------+
| Core: state machine, outcomes, invariants, reporting        |
+-----------------------------------------------------------+
| Backend contract: prepare, gated spawn, events, kill, reap  |
+-------------------+------------------+----------------------+
| Linux cgroup v2   | Windows Job     | macOS/Unix watchdog  |
+-------------------+------------------+----------------------+
| Native OS APIs and kernel resource-control primitives       |
+-----------------------------------------------------------+
```

### 13.2 Execution sequence

```text
Parse configuration
        |
        v
Probe capabilities and resolve backend
        |
        v
Prepare empty containment object
        |
        v
Spawn an internal gated launcher or suspended process
        |
        v
Attach/assign it to containment
        |
        v
Release launcher; target exec begins
        |
        v
Event loop:
  - reap direct child promptly
  - process limit/backend/signal events
  - sample telemetry where needed
        |
        v
Terminate remaining workload according to outcome/lifetime
        |
        v
Final direct-child reap and workload-empty verification
        |
        v
Backend cleanup
        |
        v
Report and map wrapper exit status
```

### 13.3 Why a gated launcher exists

The target must not be allowed to allocate substantially or fork before containment is established.

On Unix-like systems, `memcordon` launches a hidden mode of its own executable:

```text
memcordon __launcher <inherited-control-fd> -- COMMAND ARG...
```

The launcher:

1. Starts with only minimal trusted package code.
2. Closes all unintended descriptors.
3. Blocks reading one byte from a control pipe.
4. Is assigned to the cgroup/process group by the parent.
5. Receives the release byte.
6. Applies child-side signal and resource setup.
7. Calls `exec` so the target replaces the launcher in the same PID.

If containment setup fails, the parent terminates and reaps the blocked launcher without ever running the target.

Windows instead creates the target process suspended, assigns it to the Job Object, and resumes its primary thread.

### 13.4 Core state machine

```rust
pub enum RunState {
    Resolving,
    Prepared,
    SpawnedGated,
    Running,
    ChildExited,
    Terminating,
    Reaping,
    Cleaning,
    Finished,
}
```

Invalid transitions are rejected in debug builds and covered by model-based tests. Cleanup is callable from every state at or after `SpawnedGated`.

---

## 14. Backend interface

An illustrative internal interface follows. Exact Rust signatures may change, but the ownership model is normative.

```rust
pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;
    fn prepare(&self, policy: &ResolvedPolicy) -> Result<Box<dyn Prepared>, SetupError>;
}

pub trait Prepared: Send {
    /// Spawns a process that cannot execute the user command until containment
    /// has been established. On error, no user command has run.
    fn spawn_gated(
        self: Box<Self>,
        command: &CommandSpec,
    ) -> Result<Box<dyn RunningWorkload>, SpawnError>;
}

pub trait RunningWorkload: Send {
    fn child_id(&self) -> ProcessIdentity;

    /// Nonblocking and reaping: once Some is returned, subsequent calls return
    /// the same stored status rather than touching an already-consumed OS wait.
    fn try_reap_direct(&mut self) -> Result<Option<ChildTermination>, WaitError>;

    /// Waits until an event or deadline. Must not busy-spin.
    fn wait_event(&mut self, deadline: Instant) -> Result<Vec<BackendEvent>, MonitorError>;

    fn sample(&mut self) -> Result<Option<UsageSample>, MonitorError>;
    fn request_graceful_termination(&mut self) -> Result<(), TerminationError>;
    fn force_kill_all(&mut self) -> Result<(), TerminationError>;
    fn wait_workload_empty(&mut self, deadline: Instant) -> Result<bool, MonitorError>;
    fn final_reap_direct(&mut self) -> Result<ChildTermination, WaitError>;
    fn peak_usage(&mut self) -> Result<Option<Bytes>, MonitorError>;
    fn cleanup(&mut self) -> Result<(), CleanupError>;
}
```

### 14.1 Backend events

```rust
pub enum BackendEvent {
    DirectChildMayHaveExited,
    WorkloadBecameEmpty,
    MemoryThresholdReached(LimitEvidence),
    ProcessJoined(ProcessIdentity),
    UserSignal(Interruption),
    GuardianLost,
    BackendWarning(Warning),
}
```

The event loop still calls `try_reap_direct` after any wake-up and before sleeping. Notifications optimize latency; they do not replace reaping.

---

## 15. Direct-child lifecycle design

This section is normative because it addresses the reported macOS hang.

### 15.1 Rules

- The wrapper owns one direct-child handle from spawn until reaping.
- The main loop calls a nonblocking reap operation before every sleep.
- On Unix, a successful nonblocking wait both detects exit and reaps the PID.
- Exit notification through kqueue, pidfd, SIGCHLD, completion ports, or another source is only a wake-up hint.
- A process-table entry is never used as proof that the direct child is alive.
- After a nonblocking reap succeeds, the status is stored in memory and returned consistently to later callers.
- Cleanup performs a final blocking reap if no status has yet been collected.
- Stdin closure behavior is explicit so waiting cannot deadlock on a pipe the wrapper still owns.

### 15.2 Core loop sketch

```rust
loop {
    if let Some(status) = workload.try_reap_direct()? {
        direct_status = Some(status);
        if policy.lifetime == Lifetime::Command {
            break RunReason::DirectChildExited;
        }
    }

    for event in workload.wait_event(next_deadline)? {
        match event {
            BackendEvent::MemoryThresholdReached(evidence) => {
                break 'run RunReason::Limit(evidence);
            }
            BackendEvent::UserSignal(signal) => {
                break 'run RunReason::Interrupted(signal);
            }
            _ => {}
        }
    }

    if sampling_due() {
        if let Some(sample) = workload.sample()? {
            observe(sample);
        }
    }
}
```

All `?` exits after spawn are intercepted by the outer supervisor, which performs fail-closed termination and final reaping before returning an error outcome.

### 15.3 Required macOS regression tests

For each command below, run under the watchdog backend with a two-second outer timeout:

```console
/usr/bin/true
/usr/bin/false
/bin/sh -c 'exit 37'
```

Assert:

- Wrapper exits within the timeout.
- Direct child is reaped.
- No zombie remains.
- Exit status is `0`, `1`, and `37` respectively.
- No wrapper text appears on stdout.

This directly covers the user-provided defect report.

---

## 16. Linux cgroup v2 backend

### 16.1 Guarantee

The Linux backend provides a kernel-backed workload memory cap using cgroup v2 when the memory controller is available and the current environment delegates enough control to create and configure a child cgroup.

### 16.2 Capability probe

The probe checks, without launching a workload:

1. The unified cgroup v2 hierarchy is mounted.
2. The `memory` controller is available to the relevant subtree.
3. A package-owned child cgroup can be created in the delegated location.
4. `memory.max`, `memory.current`, `memory.events`, `cgroup.procs`, and `cgroup.events` are usable.
5. `cgroup.kill`, `memory.peak`, and swap files are detected as optional capabilities.
6. The package can remove the empty test cgroup it created.

Probe failures include the exact path and operation but redact irrelevant host details from ordinary output.

### 16.3 Cgroup identity and ownership

Each run creates an unguessable package-owned cgroup name containing:

- Fixed prefix.
- User ID where meaningful.
- Wrapper PID.
- Random nonce.

Example:

```text
memcordon-501-28110-a4f97d8c
```

A metadata file outside cgroupfs, under the user’s runtime directory, records the wrapper PID, creation time, cgroup path, nonce, and command hash. `cleanup` validates all fields before deleting stale state.

### 16.4 Setup sequence

1. Create the cgroup.
2. Configure `memory.oom.group=1` when supported.
3. Write the requested limit to `memory.max`.
4. Configure `memory.swap.max` according to resolved policy.
5. Open usage and event files with close-on-exec.
6. Capture baseline event counters.
7. Spawn the gated launcher.
8. Move the launcher PID into `cgroup.procs`.
9. Verify membership by reading the process’s cgroup or cgroup membership file.
10. Release the launcher to `exec` the target.

If any step before release fails, terminate and reap the launcher, remove the empty cgroup, and return a setup error.

### 16.5 Runtime event handling

The backend monitors:

- Direct-child exit through a native wait mechanism.
- `memory.events` changes.
- `cgroup.events` for populated state.
- User signals through the core signal source.

A limit event is recorded when one or more of these counters increases relative to baseline:

- `max`
- `oom`
- `oom_kill`
- `oom_group_kill`

`memory.current` alone is telemetry, not the only proof of a limit event, because usage may be reclaimed around the threshold.

On a limit event:

1. Store event counters and current/peak usage.
2. If `--limit-grace=0`, write `1` to `cgroup.kill` when available.
3. Otherwise signal the direct process group for graceful shutdown, wait the configured grace, then call `cgroup.kill`.
4. Wait until `cgroup.events` reports `populated 0`.
5. Reap the direct child if not already reaped.

If `cgroup.kill` is unavailable, enumerate all PIDs in the cgroup hierarchy, send `SIGKILL`, rescan, and repeat until empty or cleanup deadline. This fallback is weaker against fork races and is reported as such.

### 16.6 Normal command exit

Under `--lifetime command`:

1. Reap the direct child immediately.
2. Check whether the cgroup remains populated.
3. If populated, terminate remaining descendants.
4. Wait for empty.
5. Read final peak and events.
6. Remove the cgroup.
7. Return the stored direct-child outcome.

Under `--lifetime workload`, step 3 becomes a wait for natural emptiness, subject to the configured drain timeout.

### 16.7 Wrapper crash behavior

The cgroup memory limit remains configured even if the wrapper crashes, so contained tasks remain capped. Cleanup is improved through a small guardian process:

- The guardian owns no user-facing terminal role.
- It watches a close-on-exec control pipe from the wrapper.
- On unexpected EOF, it writes `1` to `cgroup.kill`, waits for emptiness, and attempts cgroup removal.
- It runs outside the target’s process group.

This is best-effort, not a security guarantee. If the wrapper and guardian are both killed, the cgroup remains as a capped stale container and can be handled by `memcordon cleanup`.

### 16.8 Linux limitations

- The host must provide and delegate cgroup v2 memory control.
- `memory.max` can be temporarily exceeded under documented kernel behavior.
- Same-user hostile code may be able to interfere with user-delegated control paths; this package is not a same-UID security sandbox.
- Swap semantics are separate and must be reported explicitly.
- Some allocation failures may occur without a group kill; wrapper event handling turns recorded limit attempts into complete workload termination where possible.

### 16.9 Optional systemd provider

A later provider may create a transient user or system unit through D-Bus when direct cgroupfs delegation is unavailable. It must preserve the same contracts:

- Target does not start before limits are attached.
- Complete workload membership is controlled by the service manager.
- Direct command status remains recoverable.
- Limit evidence is distinguishable from ordinary child failure.
- No shelling out to `systemd-run` is accepted in the core backend without robust argument, status, and lifecycle handling.

The direct cgroup v2 provider is the version-1 reference backend.

---

## 17. Windows Job Object backend

### 17.1 Guarantee

The Windows backend provides a kernel-backed job-wide committed-memory cap and descendant containment using an unnamed Job Object.

### 17.2 Setup sequence

1. Create an unnamed Job Object with a non-inheritable handle.
2. Set `JOB_OBJECT_LIMIT_JOB_MEMORY` to the requested byte limit.
3. Set `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
4. Do **not** set breakaway flags.
5. Associate an I/O completion port before adding the process.
6. Configure a job-memory notification threshold one native page below the hard cap.
7. Create the target with `CREATE_SUSPENDED` and `CREATE_NEW_PROCESS_GROUP`.
8. Assign the suspended process to the Job Object.
9. If assignment fails, terminate the suspended process, close handles, and return a setup error.
10. Resume the primary thread.

Memory operations before assignment are avoided because the target thread never runs before assignment.

### 17.3 Descendant containment

By default, child processes created by a process in a Job Object join that job when breakaway is not permitted. The package never enables `JOB_OBJECT_LIMIT_BREAKAWAY_OK` or `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` for the workload job.

If the wrapper itself is already in a job whose constraints prevent nested assignment, `--enforcement hard` fails before target execution. `auto` may choose watchdog mode only after emitting a downgrade warning.

### 17.4 Limit behavior

A Job Object memory cap prevents the set of associated processes from committing beyond the configured job-wide limit. It does not by itself guarantee that every application will terminate; an application may receive allocation failure and continue.

`memcordon` therefore combines:

- The enforceable job memory cap.
- A completion-port notification threshold immediately below the cap.
- `TerminateJobObject` when that notification occurs.

The operating system protects the host even if the wrapper is briefly delayed. The wrapper supplies deterministic “limit reached means end the workload” behavior.

### 17.5 Runtime event handling

A backend thread waits on the completion port and emits core events for:

- New process.
- Process exit.
- Active process count reaching zero.
- Job memory notification.
- Job memory limit message.

The core also monitors the direct process handle for exit and stores its full native exit code.

### 17.6 User interruption and graceful termination

For a console workload created as a new process group:

1. Attempt `CTRL_BREAK_EVENT` for graceful interruption.
2. Wait `--signal-grace`.
3. Call `TerminateJobObject` if the job is still active.

GUI processes and applications that ignore console control events proceed directly to forced job termination after the grace period.

### 17.7 Crash cleanup

Because the job handle is non-inheritable and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` is set, closing the wrapper’s last job handle terminates associated processes. This gives Windows the strongest wrapper-crash cleanup behavior among the initial backends.

### 17.8 Windows limitations

- The metric is committed memory, not RSS or physical working set.
- Nested job restrictions can prevent setup in some host environments.
- Graceful console control delivery is application-dependent.
- The notification threshold is one native page below the configured hard cap and is disclosed in reports.
- Job Objects limit resource use but do not provide a complete hostile-code sandbox.

---

## 18. macOS watchdog backend

### 18.1 Guarantee

The macOS backend is explicitly a **sampled watchdog**, not a hard aggregate memory limit. It is designed for cooperative local commands and buggy workloads, including the workstation-protection scenario in the supplied defect report.

It guarantees correct direct-child lifecycle management. It makes best efforts to discover, account, and terminate descendants.

### 18.2 Spawn and process-group setup

The target is created in a new process group before user code begins, using `posix_spawn` attributes or the gated launcher where necessary. The process-group ID is the direct child’s PID.

The wrapper retains the direct-child handle and registers:

- `EVFILT_PROC` with `NOTE_EXIT` as a wake-up optimization where available.
- A native wait/reap path using `waitpid(..., WNOHANG)` or Rust `Child::try_wait`.

A `NOTE_EXIT` event is followed by a wait operation. Notification alone is never treated as reaping.

### 18.3 Descendant discovery

At each discovery interval:

1. Enumerate process IDs.
2. Collect parent PID, process group, and a start-time or equivalent birth identity where available.
3. Seed membership with the direct child.
4. Add processes whose current ancestry reaches a known member.
5. Add processes currently in the workload process group.
6. Keep previously discovered process identities in a **sticky known set** until exit is confirmed, even if they are later reparented.
7. Reject PID reuse by comparing birth identity, not PID alone.

Sticky membership improves behavior when an intermediate parent exits after the descendant was observed.

It cannot discover a process that forks and creates a new session entirely between samples. That limitation is fundamental to this fallback and must remain visible in `probe`, `explain`, and reports.

### 18.4 Sampling

Default interval: `50ms`.

Each sample:

1. Performs one descendant refresh if due.
2. Queries each live known process exactly once.
3. Uses physical footprint where available.
4. Sums with saturation.
5. Records process count, missing-process races, and measurement errors.
6. Compares the `u64` aggregate directly with the `u64` limit.

A process that disappears between enumeration and measurement is treated as a normal exit race after a confirming lookup. Permission errors or repeated unexplained failures are monitor failures and trigger fail-closed cleanup.

### 18.5 Limit response

When a sample is greater than or equal to the configured limit:

1. Record the sample and timestamp.
2. Send `SIGKILL` to the workload process group by default because `--limit-grace=0`.
3. Send `SIGKILL` individually to sticky known members outside the group.
4. Rescan for descendants of known members.
5. Repeat termination and rescan until no known workload process remains or the cleanup deadline expires.
6. Reap the direct child.
7. Return `124`.

With a nonzero limit grace, send `SIGTERM`, wait, and then perform the forceful sequence.

### 18.6 User interruption

On `SIGINT`, `SIGTERM`, or `SIGHUP`:

1. Forward the corresponding signal to the workload process group where appropriate.
2. Also signal known members outside the group.
3. Wait `--signal-grace`.
4. Force-kill survivors.
5. Reap the direct child.
6. Return `128 + signal` on Unix unless a prior limit or monitor event has precedence.

A second user signal skips the remaining grace period.

### 18.7 Guardian

A small optional-by-default guardian process monitors the wrapper through a pipe. Unexpected wrapper death causes the guardian to signal the process group and perform a limited descendant sweep.

The guardian improves ordinary crash cleanup but cannot make process groups unescapable. A process that already created a separate session and escaped discovery may survive.

### 18.8 macOS limitations

- A memory burst shorter than the sampling interval can be missed.
- Usage can overshoot the threshold before termination completes.
- A descendant can escape the process group using `setsid`.
- An undiscovered descendant that reparents before a scan may escape accounting and cleanup.
- Summed physical footprint is platform-specific and not directly comparable to Linux cgroup memory or Windows commit.
- `RLIMIT_RSS` is not used as a substitute for a workload-wide hard limit.
- `--enforcement hard` returns unsupported on macOS unless a future VM/container backend is explicitly configured.

These are documented product limitations, not hidden implementation details.

---

## 19. Generic Unix watchdog backend

A generic Unix backend may be offered only when the implementation can identify:

- A reliable direct-child wait/reap operation.
- A process-group creation and signaling mechanism.
- A process enumeration and parent-identity source.
- A documented memory metric.

It inherits the macOS watchdog contract but must use a platform-specific backend name, such as `freebsd-watchdog`, rather than one vague `unix` label.

Unsupported operating systems should fail at build time or return a clear runtime capability error. A misleading partially functional backend is worse than explicit unsupported status.

---

## 20. Signal and cleanup model

### 20.1 Signal source

Unix signal handlers perform only async-signal-safe work and notify the event loop through a self-pipe or equivalent mechanism. Windows console handlers likewise post a core interruption event rather than running cleanup inline.

### 20.2 Cleanup phases

```text
A. Stop accepting new policy work
B. Record final outcome precedence
C. Request graceful workload termination if policy allows
D. Force-kill complete workload after grace/deadline
E. Reap direct child
F. Verify workload empty as strongly as backend permits
G. Read final usage and event data
H. Remove containment object / close job handle
I. Write report
J. Return mapped wrapper status
```

### 20.3 Cleanup error handling

Cleanup aggregates errors rather than aborting at the first failure. For example, a failed graceful signal must not prevent forceful termination or reaping.

```rust
pub struct CleanupSummary {
    pub graceful_attempted: bool,
    pub force_attempted: bool,
    pub direct_child_reaped: bool,
    pub workload_empty: Option<bool>,
    pub errors: Vec<CleanupError>,
}
```

If cleanup is incomplete, the wrapper returns `125` unless an already confirmed memory-limit event has precedence. The report still records the incomplete cleanup so operators can act.

---

## 21. Error model

No runtime `unwrap`, `expect`, or panic-based control flow is permitted outside tests and statically proven initialization.

### 21.1 Error categories

```rust
pub enum Error {
    Usage(UsageError),
    Unsupported(UnsupportedError),
    Setup(SetupError),
    Spawn(SpawnError),
    Monitor(MonitorError),
    Wait(WaitError),
    Termination(TerminationError),
    Cleanup(CleanupError),
    Report(ReportError),
}
```

Errors include:

- Stable machine-readable code.
- Human-readable context.
- OS error code where available.
- Operation and backend.
- Whether the target was ever released to run.
- Whether the workload may still be alive.

### 21.2 Error examples

```text
memcordon: hard enforcement unavailable: cgroup v2 memory controller is not delegated to /user.slice/user-501.slice (MCSETUP-CGROUP-NOT-DELEGATED)
```

```text
memcordon: command not found: hell (MCSPAWN-NOT-FOUND)
```

```text
memcordon: monitor failed after launch; workload was terminated: proc_pid_rusage returned EPERM for known member pid=28144 (MCMON-SAMPLE-PERMISSION)
```

### 21.3 Logging sensitive data

Ordinary errors may include command basename but do not dump the complete environment. JSON reports include command arguments only by default; environment capture requires an explicit opt-in and supports redaction patterns.

---

## 22. Arithmetic and identity safety

### 22.1 Byte values

- All configured and measured byte values use `u64`.
- No measurement is narrowed to `usize` for comparison.
- Aggregation uses `saturating_add`.
- Saturation sets `aggregate_saturated=true` in diagnostics and immediately proves any representable configured limit has been exceeded.
- Conversions to platform integer types are checked before native API calls.

### 22.2 Process identity

A PID alone is not a durable identity.

- Direct child: native owned handle plus PID.
- Linux cgroup: membership is cgroup-based; PID identity is secondary.
- Windows: process handles and job membership.
- Watchdog descendants: `(pid, birth_identity)` where the platform exposes process start time or equivalent.

A reused PID must not inherit sticky membership from an exited process with a different birth identity.

---

## 23. Rust package and module layout

A small workspace keeps the core testable without multiplying public APIs unnecessarily.

```text
memcordon/
├── Cargo.toml
├── crates/
│   ├── memcordon-core/
│   │   ├── policy.rs
│   │   ├── outcome.rs
│   │   ├── state_machine.rs
│   │   ├── report.rs
│   │   └── error.rs
│   ├── memcordon-platform/
│   │   ├── backend.rs
│   │   ├── launcher.rs
│   │   ├── signal.rs
│   │   ├── linux_cgroup.rs
│   │   ├── windows_job.rs
│   │   ├── macos_watchdog.rs
│   │   └── unix_watchdog.rs
│   ├── memcordon-cli/
│   │   ├── main.rs
│   │   ├── args.rs
│   │   ├── commands.rs
│   │   └── exit_mapping.rs
│   └── memcordon-testkit/
│       ├── fixtures.rs
│       ├── process_assertions.rs
│       └── capability_harness.rs
├── fixtures/
│   ├── exit-code/
│   ├── memhog/
│   ├── burst-hog/
│   ├── fork-tree/
│   ├── daemonize/
│   ├── reparent/
│   ├── setsid-escape/
│   ├── ignore-term/
│   ├── shared-map/
│   └── many-threads/
└── docs/
    ├── guarantees.md
    ├── metrics.md
    ├── backends.md
    ├── exit-status.md
    ├── threat-model.md
    └── migration.md
```

### 23.1 Dependency policy

Likely dependencies:

- `clap` for CLI parsing.
- `serde` and `serde_json` for reports.
- `thiserror` for typed errors.
- `rustix` and narrowly scoped `libc` bindings on Unix.
- `windows-sys` on Windows.
- A minimal signal-notification crate or direct self-pipe implementation.
- `tracing` only if structured internal logging justifies it.

`sysinfo` should not be the primary strong-backend mechanism. If used in a fallback, its task/thread behavior must be pinned, tested, and filtered explicitly.

### 23.2 Unsafe-code policy

- `unsafe` is allowed only in platform FFI modules and the post-fork/launcher boundary.
- Every unsafe block includes a safety comment describing lifetime, pointer, signal-safety, ownership, and threading assumptions.
- Public core crates use `#![forbid(unsafe_code)]`.
- Platform crates use `#![deny(unsafe_op_in_unsafe_fn)]`.

### 23.3 Panic policy

CI runs Clippy with panic-prone lints enabled. Production code does not use `unwrap()` or `expect()` for operating-system interactions. Panic hooks attempt only minimal diagnostics; correctness does not depend on panic cleanup.

---

## 24. Public Rust library API

The CLI is built on a reusable library so lifecycle behavior can be tested and embedded without parsing shell strings.

```rust
use memcordon_core::{
    ByteSize, CommandSpec, Enforcement, Lifetime, Limiter, Policy, RunOutcome,
};

let outcome = Limiter::new(Policy {
    memory: ByteSize::gib(8),
    enforcement: Enforcement::RequireHard,
    lifetime: Lifetime::Command,
    ..Policy::default()
})
.command(CommandSpec::new("cargo").args(["test", "--workspace"]))
.run()?;

match outcome {
    RunOutcome::Exited { child, .. } => {
        println!("child outcome: {child:?}");
    }
    RunOutcome::LimitExceeded { peak, .. } => {
        eprintln!("memory limit reached; peak={peak:?}");
    }
    other => eprintln!("wrapper outcome: {other:?}"),
}
```

The library returns outcomes and errors. It does not call `process::exit`; only the CLI maps outcomes to wrapper statuses.

---

## 25. Race analysis

### 25.1 Direct child exits before first memory sample

- Nonblocking reap runs before sampling and before sleeping.
- The child is reaped and its status returned.
- No zombie-driven liveness loop exists.

### 25.2 Direct child exits while a limit event arrives

- Backend events and child status are both collected.
- Confirmed limit evidence has precedence.
- Cleanup reuses the already stored child status.

### 25.3 Descendant forks during termination

- Linux: `cgroup.kill` covers the cgroup and descendant cgroups, including concurrent membership at kill time; emptiness is verified afterward.
- Windows: `TerminateJobObject` targets all associated processes; child job membership is automatic without breakaway.
- Watchdog: rescan and repeat, but a session escape before discovery remains possible.

### 25.4 Parent exits and child reparents

- Strong backends: membership is not based on PPID and remains intact.
- Watchdog: previously discovered members remain sticky; undiscovered members may escape.

### 25.5 PID reuse

- Native handles or birth identity prevent a new process from being mistaken for an old member.

### 25.6 Wrapper receives two termination signals

- First signal begins graceful cleanup.
- Second signal skips grace and force-kills the workload.
- The wrapper still attempts direct-child reaping before exit.

### 25.7 Kill operation fails

- Continue all other cleanup steps.
- Retry where the error is transient.
- Record survivors if discoverable.
- Return an incomplete-cleanup wrapper error unless a higher-precedence limit outcome applies.

### 25.8 Measurement aggregation overflows

- Saturation marks usage as `u64::MAX`.
- Any valid configured limit is considered exceeded.
- No debug/release behavioral divergence or panic occurs.

### 25.9 Child closes or redirects standard streams

- Stream behavior does not affect liveness or status collection.
- The wrapper does not wait on captured output unless capture was explicitly requested and drained concurrently.

---

## 26. Test strategy

### 26.1 Test layers

1. **Unit tests**
   - Byte and duration parsing.
   - Exit mapping.
   - Outcome precedence.
   - State-machine transitions.
   - Arithmetic saturation.
   - JSON schema serialization.
2. **Backend contract tests**
   - Shared test suite run against each backend capability class.
3. **End-to-end tests**
   - Real processes and process trees on each supported operating system.
4. **Race/stress tests**
   - Repeated short-lived children, rapid forks, simultaneous exits and signals.
5. **Performance tests**
   - Idle monitor cost, descendant-scan scaling, event latency.
6. **Fuzz/property tests**
   - Size parser, duration parser, report decoder, state-machine event sequences.

### 26.2 Required cross-platform acceptance tests

| Test | Required assertion |
|---|---|
| Immediate success | Wrapper promptly returns `0`; direct child reaped. |
| Immediate failure | Wrapper promptly preserves nonzero code. |
| Many short-lived children | No hang or zombie after thousands of repetitions. |
| Signal termination | Signal is not converted to success. |
| Limit event | Wrapper returns `124`, not `0`. |
| Descendant allocation | Aggregate/workload policy includes descendants. |
| Limit cleanup | No contained descendants remain after wrapper exit. |
| Background descendant | Default command lifetime terminates it when direct child exits. |
| Stdout integrity | Wrapper diagnostics never enter child stdout. |
| Spawn error | Concise typed error; no panic. |
| Monitor error | Fail-closed termination; exit `125`. |
| Ctrl-C | Forward/terminate/reap; documented status. |
| Large values | No `usize` truncation or unchecked sum overflow. |

### 26.3 Defect-report regression suite

On macOS arm64, at minimum:

```console
memcordon run --enforcement watchdog --memory 8GiB -- /usr/bin/true
memcordon run --enforcement watchdog --memory 8GiB -- /usr/bin/false
memcordon run --enforcement watchdog --memory 8GiB -- /bin/sh -c 'exit 37'
```

Each test has an outer timeout and records direct-child PID. After completion:

- PID must no longer exist.
- No `<defunct>` child may remain under the wrapper.
- Wrapper must have exited.
- Status must match the contract.

Also reproduce the real Hell-check invocation when the tool is available in the project’s private or local integration environment.

### 26.4 Linux-specific tests

- Gated launcher cannot execute target before cgroup assignment.
- `memory.max` is set correctly.
- `memory.swap.max` follows policy.
- Descendant and grandchild remain in cgroup after reparenting.
- `memory.events` establishes a limit outcome.
- `memory.oom.group=1` behavior is observed where supported.
- `cgroup.kill` removes a forking workload.
- Cgroup is removed after normal exit and limit exit.
- Wrapper crash leaves workload capped; guardian cleans it when functioning.
- No-delegation environment makes `--enforcement hard` fail before target run.

### 26.5 Windows-specific tests

- Process is suspended until assigned to job.
- Child and grandchild join the job.
- Breakaway is not permitted.
- Job commit cannot exceed the configured hard cap.
- Notification causes `TerminateJobObject` and wrapper status `124`.
- Closing the last job handle kills the workload.
- Nested-job incompatibility fails before resume.
- Full native child exit status appears in JSON.

### 26.6 macOS-specific tests

- kqueue exit wake-up is followed by a reap.
- Process group exists before target work begins.
- Many threads are charged once per process, not once per thread.
- Known descendants remain tracked after reparenting.
- `setsid` escape fixture demonstrates and documents the expected watchdog limitation.
- Burst allocator demonstrates sampling limits and records missed-peak behavior in benchmark documentation.
- Permission/sample errors fail closed.

### 26.7 CI and release gating

The release pipeline includes:

- Linux x86_64 and arm64 build/test.
- macOS arm64 and x86_64 build/test while those targets remain supported.
- Windows x86_64 build/test.
- Exact-label standard GitHub-hosted `ubuntu-24.04` and `windows-2025` jobs with
  per-run cgroup delegation/runtime qualification and Job Object integration
  tests.
- Sanitizer or Miri runs for portable core components where applicable.
- Fuzz smoke tests.
- Clippy and rustfmt.
- License and dependency audit.

Capability-dependent tests may skip in non-authoritative ordinary CI, but a
release cannot be cut unless both exact-label hard-backend certification jobs
select the required backend, pass all structured runtime checks and exact
scenarios, and report zero skipped tests for the tagged commit. A hosted-runner
capability failure fails certification; “skipped everywhere” is not a passing
backend. The `ephemeral-certified` report class denotes a fresh standard
GitHub-hosted job VM plus successful per-run evidence, not an image certified in
advance.

### 26.8 Performance gates

Reference benchmarks must establish platform-specific budgets before 1.0. At minimum:

- Kernel-backed idle monitoring must be event-driven and near-zero CPU when no telemetry sample is due.
- Watchdog mode must sleep between samples and never run an unbounded refresh loop.
- A 50ms watchdog with 100 ordinary descendants must remain low enough not to materially perturb the workload on reference hardware.
- Performance regressions greater than the project’s chosen percentage threshold require review and benchmark evidence.

The project should publish measurements rather than promise arbitrary universal percentages before data exists.

---

## 27. Traceability to identified shortcomings

| Prior shortcoming | Design response | Residual limitation |
|---|---|---|
| Direct child can remain a zombie and wrapper can hang | Owned child handle; `try_wait`/`waitpid`; final reap; bounded regression tests | None expected for supported direct-child paths. |
| Signal or enforced kill can become exit `0` | Typed outcomes; explicit limit code `124`; signal-aware mapping; no `None => success` | Shell code alone cannot distinguish a child that independently returned a reserved code; JSON does. |
| Descendants are measured but only direct child is killed | Workload scope by default; cgroup kill; Job Object termination; repeated watchdog tree cleanup | macOS watchdog cannot guarantee capture of an undiscovered session escape. |
| Polling is presented as a hard limit | Explicit hard/watchdog classes; `--enforcement hard` fails closed | macOS remains watchdog unless external isolation is added. |
| Busy-spin and repeated full-table refresh | Event-driven strong backends; bounded watchdog interval; targeted native collectors | Watchdog cost still grows with process count. |
| Summed RSS is treated as exact physical use | Explicit metric names; native cgroup/job metrics; physical-footprint preference on macOS; RSS only by request | No universal cross-platform memory metric exists. |
| Virtual memory is misleading | Expert-only explicit virtual watchdog metric; old flag deprecated | Virtual size remains unsuitable as a physical-memory proxy. |
| Linux tasks/threads may be double-counted | Strong backend uses cgroup aggregate; watchdog collectors charge one process identity once; many-thread tests | Dependency regressions remain possible and are caught by tests. |
| `usize` narrowing and unchecked sums | `u64` end to end; checked native conversions; saturating aggregate | Saturation loses exact value but safely proves limit exceeded. |
| Lifecycle operations panic | Typed `Result`; no runtime unwraps; aggregate cleanup errors | Catastrophic process aborts remain possible in any native program, but are not normal control flow. |
| Wrapper interruption may leave workload running | Signal forwarding; force cleanup; cgroup guardian; Windows kill-on-close; macOS guardian | SIGKILL plus guardian failure can leave capped Linux tasks or escaped macOS tasks. |
| Diagnostics corrupt stdout | Wrapper diagnostics stderr-only; separate JSON report file | Explicit user selection can still direct reports to stdout. |
| Tests cover parser rather than product | Multi-layer backend and race suite; defect-report regression; exact-label hosted certification jobs | Some hostile races cannot be proven absent in watchdog mode. |

---

## 28. Threat model and security notes

### 28.1 In scope

- Accidental runaway allocations.
- Fork-heavy but non-adversarial workloads.
- Commands that crash, exit quickly, ignore graceful termination, or leave background children.
- Local automation that needs deterministic status and cleanup.
- Moderately untrusted workloads that do not possess a separate means to alter the wrapper’s control plane.

### 28.2 Out of scope

A process running as the same user may be able to:

- Signal or debug the wrapper where host policy permits.
- Access user-level service-manager APIs.
- Interfere with writable delegated cgroup controls.
- Exploit unrelated kernel or wrapper vulnerabilities.
- Escape a macOS process group by creating a new session.

For hostile code, pair `memcordon` with a container, VM, dedicated UID, restricted namespace, or platform sandbox. The package’s hard backends are resource-control mechanisms, not full isolation.

### 28.3 Control-path hardening

- Use unnamed Windows jobs.
- Use random Linux cgroup names and strict metadata validation.
- Mark all control handles and FDs close-on-exec/non-inheritable.
- Pass only the launcher release FD to the internal launcher.
- Clear internal environment variables before target exec.
- Avoid predictable temporary files.
- Do not parse shell command strings; accept program and argument vectors.
- Validate report paths against symlink replacement when writing privileged or service-managed reports.

---

## 29. Migration from `memlimit 0.1.0`

### 29.1 Compatibility command

An optional adapter supports old syntax:

```text
memcordon compat [--children] [--virtual] AMOUNT COMMAND [ARG...]
```

Mappings:

- `--children`: accepted as a deprecated no-op because workload scope is already the default.
- `--virtual`: maps to watchdog virtual metric and emits a warning.
- `AMOUNT`: parsed under the new checked `u64` parser.
- Child ordinary exit codes are preserved.
- A memory-limit event now returns `124` rather than depending on the killed child’s absent ordinary code.

### 29.2 Intentional behavior changes

- Descendants are included by default.
- Limit diagnostics go to stderr.
- Limit outcomes are explicitly nonzero.
- Hard mode can refuse to run when platform containment is unavailable.
- macOS is labeled watchdog rather than presented as equivalent to cgroup/job enforcement.
- Remaining descendants are cleaned up when the direct child exits under default lifetime policy.

### 29.3 Documentation migration note

Existing users relying on “same exit code including when killed” must update automation to treat `124` as a memory-limit outcome. JSON reports are recommended for unambiguous automation.

---

## 30. Implementation plan

### Phase 0: Core contracts and test fixtures

Deliver:

- Policy and byte parsers.
- Outcome and exit mapping.
- State machine.
- Report schema.
- Cross-platform fixture binaries.
- Backend conformance harness.

Exit criteria:

- Parser and state-machine fuzz tests pass.
- No production panic-based OS error handling.
- Report schema documented.

### Phase 1: macOS lifecycle-safe watchdog

Deliver:

- Gated/process-group spawn.
- kqueue wake-up plus native reaping.
- Physical-footprint sampling.
- Sticky descendant tracking.
- Signal forwarding and repeated cleanup.
- Defect-report regression tests.

Exit criteria:

- `/usr/bin/true`, `/usr/bin/false`, and arbitrary nonzero commands return promptly on macOS arm64.
- No direct-child zombie remains.
- Limit event returns `124`.
- Watchdog warning and limitations are visible.

### Phase 2: Linux cgroup v2 backend

Deliver:

- Capability probe.
- Gated launcher assignment.
- `memory.max`, swap, OOM-group, events, peak, and kill support.
- Cgroup cleanup and stale cleanup command.
- Guardian prototype.

Exit criteria:

- Descendant fork/reparent tests pass.
- Workload remains capped if wrapper event loop is paused.
- `--enforcement hard` fails before target execution without delegation.
- Limit event and cleanup are deterministic.

### Phase 3: Windows Job Object backend

Deliver:

- Suspended process creation.
- Job assignment and memory cap.
- Completion-port event thread.
- Notification threshold and job termination.
- Kill-on-close cleanup.

Exit criteria:

- Job-wide commit cap verified.
- Child/grandchild containment verified.
- Wrapper crash closes the job and kills workload.
- Full native status appears in reports.

### Phase 4: Hardening and 1.0 readiness

Deliver:

- Guardian hardening.
- Optional systemd transient-unit provider.
- Performance baselines.
- Packaging and signed release artifacts.
- Threat-model and backend guarantee documentation.
- Long-running race suites.

Exit criteria:

- Dedicated platform runners pass.
- No known release-blocking lifecycle or containment defect.
- Every backend has an explicit guarantee/limitation page.
- Compatibility and exit-code migration are documented.

---

## 31. Release acceptance checklist

A release candidate is rejected unless all applicable items pass:

- [ ] Short-lived successful and failing children return within a bounded interval.
- [ ] Direct children are reaped exactly once.
- [ ] Limit termination never reports success.
- [ ] Child normal nonzero status is preserved.
- [ ] Unix signal termination is not collapsed to success.
- [ ] Wrapper diagnostics do not appear on stdout.
- [ ] No full-speed polling loop exists.
- [ ] `u64` is used for limits and measurements.
- [ ] Aggregate overflow cannot panic.
- [ ] Spawn, kill, wait, and sample failures are typed errors.
- [ ] Strong backends contain grandchildren and reparented members.
- [ ] Strong-backend target code does not run before assignment.
- [ ] Watchdog limitations are visible in probe and report output.
- [ ] Linux cgroup is empty and removed after normal and limit exits.
- [ ] Windows job closes and kills remaining processes.
- [ ] macOS defect-report regression passes on arm64.
- [ ] JSON report conforms to the declared schema version.
- [ ] Dedicated backend CI did not merely skip the integration suite.

---

## 32. Documentation set to ship with the package

The package README should remain concise and link to these documents:

1. `guarantees.md`
   - What kernel-backed and watchdog mean.
   - Backend capability matrix.
2. `metrics.md`
   - Linux cgroup memory.
   - Windows job commit.
   - macOS physical footprint.
   - RSS and virtual caveats.
3. `backends.md`
   - Setup requirements and capability probing.
4. `exit-status.md`
   - Status table, precedence, examples, JSON recommendation.
5. `threat-model.md`
   - Accidental exhaustion versus hostile code.
6. `migration.md`
   - Old flags and changed semantics.
7. `troubleshooting.md`
   - Cgroup delegation, nested Windows jobs, macOS sampling permissions, stale cleanup.
8. `report-schema.md`
   - Versioned JSON fields and compatibility rules.

The CLI `--help` must avoid claims stronger than the backend. It should say “limits a workload using the strongest available platform backend” rather than “guarantees the process never exceeds N bytes.”

---

## 33. Resolved design decisions

The following are deliberate decisions, not pending questions:

- Whole workload is the default and normal scope.
- The direct child is reaped through its owned handle, never process-table disappearance.
- A memory-limit outcome returns `124`.
- Monitoring failure after launch fails closed and returns `125`.
- Kernel-backed mode is available initially on Linux cgroup v2 and Windows Job Objects.
- macOS is a documented watchdog backend.
- Default command lifetime kills leftover descendants when the direct child exits.
- Wrapper output uses stderr; JSON automation uses a separate report file.
- Limits and measurements are `u64`.
- Virtual memory is not the default and is never described as physical consumption.
- Linux hard mode defaults to zero additional cgroup swap unless explicitly changed.
- Windows uses job commit and terminates the job on near-cap notification.

---

## 34. Implementation investigations that do not change the contract

These details should be validated with prototypes before code freeze:

- Exact macOS `RUSAGE_INFO_*` version selection across the supported deployment target range.
- Best available birth-identity field for PID-reuse protection on macOS.
- Whether direct cgroupfs delegation alone is sufficient for the first Linux release or whether a systemd provider is required for acceptable usability.
- Optimal watchdog discovery interval relative to memory-sample interval.
- Native Windows page/granularity value used for the notification margin.
- Guardian behavior under terminal closure, parent crash, and package upgrade.

If a platform API cannot support a documented guarantee, the guarantee must be weakened or the backend must fail capability probing. The implementation must not silently substitute an unrelated metric or weaker containment path.

---

## 35. Final design position

`memcordon` should be built as a **workload supervisor with explicit platform backends**, not as a cross-platform process-table polling loop.

The design completely addresses conventional implementation defects: child reaping, exit status, unchecked arithmetic, panic-based errors, stdout corruption, busy spinning, and missing integration tests.

It addresses descendant containment and hard limits as far as operating-system primitives permit:

- Strong, kernel-backed containment on Linux and Windows.
- Honest, bounded, best-effort monitoring on macOS.

Where identical semantics are impossible, the package exposes the difference rather than hiding it. That transparency is part of the correctness contract.

---

## 36. References

### Existing project and Rust lifecycle

- Existing repository: <https://github.com/shadyfennec/memlimit>
- Rust `std::process::Child`: <https://doc.rust-lang.org/std/process/struct.Child.html>

### Linux

- Linux cgroup v2 documentation: <https://docs.kernel.org/admin-guide/cgroup-v2.html>

Relevant documented interfaces include `memory.current`, `memory.max`, `memory.peak`, `memory.events`, `memory.oom.group`, `cgroup.events`, and `cgroup.kill`.

### Windows

- Job Objects overview: <https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>
- `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information>
- `JOBOBJECT_BASIC_LIMIT_INFORMATION`: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information>
- `AssignProcessToJobObject`: <https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject>
- Job completion-port messages: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port>
- Job notification limits: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_notification_limit_information>
- `CreateProcess`: <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw>

### macOS

- `kqueue`/`kevent` and `EVFILT_PROC`: <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html>
- `posix_spawnattr_setpgroup`: <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/posix_spawnattr_setpgroup.3.html>
- `setsid`: <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setsid.2.html>
- `setrlimit`: <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html>
- Apple documentation noting the `proc_pid_rusage` correspondence: <https://developer.apple.com/documentation/endpointsecurity/es_proc_check_type_pidrusage>

### Supplied evidence

- User-provided file: `memlimit-defect-report.md`, “`memlimit --children` does not exit after its child exits on macOS.”
