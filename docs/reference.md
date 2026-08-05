# MemCordon contract reference

This reference defines MemCordon's public CLI, platform behavior, status precedence, and machine-readable output contracts.

## Invocation

```text
memcordon [EXECUTION OPTIONS] [BUDGET]... [--] COMMAND [ARGUMENT]...
memcordon doctor [--json] [--require hard|watchdog]
memcordon plan [POLICY OPTIONS] [BUDGET]...
memcordon clean [--dry-run] [--json]
```

Budgets are optional, contiguous, and order-independent. At most one `+MEMORY` and one `+TIME` are accepted. Time units are `ms`, `s`, and `m`; `h` is not accepted. The explicit `--` boundary is required for programs beginning with `+` or `-` and for utility-like program names. Every argument after the program is opaque native argv.

No memory budget installs or samples a MemCordon memory policy and cannot produce status 124. No time budget installs a deadline and cannot produce status 123. Containment remains active without either budget.

## Deadline and restart policy

Attempt deadlines reset at the platform authorization point: Linux release-byte write, Windows suspended-thread resume, or macOS pre-spawn. A supervision deadline starts with the first authorization and includes later cleanup, setup, backoff, and cooldown. It is terminal and cannot trigger restart. Confirmed memory evidence wins a same-cycle deadline race.

Execution is one-shot unless `--restart` or `--restart-on both|memory-limit|deadline` is supplied. `--restart-on` independently enables restart. Enabled restart defaults to both applicable conditions and unlimited additional launches. A finite `--restart-limit N` counts additional launches. Only selected MemCordon limits restart, and only after the child and helpers are reaped, the workload is proven empty, and containment is removed or incapable of retaining members.

Backoff model `logistic-odds-v1` uses exact rational arithmetic and upward whole-millisecond rounding:

```text
next = max * multiplier * current / (max + (multiplier - 1) * current)
```

Defaults are 1s initial, multiplier 2, and 30s maximum. Circuit breaker options `--restart-burst`, `--restart-window`, and `--cooldown` are all-or-none. Cooldown replaces a logistic wait and does not advance its sequence.

## Platforms

Linux uses the installed MemCordon CLI launcher gate: READY validation, cgroup assignment and readback, guardian startup, release byte, then typed target `CommandExt::exec`. Time-only and budgetless execution require containment delegation but not the memory controller.

Windows creates the target suspended, assigns it to a fresh kill-on-close Job Object, then resumes it. Memory flags and notifications are configured only with a memory budget.

macOS creates a fresh process group and launches its guardian through an explicit `MemcordonExecutable`. Sampling is absent without memory. There is no hidden workload-drain deadline; only `+TIME` sets an elapsed-time limit.

## Status and schemas

Status 123 is a terminal MemCordon deadline, 124 a confirmed memory-limit event, and 125 a wrapper, monitoring, cleanup, report, or restart-safety failure. Ordinary child statuses are otherwise preserved.

Execution reports use schema 3. They include nullable budgets, requested/effective policy, backend capability, supervision summary, bounded attempt history, aggregates, restart decisions, and terminal provenance. Detailed history retains attempt 1 and the latest 255 later attempts while aggregates include every attempt. `plan` and `doctor` use schema 2. `clean` remains schema 1. Consumers must inspect `schema_version`.

MemCordon never parses command strings, launches a shell, or defines a custom environment-variable control plane. Program and arguments remain distinct native values on every attempt.

## Budget grammar

Memory budgets contain exactly one leading ASCII `+`. The remainder accepts
bare bytes, `B`, decimal `KB` through `EB`, and binary `KiB` through `EiB`.
Decimal fractions round upward. Zero, ambiguous units such as `G`, overflow,
non-ASCII text, and repeated leading plus signs are rejected.

Time budgets use decimal `ms`, `s`, or `m` values and round upward to a whole
millisecond. Zero, overflow, unsupported units (including `h`), signs, and
exponent notation are rejected. When two budgets are present, their original
order is retained in reports even though the effective memory and deadline
policies are typed separately.

### Execution options

| Option | Values | Default |
|---|---|---|
| `--enforcement` | `auto`, `hard`, `watchdog` | `auto` |
| `--wait-for` | `command`, `workload` | `command` |
| `--metric` | `native`, `physical-footprint`, `rss`, `virtual` | `native` |
| `--poll-interval` | duration of at least 10 ms | `50ms` |
| `--signal-grace` | duration | `2s` |
| `--limit-grace` | duration | `0s` |
| `--swap` | byte size, `0`, `0B`, `unlimited`, `host` | `0B` |
| `--deadline-scope` | `attempt`, `supervision` | `attempt` |
| `--restart` | flag | false |
| `--restart-on` | `both`, `memory-limit`, `deadline` | unset |
| `--restart-limit` | additional-launch count or `unlimited` | `unlimited` |
| `--backoff-initial` | duration | `1s` |
| `--backoff-multiplier` | exact decimal greater than 1 and at most 100 | `2` |
| `--backoff-max` | duration | `30s` |
| `--restart-burst` | positive count | unset |
| `--restart-window` | duration | unset |
| `--cooldown` | duration | unset |
| `--report` | existing-parent filesystem path | unset |
| `--summary` | flag | false |
| `--quiet` | flag | false |

Options precede the budget block. MemCordon removes at most one exact `--`
after the budgets. `--summary` writes one final line to stderr and conflicts
with `--quiet`. Quiet mode never suppresses required diagnostics, cleanup
errors, child streams, or a required report. Execution reports never use
stdout, and `-` is not a report path.

Restart tuning is valid only when restart is enabled. The three circuit-breaker
options are an atomic group. A requested restart condition without its
corresponding budget is recorded as dormant rather than treated as effective.

## Utilities

`doctor` reports tool and host identity, selected, available, and unavailable
backends, lifecycle and memory capabilities, startup containment, supported
deadline scopes and restart conditions, and limitations. `--require hard` or
`--require watchdog` returns 125 when the selected backend does not satisfy the
predicate. Doctor JSON uses schema 2.

`plan` applies the same qualification and policy resolver as execution without
launching a target. It reports ordered budget tokens, requested and effective
memory/deadline/restart policy, dormant conditions, option effects,
limitations, and `launch_proof: false`. Plan JSON uses schema 2.

`clean` removes only stale MemCordon-owned backend artifacts. `--dry-run`
reports candidates without changing the host. Clean JSON remains schema 1;
incomplete cleanup returns 125.

Root `--version` prints one line. Private launcher and guardian routes do not
appear in public help or the Rust facade.

## Behavior summary

The following illustration summarizes supervision goals, not universal guarantees. The exact workload membership, metrics, platform limitations, and status precedence documented below are the contract. In particular, sampled macOS monitoring can overshoot or miss short bursts, deliberately escaped descendants can leave its sampled boundary, and higher-precedence failures can replace a child status. "Low overhead" describes the bounded, non-busy polling design; it is not a measured performance claim.

![Overview of MemCordon workload supervision, metrics, cleanup, status handling, and polling goals](assets/key-guarantees.png)

## Backend-effective behavior

| Platform | Backend | Startup and effective behavior |
|---|---|---|
| Linux | `linux-cgroup-v2` | An installed MemCordon CLI starts as a gated process-group leader. The supervisor verifies cgroup assignment, validates launcher readiness, starts a guardian, and then releases the launcher to execute the typed target. |
| Windows | `windows-job-object` | The target is created suspended, assigned to a fresh unnamed kill-on-close Job Object, and resumed only after assignment. The native metric is job-wide committed memory. |
| macOS | `macos-watchdog` | A process group is established before execution. Known descendants are sampled only when a memory budget exists; enforcement can overshoot or miss short bursts. |
| Other Unix | none | Parsing remains portable, then execution fails before target launch. |

An accepted option is not necessarily effective on every backend. Typed option
effects in plan and execution reports describe ignored or adjusted settings.

### Linux cgroup v2

The process must run below a usable delegated cgroup v2 boundary. MemCordon
creates a package-owned child cgroup and always uses it for containment. The
memory controller and its files are required only when a memory budget is
requested; time-only and budgetless execution must not manufacture a memory
policy.

The installed CLI launcher emits and validates a versioned READY record. After
cgroup assignment and readback and guardian startup, the supervisor writes one
release byte. The launcher then uses typed `CommandExt::exec`, preserving PID,
native argv, inherited descriptors, current directory, and environment. A
release/exec-status race must preserve typed target-spawn failure provenance.

Memory evidence comes from `memory.events`; sampled `memory.current` is not a
substitute for the authoritative event. Under workload waiting, the cgroup is
observed until empty or another terminal event occurs. Cleanup uses whole-cgroup
termination, reaps the direct child and guardian, and removes the cgroup before
a restart can be authorized.

### Windows Job Objects

Containment is configured even without a memory budget. Memory limit flags and
completion-port memory notifications are added only when a budget exists.
Assignment precedes thread resume so target code cannot escape startup
containment. Enclosing Job Object policy can still prevent assignment.

The hard metric is job-wide committed memory, not resident physical memory.
Console graceful termination is application dependent. Limit grace applies to
memory and deadline terminals; signal grace applies only to external console
interruption. Closing or force-terminating the Job Object must leave no live
members before restart.

### macOS watchdog

MemCordon establishes a fresh process group before target execution, tracks the
direct child through an owned handle, and discovers descendants by process
identity. Physical footprint, RSS, and virtual size remain distinct metrics.
Sampling can miss short bursts, cannot prevent overshoot, and cannot recover a
descendant that deliberately escapes into another session.

Library callers provide an explicit absolute `MemcordonExecutable` for the
guardian. Workload waiting has no implicit drain timeout. It ends on workload
completion, explicit deadline, interruption, or a monitoring/cleanup failure.

## Memory metrics

| Name | Meaning |
|---|---|
| `linux-cgroup-memory` | Native Linux cgroup memory charge controlled by `memory.max` |
| `windows-job-commit` | Native Windows job-wide committed memory |
| `physical-footprint-sum` | Sum of physical footprint for known macOS workload processes |
| `rss-sum` | Summed resident-set size; shared pages may be counted more than once |
| `virtual-size-sum` | Summed virtual address-space size, not physical memory |

These quantities are not interchangeable. Configured values and measurements
use `u64`; a saturated aggregate proves comparison against representable limits
but is no longer an exact peak.

## Workload membership and waiting

Descendants are workload members by default. `--wait-for` controls behavior
after the direct child exits; it does not alter startup membership.

| Platform | `command` | Requested `workload` |
|---|---|---|
| Linux | Cleans remaining cgroup members | Waits for the cgroup to become empty |
| Windows | Cleans remaining Job Object members | Backend capability reporting describes any effective adjustment |
| macOS | Cleans known process-group members | Waits for discovered members without a hidden timeout |

## Execution report schema 3

`--report PATH` requests a mandatory pretty-printed JSON document ending in
exactly one newline. It is written through a same-directory temporary file,
synchronized, and atomically persisted. The parent directory must exist. A
write failure returns 125.

The envelope contains tool and native invocation identity, requested/effective
policy, nullable backend capability, a supervision summary, bounded attempt
records, and either terminal supervision or pre-supervision error provenance.
Native non-text arguments use an authoritative base64 raw representation:
`unix-bytes-base64` or `windows-u16le-base64`.

Its top-level sections are `tool`, `invocation`, `policy`, `backend`,
`supervision`, `attempts`, and `error`. `invocation.budget_tokens` preserves
source order. Normalized memory and deadline values are nullable. `policy`
separates requested and effective values and records dormant restart
conditions. `supervision` records duration, terminal phase and outcome,
wrapper status, attempt and restart counters, bounded-history metadata,
aggregate outcomes, maximum observed peak, deadline state, and circuit state.

Attempt history has capacity 256. Attempt 1 is retained permanently and the
latest 255 attempts form a contiguous ascending tail. Declared retained,
omitted, total, aggregate, authorization, restart, terminal-attempt, phase, and
wrapper-status fields are mutually checked when reports are deserialized. Each
attempt records its number, kind, phase, offsets, target PID, launch evidence,
outcome or error provenance, cleanup proof, and restart decision. Aggregates
include omitted attempts. A deadline reached during backoff, cooldown, or later
setup is a top-level outside-attempt terminal. Initial spawn errors use typed
`initial_spawn_failure` provenance; statuses 126 and 127 derive exclusively
from `not-executable` and `not-found`. Consumers must reject or explicitly
migrate unsupported schema versions.

## Exit status and precedence

| Status | Meaning |
|---:|---|
| child code | Ordinary direct-child exit when representable and cleanup succeeds |
| `123` | MemCordon elapsed-time deadline |
| `124` | Confirmed workload memory-limit event |
| `125` | Backend, setup, monitoring, cleanup, report, or restart-safety failure |
| `126` | Command found but not executable |
| `127` | Command not found |
| `2` | Usage or removed-interface migration diagnostic |
| `128 + signal` | Unix interruption or child signal when no higher-precedence event applies |

Within one observation cycle, confirmed memory evidence precedes deadline,
monitor/wait failure, interruption, and ordinary completion. Cleanup failure can
replace an otherwise ordinary or interrupted result with status 125. A child
may independently return a reserved number; the report establishes provenance.

## Security boundary

MemCordon controls the documented workload resources and lifecycle; it is not a hostile-code security sandbox. On macOS, a descendant that deliberately escapes into another session can also leave the sampled workload boundary.
