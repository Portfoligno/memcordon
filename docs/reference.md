# MemCordon contract reference

This reference defines MemCordon's public CLI, platform behavior, status
precedence, and machine-readable output contracts. For installation and a
first run, see the [README](../README.md).

## Invocation

```text
memcordon [EXECUTION OPTIONS] [BUDGET]... [--] COMMAND [ARGUMENT]...
memcordon help TOPIC
memcordon doctor [--json] [--require hard|watchdog]
memcordon plan [POLICY OPTIONS] [--json] [BUDGET]...
memcordon clean [--dry-run] [--json]
```

Budgets are optional, contiguous, and order-independent. At most one `+MEMORY` and one `+TIME` are accepted. Time units are `ms`, `s`, and `m`; `h` is not accepted. The explicit `--` boundary is required for programs beginning with `+` or `-`, and for utility-like program names in the first position. Every argument after the program is opaque native argv.

Topic help is available for `usage`, `budgets`, `memory`, `deadline`,
`lifecycle`, `restart`, `backoff`, `circuit`, `output`, `utilities`,
`exit-status`, and `all`. `help` selects this namespace only as the first token;
after options or budgets it is a workload program, and `-- help` is the explicit
boundary form.

No memory budget installs or samples a MemCordon memory policy and cannot produce status 124. No time budget installs a deadline and cannot produce status 123. Containment remains active without either budget.

MemCordon never parses command strings, launches a shell, or defines a custom
environment-variable control plane. Program and arguments remain distinct
native values on every attempt.

## Budget grammar

Memory budgets contain exactly one leading ASCII `+`. The remainder accepts
bare bytes, `B`, decimal `KB` through `EB`, and binary `KiB` through `EiB`.
Decimal fractions round upward. Ambiguous units such as `G`,
overflow, non-ASCII text, and repeated leading plus signs are rejected.

Time budgets use decimal `ms`, `s`, or `m` values and round upward to a whole
millisecond. Overflow, unsupported units (including `h`), signs, and exponent
notation are rejected. An explicit zero configures a zero ceiling or immediate
deadline and remains distinct from omission. When two
budgets are present, their original order is retained in reports even though
the effective memory and deadline policies are typed separately.

## Execution options

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
| `--backoff-base` | duration of at least 1 ms | `250ms` |
| `--backoff-multiplier` | exact decimal from 1 through 100 | `4` |
| `--backoff-asymptote` | duration of at least 1 ms | `15m` |
| `--backoff-recovery-half-life` | duration of at least 1 ms | `15m` |
| `--circuit-threshold` | positive decayed failure score | unset |
| `--circuit-cooldown` | nonnegative duration | unset |
| `--circuit-half-life` | duration of at least 1 ms | backoff recovery half-life |
| `--report` | existing-parent filesystem path | unset |
| `--summary` | flag | false |
| `--quiet` | flag | false |

Options precede the budget block. MemCordon removes at most one exact `--`
after the budgets. `--summary` writes one final line to stderr and conflicts
with `--quiet`. Quiet mode never suppresses required diagnostics, cleanup
errors, child streams, or a required report. Execution reports never use
stdout, and `-` is not a report path.

Restart tuning is valid only when restart is enabled. Circuit threshold and
circuit cooldown must be supplied together; the circuit half-life is an
optional override that is valid only with that pair. A requested restart
condition without its corresponding budget is recorded as dormant rather than
treated as effective.

## Utilities

`doctor` prints the version and selected backend. `doctor --json` emits
schema-2 tool and host identity, selected/available/unavailable backend
capabilities and limitations, and the requirement result. An unmet
`--require hard|watchdog` returns 125.

`plan` resolves policy without launching a target. Text output prints the
selected backend and `launch proof: false`; `plan --json` emits the
schema-3 request and resolution: ordered budgets, requested/effective policy,
dormant restart conditions, effects, and limitations. Backoff configuration is
at `request.restart.backoff`; `resolution.backoff_sample_ms` holds the first
calculated wait when restart is enabled, otherwise `[]`.

`clean` removes only stale MemCordon-owned backend artifacts. `--dry-run`
reports candidates without changing the host. Clean JSON remains schema-1;
incomplete cleanup returns 125.

Machine-readable consumers must inspect `schema_version`.

Root `--version` prints one line. Private launcher and guardian routes do not
appear in public help or the Rust facade.

## Behavior summary

MemCordon treats the command and descendants within its platform boundary as
one workload, reports explicitly named platform metrics, preserves ordinary
exit status when no higher-precedence result applies, and uses bounded,
non-busy monitoring. When a configured limit or monitoring failure requires
termination, it performs bounded cleanup and reports any failure. On macOS,
sampling can overshoot or miss short bursts, and escaped descendants can leave
the sampled boundary.

![Non-normative overview of workload supervision, named metrics, cleanup, status precedence, and bounded polling](assets/key-guarantees.png)

## Platform behavior

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

## Deadline and restart policy

Execution is one-shot unless `--restart` or `--restart-on both|memory-limit|deadline` is supplied. `--restart-on` independently enables restart. Enabled restart defaults to both applicable conditions and unlimited additional launches. A finite `--restart-limit N` counts additional launches. Only selected MemCordon limits restart, and only after the child and helpers are reaped, the workload is proven empty, and containment is removed or incapable of retaining members.

Attempt deadlines reset at the platform authorization point: Linux release-byte write, Windows suspended-thread resume, or macOS pre-spawn. A supervision deadline starts with the first authorization and includes later cleanup, setup, backoff, and cooldown. It is terminal and cannot trigger restart. Confirmed memory evidence wins a same-cycle deadline race.

Each retry delay first recovers the stored interval toward `--backoff-base`, then
applies a logistic adjustment relative to `--backoff-asymptote`:

```text
decay = 2 ** (-elapsed_since_last_backoff / recovery_half_life)
recovered = base + (current - base) * decay
next = asymptote * multiplier * recovered
       / (asymptote + (multiplier - 1) * recovered)
```

`base` is the pre-event resting state and `asymptote` is the interval approached
through repeated restart events. They are independently positive: either may be
larger, or they may be equal. The returned wait can lie on either side of either
configured interval.
Recovery uses all time since the previous backoff, including its scheduled wait,
without requiring success or a reset. By default, the first wait is 1s,
immediate failures converge near 11m30s, and quiet periods move the next wait
toward 1s.

When the circuit breaker is configured, each limit failure updates an
exponentially decayed pressure score:

```text
score = 1 + previous_score * 2 ** (-elapsed_since_previous_failure / circuit_half_life)
```

The circuit opens when this score reaches `--circuit-threshold`. Its half-life
defaults to `--backoff-recovery-half-life`; `--circuit-half-life` selects an
independent timescale. This is continuous decay, not a rolling-window count.
Opening the circuit, or failing a half-open probe, schedules the greater of the
calculated logistic wait and `--circuit-cooldown`. The logistic backoff always
advances, so enabling the circuit never shortens the normal retry wait.

Returned durations round upward to whole milliseconds. Reports identify the
schedule as `half-life-logistic-v1` and expose `base_interval_ms`,
`multiplier_numerator`, `multiplier_denominator`, `asymptote_interval_ms`, and
`recovery_half_life_ms`. Circuit policy reports expose `threshold`,
`half_life_ms`, and `cooldown_ms`.

## Execution report schema-4

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
include omitted attempts. Half-life waits set
`attempts[].restart_decision.decision` and
`attempts[].restart_decision.wait_kind` to `half-life-logistic-backoff`;
`attempts[].restart_decision.half_life_logistic_sequence_index` is zero-based,
and `supervision.restart.half_life_logistic_waits` counts all such waits. A
deadline reached during backoff, cooldown, or later setup is a top-level
outside-attempt terminal. Initial spawn errors use typed
`initial_spawn_failure` provenance; statuses 126 and 127 derive exclusively
from `not-executable` and `not-found`. Consumers must reject unsupported schema
versions.

## Exit status and precedence

| Status | Meaning |
|---:|---|
| child code | Ordinary direct-child exit when representable and cleanup succeeds |
| `123` | MemCordon elapsed-time deadline |
| `124` | Confirmed workload memory-limit event |
| `125` | Backend, setup, monitoring, cleanup, report, or restart-safety failure |
| `126` | Command found but not executable |
| `127` | Command not found |
| `2` | Usage diagnostic |
| `128 + signal` | Unix interruption or child signal when no higher-precedence event applies |

Within one observation cycle, confirmed memory evidence precedes deadline,
monitor/wait failure, interruption, and ordinary completion. Cleanup failure can
replace an otherwise ordinary or interrupted result with status 125. A child
may independently return a reserved number; the report establishes provenance.

## Security boundary

MemCordon controls the documented workload resources and lifecycle; it is not a hostile-code security sandbox. On macOS, a descendant that deliberately escapes into another session can also leave the sampled workload boundary.
