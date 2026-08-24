# MemCordon contract reference

Use this reference to configure workload limits and completion, understand
platform-specific behavior, or integrate with MemCordon's machine-readable
output. For installation and a first run, see the [README](../README.md).

## Invocation

```text
memcordon [OPTION|BUDGET]... [--] COMMAND [ARGUMENT]...
memcordon help [TOPIC]
memcordon doctor [--json] [--require hard|watchdog|sealed]
memcordon plan [OPTION|BUDGET]...
memcordon clean [--dry-run] [--json]
```

Options and budgets may be interleaved before the command. At most one
`+MEMORY` and one `+TIME` are accepted. Use the explicit `--` boundary before a
program beginning with `+` or `-`, or before a utility name in the first
position. Once the command starts, every remaining argument passes through as
opaque native argv.

Omitting `TOPIC` lists the available topics. Topic help is available for
`usage`, `budgets`, `memory`, `containment`, `deadline`, `lifecycle`, `restart`, `backoff`,
`circuit`, `output`, `utilities`, `exit-status`, and `all`.

- Without `+MEMORY`, MemCordon installs no memory policy and cannot produce
  status `124`.
- Without `+TIME`, MemCordon installs no deadline and cannot produce status
  `123`.
- Containment remains active when either or both budgets are omitted.

MemCordon does not interpret command strings or insert a shell. The program and
arguments remain distinct native values on every attempt.

## Budget grammar

Memory budgets contain exactly one leading ASCII `+`. The remainder accepts
bare bytes, `B`, decimal `KB` through `EB`, and binary `KiB` through `EiB`.
Decimal fractions round upward. Ambiguous units such as `G`,
overflow, non-ASCII text, and repeated leading plus signs are rejected.

Time budgets and duration-valued options use decimal `ms`, `s`, `m`, or `h`
values and round upward to a whole millisecond. Overflow, unsupported units,
signs, and exponent notation are rejected. An explicit zero configures a zero
ceiling or immediate deadline and remains distinct from omission. Reports
retain the relative order of memory and time budget tokens, even when options
appear between them.

## Execution options

| Option | Values | Default |
|---|---|---|
| `--enforcement` | `auto`, `hard`, `watchdog` | `auto` |
| `--wait-for` | `command`, `workload` | `command` |
| `--command-exit-grace` | duration | `0s` |
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

With `+MEMORY`, Linux and Windows always enforce their backend-native kernel
metric; non-native `--metric` selections are effective only on the macOS
watchdog. A separate `--swap` policy is effective only on Linux cgroup v2;
Windows and macOS have no separately configurable swap policy, so the default
`--swap 0B` is retained only as a requested value there while effective swap
remains unset. Plan and execution reports record the effective policy and any
ignored effects.

`--summary` writes one final line to stderr and conflicts with `--quiet`. Quiet
mode never suppresses required diagnostics, cleanup errors, child streams, or a
required report. Execution reports never use stdout, and `-` is not a report
path.

Restart tuning is valid only when restart is enabled. Circuit threshold and
circuit cooldown must be supplied together; the circuit half-life is an
optional override that is valid only with that pair. An explicit
`--command-exit-grace` requires `--wait-for command` but does not require a
budget.

## Completion and workload membership

The direct command and every process retained within the platform boundary form
one workload. `--wait-for` changes when MemCordon completes, not which processes
belong to that workload.

| Value | After the direct command exits | Completion condition |
|---|---|---|
| `command` (default) | Wait up to command-exit grace for remaining members to finish naturally, then forcibly terminate and clean survivors | Required cleanup and teardown succeed; the direct command's status is then eligible to be returned |
| `workload` | Keep remaining workload members running and continue supervision | The workload becomes empty, or a deadline, interruption, configured limit, or monitoring/cleanup failure produces another terminal result |

The default command-exit grace is zero, so command mode force-cleans remaining
members without an added delay. A nonzero `--command-exit-grace` sends no signal
during the grace: MemCordon returns early if the workload empties and otherwise
force-cleans survivors at expiry. The direct command's status is returned only
after cleanup succeeds; cleanup failure returns `125`.

The three grace options have separate triggers:

- `--command-exit-grace` allows signal-free natural drain after ordinary direct
  command exit.
- `--signal-grace` applies after an external interruption.
- `--limit-grace` applies after a configured memory or time limit and therefore
  requires at least one budget.

Workload mode does not promote descendant statuses into a combined exit status.
The direct command remains the ordinary status authority while MemCordon waits
for the workload to empty. On Linux and macOS, workload waiting has no implicit
drain timeout; without a configured deadline or another terminal event, a
surviving member can keep the attempt alive indefinitely. An attempt-scoped
`+TIME` bounds one attempt, not an unlimited restart sequence; use a supervision
deadline when the whole supervision run must be bounded.

| Platform | `command` | Requested `workload` |
|---|---|---|
| Linux | Observe whole-cgroup emptiness during command-exit grace, then force whole-cgroup cleanup | Observe the cgroup until it is empty |
| Windows | Observe Job Object activity during command-exit grace, then terminate remaining Job Object members | Currently adjusted to effective `command`; plan and execution reports record an ignored `wait-for` effect |
| macOS | Observe discovered membership during command-exit grace, then force-clean known process-group/discovered members | Wait for discovered members to disappear; deliberately escaped descendants remain outside the sampled boundary |

### Unix launcher examples

```console
memcordon sh -c 'sleep 3600 & exit 0'
```

The shell is the direct command. With the zero default grace, MemCordon
force-cleans the contained `sleep` and then returns the shell's status if no
higher-precedence result applies.

```console
memcordon --command-exit-grace 3s -- sh -c 'sleep 2 & exit 0'
```

The contained `sleep` can finish naturally during the signal-free grace. If it
survives three seconds, MemCordon force-cleans it before returning the shell's
retained status.

```console
memcordon --wait-for workload +10s -- sh -c 'sleep 3600 & exit 0'
```

On Linux and macOS, workload mode keeps supervising after the shell exits. The
attempt deadline bounds this attempt; if `sleep` is still alive at the deadline,
MemCordon cleans the workload and returns `123` unless cleanup fails.

## Exit status and precedence

| Status | Meaning |
|---:|---|
| child code | Ordinary direct-command exit when representable and cleanup succeeds |
| `123` | MemCordon elapsed-time deadline |
| `124` | Confirmed workload memory-limit event |
| `125` | Backend, setup, monitoring, cleanup, report, or restart-safety failure |
| `126` | Command found but not executable |
| `127` | Command not found |
| `2` | Usage diagnostic |
| `128 + signal` | Unix interruption or child signal when no higher-precedence event applies |

The direct command remains the ordinary status authority in both completion
modes. Within one observation cycle, confirmed memory evidence precedes
deadline, monitor or wait failure, interruption, and ordinary completion.
Cleanup failure can replace an otherwise ordinary or interrupted result with
status `125`. Reports distinguish a child's reserved-number exit from a
MemCordon-generated status.

## Utilities

| Utility | Result | JSON contract |
|---|---|---|
| `doctor` | Prints the version and selected backend; `--require hard|watchdog` returns `125` when unmet | Schema-2 host, backend, capability, limitation, and requirement data |
| `plan` | Resolves policy without launching; text includes `launch proof: false` | Schema-4 budgets, requested/effective policy, dormant conditions, effects, limitations, and backoff sample |
| `clean` | Removes stale MemCordon-owned artifacts; `--dry-run` only lists them; incomplete cleanup returns `125` | Schema-1 cleanup result |

In plan JSON, backoff configuration is under `request.restart.backoff`.
`resolution.backoff_sample_ms` contains the first calculated wait when restart
is enabled and is otherwise empty.

Machine-readable consumers must inspect `schema_version`.

Human-readable output follows `NO_COLOR`, `CLICOLOR`, and `CLICOLOR_FORCE` and
is plain when redirected by default. JSON, report files, and child streams are
never styled. Root `--version` prints one line.

## Platform behavior

![Non-normative overview of workload supervision, named metrics, cleanup, status precedence, and bounded polling](assets/key-guarantees.png)

| Platform | Backend | Behavior that affects use |
|---|---|---|
| Linux | `linux-cgroup-v2` | Requires a usable delegated cgroup v2 boundary; the target starts only after containment is verified. |
| Windows | `windows-job-object` | The target is created suspended, assigned to a fresh unnamed kill-on-close Job Object, and resumed only after assignment. The native metric is job-wide committed memory. |
| macOS | `macos-watchdog` | Uses a process group and sampled descendant discovery; memory enforcement can overshoot or miss short bursts. |
| Other Unix | none | Parsing remains portable, then execution fails before target launch. |

An accepted option is not necessarily effective on every backend. Typed option
effects in plan and execution reports describe ignored or adjusted settings.

### Linux cgroup v2

The process must run below a usable delegated cgroup v2 boundary. MemCordon
creates a package-owned child cgroup for every workload. The memory controller
is required only when `+MEMORY` is present.

The target is released only after cgroup assignment is read back and the
guardian is ready. Execution preserves native argv, inherited descriptors,
current directory, and environment; launch failures retain typed provenance.

Memory-limit evidence comes from `memory.events`; sampled `memory.current` is
not a substitute for that event. Workload mode observes the cgroup until empty
or another terminal event occurs. Cleanup terminates the whole cgroup, reaps the
direct child and guardian, and removes the cgroup before a restart is authorized.

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

## Deadline and restart policy

### Restart eligibility

Execution is one-shot unless `--restart` or
`--restart-on both|memory-limit|deadline` is supplied. `--restart` and
`--restart-on both` request both limit conditions. A memory-limit condition is
effective only with `+MEMORY`; a deadline condition is effective only with an
attempt-scoped `+TIME`, because a supervision deadline is terminal. If at least
one condition is effective, any other requested condition is reported as
dormant; requesting only an inapplicable condition is rejected. Restart allows
unlimited additional launches by default; `--restart-limit N` counts additional
launches. Only selected MemCordon limits restart, and only after the direct child
and helpers are reaped, the workload is proven empty, and containment is removed
or incapable of retaining members.

### Deadline scopes

An attempt deadline resets when each target is authorized to run: at the Linux
release-byte write, Windows suspended-thread resume, or macOS pre-spawn. It may
trigger a configured restart. A supervision deadline starts with the first
authorization, includes later cleanup, setup, backoff, and cooldown, and is
terminal. Confirmed memory evidence wins a same-cycle deadline race.

### Backoff

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

Returned durations round upward to whole milliseconds. Reports identify the
schedule as `half-life-logistic-v1` and expose `base_interval_ms`,
`multiplier_numerator`, `multiplier_denominator`, `asymptote_interval_ms`, and
`recovery_half_life_ms`.

### Circuit breaker

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

Circuit policy reports expose `threshold`, `half_life_ms`, and `cooldown_ms`.

## Execution reports

`--report PATH` writes a mandatory schema-8 JSON document. The document is
pretty-printed, ends in one newline, and is atomically persisted through a
same-directory temporary file. The parent directory must exist. A write failure
returns `125`.

The envelope contains tool and native invocation identity, requested/effective
policy, nullable backend capability, a supervision summary, bounded attempt
records, and either terminal supervision or pre-supervision error provenance.
Requested and effective policy include `command_exit_grace_ms`, distinct from
the external-interruption and configured-limit grace fields.
Native non-text arguments use an authoritative base64 raw representation:
`unix-bytes-base64` or `windows-u16le-base64`.

Its top-level sections are `tool`, `invocation`, `policy`, `backend`,
`supervision`, `attempts`, and `error`. `invocation.budget_tokens` preserves the
relative budget encounter order; option positions are not encoded. Normalized
memory and deadline values are nullable. `policy` separates requested and
effective values and records dormant restart conditions. `supervision` records
duration, terminal phase and outcome, wrapper status, attempt and restart
counters, bounded-history metadata, aggregate outcomes, maximum observed peak,
deadline state, and circuit state.

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
`initial_spawn_failure` provenance; their wrapper statuses 126 and 127 derive
from `not-executable` and `not-found`. A successfully executed program may also
exit 126 or 127, so consumers distinguish those ordinary child outcomes using
the typed spawn provenance rather than the number alone. Consumers must reject
unsupported schema versions.

## Security boundary

MemCordon controls the documented workload resources and lifecycle; it is not a
hostile-code security sandbox. On macOS, a descendant that deliberately escapes
into another session can also leave the sampled workload boundary.
## Sealed supervision

`--sealed` requires certified process-boundary setup, independent cleanup authority, and terminal emptiness proof. It fails before target authorization if unavailable and never falls back. See [sealed supervision](sealed-supervision.md) for the normative threat model and exclusions.
