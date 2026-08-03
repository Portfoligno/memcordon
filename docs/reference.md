# MemCordon contract reference

This document describes the public contracts of the source revision that
contains it. Automation should pin a MemCordon release and consult the matching
tagged copy. Generated `--help`, the CLI parser, and serialized Rust types are
the implementation sources of truth.

MemCordon addresses accidental or buggy resource exhaustion, not hostile code.
Use a container, virtual machine, dedicated identity, or platform sandbox when
the workload may attack its supervisor.

<a id="cli"></a>
## CLI

```text
memcordon run [OPTIONS] --memory MEMORY -- COMMAND...
memcordon probe [--json]
memcordon explain [--enforcement MODE] [--memory MEMORY]
memcordon cleanup [--dry-run]
memcordon version [--verbose]
memcordon compat [--children] [--virtual] AMOUNT COMMAND...
```

The `--` boundary is required before the `run` command vector. MemCordon passes
the program and arguments directly and does not parse shell source.

### Run options

| Option | Accepted value | Default |
|---|---|---|
| `--memory` | byte size | required |
| `--enforcement` | `auto`, `hard`, `watchdog` | `auto` |
| `--lifetime` | `command`, `workload` | `command` |
| `--metric` | `native`, `physical-footprint`, `rss`, `virtual` | `native` |
| `--poll-interval` | duration, at least 10 ms | `50ms` |
| `--signal-grace` | duration | `2s` |
| `--limit-grace` | duration | `0s` |
| `--swap` | byte size, `0`, `0B`, `unlimited`, or `host` | `0B` |
| `--report` | `none`, `text`, `json` | `none` |
| `--report-file` | path; required with JSON reporting | unset |
| `--quiet` | flag | false |
| `--no-backend-warning` | flag | false |

Memory sizes accept bare bytes, `B`, decimal `KB` through `EB`, and binary
`KiB` through `EiB`. Decimal fractions are rounded upward to a whole byte;
ambiguous units such as `G`, zero memory limits, and values outside `u64` are
rejected. Durations accept decimal `ms`, `s`, or `m` values and are rounded
upward to a whole millisecond.

`--quiet` suppresses optional wrapper output, not child streams or required
errors. `--no-backend-warning` suppresses the warning emitted when macOS `auto`
selects watchdog enforcement; it does not change the backend.

Text reports are written to stderr. Only JSON reporting writes
`--report-file`; a supplied path has no effect on text reporting.

<a id="compat"></a>
### `memlimit` compatibility

`memcordon compat [--children] [--virtual] AMOUNT COMMAND...` is a macOS-only
migration interface. It always requests watchdog enforcement. `--children` is a
deprecated no-op because descendants are already workload members, and
`--virtual` selects the compatibility-only virtual-size metric. New use should
prefer `memcordon run`.

<a id="backends"></a>
## Backend-effective behavior

The host platform determines which backend can run. An accepted option is not
necessarily effective on every backend.

| Platform | Backend | Enforcement accepted | Effective policy |
|---|---|---|---|
| Linux | `linux-cgroup-v2` | `auto`, `hard`; rejects `watchdog` | Both lifetimes, limit grace, signal grace, and swap policy are implemented; non-native metric requests do not change the cgroup metric |
| Windows | `windows-job-object` | `auto`, `hard`; rejects `watchdog` | Command-style cleanup always applies; `workload` lifetime, limit grace, swap, and non-native metrics have no effect; signal grace applies to interruption |
| macOS | `macos-watchdog` | `auto`, `watchdog`; rejects `hard` | Both lifetimes, metric selection, polling, signal grace, and limit grace are implemented; swap has no effect |
| Other Unix | none | none | `run` fails with `MCUNSUPPORTED-UNIX` before target launch |

### Linux cgroup v2

MemCordon creates a package-owned child cgroup, configures its memory policy,
assigns and verifies a gated launcher, and releases the target only after that
setup succeeds. Its process must be below an empty cgroup v2 ancestry entry
marked with systemd `user.delegate=1`, with the memory controller delegated and
available for MemCordon to enable in `cgroup.subtree_control`. Installing
MemCordon does not create this delegation; the session or service manager must
provide it in the exact execution context.

Probe requires `cgroup.procs`, `cgroup.events`, `cgroup.kill`,
`memory.current`, `memory.events`, `memory.max`, and `memory.swap.max`. It
creates an empty child cgroup and verifies write/read-back of
`memory.max=max` and `memory.swap.max=0`. A populated delegation root must be
emptied by the service manager rather than bypassed by MemCordon. Limit evidence
comes from `memory.events`.

The kernel may temporarily report `memory.current` above `memory.max`. Swap is
a separately configured cgroup policy. Some allocation failures can occur
without a recorded group kill; MemCordon turns recorded limit attempts into
complete workload termination where possible. Under workload lifetime,
MemCordon waits without a separate drain timeout until the cgroup becomes empty
or another outcome occurs.

### Windows Job Objects

MemCordon creates the target suspended, assigns it to an unnamed kill-on-close
Job Object, and resumes it only after successful assignment. Probe can create a
Job Object but cannot prove that a future target can be assigned under the
runner's enclosing job. The notification threshold is one native page below
the hard job-wide commit cap.

After direct-child exit, remaining job members are force-terminated regardless
of the requested lifetime. Console graceful termination is application
dependent. JSON preserves a child's full unsigned 32-bit native status even
when the invoking shell cannot represent it.

The job-wide commit cap can cause an application allocation to fail without
immediately ending the application. MemCordon combines the cap with a
completion-port threshold and terminates the job when the notification arrives.

### macOS watchdog

MemCordon establishes a process group before target execution, tracks the
direct child through an owned handle, samples known descendants, and repeatedly
attempts cleanup. Sampling can miss short bursts and cannot prevent overshoot.
An undiscovered descendant can escape by creating a new session.

Under workload lifetime, a discovered workload that remains alive after the
direct child exits fails once total run time exceeds 30 seconds. This is not a
fresh 30-second allowance measured from child exit.

![MemCordon workload handling, metrics, failure handling, status mapping, and watchdog polling](assets/key-guarantees.png)

<a id="metrics"></a>
## Memory metrics

| Name | Meaning |
|---|---|
| `linux-cgroup-memory` | Native Linux cgroup memory charge controlled by `memory.max` |
| `windows-job-commit` | Native Windows job-wide committed memory, not resident physical memory |
| `physical-footprint-sum` | Sum of physical footprint for known macOS workload processes |
| `rss-sum` | Optional macOS summed resident-set size; shared pages may be counted more than once and swapped pages are absent |
| `virtual-size-sum` | Compatibility-only macOS summed virtual size; not physical memory |

These quantities are not directly interchangeable. All configured limits and
measurements use `u64`. A saturated aggregate proves, for comparison purposes,
that every representable limit was crossed, but no longer represents an exact
peak.

<a id="lifetime"></a>
## Workload membership and lifetime

Descendants are workload members by default. Lifetime controls what happens
after the direct child exits; it does not change initial membership.

| Platform | `command` | Requested `workload` |
|---|---|---|
| Linux | Cleans remaining cgroup members | Waits for the cgroup to become empty |
| Windows | Force-cleans remaining Job Object members | Currently ignored; command-style cleanup applies |
| macOS | Cleans known process-group members | Waits for discovered members within the total-run deadline described above |

The run report records the requested lifetime, not a separately resolved
effective lifetime.

<a id="exit-status"></a>
## Exit status

| Status | Meaning |
|---:|---|
| child code | Ordinary direct-child exit when representable and cleanup completes |
| `124` | Confirmed workload memory-limit event |
| `125` | Backend, wrapper, monitoring, required-report, unavailable child status, out-of-range Windows status, or incomplete-cleanup failure |
| `126` | Command found but not executable |
| `127` | Command not found |
| `2` | CLI usage or configuration error before launch |
| `128 + signal` | Unix interruption or child signal when cleanup completes and no higher-precedence event applies |

A confirmed limit maps to 124 and a monitor failure maps to 125. Cleanup errors
or a nonempty workload override an interruption or ordinary child result with
125. Otherwise an interruption, child signal, or ordinary child code is
preserved. A child can independently return a reserved value, so numeric status
alone does not establish provenance.

<a id="probe-json"></a>
## Probe JSON document

`memcordon probe --json` emits an unversioned object:

| Field | Type | Meaning |
|---|---|---|
| `selected` | backend object or `null` | Backend selected by `auto` on this host |
| `available` | array of backend objects | Backends that passed implemented qualification |
| `unavailable` | array of unavailable objects | Backend names and qualification reasons |

A backend object contains `name`, `class`, `metric`, `hard_limit`,
`startup_containment`, and `limitations`. An unavailable object contains `name`
and `reason`.

Probe returns status 0 after successfully serializing the document even when
`selected` is null. Consumers should pin MemCordon, reject missing fields, and
test content rather than status alone:

```sh
memcordon probe --json \
  | jq -e '.selected != null and .selected.hard_limit == true' \
  >/dev/null
```

This is an early diagnostic, not launch proof. Keep `--enforcement hard` on a
run that must fail before launch when hard enforcement cannot be established.

<a id="hard-enforcement-automation"></a>
### Hard enforcement in automation

For an early diagnostic in a POSIX shell, fail the job when probe does not
select a hard backend. Keep `--enforcement hard` on the real invocation:

```sh
set -eu

probe_json="$(memcordon probe --json)"
printf '%s\n' "$probe_json" \
  | jq -e '.selected != null and .selected.hard_limit == true' \
  >/dev/null

memcordon run \
  --enforcement hard \
  --memory 8GiB \
  --report json \
  --report-file memcordon-result.json \
  -- cargo test --workspace
```

The equivalent PowerShell gate is:

```powershell
$probe = memcordon probe --json | ConvertFrom-Json
if ($null -eq $probe.selected -or -not $probe.selected.hard_limit) {
    throw "Required hard MemCordon backend is unavailable"
}

& memcordon run `
    --enforcement hard `
    --memory 8GiB `
    --report json `
    --report-file memcordon-result.json `
    -- cargo test --workspace
exit $LASTEXITCODE
```

Retain the report and stderr with the job logs. Probe success on Windows does
not prove that the later target can be assigned under the enclosing Job Object;
the hard run remains the launch-time check.

<a id="run-report"></a>
## JSON run report

JSON output requires `--report json --report-file PATH`. Schema 1 is an object
with these fields:

- `schema_version`: integer `1`.
- `tool`: strings `name` and `version`.
- `command`: string `program`, string array `args`, and nullable integer `pid`.
- `policy`: strings `requested_enforcement`, `effective_enforcement`,
  `swap_policy`, and `lifetime`; integer `memory_limit_bytes`; nullable integer
  `swap_limit_bytes`; and integer `poll_interval_ms`.
- `backend`: strings `name`, `class`, and `metric`; boolean `hard_limit`; and a
  string array `limitations`.
- `result`: string `outcome`; signed integer `wrapper_exit_code`; nullable
  `child`; nullable `limit_evidence`; nullable integer `peak_bytes`; and integer
  `duration_ms`.
- `cleanup`: booleans `graceful_attempted`, `force_attempted`, and
  `direct_child_reaped`; nullable boolean `workload_empty`; and array `errors`.

`result.outcome` is `child-exited`, `limit-exceeded`, `interrupted`, or
`monitor-failed`. A child object is tagged by `kind`: `exit-code` with signed
`code`, `unix-signal` with signed `signal`, `windows-status` with unsigned
`status`, or `unavailable`. Limit evidence contains string `backend`, `metric`,
and `detail`. Each cleanup error contains string `operation` and `message`.

The file is written as pretty JSON with a trailing newline to a sibling
temporary file, synchronized, and renamed over the requested path. Failure of a
required write returns 125 and removes the temporary file when possible.

### Schema 1 observability limits

The report is assembled only after backend execution returns an outcome, so
usage, setup, or spawn failures can return 125 without a report. A report-write
failure can also leave no durable file. Preserve stderr when diagnosis matters.

The policy section is not a fully resolved policy record. It does not contain
requested/effective metric pairs, signal grace, or limit grace, and its
lifetime, swap, and polling fields do not prove that those requests affected the
selected backend. `monitor-failed` does not retain the monitor error string.
