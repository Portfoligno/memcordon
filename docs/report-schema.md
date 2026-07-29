# Report schema

Schema version 1 contains:

- `tool`: executable name and version.
- `command`: program, argument vector, and direct-child PID.
- `policy`: requested/effective enforcement, byte limit, lifetime, and sampling
  interval.
- `backend`: name, class, metric, hard-limit flag, and limitations.
- `result`: outcome, mapped wrapper status, child termination, limit evidence,
  peak bytes, and duration.
- `cleanup`: reap state, workload-empty state, termination attempts, and
  aggregated errors.

JSON reports are written to a sibling temporary file, flushed, and atomically
renamed. A required report-write failure returns `125`.

