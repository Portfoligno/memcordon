# Metrics

- `physical-footprint-sum` is the macOS native watchdog metric. Each known
  process is queried once with `proc_pid_rusage`; threads are not separate
  members.
- `rss-sum` is an explicit watchdog alternative. Shared pages may be represented
  in more than one process and swapped pages are absent.
- `virtual-size-sum` is compatibility-only and is collected explicitly from
  macOS task information. It is never described as physical memory.
- Linux cgroup memory and Windows job commit are different native quantities and
  must never be presented as directly interchangeable.

All measurements and configured limits use `u64`. Aggregate overflow saturates,
which safely establishes that any representable limit was crossed.
