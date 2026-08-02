# Changelog

All notable user-visible changes to MemCordon are documented here.

## Unreleased

### Added

- Introduced the MemCordon CLI and Rust API for running commands under
  workload-wide memory controls on Linux, macOS, and Windows.
- Added Linux cgroup v2 and Windows Job Object hard-enforcement backends, plus a
  clearly identified sampled macOS watchdog with fail-closed capability checks.
- Added `run`, `probe`, `explain`, `cleanup`, `version`, and compatibility
  commands with configurable memory, enforcement, lifetime, metric, swap,
  polling, grace-period, and reporting policies.
- Added descendant containment and cleanup, preserved child exit status, Unix
  signal handling, and stable exit codes for memory limits and wrapper failures.
- Added machine-readable capability probing and atomic, schema-versioned JSON
  reports containing backend, outcome, peak-memory, limit, duration, and cleanup
  evidence.
- Added exact decimal and binary memory-size parsing, bounded duration parsing,
  and a public `Limiter` builder API.
- Added native release archives for Linux x86-64 and ARM64, macOS x86-64 and
  ARM64, and Windows x86-64, with SHA-256 checksums.

### Known limitations

- macOS enforcement is sampled rather than hard and can overshoot or miss short
  memory bursts.
- Linux hard enforcement requires delegated cgroup v2 memory control; Windows
  setup can be restricted by an enclosing Job Object.
- MemCordon controls resource usage but is not a hostile-code security sandbox.
