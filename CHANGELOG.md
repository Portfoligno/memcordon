# Changelog

All notable user-visible changes to MemCordon are documented here.

## [0.3.4] - 2026-08-06

### Added

- Added optional `+MEMORY` and `+TIME` budgets, workload containment without
  either limit, and deadline exit status `123`.
- Added attempt- and supervision-scoped deadlines, cleanup-gated restarts,
  half-life logistic backoff with quiet-time recovery, circuit breaking, and
  bounded per-attempt history.
- Added `doctor`, `plan`, and `clean` utilities for backend inspection, policy
  resolution without launch, and stale-artifact cleanup.
- Added a Rust `Supervisor` API with typed deadline and restart policies while
  retaining `Limiter` for one-shot execution.

### Changed

- Strengthened startup containment and cleanup proofs across Linux cgroup v2,
  Windows Job Objects, and the macOS watchdog, including lossless native
  argument handling and explicit target-spawn provenance.
- Release archives now include the changelog, contract reference, and
  documentation images; published crates use package-specific READMEs.
- crates.io publication now uses per-slot short-lived OIDC credentials bound to
  the selected release artifact.

### Breaking changes

- Replaced the `run`, `probe`, `explain`, `cleanup`, `version`, and `compat`
  command forms with direct budget execution, `doctor`, `plan`, `clean`, and
  `--version`; removed forms return actionable usage diagnostics.
- Replaced execution report schema-1 with schema-4, adding requested/effective
  policy, native invocation identity, supervision summaries, attempt records,
  and typed failure provenance. Doctor JSON uses schema-2 and plan JSON uses
  schema-3.
- Changed the public policy and report models for optional memory and deadline
  budgets, and added typed supervision outcomes; consumers must update for the
  0.3 interfaces.

## [0.1.3] - 2026-08-03

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
