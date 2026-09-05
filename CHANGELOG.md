# Changelog

All notable user-visible changes to MemCordon are documented here.

## [0.5.2-rc.11] - 2026-09-06

### Added

- Added `--sealed` support on Windows x64 and ARM64. After provider setup,
  MemCordon contains the command and its descendants and verifies that they
  have all stopped before reporting completion.
- Cargo installations and Linux and Windows release archives now include the
  matching `memcordon-sealed-agent` companion. Setting up sealed supervision
  no longer requires a source checkout or a separate provider download.
- Added provider version information and JSON output for `package inspect`
  and `package verify`, making it easier to inspect and check an installation.

### Changed

- A CLI/provider version mismatch now stops execution before the command
  starts and explains how to install the matching version.
- When backend capabilities change between preflight and execution, failure
  reports now retain the affected attempt, identify what changed, and report
  whether cleanup completed.

## [0.5.1-rc.2] - 2026-08-25

### Added

- Added credential-transition-aware Linux sealed supervision. Before
  authorization, the provider reproduces the authenticated caller's
  credentials, groups, working directory, mount context, `NoNewPrivs` value,
  capability ceiling, native arguments, environment, and streams while
  removing provider-only authority. The sealed boundary remains effective
  across permitted set-ID, file-capability, `sudo`, `setsid`, and daemonization
  transitions.

### Changed

- Split the installed Linux provider into a hardened public control
  service/socket and a root-only launcher service/socket. A packaged tmpfiles
  policy owns the runtime directory and stable package lease, and package
  verification checks the complete installed artifact identities, modes, and
  contents.
- Linux package upgrade and uninstall now check authenticated recovery state
  before stopping provider units, retain transition-safe locking, and refuse
  live or ambiguous attempts without disrupting the active provider.

### Fixed

- Preserved typed `request-validation` provider rejections in public reports,
  authenticated systemd socket-activated launcher workers, and rejected unsafe
  recursive-provider inventory without mistaking cgroup v2 control files for
  active attempts.
- Made Linux runtime ownership and the root-only package lease boot-safe,
  allowed unprivileged package verification without widening lease access, and
  retained complete failure diagnostics in certification artifacts.

### Breaking Changes

- Execution reports advance from schema 7 to 8, plan reports from schema 6 to
  7, and doctor reports from schema 4 to 5. Sealed mechanism, evidence,
  qualification, and terminal records advance to v2, and provider protocol v1
  is rejected rather than negotiated.
- Public Rust sealed-boundary evidence gains required credential-transition,
  caller-envelope, control/launcher identity, and recursive-request fields.
  `BoundarySetupPhase` also adds `RequestValidation`; external struct literals
  and exhaustive matches must be updated.

## [0.5.0-rc.4] - 2026-08-24

### Added

- Added `--sealed` and the `BoundaryRequirement::Sealed` Rust API for certified
  process supervision. Qualified Linux installations gate the target inside
  provider-owned cgroup v2, PID, mount, and cgroup namespaces, retain an
  external guardian, and prove the boundary empty, reaped, and removed before
  returning or restarting.
- Added the root-owned `memcordon-sealed-agent` Linux provider and fixed systemd
  socket. Package verification checks the installed binary and unit ownership,
  modes, and contents; upgrade and uninstall recover authenticated abandoned
  attempts and refuse live or ambiguous state.
- Added sealed capability and qualification details to `doctor`, `plan`, and
  execution reports, including requested and effective boundaries, missing
  prerequisites, native launch and retirement facts, and typed provider setup
  or target-exec failures. A sealed request never falls back and fails with
  `MCBOUNDARY-UNSUPPORTED` before target authorization when no qualified native
  provider is available.

### Changed

- Sealed restarts create a fresh native boundary for every attempt and consume
  the remaining supervision deadline. Authenticated exec failures remain
  distinct from successful child exits 126 and 127, and no result is returned
  without complete containment and helper-retirement evidence.

### Breaking Changes

- Execution reports advance from schema 5 to 7, plan reports from schema 4 to
  6, doctor reports from schema 2 to 4, and clean reports from schema 1 to 2.
  The new schemas separate requested and effective process-boundary assurance
  from memory enforcement and add provider qualification, setup-failure,
  rejection, launch, and retirement evidence. `MemcordonReport::schema5` is
  renamed to `schema7`.
- Public Rust policy, capability, supervision, error, and report models add
  required boundary and provider-evidence fields and variants. External struct
  literals and exhaustive matches must be updated.

## [0.4.1] - 2026-08-07

### Fixed

- Stopped warning about inapplicable restart conditions inferred by `--restart`
  and the implicit default `--swap 0B` on platforms without a separate swap
  policy. Explicit ineffective requests still warn.

## [0.4.0] - 2026-08-07

### Added

- Added `--command-exit-grace DURATION`, defaulting to zero, to let remaining
  workload members drain naturally after the direct command exits before
  command-mode cleanup force-cleans survivors.
- Added lowercase decimal `h` support to time budgets and every duration-valued
  policy option, with the existing upward whole-millisecond rounding.
- Added a topic index when `memcordon help` is invoked without a topic.
- Added Windows ARM64 native CI, stress, and release archive coverage.

### Changed

- Wrapper options and the optional memory and time budgets may now be
  interleaved before the command and throughout `plan`; reports retain the
  budgets' relative encounter order.
- Lifecycle help now distinguishes direct-command status, command-mode cleanup,
  workload-empty waiting, and the separate command-exit, interruption, and
  configured-limit grace periods.
- Terminal styling now honors `CLICOLOR` and `CLICOLOR_FORCE` alongside
  `NO_COLOR`, while redirected output and machine-readable JSON remain plain.

### Fixed

- Windows command completion now fails closed when Job Object membership cannot
  be queried, force-cleaning the job and reporting the cleanup error instead of
  treating the workload as empty.

### Breaking Changes

- Execution reports advance from schema-4 to schema-5 and plan JSON advances
  from schema-3 to schema-4. Both add requested and effective
  `command_exit_grace_ms`; `MemcordonReport::schema4` is renamed to `schema5`.
- The public Rust `Policy`, `RequestedPolicyReport`, and `EffectivePolicyReport`
  structs add required command-exit-grace fields, so external struct literals
  must be updated.

## [0.3.7] - 2026-08-07

### Added

- Added topic-oriented offline CLI help through `memcordon help TOPIC`, with
  concise root help and a complete `memcordon help all` reference.

### Changed

- Human-readable help, diagnostics, summaries, and utility output now use
  adaptive terminal styling. Redirected output is plain by default, `NO_COLOR`
  is respected, and machine-readable output and child streams remain unstyled.

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
