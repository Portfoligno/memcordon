# Maintaining MemCordon

This document describes the current workspace, validation paths, and CI trust
boundary. Public behavior belongs in `README.md`, `docs/reference.md`, generated
CLI help, and Rust API documentation. Historical proposals are available in Git
history and are not current contracts.

## Workspace architecture

The workspace separates platform-neutral contracts from native execution:

- `memcordon-core` owns policies, outcomes, state, errors, and report types.
- `memcordon-platform` owns native backends and depends on core.
- The `memcordon` facade and binary own `Limiter`, CLI behavior, report assembly,
  exit mapping, and stable public re-exports.
- `memcordon-testkit` owns black-box process-test support.
- `tools/memcordon-ci` owns repository policy, certification, and release checks.

Every supported launch path establishes containment before allowing target code
to run. Linux starts an installed MemCordon CLI as a process-group leader and
uses its binary-private launcher mode. The supervisor assigns and verifies the
launcher in the cgroup, validates a versioned READY record, starts a crash
guardian, and only then releases the launcher to execute the typed target.
Windows creates the target suspended and assigns it to a Job Object; macOS
establishes a process group before execution. The supervisor retains the
direct-child handle until it has been reaped. Process-table presence is never
the authority for direct-child liveness.

The launcher and guardian routes are binary-private and absent from public help
and the Rust facade. Direct CLI execution resolves its current executable;
Linux `Limiter::run` instead requires an explicit absolute path to an installed
MemCordon CLI, which must remain available for the run. Versioned native READY
and exec-status records validate compatible launcher state and preserve
target-exec errors; a separate inherited descriptor capability carries the
one-byte release record. Protocol descriptors close on target exec, and no
custom environment variable reaches target code.

Changes to public behavior must update the owning source, generated help or API
documentation, the contract reference, and any affected README recipe together.
Do not present an accepted option as effective on a backend unless the backend
implements it.

## Local validation

Credential-free entry points include:

```console
cargo run --locked --package memcordon-ci -- suite policy
cargo run --locked --package memcordon-ci -- suite quality
cargo run --locked --package memcordon-ci -- suite native
```

The production packages support Rust 1.85. The non-publishable `memcordon-ci`
package requires Rust 1.88 and is compiled in CI with the pinned stable
toolchain. Workspace-wide Cargo commands are therefore not the Rust 1.85
contract; use the package-selected MSRV suite.

Choose validation from the behavior changed:

- policy, parsing, outcome, and report changes require focused unit and CLI
  tests;
- lifecycle and cleanup changes require black-box process tests;
- backend changes require the relevant native contract tests and stress tests;
- release or workflow changes require repository policy and release preflight
  coverage;
- Rust changes require `cargo fmt` before commit.

Tests and fixtures under `tests/`, snapshots, and regression files are evidence
of previously identified behavior. Do not delete them to make a failure pass.
When a test fails, verify that its input is valid before changing production
code or expected output.

## Documentation validation

Review documentation changes against:

- generated command help and defaults;
- the current public Rust surface on docs.rs;
- serialized probe and report structures;
- all three backend implementations;
- internal anchors and repository links;
- release, schema, target, and MSRV statements.

The README provides one complete ordinary path and concise conditional recipes.
`docs/reference.md` owns exact CLI and machine contracts. Avoid new standalone
pages unless their audience or compatibility requirements cannot be served by
those two files.

## Continuous integration

GitHub Actions selects events, runners, permissions, caches, artifacts, and the
credential boundary. The typed `memcordon-ci` driver performs sequencing with
argument vectors and monotonic subprocess deadlines.

- `ci.yml` runs repository policy, quality, MSRV, supply-chain, and five-target
  native checks.
- `deep-ci.yml` runs Miri, fuzz smoke tests, and native stress tests.
- `backend-certification.yml` produces exact-run Linux and Windows
  sealed-provider evidence.
- `release.yml` repeats release-grade gates before assembly, publication, and
  public-state verification.

The architecture uses GitHub-hosted runners only. Public CI covers Linux x64 and
ARM64, macOS x64 and ARM64, and Windows x64 and ARM64. Deep CI and backend certification
run on every unfiltered branch or tag push and support inputless manual
dispatch. Repository policy is the source of truth for exact triggers,
permissions, pins, cache separation, and dependency-update coverage.

## Backend certification

Linux sealed certification is owned by the typed `backend-linux-sealed` suite.
It verifies provider package identity, ephemeral install/upgrade/uninstall,
runtime qualification, adversarial lifecycle and escape scenarios, fault
injection, recovery, and the exact six-file evidence inventory documented in
`spec/sealed-linux-v1.md`. Missing provider prerequisites fail; they are never
converted to skips or standard-backend success. The provider endpoint is fixed
and no project-specific environment variable configures certification.

Hard-backend certification uses the exact GitHub-hosted labels `ubuntu-24.04`,
`windows-2025`, and the Windows ARM64 runner declared in the workflow. Each job receives a fresh VM, performs runtime
qualification, runs every required scenario, and fails instead of accepting an
unavailable backend as a skip.

Linux uses privilege only inside the typed CI driver to establish a systemd
delegation; qualification and scenarios run as the unprivileged runner user.
Windows runtime certification invokes the typed `backend-windows-sealed-v2`,
`package-windows-sealed`, and `channel-parity-windows-sealed` suites on separate
elevated x64 and ARM64 jobs. The
provider is installed with native SCM APIs, qualified, exercised through the
public CLI, and uninstalled on each runner. Package, qualification, execution,
doctor, and cleanup JSON evidence are uploaded as one exact-run inventory.
The package and parity suites are release-blocking. Post-public verification
also installs the published Cargo package and exercises the native archive on
matching x64 and ARM64 Windows runners.

In certification schema 2, `runner_class: "ephemeral-certified"` describes the
evidence from that exact hosted job run. It includes provider, fixed label,
runtime qualification, commit identity, and per-test results; it is not advance
certification of a rolling runner image. Reports and credentials are never
cached, and all qualification and scenarios execute on every certification job.

Local or generic CI success establishes only behavior exercised by that
environment. A release cannot proceed until both hard-backend jobs pass every
required scenario with zero skips for the tagged commit.

## Release maintenance

The published runtime remains three crates in dependency order:
`memcordon-core`, `memcordon-platform`, and `memcordon`. The sealed
agent is a binary-private module tree in the `memcordon` package, not a
fourth crate or a public Rust API. Cargo installs two default runtime binaries.
Linux and Windows native archives contain those same two binaries and a
generated runtime manifest. Other native archives contain only the CLI.

Release schema 3 binds each archive's runtime-manifest digest and exact
component size, mode, role, and digest. Native asset report schema 2 records
the exact member-inventory digest and smoke results. Publication report schema
2 carries the same runtime inventory through credential-free public
verification.

The actionable release procedure and credential invariants live in
[RELEASING.md](RELEASING.md). User-visible changes belong in
[CHANGELOG.md](CHANGELOG.md), which is parsed by release tooling.

Release source identity is derived from Git and GitHub event metadata. The
OIDC-only path uses a fresh short-lived crates.io capability for each
dependency-ordered publication slot. Stored registry tokens, named GitHub
Environments, credential-bearing caches or artifacts, and force-moving a
published tag are outside the release policy.

When changing release configuration, update its tests and policy identities in
the same change. The workflow and typed driver must agree on the tag, commit,
package graph, artifact checksums, certification evidence, and public state.
