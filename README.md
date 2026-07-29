# MemCordon

![MemCordon banner](docs/assets/banner.png)

MemCordon launches a command inside the strongest supported workload boundary and
limits or watches the memory used by the command and its descendants.

The executable provides a lifecycle-safe macOS watchdog, a delegated Linux
cgroup v2 backend, and a Windows Job Object backend. Capability probing happens
before target launch and never silently weakens `--enforcement hard`.

```console
cargo run -p memcordon -- run --memory 8GiB -- cargo test --workspace
cargo run -p memcordon -- probe
```

On macOS, `auto` selects sampled physical-footprint accounting and emits a
warning. Use `--enforcement hard` when automation must fail closed rather than
accept watchdog semantics.

Important contracts:

- The direct child's owned handle is the liveness authority and is reaped
  promptly.
- Descendants are workload members by default.
- A confirmed limit event returns `124`; monitor failure returns `125`.
- Child output remains untouched and wrapper diagnostics go to stderr.
- Memory values remain `u64` and aggregate sampling saturates safely.

See [guarantees](docs/guarantees.md), [metrics](docs/metrics.md),
[backends](docs/backends.md), and the complete
[normative design](docs/design.md).

## Workspace architecture

The design's public API example creates a dependency cycle if `Limiter` lives in
the platform-neutral core. This workspace resolves it without weakening the
layers:

- `memcordon-core` owns policies, outcomes, state, errors, and report types.
- `memcordon-platform` depends on core and owns native backends.
- The `memcordon` facade/binary depends on both, owns `Limiter`, and re-exports
  the stable public types.
- `memcordon-testkit` contains black-box process-test support.
