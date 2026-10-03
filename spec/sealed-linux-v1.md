# Linux sealed mechanism v1

> Historical specification. Current production clients and release policy reject this mechanism; see [Linux sealed mechanism v2](sealed-linux-v2.md).

`linux-pid-namespace-cgroup-v1` was available only through the installed root-owned MemCordon provider. The public caller could not select its socket, cgroup, namespaces, identities, guardian, or recovery state.

## Capability qualification

Before advertising sealed capability, the provider verifies its installed identity and fixed root-owned endpoint, completes authenticated recovery, and runs a sacrificial attempt. The qualification receipt is accepted only when it proves all of the following:

The root provider's reviewed service capability set includes `CAP_SYS_PTRACE` solely so it can perform kernel-governed `/proc` descriptor, namespace, credential, and mount readback after a gated target has assumed the authenticated nonroot caller identity. `NoNewPrivileges=yes`, the explicit capability bounding set, and the service filesystem restrictions remain active. The target receives no capabilities, remains gated during readback, and is never made dumpable to avoid this provider-side check.

- unified cgroup v2 and a private provider-owned subtree;
- `clone3` creation directly into the attempt cgroup with PID, mount, and cgroup namespaces plus a pidfd;
- race-free descriptor closure using `close_range`;
- a gated target and independent root guardian outside the workload;
- assignment, credentials, capabilities, `no_new_privs`, inherited descriptors, and non-writable cgroup view verified before authorization;
- `cgroup.kill`, `populated 0`, namespace-init and guardian reaping, and cgroup removal; and
- a durable record advanced to `Retired` with a provider identity and receipt digest.

Any absent, false, malformed, stale, or unsupported field makes the capability unavailable. Qualification never runs caller code.

## Per-attempt authorization

The namespace init is born into a fresh root-owned cgroup. PID 1 remains trusted provider code and creates a single-threaded gated target. Before target observation, an attempt-local bounded startup channel reports either exact target-fork readiness or a typed namespace-init phase and native error. The provider watches that channel and namespace-init liveness together, rejects malformed or unprovenanced messages, and never degrades an early namespace-init death into the generic target-observation timeout. The target receives only the caller's native program and argument vector, environment, current directory, and approved streams. It receives no provider control descriptor or writable host cgroup view.

Authorization occurs only after the provider independently verifies every generic and Linux-specific launch predicate while the target remains gated. A setup fault destroys and reaps every created resource without releasing the marker fixture.

The target's only pre-exec control descriptor is verified fd 3, a bidirectional close-on-exec Unix sequenced-packet socket. After authorization, a fixed armed record precedes the native `exec`. EOF is accepted as image-replacement success only after that record; an `exec` error instead produces one bounded typed target-exec record with a cross-checked errno class and native errno. The provider carries that authenticated distinction through terminal evidence and cleanup, so successful program exits 126/127 cannot be confused with `ENOENT`, `EACCES`, `ENOEXEC`, or another exec failure.

## Terminal and restart proof

Direct-target status is provisional. Terminal cleanup invokes `cgroup.kill`, proves `populated 0`, reaps namespace init and guardian, removes the authenticated cgroup, and retires the durable record. A result or restart is forbidden when any step is false, unknown, timed out, or carries an error. Every restart uses a fresh attempt id, cgroup, namespace init, gate, guardian, and record.

## Recovery and package identity

Provider startup recovers authenticated records before serving probes. A record/cgroup identity mismatch is quarantined and keeps sealed unavailable; names or numeric process ids alone never authorize killing. Upgrade preserves recovery authority, resolves authenticated abandoned records while quiescent, verifies the repaired installed package, and only then advertises the service. Package verification opens the fixed provider binary and systemd units without following symlinks and requires a complete root-owned, exact-mode installation whose unit bytes match the packaged metadata. Uninstall refuses live authenticated attempts and removes only verified package-owned service metadata after the provider is quiescent.

CI invokes the private provider through direct argv:

```text
memcordon-sealed-agent package install
memcordon-sealed-agent package verify
memcordon-sealed-agent package upgrade
memcordon-sealed-agent probe
memcordon-sealed-agent package uninstall
```

The endpoint remains `/run/memcordon/sealed-agent.sock`; no environment variable overrides it.

## Native observations

Native suites retain actual concurrency, caller identity, lineage, package
mutation, owner loss and cleanup assertions. They record
the selected source, exact executed cases and bounded raw output, distinguishing
execution failure, unavailable host and incomplete retirement. Saved output cannot
grant another invocation permission. Current provider operation is described by
[mechanism V2](sealed-linux-v2.md); optional private TCP additionally follows the
[V2 workload contract](../docs/spec-workload-contract-v2.md).
