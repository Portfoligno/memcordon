# Linux sealed mechanism v1

`linux-pid-namespace-cgroup-v1` is available only through the installed root-owned MemCordon provider. The public caller cannot select its socket, cgroup, namespaces, identities, guardian, or recovery state.

## Capability qualification

Before advertising sealed capability, the provider verifies its installed identity and fixed root-owned endpoint, completes authenticated recovery, and runs a sacrificial attempt. The qualification receipt is accepted only when it proves all of the following:

- unified cgroup v2 and a private provider-owned subtree;
- `clone3` creation directly into the attempt cgroup with PID, mount, and cgroup namespaces plus a pidfd;
- race-free descriptor closure using `close_range`;
- a gated target and independent root guardian outside the workload;
- assignment, credentials, capabilities, `no_new_privs`, inherited descriptors, and non-writable cgroup view verified before authorization;
- `cgroup.kill`, `populated 0`, namespace-init and guardian reaping, and cgroup removal; and
- a durable record advanced to `Retired` with a provider identity and receipt digest.

Any absent, false, malformed, stale, or unsupported field makes the capability unavailable. Qualification never runs caller code.

## Per-attempt authorization

The namespace init is born into a fresh root-owned cgroup. PID 1 remains trusted provider code and creates a single-threaded gated target. The target receives only the caller's native program and argument vector, environment, current directory, and approved streams. It receives no provider control descriptor or writable host cgroup view.

Authorization occurs only after the provider independently verifies every generic and Linux-specific launch predicate while the target remains gated. A setup fault destroys and reaps every created resource without releasing the marker fixture.

## Terminal and restart proof

Direct-target status is provisional. Terminal cleanup invokes `cgroup.kill`, proves `populated 0`, reaps namespace init and guardian, removes the authenticated cgroup, and retires the durable record. A result or restart is forbidden when any step is false, unknown, timed out, or carries an error. Every restart uses a fresh attempt id, cgroup, namespace init, gate, guardian, and record.

## Recovery and package identity

Provider startup recovers authenticated records before serving probes. A record/cgroup identity mismatch is quarantined and keeps sealed unavailable; names or numeric process ids alone never authorize killing. Upgrade preserves recovery authority. Uninstall refuses live authenticated attempts and removes only verified package-owned service metadata after the provider is quiescent.

CI invokes the private provider through direct argv:

```text
memcordon-sealed-agent package verify
memcordon-sealed-agent package install --ephemeral-ci
memcordon-sealed-agent package upgrade --ephemeral-ci
memcordon-sealed-agent qualify
memcordon-sealed-agent package uninstall --ephemeral-ci
```

The endpoint remains `/run/memcordon/sealed-agent.sock`; no environment variable overrides it.

## Certification evidence

Linux certification uploads exactly these newline-terminated JSON files:

- `provider-identity.json`;
- `qualification-receipt.json`;
- `sealed-scenario-report.json`;
- `fault-injection-report.json`;
- `cleanup-recovery-report.json`; and
- `platform-environment.json`.

Certification uses exact test selectors, zero skips, marker-based preauthorization faults, adversarial lineage/escape scenarios, provider/front-end/guardian loss, recovery ambiguity, package tampering, upgrade, uninstall, simultaneous attempts, and restart freshness. Missing tests or receipts fail the job.
