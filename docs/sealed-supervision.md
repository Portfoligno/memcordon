# Sealed supervision

`--sealed` requires MemCordon to establish and verify a certified process-supervision boundary before authorizing the command. It retains cleanup authority outside the workload, restricts inherited supervisor resources, and does not return an ordinary child result until the direct child and helpers are reaped and the boundary is proven empty and retired.

The request fails before target execution when the host cannot satisfy every part of the contract. There is no fallback to standard supervision. Capability probing reports standard and sealed availability separately, including the provider prerequisites that are missing. A platform is promoted to `sealed` only after its installed native provider and mechanism pass runtime qualification; stock macOS remains unavailable pending an entitlement-backed process-event agent.

## Threat model

The boundary covers ordinary lineage descendants that fork, double-fork, create process groups, call `setsid`, daemonize, outlive the direct command, retain standard streams, ignore graceful termination, or race launch and cleanup. Every restart attempt requires a fresh boundary and terminal retirement proof for the prior attempt.

Sealed supervision is not filesystem, network, syscall, package-manager, secret, kernel, or hypervisor isolation. It does not prevent a workload from asking an unrelated trusted host service to create a process outside its lineage, nor protect files and credentials already available to the caller.

Reports distinguish the requested boundary from the effective boundary and expose the individual authorization and cleanup predicates. A backend may report `sealed` only when every required predicate is supported and verified.

## Native mechanisms

- Linux certification requires a root-owned cgroup v2 boundary, PID/mount/cgroup namespaces, a gated target, trusted namespace init, and an external guardian. Terminal proof requires `cgroup.kill`, `populated 0`, helper reaping, and cgroup removal.
- Windows certification requires the LocalSystem provider, a caller-derived restricted token, creation-time Job association, an exact inherited-handle list, a suspended target, and an external guardian. Terminal proof requires zero active Job processes and closure of final Job handles.
- macOS stock process-group supervision remains standard/watchdog only. A future sealed backend requires a signed Endpoint Security system extension and root launch daemon with detectable event continuity and process-table reconciliation.

The private provider uses a fixed local endpoint and authenticates caller identity from the transport. Provider paths, principals, tokens, cgroups, Jobs, handles, and cleanup callbacks are not caller configuration. See [sealed provider operation](sealed-provider.md).
