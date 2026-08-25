# Sealed supervision

`--sealed` requires MemCordon to establish and verify a certified process-supervision boundary before authorizing the command. It retains cleanup authority outside the workload, restricts inherited supervisor resources, and does not return an ordinary child result until the direct child and helpers are reaped and the boundary is proven empty and retired.

Sealed supervision is transparent to credential transitions permitted by the authenticated caller's execution context and the operating system. MemCordon does not select an alternate identity and does not expose identity controls. A target may execute set-ID programs, acquire file capabilities, use `sudo`, or create descendants with alternate credentials when those operations would otherwise be permitted. Such transitions do not change sealed-boundary membership, cleanup authority, or the requirement for terminal emptiness.

The request fails before target execution when the host cannot satisfy every part of the contract. There is no fallback to standard supervision. Capability probing reports standard and sealed availability separately, including the provider prerequisites that are missing. A platform is promoted to `sealed` only after its installed native provider and mechanism pass runtime qualification; stock macOS remains unavailable pending an entitlement-backed process-event agent.

## Threat model

The boundary covers ordinary lineage descendants that fork, double-fork, create process groups, call `setsid`, daemonize, outlive the direct command, retain standard streams, ignore graceful termination, or race launch and cleanup. Every restart attempt requires a fresh boundary and terminal retirement proof for the prior attempt.

Sealed supervision is not filesystem, network, syscall, package-manager, secret, kernel, or hypervisor isolation. It does not prevent a workload from asking an unrelated trusted host service to create a process outside its lineage, guarantee that an authorized credential transition succeeds, or protect host resources already available to the caller or to credentials the caller deliberately acquires. Caller `NoNewPrivs`, capability bounding sets, `nosuid` mounts, sudoers/PAM policy, user namespaces, LSMs, and system policy remain authoritative.

Reports distinguish the requested boundary from the effective boundary and expose the individual authorization and cleanup predicates. A backend may report `sealed` only when every required predicate is supported and verified.

## Native mechanisms

- Linux mechanism `linux-pid-namespace-cgroup-v2` uses a hardened public control service and a separate root-only launch broker. It reproduces the authenticated caller's mount context, `NoNewPrivs` value, capability bounding set, credentials, groups, native argv, environment, working directory, and streams before authorization, while stripping provider-only capabilities and handles. Reports describe this credential-transition policy as `preserve-caller-envelope`. Its root-owned cgroup v2 boundary and nested PID/mount/cgroup namespaces survive `exec`, set-ID, file-capability, `sudo`, `setsid`, and daemonization. Terminal proof requires `cgroup.kill`, `populated 0`, helper reaping, and cgroup removal.
- Windows mechanism `windows-job-object-v2` uses restricted-service-SID LocalService control and LocalSystem launcher services. It reproduces the authenticated caller token, native UTF-16 argv, environment, working directory, and streams; applies a fresh unnamed non-breakaway Job and exactly three inherited stream handles at process creation; and verifies the suspended target before one-instruction authorization. An external guardian retains kill authority across frontend or launcher loss. Terminal proof requires `TerminateJobObject`, zero active Job processes, relay and guardian retirement, and closure of final Job handles. See the [mechanism](../spec/sealed-windows-v2.md) and [protocol](../spec/sealed-windows-provider-v1.md) specifications.
- macOS stock process-group supervision remains standard/watchdog only. A future sealed backend requires a signed Endpoint Security system extension and root launch daemon with detectable event continuity and process-table reconciliation.

The private provider uses a fixed local endpoint and authenticates caller identity from the transport. Provider paths, principals, tokens, cgroups, Jobs, handles, and cleanup callbacks are not caller configuration. See [sealed provider operation](sealed-provider.md).
