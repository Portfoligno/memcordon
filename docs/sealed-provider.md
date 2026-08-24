# Sealed provider operation

The sealed provider is private MemCordon machinery installed by the native package. The public request remains `memcordon --sealed ... COMMAND ARGUMENT...`; the CLI never accepts a provider endpoint, platform principal, boundary handle, or cleanup hook.

## Trust and transport

Linux mechanism v2 uses the fixed public local socket `/run/memcordon/sealed-agent.sock` and the root-only private broker socket `/run/memcordon/sealed-launcher.sock`. The hardened `memcordon-sealed-agent.service` control plane owns the public socket, runs with `NoNewPrivileges=yes`, authenticates the peer, captures its execution envelope, rejects callers already inside an active attempt, and never executes caller code. The minimally scoped `memcordon-sealed-launcher.service` accepts only the authenticated control service, runs with `NoNewPrivileges=no`, and creates the target from the caller's mount and privilege-transition context. A packaged tmpfiles declaration recreates `/run/memcordon` as mode `0750` `root:memcordon` before either socket activates, so reboot cannot replace the traversable public endpoint parent with a root-only directory. Windows uses a fixed local pipe; a future macOS package supplies a fixed launchd-owned endpoint. Before capability is advertised, the client verifies the installed binary, both Linux services and sockets, ownership and permissions, protocol/build identity, mechanism identity, and qualification receipt. Caller identity and namespace state come from peer credentials and authenticated kernel descriptors, never authoritative request fields.

Messages use the bounded binary protocol in [provider protocol v2](../spec/sealed-provider-protocol-v2.md). Unknown versions, kinds, oversized lengths, replayed nonces, descriptor-count mismatches, caller-envelope mismatches, and protocol v1 providers are rejected before target authorization. The public launch payload remains mechanism-free. The control service derives and digest-binds a private `LaunchBrokerRequestV2` containing the caller envelope and descriptor manifest. Programs and arguments remain separate native values and are never represented as shell commands.

## Attempts and recovery

Every attempt advances through `Allocated`, `BoundaryCreated`, `GuardianReady`, `TargetCreatedGated`, `AssignmentVerified`, `ResourceInheritanceVerified`, `Authorized`, `Running`, `Terminating`, `Empty`, and `Retired`. Authorization cannot precede authenticated caller-envelope capture, launcher authentication, caller mount-namespace adoption, caller capability-envelope reproduction, exact descriptor verification, and all existing boundary checks. Retirement cannot precede an emptiness proof.

Before authorization the provider persists only recovery identity: attempt/provider generation, native boundary identity, helper identities, front-end identity, authorization/cleanup state, and an integrity digest. It does not persist command arguments, environment values, stream contents, or secrets.

Provider startup resolves authenticated abandoned attempts before advertising capability. Ambiguous live state quarantines the record and keeps sealed unavailable. Names, paths, and numeric process ids alone are never sufficient authority to kill or retire a workload.

Front-end loss triggers the independent guardian. Provider or launcher loss cannot produce ordinary success: Linux retains a per-attempt root guardian and broker-owned `cgroup.kill` authority outside the workload, Windows retains guardian and kernel kill-on-last-handle authority, and a future macOS daemon/extension pair retains its event graph. Upgrade and uninstall refuse to mutate either Linux service while an authenticated control, broker, or guardian attempt is live or recovery is ambiguous.
