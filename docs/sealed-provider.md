# Sealed provider operation

The sealed provider is private MemCordon machinery installed by the native package. The public request remains `memcordon --sealed ... COMMAND ARGUMENT...`; the CLI never accepts a provider endpoint, platform principal, boundary handle, or cleanup hook.

## Trust and transport

Linux uses the fixed root-owned local socket `/run/memcordon/sealed-agent.sock`. Windows uses the fixed local pipe `\\.\pipe\memcordon-sealed-agent-v1`. A future macOS package supplies a fixed launchd-owned endpoint. Before capability is advertised, the client verifies the installed binary/service identity, ownership and permissions, protocol/build identity, mechanism identity, and qualification receipt. Caller identity comes from peer credentials or named-pipe client authentication, never an authoritative request field.

Messages use the bounded binary protocol in `spec/sealed-provider-protocol-v1.md`. Unknown versions, kinds, oversized lengths, replayed nonces, descriptor-count mismatches, and caller-identity mismatches are rejected before target creation. Programs and arguments remain separate native values and are never represented as shell commands.

## Attempts and recovery

Every attempt advances through `Allocated`, `BoundaryCreated`, `GuardianReady`, `TargetCreatedGated`, `AssignmentVerified`, `ResourceInheritanceVerified`, `Authorized`, `Running`, `Terminating`, `Empty`, and `Retired`. Authorization cannot precede all verification states, and retirement cannot precede an emptiness proof.

Before authorization the provider persists only recovery identity: attempt/provider generation, native boundary identity, helper identities, front-end identity, authorization/cleanup state, and an integrity digest. It does not persist command arguments, environment values, stream contents, or secrets.

Provider startup resolves authenticated abandoned attempts before advertising capability. Ambiguous live state quarantines the record and keeps sealed unavailable. Names, paths, and numeric process ids alone are never sufficient authority to kill or retire a workload.

Front-end loss triggers the independent guardian. Provider loss cannot produce ordinary success: Linux retains a per-attempt root guardian, Windows retains guardian and kernel kill-on-last-handle authority, and a future macOS daemon/extension pair retains its event graph.
