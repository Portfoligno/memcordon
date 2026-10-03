# Linux workload contract V2

V2 selects a protected local grant and either the authenticated caller's identity
or an exact administrator-defined target identity. The optional `private-tcp`
provider implements `linux-tcp4-private-v1` on native GNU Linux x64 and ARM64.
Availability requires the actual selected installation and host resources. A
contract, registry document, plan, report or manifest cannot independently authorize
execution.

## Request and compatibility

`WorkloadContract::parse` accepts at most 64 KiB, rejects duplicate and unknown
fields, and dispatches only explicit numeric `schema_version` 1 or 2. V1 request
encodings and semantic digest vectors are frozen. Windows uses V1. A V2 request
is never silently downgraded.

V2 retains the plan, profile, grant, ceilings, requirements, endpoint and expected
epoch fields, adding exactly one execution identity:

```json
{"kind":"preserve-caller"}
```

```json
{"kind":"administrator-profile","reference":{"id":"target-worker","semantic_digest":"<64 lowercase hexadecimal characters>"}}
```

The delegated request supplies no numeric UID/GID, supplementary groups or target
path. The protected identity definition supplies those facts and approved ELF
entrypoints. PreserveCaller permits no cross-UID transition and requires an
unprivileged authenticated caller envelope. Neither branch permits capability gain
after trusted setup.

IDs are bounded to 64 bytes; registries to 1 MiB, 16 profiles, 32 identities and
128 grants. Each grant has at most four callers and 16 plans. Identities have
nonzero UID/GID, at most 32 unique supplementary groups and eight unique approved
entrypoints. Absolute entrypoint paths are bounded to 4096 UTF-8 bytes and reject
empty, dot and parent components. Native held-file checks additionally establish
the actual ELF, content, mode, owner and stable identity.

## Local administration

Current activation documents use `format: memcordon.local-private-activation`,
`revision: 1`; their registry uses `memcordon.local-private-policy`, revision 1.
The baseline equivalents are `memcordon.local-activation` and
`memcordon.local-policy`. These distinct envelopes contain actual local profiles,
identities, grants and change disposition, without qualification digests.
Old numeric activation documents are rejected rather than reinterpreted.

An administrator-provided image must first be copied into a fresh protected
inode. On a Linux agent built with `private-tcp`, use:

```console
sudo /absolute/path/memcordon-sealed-agent package policy entrypoint install --definition /root/image.json --source /absolute/source/image
```

The root-owned definition has format `memcordon.local-entrypoint-install`,
revision 1, and an `entrypoint` object containing `id`, `absolute_path`, `sha256`
and `size`. The installer checks the actual bytes, native ELF and protected
destination, publishes without replacing an existing image, and records its
actual inode identity. Its output is an observation; it neither activates policy
nor grants a launch. Launch independently checks the live local grant and held
image. A later chmod of an arbitrary inode does not replace this installation.

An administrator applies a protected file with:

```console
sudo /absolute/path/memcordon-sealed-agent package policy apply --file activation.json
sudo /absolute/path/memcordon-sealed-agent package policy inspect --json
```

Activation returns the actual epoch. A launch must name that exact epoch and match
the authenticated caller, plan, enabled profile and identity, grant revision,
ceilings and requirements. DrainExisting prevents new admission while allowing
already released attempts to retire; RevokeActive also latches their native
cancellation. Every restart performs a new resolution. Descriptive journal
metadata preserves revocation accounting without reconstructing launch permission.

## Native release and execution

The network launcher independently holds caller PID/birth, pidfd, root/mount/cwd
and credential observations. It reserves the protected namespace/account key before
creating the boundary, then creates an attempt-owned user/network namespace,
cgroup, anonymous-pipe stdio and crash guardian. No imported socket or arbitrary
frontend descriptor becomes target stdio.

Trusted setup fixes the final UID/GID/groups, clears all capabilities, sets
NoNewPrivileges and nondumpability, and installs the finite x64/ARM64 seccomp
policy. The private namespace has IPv4 loopback, unprivileged-port start 0,
ephemeral ports 32768 through 60999, no reserved ports and IPv6 disabled. Unix,
IPv6, datagram/raw sockets, descriptor import, namespace reconfiguration and
unreviewed syscall/ABI paths are denied. This is private IPv4 TCP capability, not
complete communication isolation or unrestricted filesystem authority.

The gated target has exactly five descriptors: three provider-created pipes,
transient control and held ELF. The single-threaded namespace parent traces its
direct child from an initial trusted stop with TRACEEXEC and EXITKILL. Only the
live, non-deserializable admission owner may send the release byte after durable
native preparation and a short locked recheck of current grant, epoch, caller and
revocation state. At the real kernel exec stop, that same task checks the held ELF,
final credentials and exact pipe descriptors 0/1/2 before detaching. EOF or a
later procfs image observation is not proof that target instructions were gated.

Failures retain exact launch/release/exec uncertainty. Authenticated preallocation
rejection is a named factual response bound to the independent provider, raw
attempt ID, public request bytes, native invocation and full contract. Generic
connection or provider loss never implies that no target was created. Cleanup
completion requires actual retirement; surviving account, process, namespace,
cgroup, pipe or journal obligations remain charged and block unsafe reuse.

## Advisory and result formats

```console
memcordon plan --sealed --workload-contract contract.json --plan-format plan-v1 -- workload
memcordon doctor --require sealed --workload-contract contract.json --capability-format capabilities-v1
memcordon --sealed --workload-contract contract.json --report-format result-v1 --report result.json -- workload
```

Plan and capability envelopes validate their named format/revision and always
declare `authorizes_launch: false`. They report actual local state and conflicts;
the runtime rechecks independently. ResultV1 retains the actual full private
contract, descriptive admission metadata, namespace and exec observations,
native termination, frontend delivery and cleanup uncertainty. New facts cannot
be serialized under frozen numeric execution, plan or doctor domains. Selecting
an incompatible legacy format rejects before native allocation.

## Frozen schema vectors

Canonical encoders use the ASCII domain, a zero byte and big-endian encoding
version 1; IDs/list counts use u16 lengths, fixed digests/nonces remain raw bytes,
and semantic sets are sorted. The frozen V2 request domain is
`memcordon-workload-contract-v2`; execution identity commitments use
`execution-identity-v2`. The unchanged empty PreserveCaller request vector in
`crates/memcordon-core/tests/workload_v2.rs` has digest
`736967c1da4c77c4e1e724087e96fcb8d7e718148bc82cb092303c4c035a31dd`.
Its private profile digest is
`fefad78a6eb35d49a99ca8a2f4771d575331c72a5cabc130fdd64d84d699d1e5`.

Historical checkpoint and retirement vectors retain respectively
`eccea5cc72146be107a5913a0d7a0fb0cc4f53799a0e797b89e2e649ea20f1a4`
and `7dba00078c910876d8df28169bbb9b16cb78d36a761142854433390c3f26e7f4`.
They are frozen diagnostic commitments. Their true flags do not grant permission,
prove current native availability or describe a future exec observation. Current
gated and post-exec observations use separate named factual records.

## Installed tests

The ordinary Working-source private suite builds both native and independent
Cargo-installed payloads, uses their measured manifests and executes both identity
branches. It checks native namespace/credentials/FD/filter facts, TCP success and
deadline, concurrent isolation, local grant transitions and exact rejection
association. The two listener anchors retain a real prebound listener through
readiness/competitor/HTTP-body checks and distinguish candidate port mismatch
exit 42 before readiness from a prelaunch denial. Root-native ptrace and recovery
fixtures are selected by exact name; unavailable hosts never count as passes.
