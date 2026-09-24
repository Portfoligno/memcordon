# Workload contract V2 schema foundation

This document describes the V2 types and canonical commitments in
`memcordon-core`. It does **not** claim that a provider currently offers the
`linux-tcp4-private-v1` profile. A registry entry, parser success, or static
`resolve_v2` success is not native qualification or launch authorization. The
private profile remains unavailable until the optional launcher, network
namespace, target-identity transition, pinned entrypoint, filter, lifecycle
evidence, and per-target qualification are implemented and observed.

## Version and compatibility

`WorkloadContract::parse` performs the existing 64 KiB and duplicate-key
checks, reads only the explicit numeric `schema_version`, and dispatches to
the closed V1 or V2 decoder. Unknown versions and fields reject. V1 request
encoding, profile references, and canonical digests are unchanged. Windows
continues to use V1; V2 is a Linux schema and is not downgraded to V1.

V2 carries the same plan/profile/authorization/ceiling/requirement/endpoint/
epoch fields as V1, plus `execution_identity`. The latter is exactly one of:

- `{ "kind": "preserve-caller" }`
- `{ "kind": "administrator-profile", "reference": { "id": "...", "semantic_digest": "..." } }`

An administrator-profile request never supplies numeric UID, GID, groups, or
an executable path. It names one exact enabled identity in a protected V2
registry and must match an enabled grant for the authenticated Linux caller,
approved plan, profile, and epoch. `PreserveCaller` does not authorize a
cross-UID transition.

## Bounds and exact authority

The request remains at most 64 KiB, its provider envelope 128 KiB, and the
registry 1 MiB. There are at most 16 profiles, 32 execution identities, 128
grants, four callers and 16 plans per grant, 32 supplementary groups and eight
approved entrypoints per identity. Logical IDs remain at most 64 bytes. The
current schema accepts UTF-8 absolute entrypoint paths of at most 4096 bytes;
empty components, `.` and `..` reject. An identity's UID and GID are nonzero,
and duplicate groups and entrypoint IDs reject. These are schema checks, not
proof of filesystem provenance or account safety.

`PolicyRegistryV2::validate` checks profile references, exact identity
semantic digests, unique records, Linux caller selectors, nonempty grants,
and enabled identity references for active delegated grants. `resolve_v2`
authenticates the supplied caller selector against an exact grant before
inspecting identity availability, then checks epoch, profile, identity,
ceilings, sorted requirements, and the supplied native qualification digest.
It remains a *static* resolver: the provider must independently verify the
live caller envelope, pinned executable, target credentials, namespace,
descriptor table, filter, checkpoint, and retirement before release.

The private profile ceiling is an attempt-private IPv4 TCP stack, no socket at
target entry, no credential gain after the authorized setup transition, and
externally governed filesystem/stdio mediation. It does not promise complete
communication isolation. Its Unix ceiling is a maximum; the immutable
profile semantics deny Unix socket and socketpair creation altogether.
Successful Unix requirements and supplied listeners therefore reject. An
exact-address private TCP peer must be IPv4 loopback. A host-shared-loopback
exact peer in V1 or V2 must be family-consistent loopback; IPv4-mapped IPv6
addresses reject as ambiguous.

## Canonical bytes

All integers are big-endian. The canonical encoder starts with the ASCII
domain, one zero byte, then a `u16` encoding version of `1`. IDs and list
counts use `u16` lengths. Digests and nonces are raw fixed bytes. Sets are
sorted by their stable IDs or raw digest bytes; duplicate semantic members
reject before encoding. The new domains do not alter any V1 preimage.

| Domain | Ordered payload after encoding version |
| --- | --- |
| `memcordon-workload-contract-v2` | Plan digest; profile ID/digest; grant ID/revision/plan digest; five ceiling tags; sorted requirements; sorted endpoint declarations; epoch nonce/revision; identity tag and, for administrator profile, identity ID/digest |
| `profile-definition-v2` | Private profile ID; five ceiling tags; Unix-creation-denial, isolated-loopback, reviewed-ABI-policy and target-transition tags; unprivileged-port-start `0`; ephemeral range `32768..60999`; empty reserved-port list |
| `execution-identity-v2` | Identity ID; UID/GID as `u64`; sorted unique groups as `u64`; sorted entrypoint IDs with UTF-8 path bytes, size and content digest. `enabled` is excluded |
| `authorization-snapshot-v2` | Sorted profile references/enabled flags/qualification digests; sorted complete identity records including enabled flags; sorted grants with exact identity selector; change disposition |
| `private-tcp-checkpoint-v2` | Attempt-binding digest; profile ID/digest; identity tag and optional identity ID/digest; actual pinned entrypoint digest; four identity-control true bytes; caller-envelope nonce; caller and target network-namespace inode numbers as `u64`; two topology true bytes; topology/filter digests; native ABI tag; three port-policy `u16` values and empty-reservations true byte; gated/post-exec descriptor counts and five custody true bytes; guardian, epoch and durable-checkpoint true bytes |
| `private-tcp-terminal-v2` | Attempt-binding digest; checkpoint digest; six required retirement true bytes |

Identity tags are `1` for preserve-caller and `2` for administrator-profile.
The private profile's four fixed semantic tags are each `1`; the reserved-port
list count is `u16(0)`. V2 admission reason codes are closed and add
`execution-identity-not-authorized`, `execution-identity-unavailable`, and
`entrypoint-authority-mismatch` to the eleven V1 meanings. A native
authorization or setup failure must retain its causal diagnostic rather than
being reclassified as a requirement conflict.

The fixed empty-request vector in `crates/memcordon-core/tests/workload_v2.rs`
uses plan/grant digest bytes `07` repeated 32 times, profile
`linux-tcp4-private-v1`, grant `private-grant`, epoch nonce bytes `03` repeated
16 times, epoch revision `1`, no requirements/endpoints, and preserve-caller
tag `1`. Its workload digest is
`736967c1da4c77c4e1e724087e96fcb8d7e718148bc82cb092303c4c035a31dd`.
The private profile reference digest is
`fefad78a6eb35d49a99ca8a2f4771d575331c72a5cabc130fdd64d84d699d1e5`.
The test independently constructs the complete workload preimage before
comparing it with the encoder and checks strict V2 decoding.

These are schema-format answers, not release qualification, package hashes,
or evidence that native private networking is available.

## Private TCP lifecycle claims

`PrivateTcpCheckpointV2` is a closed pre-release claim for the exact
`linux-tcp4-private-v1` profile. The target namespace must differ from the
authenticated caller namespace. The port policy is exactly unprivileged start
`0`, ephemeral range `32768..60999`, and no reserved ports. The gated
descriptor inventory is five objects (anonymous-pipe stdio, transient control
and pinned ELF); post-exec entry has exactly three pipe descriptors. Each
credential, namespace, descriptor, guardian, epoch and durability true byte
must be explicitly observed. An omitted or false field rejects decoding.

`PrivateTcpRetiredV2` binds the same attempt and the checkpoint digest. Its
six required facts are workload empty, helpers reaped, cgroup retired,
provider network references closed, stdio/setup resources closed and policy
snapshot released. `terminal_success` requires an exact checkpoint match.
Neither structure alone proves its native facts: a consumer authenticates the
provider chain, compares the attempt binding and validates the underlying
resource ledger before accepting the claims. No V2 native producer or profile
availability is introduced by these schemas.

The checkpoint vector in `crates/memcordon-core/tests/workload_evidence_v2.rs`
uses repeated digest bytes `01` through `06`, a preserve-caller identity,
caller/target namespace inodes `11` and `22`, x86_64 Linux GNU ABI tag `1`,
and all required facts true. Its canonical SHA-256 answer is
`eccea5cc72146be107a5913a0d7a0fb0cc4f53799a0e797b89e2e649ea20f1a4`.
The corresponding complete-retirement answer is
`7dba00078c910876d8df28169bbb9b16cb78d36a761142854433390c3f26e7f4`.
Both preimages are independently assembled in the test; the fixed answers
were cross-checked with an external SHA-256 implementation.

## Advisory discovery

`WorkloadDiscoveryV2` uses a complete, sorted two-profile Linux catalogue:
the existing Linux Unix-creation baseline and the private IPv4 TCP profile.
Its fixed catalogue digest is
`c87c704237b1d74f70271e64dadcb617421943a1b77f53f11b7b247983fb165d`.
Each profile reports separate target support, package state, required
qualification digest (when a registry definition exists), availability,
visible grants, and only the identity *references* visible to the authenticated
caller. It never discloses UID, GID, groups, or entrypoint paths. The complete
JSON object must fit 128 KiB; overflow is an error, not truncation. Discovery
has a maximum 60-second cache TTL and `target_authorized=false`.

Until the native private-profile qualification source exists, its V2 discovery
entry is explicitly unsupported and unavailable, and any attempt to mark it
supported or enabled-qualified is rejected. Its grant and identity references
may still be visible as advisory administrator policy. Such references do not
make the profile executable. The provider must revalidate current package,
host, registry, caller and target-entry authority at launch.

## Future runtime-manifest boundary

`VersionedRuntimeManifest::parse` retains the historical V2 decoder and adds
a closed, parse-only V3 shape. A V3 Linux workload-V2 record must bind the
proposed wire/report/qualification version matrix, `[1, 2]` supported contract
versions, the exact V2 profile catalogue, component roles and hashes, and
per-profile artifact references for the same source commit and native target.
Its private-TCP profile is rejected if marked qualified until a native
qualification producer and independent artifact verifier are integrated.
The Windows `legacy-v1` branch preserves Windows V1 authority rather than
claiming V2 enforcement.

An artifact reference gives expected bytes and target identity; it is not a
runner completion receipt. Publication must read the actual artifact, verify
its digest and native observed test inventory, and then join it to the release
record. The active runtime producer still emits V2, and the installed package
inspection remains V5. Neither V3 nor inspection V6 is published or used to
authorize a launch by these parse-only types.

## Qualification artifact verification boundary

`QualificationArtifactV2::parse_and_validate` is a parse-only verifier for a
per-profile, per-target native qualification artifact. It checks the exact
artifact-byte digest against its V3 runtime-manifest reference, source commit,
native GNU target, private-profile reference, V2 catalogue digest, filter,
unit and component digests, test inventory, runner run and host-prerequisite
digests. Every required test must have one ordered, native-target `passed`
record with a completion digest that equals an independently supplied trusted
runner record. A skipped, failed, missing, duplicate or extra observation
rejects. The required test names must be sorted and unique; the inventory is
bounded to 256 tests and the artifact to 1 MiB.

The verifier cannot establish that the caller's completion records are
authentic. A future release producer must obtain those records from executed
native x64 and ARM64 jobs, authenticate their provenance and join them to the
checked-in inventory, shipped bytes and installed generation. It may not
derive trusted completions from the artifact's own claims. This schema alone
does not qualify a provider, activate V3 production, enable the private
profile or change the V2 runtime-manifest/V5 inspection currently emitted.

## Proposed Linux package inspection V6

`LinuxInstalledInspectionV6::parse_and_validate` is a separate, parse-only
schema. It binds exact V3 runtime-manifest bytes to source commit, target,
components, Linux native protocol, V2 profile catalogue and agent executable.
Seven compiled/installed unit hashes cover the five baseline systemd inputs
and both optional network-launcher units. The proposed private-filter digest,
fresh launcher state, provider reachability and baseline qualification must
match independent protected inventory and installed readback. False compiled
metadata or installed-artifact validity rejects. Parsing is strict and bounded
to 128 KiB.

The V6 validator rejects an `enabled-qualified` network-launcher state or any
private qualification reference. Native launch, host/boot qualification and
trusted installed readback must be implemented before that prohibition can be
replaced with verified availability. Current package inspection still emits
V5; this V6 shape is not an authorization or an installed-provider claim.

## Linux policy activation and fail-closed V2 plan routing

The Linux administrator apply path dispatches exact V1/V2 registry bytes and
atomically stores one versioned activation in the protected policy directory.
An activated V2 registry retains its version and increments its service epoch
on restart. Existing V1 baseline callers see only an explicit projection of
V2 `linux-unix-create-v1` profiles and `preserve-caller` grants; private and
delegated grants cannot become V1 authority. The projected V1 registry has
its own canonical V1 digest. Revocation and immutable snapshot retention use
the shared live-attempt lease across version changes.

A Linux workload-plan request is version-dispatched before admission. The V2
branch authenticates the caller and checks current registry, epoch, exact
profile/identity grant and requirement compatibility, then returns an explicit
unavailable rejection. It cannot issue a planned or authorized target result
while the native V4 broker, entrypoint custody, checkpoint and qualification
path are absent. V1 baseline plan and launch behavior remains unchanged.
The public `--workload-contract` file parser also distinguishes a valid V2
request from malformed input, returning `MCWORKLOAD-V2-UNAVAILABLE` before
constructing an executable invocation; it does not forward V2 as V1.

## Proposed Linux V4 network broker wire

The optional `network-launch-broker` mode uses a separate protocol V4 frame
reader and writer on the package-owned network-launcher socket. The legacy
control and baseline launcher remain on protocol V3. V4 launch requests carry
an exact V2 contract, its canonical digest, frozen registry and qualification
digests, and a nested native-argv request whose historical V1 contract field
must be empty. The V4 broker envelope binds that launch digest, control peer
PID and start time, caller envelope, attempt identity, and an ordered eight-fd
manifest ending in a verified executable. V3 decoders reject V4, and vice
versa; no downgrade is attempted.

The optional endpoint authenticates the installed control service and process
lifetime before parsing a broker request. It currently returns a typed
`MCSEALED-NETWORK-LAUNCHER-UNQUALIFIED` rejection even for a valid V4 request,
without allocating an attempt or releasing a target. It does not yet verify
the proposed executable descriptor or produce qualified private-profile
evidence. The package-owned unit remains installed-disabled and this wire
must not be interpreted as private-profile availability.
