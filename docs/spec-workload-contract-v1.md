# Workload contract V1

This document describes the implemented workload admission interfaces. Native
qualification and release publication remain separate evidence requirements;
the presence of these interfaces does not certify a host or grant a workload
permission. Implementation references are linked below so schema and behavior
changes can be reviewed together.

## Authority and supported profiles

The strict request binds one workload-plan digest, one profile ID and semantic
digest, one grant ID/revision and approved-plan digest, a security ceiling,
functional requirements, logical endpoints, and an expected policy epoch.
The provider obtains caller identity from its authenticated native channel.
A workload file cannot supply authoritative caller identity or create a grant.

The implemented [profile catalogue](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-core/src/workload_registry.rs)
contains these two baseline definitions:

| Profile | Direct socket ceiling | Implemented functional admission |
| --- | --- | --- |
| `linux-unix-create-v1` | `pinned-legacy-socket-filter-accepted` | Unix socket creation/socketpair requirements and an INET-creation denial exercise |
| `windows-host-network-external-v1` | `external-host-policy-accepted` | TCP requirements with `host-shared-loopback` scope |

Linux describes the existing Unix-only socket syscall filter with alternate
creation-path coverage unknown. It does not claim comprehensive prevention of
new INET sockets, control of existing sockets, or absence of external
communication. Windows networking remains governed by Windows and site policy;
Job containment does not establish a private network compartment. Functional
admission does not promise that a bind, connection, or application exchange
will succeed under current host conditions.

Both profiles accept existing host Unix authority, existing standard-stream
authority, the existing caller credential envelope, and external filesystem/
stdio-mediated communication policy. These are separate ceiling dimensions.
The implemented comparison requires equality in those four dimensions. For
direct socket authority it accepts equality, or the broader external-host
ceiling containing the pinned Linux legacy-filter authority. It does not use
enum ordinals as a general permission ordering.

The types recognize stricter ceilings, private-stack TCP, supplied listeners,
and other denial exercises. Recognition does not imply enforceability. There
is no implemented `linux-tcp4-private-v1` profile in this catalogue. No request
enables a new network launcher, broadens the baseline service filter, imports a
listener, or silently substitutes another profile. A Linux request requiring
successful TCP is rejected as `policy-incompatible` before target authorization.

## Strict input and deterministic resolution

[WorkloadContractV1](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-core/src/workload_contract.rs) uses a
closed schema. Its strict parser rejects unknown fields/variants, duplicate
JSON keys, malformed digests/nonces, zero revisions, excessive bounds,
duplicate IDs, and unresolved or cyclic endpoint references. Logical IDs are
bounded lowercase ASCII identifiers, not native paths. Native invocation and
credential data remain in their private protocol domains.

TCP operations are a nonempty set: create, bind, listen, accept, connect,
stream-read, and stream-write. Listen requires bind; accept requires listen;
stream I/O requires accept or connect. Endpoint declarations must refer to a
TCP listener role. Referencing peers must agree with that role's family and
scope. Kernel-assigned ports remain a selector; exact/range ports are nonzero,
with ordered range endpoints. These checks validate the request's meaning;
they do not turn its requirements into authority.

After strict decoding, the resolver checks:

1. An enabled exact grant ID/revision applies to the authenticated caller and
   exact workload-plan digest, including the approved-plan reference.
2. The expected epoch equals the active epoch.
3. The granted profile reference equals the requested ID and digest, and its
   catalogue entry is enabled.
4. The profile matches the native backend and current qualification digest.
5. The request ceiling fits the grant ceiling and contains the profile's
   complete authority.
6. Every requirement is supported by that profile.

Grant matching precedes disclosure of detailed functional conflicts.
Requirements are checked in logical-ID order; at most 16 conflicts are
returned with an explicit remaining count. Unknown or unavailable functionality
never becomes an implicit permission. A rejection cannot authorize the target;
allocated resources still require native cleanup.

The [shared limits](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-core/src/workload_limits.rs) include:

| Object | Limit |
| --- | --- |
| Contract body / request envelope | 64 KiB / 128 KiB |
| Requirements / endpoint declarations | 64 / 32 |
| Logical identifier | 64 ASCII bytes |
| Registry body | 1 MiB |
| Profiles / grants | 16 / 128 |
| Approved plans per grant / callers per grant | 16 / 4 |
| Retained snapshots / live binding references | 16 / 256 |
| Public admission/discovery subobject | 128 KiB |
| Added workload report contribution | 1 MiB |

Count limits do not override byte limits. A valid registry with 128 grants and
16 plans per grant can exceed the caller-specific discovery byte budget. That
discovery request fails explicitly; it does not return a truncated response
marked complete.

## Canonical bytes and commitment order

The [canonical codec](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-core/src/workload_codec.rs) is separate
from JSON formatting. Each domain is ASCII followed by NUL and schema 1 as a
big-endian u16. Strings and vector counts use big-endian u16 lengths/counts;
revisions and restart numbers use big-endian u64. Digests and nonces use raw
32-byte and 16-byte values. IP addresses use raw family-specific bytes.
Canonical decoding rejects trailing bytes, unknown tags, and noncanonical set
order. Duplicate semantic entries are rejected rather than deduplicated.

| Enum | Canonical tags |
| --- | --- |
| Requirement | 1 Unix creation; 2 Unix socketpair; 3 TCP; 4 supplied listener; 5 denial exercise |
| TCP operation | 1 create; 2 bind; 3 listen; 4 accept; 5 connect; 6 read; 7 write |
| TCP scope | 1 attempt-private stack; 2 host-shared loopback |
| IP family / endpoint address family | 1 IPv4; 2 IPv6 |
| Unix kind | 1 stream; 2 datagram; 3 sequence-packet |
| Local port selector | 1 kernel-assigned; 2 exact; 3 inclusive range |
| Peer selector | 1 same-attempt endpoint; 2 exact address |
| Direct ceiling | 1 pinned legacy filter; 2 no new INET; 3 private IPv4 all ports; 4 external host policy |
| Unix ceiling | 1 socketpairs only; 2 existing host authority |
| External socket ceiling | 1 no socket at entry; 2 existing stdio authority |
| Credential ceiling | 1 no gain; 2 existing caller envelope |
| Mediated communication ceiling | 1 external filesystem/stdio policy; 2 no external communication |
| Denial operation | 1 INET creation; 2 named Unix creation; 3 external socket import |

Zero and unassigned tags reject. Tag numbers belong to their named enum.
The following preimages establish the commitment dependency order:

| Domain | Ordered contents after domain/schema |
| --- | --- |
| `memcordon-workload-contract-v1` | Plan digest; profile ID/digest; grant ID/revision/approved-plan digest; five ceiling tags; requirements sorted by ID; endpoints sorted by ID; epoch nonce/revision |
| `profile-definition-v1` | Profile ID; five ceiling tags; baseline restriction tag; alternate-path knowledge tag |
| `authorization-snapshot-v1` | Profiles sorted by ID; grants sorted by ID; active-attempt disposition |
| `effective-workload-policy-v1` | Request digest; profile digest; registry digest; five effective ceiling tags |
| `attempt-policy-binding-v1` | Request/plan/profile/grant/epoch binding; registry/qualification; provider generation/source/runtime digest; boot identity; effective digest; attempt ID/restart number; admission nonce; opaque caller/invocation reference |
| `attempt-policy-enforcement-v1` | Attempt-binding digest; restriction tag; six verified preauthorization facts |

Registry profile entries encode ID/digest, enabled byte, and qualification
digest. Grant entries encode ID/revision, profile ID/digest, ceiling, enabled
byte, callers sorted by binary encoding, and plans sorted by digest. Caller
tags are 1 for a big-endian Linux UID and 2 for a length-prefixed Windows SID.
Disposition tags are 1 drain and 2 revoke. Epoch activation metadata is outside
the registry digest, preventing a circular commitment.

An attempt preimage contains no checkpoint digest. Its checkpoint commits to
the attempt, and terminal evidence references both. A plan cannot invent an
attempt nonce or preauthorization proof. Public references bind private caller
and invocation records without publishing environment, argv, or raw credentials.
Hashes detect substitution against independently trusted expected values; they
do not authenticate a provider by themselves.

The [independent fixed vectors and derivation](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-core/tests/fixtures/workload_independent/README.md)
specify concrete contract, registry, effective, attempt, and checkpoint
preimages and external SHA-256 answers. Their [tests](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-core/tests/workload_independent_vectors.rs)
also exercise ordering invariance, malformed decoding, identity substitution,
discovery capacity, and incomplete checkpoints/retirement.

## Registry lifecycle and advisory discovery

The native agent implements these administrator operations:

```text
memcordon-sealed-agent package policy inspect --json
memcordon-sealed-agent package policy apply --file approved-policy.json
```

Apply parses the bounded configuration before activation. Native leases
serialize activation against admission, preserve immutable snapshots needed by
live bindings, and reject capacity exhaustion. See the
[Linux registry](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-cli/src/bin/memcordon-sealed-agent/policy_registry.rs)
and [Windows registry](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/policy_registry.rs).
The administrator-facing policy area is distinct from private attempt state.

An activation binds a registry digest to a service-instance nonce and nonzero
revision. Policy changes increment revision with checked overflow; service
startup establishes a new instance. Launch rechecks the frozen admission
against current authority under the native policy lease before authorization.
Every restart needs a fresh admission binding.

`drain-existing` retains already admitted attempts under frozen policy.
`revoke-active` records revocation for live admission nonces and requires
observed retirement before successful completion of the apply operation.
Failure to observe retirement before the bounded deadline returns an error
even when revocation has already activated. A later drain activation cannot
clear the revocation latch for an admission still live.

[Discovery](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-core/src/workload_discovery.rs) returns
caller-filtered grants, support/availability, profile/catalog/qualification
bindings, optional active epoch/registry identity, completeness, and a maximum
TTL of 60 seconds. Its target-authorized field is fixed false. Discovery is
advisory; a cached result or profile name cannot replace live admission. A
caller with no grants can receive a complete empty grant list without gaining
launch authority. Unconfigured policy is distinct from unavailable inspection.

## Reports and version domains

Requested workload policy is explicitly legacy-unspecified or strict V1.
Resolution distinguishes planned, rejected, admitted, and unavailable states.
Attempt policy evidence distinguishes not-authorized, authorized, and uncertain
authorization. An unavailable terminal record cannot prove success, and a
diagnostic projection cannot replace native retirement evidence. Verified
checkpoints require gated target, caller, resources, guardian, epoch, and
durability facts, bound to the exact attempt and baseline restriction.

| Surface | Implemented revision |
| --- | --- |
| Execution / plan / doctor report | 9 / 8 / 6 |
| Workload contract and profile semantics | 1 |
| Generic provider contract / Linux launch wire | 3 / 3 |
| Windows public / private wire | 2 / 2 |
| Policy-bearing Linux durable attempt / Windows durable attempt | 3 / 3 |
| Runtime manifest | 2 |
| Package and installed-provider inspection | 5 |

These are independent schema domains, not one interchangeable protocol
number. Historical Linux records retain their older record conventions;
decoding them does not manufacture strict V1 admission. Runtime manifests bind
the platform protocol inventory, component provenance, profile catalogue, and
qualification artifact references. Mixed or stale bindings cannot be promoted
to a current qualified strict attempt.

## Qualification, certification, and release scope

[Runtime artifact references](https://github.com/Portfoligno/memcordon/blob/main/crates/memcordon-core/src/runtime_manifest.rs)
state both the qualified target and whether it qualifies the package target.
The Linux profile artifact currently names `x86_64-unknown-linux-gnu`; attaching
that artifact to another Linux package does not qualify that package target.
Windows references distinguish x64 and ARM64 profile and causal-diagnostic
qualification artifacts. Actual native qualification remains necessary for
the corresponding installed component set and host observations.

Ordinary backend certification remains independent of sealed workload
admission. The [standard catalogue](https://github.com/Portfoligno/memcordon/blob/main/tools/memcordon-ci/src/standard_contract.rs)
requires 23 Linux x64 scenarios on `ubuntu-24.04` and 17 Windows x64 scenarios
on `windows-2025`. The historical standard floor is preserved separately from
the current catalogue, with the Linux guardian-observation regression appended.

Standard certificate schema 3 binds the exact catalogue digest, standard
boundary/backend, native target, source commit, runtime observations, ordered
named passing tests, and zero skips. Hosted release certificates additionally
bind repository, run, workflow reference/commit, source, and exact release job
through [certification provenance](https://github.com/Portfoligno/memcordon/blob/main/tools/memcordon-ci/src/certification_context.rs).
A local observation cannot satisfy a hosted producer-origin check. Standard
and sealed jobs, artifacts, and required release records remain distinct.
Compilation caches cannot substitute for fresh native scenario execution.

Release configuration uses schema 4, and the release manifest records the
`standard-and-sealed-v1` certification contract. Its producer-origin checks
bind the separate standard certificates to the releasing workflow run;
valid sealed evidence cannot compensate for missing ordinary certification.

Portable codec tests and seeded fuzz smoke substantiate data validation only.
They do not establish OS enforcement, private TCP support, native revocation
cleanup, publication, downstream pin acceptance, or successful execution of a
consumer's unchanged TCP workload. Those claims require their respective native,
release, and consumer evidence.
