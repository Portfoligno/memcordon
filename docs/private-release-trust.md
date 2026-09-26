# Private native qualification trust

The installed Linux agent accepts native Q only with a completed-CI Ed25519
certificate (CQ) under an administrator-provisioned release trust root. Q,
the build inventory (B), and CQ are installed as exact bytes below
`/usr/libexec/memcordon/certification/workload/`. For each supported GNU target,
the fixed leaves are `linux-<x64|arm64>-private-v2.json`,
`<x64|arm64>-private-build-v1.json`, and
`<x64|arm64>-private-cq-v1.json`.

The administrator independently provisions these protected files before
installing a qualified M1 (an unqualified M0 needs no release trust):

- `/etc/memcordon/release-trust/root-anchor.v1.json`: JSON object with
  `schema_version: 1`, `root_key_id`, and lowercase hex `public_key_hex`.
- `/etc/memcordon/release-trust/policy.v1.json`: a
  `SignedReleaseTrustPolicyV1` whose payload pins repository id/name, reviewed
  workflow path/revision, verifier executable and policy digests, catalogue
  digest, delegated key roles and validity, minimum release sequence, and
  sorted revocation sets.
- `/var/lib/memcordon/sealed/release-trust/`: root-owned state directory for
  the durable `high-water.v1.json` and `state.lock` leaves.

For an exceptional sequence rollback, the administrator may additionally
install `/etc/memcordon/release-trust/rollback-exception.v1.json` (mode 0600).
It must carry an offline-root signature over the exact B and Q digests,
allowed older sequence, current policy version, and short validity interval.
The durable high-water sequence is never lowered; removing or expiring the
exception restores the normal floor. A revoked B or Q cannot be excepted.

To rotate the offline root, the administrator installs a new root anchor,
policy, and `/etc/memcordon/release-trust/root-rotation.v1.json` atomically
under protected custody. The rotation document names both exact root public
keys and key ids, requires a strictly higher policy version, has a bounded
validity interval, and must be signed by both the previously persisted root
and the new root. The agent persists the new root only after verifying the
dual signature and new policy. An anchor replacement without that transition
denies admission.

The root key must be delivered outside the release bundle. The collector uses
only a delegated `NativeQ` signing key; its private bytes never enter the
installed artifact, argument vector, or workflow log. The offline root signs
the policy's `canonical_bytes()`; the collector signs the Q certificate's
`canonical_bytes()`. Both encodings are domain-separated and length-prefixed.
The JSON envelope is only a bounded transport representation. The exact
signing and verification structures are in
`crates/memcordon-core/src/release_trust.rs`.

Policy version, release sequence, pinned root key, and last accepted wall and
same-boot monotonic times advance in protected state. A valid newer policy
advances the version even if it revokes the current CQ. Package uninstall
retains this state so reinstall cannot lower the release floor. Qualified package
installation verifies installed B/Q/CQ under the independent root before service
activation; it does not publish H1. Admission rereads the policy,
certificate, Q, B, and current H1 while retaining the package generation
lease; the release barrier repeats the trust and H1 checks. An unchanged B/Q
may reuse its valid CQ on another host, but every host and installation epoch
must create its own H1. Changed policy bytes at the same version, expired or
revoked evidence, clock rollback, and a stale release sequence deny admission.
An offline host cannot learn an unpublished revocation; policy and certificate
expiry bound that interval. Root rotation is an administrator-controlled
operation and is not implicit in a downloaded bundle.

For a same-host final-public collector, root runs
`/usr/libexec/memcordon-sealed-agent package qualify-private`, then
`/usr/libexec/memcordon-sealed-agent package verify-private-host --json`.
The second command holds the package-generation lock and verifies current
M1/B/Q/CQ, policy, active H1, installation epoch, and release boundary before
emitting schema-1 file-byte hashes and H1 identity. It does not publish H1 or
authorize P by itself; independent archive and final-public evidence must join
that readback. Trust verification can advance durable high-water state.

The final-public provider journal is a separate, deliberately partial proof.
Root registers an exact live child PID/start time, fixed selector and
root-pinned challenge with `package register-public-release-case`; after that
child execs the installed public CLI, the service binds its peer credentials,
contract, current H1 and plan/launch frames before writing provider-owned
records under `/var/lib/memcordon/sealed/private-public-cases/`. Root can run
`package verify-public-release-provider --selector ... --challenge ... --json`
for detached readback. These records do not contain independent CLI report,
stdio, kernel or retirement observations and cannot by themselves authorize P.

No production root or delegated private key is generated by this repository.
The release operator must provision the root anchor/policy, delegated signing
credential, trusted host clock, and protected state directory. Portable tests
use deterministic test-only signing keys and do not issue release authority.
