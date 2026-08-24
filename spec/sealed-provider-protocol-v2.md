# Sealed provider protocol v2

This is a private, local, fail-closed protocol. It is not a stable caller configuration API. A v2 client rejects a v1 provider for sealed execution, and a v2 provider never interprets a v1 launch as v2.

## Public control transport

Each public frame starts with a 72-byte header: big-endian protocol version (`u16`), message kind (`u16`), total frame length (`u32`), 16-byte request nonce, 16-byte attempt id, and the 32-byte SHA-256 digest of the payload. The remaining bytes are a counted payload. Total length is checked before allocation and is limited to 1 MiB. A digest mismatch rejects the frame before payload interpretation. Transport-derived peer identity and the nonce bind the transaction; the payload digest is an integrity check, not peer authentication.

One authenticated request owns one connection. Client kinds are `Probe`, `Launch`, `Cancel`, and `Query`; provider kinds are `ProbeReceipt`, `LaunchPrepared`, `Authorized`, `Progress`, `Terminal`, and `Rejected`. Unknown versions, kinds, fields, duplicate fields, oversized counts, replayed nonces, descriptor-count mismatches, and caller-identity mismatches fail closed.

`LaunchRequestV2` contains only the native program, ordered native arguments, environment entries, execution policy, absolute deadline, stream disposition, and descriptor inventory. It contains no UID, GID, token, capability mask, namespace, cgroup, endpoint, credential-transition selector, or shell command. Unix descriptors are transferred out of band and their exact count and purpose must match the payload.

## Authenticated caller envelope

The control service derives the caller process from `SO_PEERCRED` and authenticated process identity. It captures the caller pidfd; status; mount, PID, user, network, IPC, UTS, and time namespace identities; root and current-directory identities; `NoNewPrivs`; capability bounding set; UID/GID/supplementary groups; and transferred streams. The request payload cannot claim or replace these facts.

Unsupported namespace dimensions, nonzero initial caller effective/permitted/ambient capabilities, a dead or identity-changed caller, or a caller already inside an authenticated attempt are setup rejections before target authorization.

## Private launch-broker transport

The root-only launcher socket accepts one normalized `LaunchBrokerRequestV2` per connection from the exact control-service peer. Peer PID/start identity, executable and systemd-unit/cgroup identity, protocol version, control generation, request digest, descriptor manifest, and request authentication binding are verified before bootstrap.

The broker request contains the attempt id, public request digest, native command record, policy, absolute deadline, authenticated `CallerExecutionEnvelopeV2`, environment, exact descriptor manifest, and durable record identity. Namespace, root, directory, stream, and liveness descriptors are transferred out of band and cross-checked against the digest-bound manifest. The broker has no public workload CLI, network listener, environment-selected endpoint, arbitrary method, or shell surface.

## Authorization and terminal receipts

An authorization receipt is valid only after provider and launcher identity, guardian readiness, creation-time cgroup and namespace assignment, authenticated caller mount-context adoption, exact caller UID/GID/groups, caller `NoNewPrivs` reproduction, caller capability-bounding-set reproduction, absence of provider current capabilities, exact inherited descriptors, spawn-error reporting, recursive-provider denial, and front-end-loss authority are established while the target remains gated.

The target sends one fixed armed record immediately before native `exec`. Close-on-exec EOF then proves successful image replacement. A failed `exec` sends one fixed versioned record containing the target-exec phase, errno-derived class, and native errno. Missing, malformed, duplicate, trailing, unclassified, or class/errno-inconsistent records fail closed. Child exits 126 and 127 remain ordinary exits when `exec-status=success`.

`TerminalReceiptV2` replaces the v1 `capabilities-empty` predicate with `initial-provider-capabilities-absent` and includes caller/target `NoNewPrivs` matching, caller/target capability-bounding-set matching and digest, caller mount-namespace digest and derived mount-context proof, `preserve-caller-envelope`, and boundary independence from credentials. It never claims that post-exec credentials remain fixed. Ordinary completion additionally requires `cgroup.kill`, recursive `populated 0`, namespace-init and guardian reaping, cgroup removal, and durable record retirement.

`QualificationReceiptV2` uses schema 2 and mechanism `linux-pid-namespace-cgroup-v2`. It binds the split-service identities, caller-envelope reproduction predicates, initial provider-capability absence, release-certification inventory/digests for set-ID and `sudo`, post-transition cgroup/PID-namespace/cleanup proofs, and recursive-provider rejection. Every normative boolean must be true and every required identity or digest must be nonempty.

A typed setup rejection identifies the failed phase, whether a target was created or authorized, and terminal cleanup/restart-safety evidence. V2 adds `caller-envelope-capture`, `launcher-service-authentication`, `caller-mount-namespace-adoption`, `caller-capability-envelope`, and `credential-transition-policy`. Provider journals remain bounded and secret-free: they never contain argv, environment values, stream contents, or transferred descriptor contents.
