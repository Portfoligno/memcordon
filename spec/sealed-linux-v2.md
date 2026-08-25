# Linux sealed mechanism v2

`linux-pid-namespace-cgroup-v2` is available only through the installed root-owned MemCordon provider package. The public caller asks only for `--sealed` with a native command and argument vector; it cannot select a provider socket, identity, capability, namespace, cgroup, guardian, credential mode, or cleanup mechanism.

## Split service boundary

The public `memcordon-sealed-agent.service` is the hardened control plane. It owns `/run/memcordon/sealed-agent.sock`, authenticates the caller, parses bounded protocol v2, captures the caller execution envelope, rejects recursive attempts, owns durable records and recovery, and never executes caller code. It retains `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, a narrow capability bounding set, and no ambient capabilities.

The private `memcordon-sealed-launcher.service` owns the root-only mode-`0600` `/run/memcordon/sealed-launcher.sock` and accepts only the exact authenticated control service. It uses `NoNewPrivileges=no` and no ambient capabilities. It omits `PrivateTmp`, `ProtectSystem`, `RestrictSUIDSGID`, and a guessed `CapabilityBoundingSet`; a child cannot undo those inherited restrictions, so the launcher must begin in a context capable of reproducing every supported caller envelope. Its implementation accepts only the fixed broker request and performs attempt bootstrap, never arbitrary workload CLI, shell, network, plugin, archive, Git, YAML, package mutation, or caller-selected cleanup operations.

Package installation and verification cover the provider binary, both services, both sockets, and the tmpfiles declaration that recreates `/run/memcordon` as mode `0750` `root:memcordon` before socket activation, all with exact bytes, root ownership, exact modes, fixed endpoints, binary identity, and required/forbidden directives. Upgrade and uninstall stop and prove both roles inactive and refuse while a control attempt, broker attempt, guardian, or ambiguous recovery state exists. Protocol v1 attempts are terminally cleaned, never resumed with v2 semantics.

## Caller execution envelope

The control service authenticates the socket peer and opens its pidfd, `/proc` status, mount-namespace descriptor, root and current-directory descriptors, and transferred standard streams. The private envelope records UID/GID/supplementary groups, `NoNewPrivs`, capability bounding set, namespace identities, and root/directory identities. Same-provider user, network, IPC, UTS, and time namespace contexts plus safely joinable arbitrary caller mount namespaces are supported initially; unsupported contexts fail before authorization.

The broker starts a dedicated single-threaded bootstrap, joins the authenticated caller mount namespace with `setns`, verifies its identity, and invokes `clone3(CLONE_INTO_CGROUP)` with new PID, mount, and cgroup namespaces. The nested mount namespace begins from the caller view. It makes propagation private, remounts `/proc` for the nested PID namespace, hides the host cgroup filesystem and provider control paths, and retains no host namespace handle. It does not create a private `/tmp`, make the workspace read-only, replace the home directory, hide toolchain paths, or rewrite the current directory.

Before gate release the target must prove all real/effective/saved/filesystem UID/GID values and supplementary groups match the authenticated caller; its capability bounding set equals the caller's; its effective, permitted, inheritable, and ambient provider capabilities are zero; and its `NoNewPrivs` equals the caller's. A caller with initial effective, permitted, or ambient capabilities is unsupported by v2 and fails closed rather than having authority silently dropped.

Bounding-set capabilities absent from the caller are dropped while the bootstrap still has `CAP_SETPCAP`. Root-only namespace and group setup precedes final UID/GID transition. Current and ambient provider capabilities are then cleared. `PR_SET_NO_NEW_PRIVS` is called only when the authenticated caller already had `NoNewPrivs: 1`. The exact descriptor set and close-on-exec control socket are verified before authorization. Native `std::process::Command` receives the separate program, arguments, and environment; after the gate it ends in reviewed `CommandExt::exec` with a live failure-status channel.

## Credential-independent containment

After authorization, set-ID execution, file-capability acquisition, `sudo`, UID/GID changes, `setsid`, double-fork, and daemonization do not change boundary membership. Monitoring treats credential changes as ordinary workload behavior and continues to verify the provider-owned attempt cgroup, nested namespace-init identity, guardian liveness, policy, direct-target status, and provider ownership.

The attempt cgroup is the nested cgroup-namespace root. No writable ancestor cgroup, parent PID/cgroup/mount/user namespace descriptor, provider or guardian pidfd, cgroup directory, control socket, launcher socket, or provider record is inherited. An elevated descendant may manage only an attempt subtree and remains subject to recursive `cgroup.kill` at the attempt root. The provider, launcher, and guardian remain outside the target PID namespace. The public provider rejects authenticated peers whose cgroup, PID/mount/cgroup namespace identity, durable membership, or provenance places them inside an active attempt, independent of UID.

Unrelated privileged host brokers remain outside the process-lineage threat model. Sealed supervision is not a filesystem, network, syscall, secret, package-manager, or general host isolation boundary; elevated target code may modify host resources its intentionally acquired credentials can reach.

## Qualification, evidence, and certification

Runtime qualification schema 2 proves split-service installation/authentication, launcher NNP disabled, caller mount/NNP/CapBnd reproduction, initial provider capabilities absent, cgroup and namespace containment, exact descriptors, recursive-provider rejection, front-end-loss cleanup, recursive emptiness, helper reaping, boundary retirement, and recovery. The receipt binds the release certification scenario inventory and required set-ID/`sudo` digests.

The receipt also carries the exact MemCordon package version. The public client
rejects a provider whose version differs from its own before target
authorization; an operator must explicitly install the matching package and
run the package upgrade command.

Execution report schema 8 carries `LinuxSealedEvidenceV2` and `preserve-caller-envelope`. Consistency requires caller envelope reproduction and boundary independence from credentials; it does not require permanently empty target capabilities or `NoNewPrivs: 1`. Plan and doctor schemas are 7 and 5. V1 provider/mechanism/evidence is never accepted under the new schemas.

Linux x86-64 release certification builds temporary Rust fixtures, a root-owned mode-`04755` set-ID fixture, a minimal file-capability fixture, and an ephemeral test user. It verifies set-ID, `sudo -n -u`, file-capability, caller NNP 0 and 1, reduced CapBnd, caller-specific mount context, post-transition cgroup/PID membership, elevated escape denial, recursive-provider rejection, front-end/provider/launcher/guardian loss, `cgroup.kill`, `populated 0`, complete reaping, package upgrade/recovery, and absence of leaked users/processes/records/cgroups/fixtures/units. All subprocesses use native argv from Rust; no shell or workflow environment protocol is involved.

Certification uploads newline-terminated structured reports:

- `provider-package-verification.json`;
- `provider-qualification-v2.json`;
- `setid-transition.json`;
- `sudo-transition.json`;
- `file-capability-transition.json`;
- `caller-envelope.json`;
- `mount-context.json`;
- `fault-injection.json`; and
- `cleanup-leak-check.json`.

Every required scenario must be present and passed; Linux x86-64 cannot advertise v2 when a set-ID, `sudo`, or file-capability prerequisite is unavailable. Missing, skipped, false, stale, contradictory, or v1 evidence fails the release.
