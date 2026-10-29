# Linux sealed mechanism v2

`linux-pid-namespace-cgroup-v2` is available only through the installed root-owned MemCordon provider package. The public caller asks only for `--sealed` with a native command and argument vector; it cannot select a provider socket, identity, capability, namespace, cgroup, guardian, credential mode, or cleanup mechanism.

## Split service boundary

The public `memcordon-sealed-agent.service` is the hardened control plane. It owns `/run/memcordon/sealed-agent.sock`, authenticates the caller, parses bounded current transport, captures the caller execution envelope, rejects recursive attempts, owns durable records and recovery, and never executes caller code. It retains `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, a narrow capability bounding set, and no ambient capabilities.

The private `memcordon-sealed-launcher.service` owns the root-only mode-`0600` `/run/memcordon/sealed-launcher.sock` and accepts only the exact authenticated control service. It uses `NoNewPrivileges=no` and no ambient capabilities. It omits `PrivateTmp`, `ProtectSystem`, `RestrictSUIDSGID`, and a guessed `CapabilityBoundingSet`; a child cannot undo those inherited restrictions, so the launcher must begin in a context capable of reproducing every supported caller envelope. Its implementation accepts only the fixed broker request and performs attempt bootstrap, never arbitrary workload CLI, shell, network, plugin, archive, Git, YAML, package mutation, or caller-selected cleanup operations.

Package installation and verification cover the provider binary, both services, both sockets, and the tmpfiles declaration that recreates `/run/memcordon` as mode `0750` `root:memcordon` before socket activation, all with exact bytes, root ownership, exact modes, fixed endpoints, binary identity, and required/forbidden directives. Current mutation stops and proves both roles inactive and refuses while a control attempt, broker attempt, guardian, or unknown recovery state exists. Incompatible occupied installations are refused without interpreting their state.

## Caller execution envelope

The control service authenticates the socket peer and opens its pidfd, `/proc` status, mount-namespace descriptor, root and current-directory descriptors, and transferred standard streams. The private envelope records UID/GID/supplementary groups, `NoNewPrivs`, capability bounding set, namespace identities, and root/directory identities. Same-provider user, network, IPC, UTS, and time namespace contexts plus safely joinable arbitrary caller mount namespaces are supported initially; unsupported contexts fail before authorization.

The broker starts a dedicated single-threaded bootstrap, joins the authenticated caller mount namespace with `setns`, verifies its identity, and invokes `clone3(CLONE_INTO_CGROUP)` with new PID, mount, and cgroup namespaces. The nested mount namespace begins from the caller view. It makes propagation private, remounts `/proc` for the nested PID namespace, hides the host cgroup filesystem and provider control paths, and retains no host namespace handle. It does not create a private `/tmp`, make the workspace read-only, replace the home directory, hide toolchain paths, or rewrite the current directory.

Before gate release the target must prove all real/effective/saved/filesystem UID/GID values and supplementary groups match the authenticated caller; its capability bounding set equals the caller's; its effective, permitted, inheritable, and ambient provider capabilities are zero; and its `NoNewPrivs` equals the caller's. A caller with initial effective, permitted, or ambient capabilities is unsupported by v2 and fails closed rather than having authority silently dropped.

Bounding-set capabilities absent from the caller are dropped while the bootstrap still has `CAP_SETPCAP`. Root-only namespace and group setup precedes final UID/GID transition. Current and ambient provider capabilities are then cleared. `PR_SET_NO_NEW_PRIVS` is called only when the authenticated caller already had `NoNewPrivs: 1`. The exact descriptor set and close-on-exec control socket are verified before authorization. Native `std::process::Command` receives the separate program, arguments, and environment; after the gate it ends in reviewed `CommandExt::exec` with a live failure-status channel.

## Credential-independent containment

After authorization, set-ID execution, file-capability acquisition, `sudo`, UID/GID changes, `setsid`, double-fork, and daemonization do not change boundary membership. Monitoring treats credential changes as ordinary workload behavior and continues to verify the provider-owned attempt cgroup, nested namespace-init identity, guardian liveness, policy, direct-target status, and provider ownership.

The attempt cgroup is the nested cgroup-namespace root. No writable ancestor cgroup, parent PID/cgroup/mount/user namespace descriptor, provider or guardian pidfd, cgroup directory, control socket, launcher socket, or provider record is inherited. An elevated descendant may manage only an attempt subtree and remains subject to recursive `cgroup.kill` at the attempt root. The provider, launcher, and guardian remain outside the target PID namespace. The public provider rejects authenticated peers whose cgroup, PID/mount/cgroup namespace identity, durable membership, or provenance places them inside an active attempt, independent of UID.

Unrelated privileged host brokers remain outside the process-lineage threat model. Sealed supervision is not a filesystem, network, syscall, secret, package-manager, or general host isolation boundary; elevated target code may modify host resources its intentionally acquired credentials can reach.

## Readiness, runtime facts and native tests

Current readiness is a named factual observation of the actual installation,
authenticated services, native baseline setup and cleanup. It does not bind
set-ID/sudo hashes or issue a saved permission token. Every launch independently
checks the actual caller and installed components. The client rejects a provider whose
package version differs before target authorization; an operator must explicitly
install or upgrade the matching package.

Current result revision 3 carries ordinary Linux sealed native facts and `preserve-caller-envelope`. Consistency requires caller envelope reproduction and boundary independence from credentials; it does not require permanently empty target capabilities or `NoNewPrivs: 1`. Plans and capabilities use named revision 3. Ordinary native transport is version 3. No administrator contract or saved permission token is interpreted.

Ordinary native regressions preserve actual caller NNP/CapBnd, credential
transition, mount context, cgroup/PID membership, escape denial, recursive-provider
rejection, owner loss, cgroup.kill, populated0, reaping and package recovery
behavior. Test-owned users, processes, records, cgroups, fixtures and units must
retire. Missing or unavailable prerequisites are recorded truthfully rather than
passing skipped cases. Passing regressions does not replace the runtime's live
checks. All subprocesses use native structured argv.

The private TCP feature has a distinct target identity and seccomp contract,
release-started attempt timer and real ptrace exec-stop handshake. Its current
gated and post-exec facts are described in the
[workload request contract](../docs/spec-workload-request-v1.md).
