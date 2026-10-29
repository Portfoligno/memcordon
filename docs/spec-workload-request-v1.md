# Workload requests, revision 1

The current input format is `memcordon.workload-request`, revision 1. It describes
required runtime behavior and input content. It contains no grant, policy epoch,
approved plan, administrator-selected account, or caller filesystem destination.
The operating system's provider endpoint permissions determine who can request
execution. A request never widens those permissions.

The parser accepts only the exact current format and revision. Other formats
are unsupported; no previous contract reader or cleanup adapter is shipped.

## Linux private workloads

The `linux-private-workload-v1` profile requires the installed privileged provider
and its package-owned, locked, nonlogin `memcordon-workload` account. Targets share
that account. Each attempt receives separate mount, PID, network and IPC
namespaces, a fresh root, a cgroup and the selected architecture's native filter.
The shared account is not a boundary between attempts. The namespace, descriptor,
root, filter and cgroup observations provide that boundary.

The caller supplies `--workload-input PATH`, a local bundle containing measured
runtime and input manifests followed by their regular file contents. The frontend
opens this file with caller rights and streams bounded chunks. The provider
creates fresh protected inodes, checks lengths and content digests, and validates
the executable and ELF dependency closure before release. It does not open the
caller's source paths. `--image-entrypoint ID` selects a declared logical entrypoint;
it is not an administrator image approval.

Writable root declarations are bounded and identify private-root paths. Optional
`--workload-cwd ROOT_RELATIVE_PATH` selects the initial private directory; omission
selects the held private root itself. Retained requirements include private TCP,
Unix stream and sequenced-packet sockets, abstract sockets, descriptor transfer,
generated executables and expected denial observations. Unsupported requirements
are rejected before release rather than silently omitted.

Writable tmpfs mounts also have a finite inode budget derived from their byte
quota, with a maximum of 65,536 inodes per mount. Shared memory has its own bounded
byte and inode budgets. Admission accounts for page-rounded content, metadata,
staging and export copies against both available storage and memory.

Declared output files require `--workload-output DIRECTORY`. After actual native
process retirement, the provider reads from held original writable-root
descriptors and streams bytes. The frontend creates files beneath a directory
held with caller rights, refusing symlink traversal and collisions. The destination
path is never sent to the provider. Output delivery can fail after successful
target execution; its status remains separate from native outcome and cleanup.

`--workload-observation PATH` persists an exact attempt locator before input is
sent. `memcordon workload recover --observation PATH --report PATH` requests
cleanup of that original attempt. Recovery validates the authenticated caller,
native birth identities, protected journal and original cutoff. It cannot rerun
the target, reconstruct a live owner from terminal JSON, or recreate lost output
handles. Its response is cleanup evidence, not the original invocation result.

`memcordon workload acknowledge --observation PATH` retires completed recovery
metadata after the original worker and control process have exited and their
native allocations are absent. It returns an acknowledgment for that exact
locator. A caller should retain its delivered result before acknowledging;
unacknowledged metadata consumes the provider's bounded retention capacity.

An optional `--workload-observation-directory DIRECTORY` holds execution at the
prepared gate. The caller-owned directory receives the exact original
`<attempt>.start.json` bytes before input transfer and the exact native
`<attempt>.prepared.json` bytes before release. A corresponding
`<attempt>.prepared-ack.json` must bind the full original association and SHA-256
of those prepared bytes. The original setup cutoff still applies while waiting.
Cancellation at this gate does not release target instructions.

The current invocation commitment hashes the domain
`memcordon.native-invocation/version1` followed by a NUL byte, the big-endian
64-bit length and exact native launch bytes, and a cwd presence byte. A present
private-root cwd adds its big-endian 64-bit UTF-8 length and bytes. Thus changing
only the cwd changes the invocation commitment. Resource policy has a separate
domain and binds its exact native codec range and original attempt duration.

Ordinary Linux `--sealed` without a workload request continues to preserve caller
credentials. Its result does not claim the shared-account private workload profile.

## Windows sealed workloads

A minimal request is:

```json
{"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}
```

The provider authenticates the actual connection and uses the caller's effective
token. Job, guardian and durable recovery mechanisms contain descendants and
retain native retirement obligations. This profile does not claim a filesystem
or network sandbox, caller-selected execution identity, or administrator grant.

## Observations and versioning

Current named capabilities, plan and result documents use revision 3. Capabilities
and plans are advisory and never authorize a launch. Results distinguish release
knowledge, directly observed target outcome, native cleanup, frontend relay and
control settlement, output delivery, and result-file delivery. Unknown ownership
or incomplete cleanup remains explicit. Native termination is reported only from
the corresponding native observation; recovery never invents an exit status.
Linux native observations also retain the SHA-256 of the held, sealed first
executable. Prepared and terminal observations bind the same image bytes.

Runtime manifests use revision 2 and package inspection uses revision 2. Linux
private workload transport uses native wire revision 5. Windows current transport
uses revision 4, durable attempts revision 5, and terminal receipts revision 3.
Only current named output and native transport revisions are accepted. No
previous policy format is decoded, projected, recovered, or launched.

Installation requires a clean managed location or a verified compatible current
installation. An occupied incompatible location or unknown current state is
refused without decoding or deleting its contents. Current recovery acts only on
exact native resources owned by its current journal. There is no policy-era
upgrade, environment purge, administrator-account discovery plane, or approved
image store. Native validation still checks that the fixed package account has
the exact recorded UID/GID and no conflicting operating-system aliases.

The Linux current package transaction records staged files, original images and
empty backup placeholders by native inode and content digest. Its journal stays
present through preparing, published and retiring phases. Published verification
requires the exact current postimages; recovery rolls back a preparing/published
transaction or finishes an already committed retirement. Unknown replacement
files are retained, and the journal is removed after owned backup retirement.

Source compilation and pure codec tests do not qualify installed native behavior.
Linux retains one empty, root-owned package lock inode across installation and
uninstallation so concurrent package operations use the same native lock.
Native Linux x86-64/ARM64 and Windows x86-64/ARM64 execution, interrupted delivery,
recovery and current package transactions require native installed-provider CI.
