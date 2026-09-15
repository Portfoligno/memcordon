# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.security

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/security.rs`  
Registry owner: `sealed-provider`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-01`

## Decision

Split SID/descriptor representation and pure policy construction from native ACL mutation/access checks. Keep each native capture-readback operation cohesive, with owned descriptors/buffers and explicit object kind.

## Observed phases and custody

`TargetUserObjectPolicy::capture` (line 685) takes a before snapshot, inventories restricting SIDs, obtains a write-restricted behavior attestation, captures logon SID, then takes an after snapshot and rejects contradictory observations. The module also contains SCM DACL mutation and distinct SDDL builders for public/private pipes, jobs, processes, tokens, state and user objects. These are separate policy domains, but they are not permission-neutral strings.

The seam is immutable SID/SDDL policy values → object-specific native application → readback/behavioral verification. Captured token state must remain stable throughout one policy decision. `SecurityDescriptor` and native query buffers own allocations; extracted wrappers must preserve their allocation/free pairing and leave raw pointers local to native calls. SCM changes and token peer-query convergence retain explicit mutation owners.

## Compatibility and evidence gates

Preserve access masks, mandatory-label/DACL semantics, normalized descriptor fingerprints and role-specific diagnostics. The current security suite includes real handle/token/user-object operations as well as synthetic loader schema tests; separate those domains without weakening native checks. Before splitting, characterize owner/group/ACL readback, write-restricted versus ordinary restricted tokens, inheritance, service SID permissions and restoration on errors. Native Windows x64/arm64 access-check behavior remains a required gate, not inferable from SDDL string equality. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
