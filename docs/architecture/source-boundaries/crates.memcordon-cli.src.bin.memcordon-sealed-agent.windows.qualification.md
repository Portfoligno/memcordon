# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.qualification

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/qualification.rs`  
Registry owner: `sealed-provider`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `PROV-03`, `WIN-01`

## Decision

Extract pure receipt validation, result projection and scenario specifications behind the existing qualification transaction. Keep package lease, qualification admission, cleanup and receipt publication in one orchestrator.

## Observed phases and custody

`qualify_and_store_for_scope` (line 1102) receives an owned `PackageLease`, begins `QualificationAdmission`, runs `qualify_admitted`, and returns the lease with the result. Success goes through `finalize_qualification_after_admission` with explicit admission finish, recovery-complete and storage callbacks. On primary failure, admission-finish failure is appended as secondary evidence. `qualify_admitted` starts by verifying installed state and reading SCM-derived control/launcher identities.

The phase graph is package serialization → admitted service identity → native probes/canaries → terminal/relay retirement → admission finish → recovery proof → receipt storage. Receipt generation cannot be pulled ahead of cleanup, and extracting probes cannot give each probe independent publication authority. Native process handles opened for service identity deliberately request query authority rather than token authority.

## Compatibility and evidence gates

Preserve qualification schema, receipt digest, provider/process binding, replay acknowledgement and primary/secondary diagnostic ordering. Existing `finalize_qualification_after_admission_for_test`, terminal acknowledgement and publication hooks are useful characterization points. Required Windows evidence includes failing admission retirement, false recovery, failed receipt publication, token/front-end canaries, authority loss and restart recovery. A passing parser or fabricated complete receipt is not native qualification. Proposed `QualificationRun` remains an intended ownership abstraction until introduced with complete custody. Review remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
