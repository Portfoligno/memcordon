# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.package

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/package.rs`  
Registry owner: `sealed-provider`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-01`

## Decision

Split immutable artifact inspection and installation planning first. Keep lease acquisition, `InstallTransition`, SCM changes, rollback and post-install qualification orchestration under one package transaction owner.

## Observed phases and custody

`install_captured_transaction` (line 1821) validates the captured manifest/artifact snapshot, rejects reparse roots, atomically copies three binaries and optional manifest, creates secured state directories and records them in `InstallTransition`. It installs policy, configures services, hardens state, advances `RuntimeSealed`, starts services, advances `ServiceCleanupAvailable`, verifies live state, and reaches `ReadyForQualification`.

The phase graph is capture/verify → secure materialization → retained state/policy → SCM configuration → hardening → service availability → live verification/qualification. The phase markers determine which cleanup authority is available. `rollback_fresh_install`, `restore_upgrade`, `cleanup_upgrade_rollback` and removal-convergence functions are not interchangeable generic cleanup: rollback must preserve whether this was a fresh install or replacement and whether service-owned cleanup can run.

## Compatibility and evidence gates

Preserve runtime manifest schemas, three-binary inventory, source/PE/digest checks, service configuration and precise residual-state errors. Existing named rollback/retired-workspace hooks expose behavior but do not establish native acceptance. Characterize failure after each retained directory, policy installation, service configuration/start and qualification; assert exact prior-state restoration or explicit residual inventory. Windows native fresh-install, upgrade, active-attempt refusal and full uninstall gates remain required. Splitting pure inspection must not release the package lease or replace immutable captured bytes with later path reads. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
