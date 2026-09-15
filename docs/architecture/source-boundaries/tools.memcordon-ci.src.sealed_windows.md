# tools.memcordon-ci.src.sealed_windows

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `tools/memcordon-ci/src/sealed_windows.rs`  
Registry owner: `ci`  
Design disposition: Likely decomposition candidate  
Work packages: `CI-06`, `CI-08`, `GOV-01`, `GOV-06`

## Decision

Separate channel parity, package lifecycle, qualification/scenarios and artifact validation, retaining one certification coordinator and explicit cleanup-result merge. Do not allow extracted stages to report success merely because their own command exited successfully.

## Observed phases and custody

`certify` (line 689) requires Windows and native architecture, executes preflight/causal-diagnostic regressions, resolves native helper binaries, clears its report directory and verifies bootstrap/session-broker binaries. It binds commit identity, inspects package state, performs cold install/fresh-install rollback, verifies installation, then validates qualification and fault/token/authority-loss matrices before writing evidence. Helpers such as `with_active_attempt`, `terminate_child` and `merge_primary_and_cleanup` expose separate process/cleanup responsibilities.

The phase graph is native binary/architecture admission → package lifecycle → qualification → scenario matrices → identity-bound artifacts → cleanup/convergence verdict. State-changing package scenarios need one owner of active attempts and removal proof. Extracted validators may be pure, but they cannot authorize a missing matrix or infer cleanup from a missing artifact.

## Compatibility and evidence gates

Preserve helper inventory, public qualification binding, complete matrices, schema versions and artifact names consumed by release evidence. Existing status-matrix, package rollback/convergence and causal-diagnostic tests require explicit execution mapping. Native x64/arm64 gates cover service lifecycle, active mutation refusal, fresh-install rollback, token/guardian loss and full provider removal. The exact global failure-cleanup coverage still needs reviewer confirmation; named cleanup helpers alone are not proof every early return is covered. Independent review remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
