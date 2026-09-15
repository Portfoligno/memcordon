# tools.memcordon-ci.src.release

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `tools/memcordon-ci/src/release.rs`  
Registry owner: `ci`  
Design disposition: Likely decomposition candidate  
Work packages: `CI-06`, `CI-08`, `GOV-01`, `GOV-06`

## Decision

Extract archive inventory, manifest/evidence projection and read-only public-state inspection. Keep credential-slot selection, publication attempts and remote reconciliation in one explicit publication transaction; irreversible publication has reconciliation, not fictitious rollback.

## Observed phases and custody

`preflight` (line 613) rejects a dirty tree, validates commit identity, requires exactly one release tag at HEAD and verifies the remote tag. `select_publication_slot` scans public registry state, waits for already published crates and selects the first absent configured slot. `run_cargo_publication` (line 5099) validates credential policy, builds structured Cargo arguments, passes only the selected token authority, checks that credential files were not persisted, and retains observed output or process failure for later interpretation/redaction.

The phase graph is immutable release identity → local artifact/evidence assembly → remote-state reconciliation → one admitted publication slot → observed outcome → reconciliation/next slot. Archive helpers own files; publication owns credentials and irreversible remote mutations. A timeout cannot mean absence, and response loss cannot justify blindly repeating a mutation.

## Compatibility and evidence gates

Preserve archive/member inventory, manifest digests, publication order, slot evidence, OIDC/fallback restrictions and credential redaction. Existing release unit tests cover response-loss reconciliation, immutable published releases, partial publication, throttled mutation once-only behavior and credentials. Required characterization distinguishes absent/conflicting/already-published states and proves no secret appears in diagnostics or artifacts. Actual credentialed publication is a separate release gate; no network publication or CI inspection was performed here. Concurrent GOV-02 preflight integration must be reflected in the final source digest before acceptance. Independent review remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
