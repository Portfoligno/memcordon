# tools.memcordon-ci.src.sealed_linux

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `tools/memcordon-ci/src/sealed_linux.rs`  
Registry owner: `ci`  
Design disposition: Likely decomposition candidate  
Work packages: `CI-06`, `CI-08`, `GOV-01`, `GOV-06`

## Decision

Split build/package setup, native scenarios, recovery and evidence inventory behind `certify` as the single certification/cleanup owner. Keep partial-install cleanup and primary/cleanup diagnostics together.

## Observed phases and custody

`certify` (line 1900) rejects the wrong platform, creates a run report, captures commit identity and tracks `installation_attempted`. It sets that flag before `certification_body`, so partial installation still triggers privileged uninstall. On failure it gathers provider diagnostics and public execution evidence, then records primary and cleanup errors separately. A run is not successful if either exists; final run-marker removal and directory sync follow successful completion.

The phase graph is native admission/build → run marker → installation/scenarios → diagnostic capture on failure → unconditional attempted-install cleanup → combined evidence verdict → settled report directory. Scenario extraction must return observations to this owner, not own uninstall independently or erase the initial failure.

## Compatibility and evidence gates

Preserve report filenames/schemas, mechanism/commit binding, exact promoted test inventories, post-upgrade public proof and failure diagnostics. Existing concurrency/fault validation helpers are pure extraction candidates. Required Linux native gates cover interrupted/partial install, nonroot frontend credentials, restart recovery, fault scenarios, uninstall failure and residual process/cgroup/service state. Report parser tests do not certify those scenarios. An artifact directory with a running/failed marker must remain unreleasable. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
