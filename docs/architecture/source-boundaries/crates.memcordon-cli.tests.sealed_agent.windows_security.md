# crates.memcordon-cli.tests.sealed_agent.windows_security

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/tests/sealed_agent/windows_security.rs`  
Registry owner: `tests`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-02`, `GOV-06`, `TEST-01`, `TEST-02`, `WIN-01`

## Decision

Split tests by production responsibility while preserving the existing root test route and test names. Add a distinct loader-access/API-set test group alongside SID/descriptor, token/user-object and service-policy groups; the current imports show broader ownership than the filename suggests.

## Observed fixture and assertion boundaries

The opening imports directly consume `crate::windows::{loader_access,package,process,security}` and native token, thread, filesystem and job APIs. Synthetic API-set schema builders begin at line 109, while cases such as `native_loader_evidence_separates_ancestor_identity_from_final_access` and `native_known_dll_policy_distinguishes_absence_from_denial` exercise loader evidence. Other cases open real handles and alter thread token state. Thus this is not one homogeneous descriptor fixture suite.

The phase graph for native cases is scoped fixture creation → native observation/mutation → assertion → token/handle restoration. Fixture ownership must stay local to the case or an explicit guard. Synthetic schema fixtures can be shared as value builders; ambient impersonation state cannot be shared as a global convenience fixture.

## Compatibility and evidence gates

Retain the `sealed_agent` integration target and `windows_security::` selector prefix owned by `tests/sealed_agent.rs` (lines 91–93), including its existing cfg/feature gates and private production-module inclusion. Preserve all historical fixtures. A split needs before/after test inventories, ignored-test accounting and native Windows x64/arm64 execution through that exact integration route. Pure API-set tests must not replace target-token access tests. Match each new test module to its production domain and preserve cleanup on assertion failure. No test bodies or fixtures are moved by this record; independent review and execution inventory remain pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
