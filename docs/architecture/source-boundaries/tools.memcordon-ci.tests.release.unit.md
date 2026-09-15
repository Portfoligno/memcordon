# tools.memcordon-ci.tests.release.unit

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `tools/memcordon-ci/tests/release/unit.rs`  
Registry owner: `tests`  
Design disposition: Likely decomposition candidate  
Work packages: `CI-06`, `GOV-01`, `GOV-02`, `GOV-06`, `TEST-01`, `TEST-02`

## Decision

Split archive/identity, remote read/reconciliation, publication/credential and provider-package tests while retaining the root module's private access and exact test selectors. Keep shared HTTP fixtures small and explicitly owned.

## Observed fixture and assertion boundaries

The file begins with `use super::*`, local TCP listener/stream helpers and shared synchronization, so it tests private release implementation as well as public behavior. Provider qualification/package JSON fixtures encode schema versions and exact predicate inventories; named tests cover archive traversal, deterministic crate identity, remote response loss, absent-slot selection, immutable published releases, throttling and credential redaction.

The test phase graph is isolated fixture/server setup → one release operation → exact request/state/error assertions → server/temp-resource settlement. Pure archive fixtures can move independently. Credential and remote-mutation mocks must preserve observed request counts and response-loss ordering; merely returning an expected JSON object would remove the assertion being protected.

## Compatibility and evidence gates

Preserve test module routing, names, fixture versions and all regression inputs. Before/after inventory must demonstrate every assertion still runs. Characterize private-helper visibility through the aggregator rather than widening production APIs solely for a split. Local HTTP tests verify protocol/reconciliation logic, not successful real publication. Native package smoke checks remain separate. No fixture deletion or suite move is performed here; independent review and exact target execution remain pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
