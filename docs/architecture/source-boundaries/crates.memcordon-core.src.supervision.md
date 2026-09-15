# crates.memcordon-core.src.supervision

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-core/src/supervision.rs`  
Registry owner: `core`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-05`, `GOV-06`, `MAC-04`

## Decision

Split value-model domains into capability, attempt/evidence, restart/aggregate and validation modules with stable root re-exports. Keep mutation of an attempt history and its aggregates in a single checked operation.

## Observed phases and custody

This file defines backend evidence, attempts, errors, restart decisions, bounded history and aggregate/terminal models. `AttemptHistory::validate` (line 826) checks first/recent numbering, retained/omitted accounting and consistency. `append` computes a checked next number and clones aggregates before observing authorization/outcome/error; a failure must not partially advance history while leaving aggregates unchanged. Custom deserialization uses intermediate wire structures before exposing valid domain values.

The phase graph is bounded decode → semantic validation → tentative history/aggregate update → commit validated state → report projection. Resources are owned Rust values rather than OS handles; the authority seam is consistency of publicly serialized facts. Separate files may share types, but must not duplicate validators or turn append into two independently fallible updates.

## Compatibility and evidence gates

Preserve serde field/tag/default behavior, bounded-history capacity, root public API, error distinctions and arithmetic overflow handling. Required characterization covers invalid history numbering, omitted-count drift, inconsistent sealed evidence, aggregate overflow and failed append leaving prior state unchanged. Core serialization/property tests and cross-layer report consumers provide the appropriate gates; native execution is only needed for producer-side evidence truth, not for pure model moves. This decision does not assert those tests ran in this unit. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
