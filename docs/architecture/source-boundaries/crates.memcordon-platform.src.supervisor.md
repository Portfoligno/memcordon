# crates.memcordon-platform.src.supervisor

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-platform/src/supervisor.rs`  
Registry owner: `platform`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-06`, `MAC-04`

## Decision

Separate macOS execution context, backend-neutral attempt coordination and evidence projection, retaining the public supervision entrypoints and one restart/terminal decision loop.

## Observed phases and custody

`supervise_with_origin` (line 450) establishes timing, preserves an optional macOS continuous-clock origin, derives supervision expiry, then owns `AttemptHistory`, `SupervisionAggregates`, authorization count and optional `RestartCoordinator`. Each iteration builds `AttemptContext` from that shared state. Backend validation, execution and error/evidence projection are named helpers around the same loop; cfg alternatives intentionally provide different platform launch mechanisms.

The phase graph is resolved backend/clock → attempt context → backend execution → validated evidence/history update → restart or terminal decision. A projection helper can return complete model values, but must not increment counters or choose restart independently. macOS signal/custody restoration belongs to its owned execution context, not to a generic serializer.

## Compatibility and evidence gates

Preserve backend-drift errors, authorized-versus-released accounting, deadline scope, restart safety proof and wrapper exit precedence. Existing drift and sealed-deadline rejection hooks are useful characterization surfaces. Required tests cover setup refusal outside an attempt, failed evidence validation, restart exhaustion, counter overflow and deadline expiry before retry. Native Linux/Windows/macOS producer tests must show the same terminal ordering, with macOS origin and cleanup budgets retained. Stable API re-exports and serialized `SupervisionExecution` remain unchanged. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
