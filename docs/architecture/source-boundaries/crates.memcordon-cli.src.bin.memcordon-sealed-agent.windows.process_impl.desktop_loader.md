# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.process_impl.desktop_loader

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process_impl/desktop_loader.rs`  
Registry owner: `sealed-provider`  
Design disposition: Keep cohesive pending evidence  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-02`

## Decision

Keep desktop creation, creator-arm consumption and loader-control qualification cohesive. Permit pure stage/error projection and plan serialization helpers to move, while retaining desktop/token/job custody in the current process owner.

## Observed phases and custody

`launch_target_desktop_loader_control_inner` (line 2919) reattests the exact token instance, creates a nonce-bound ready endpoint, prepares a noninheritable pipe and control job, validates the installed bootstrap, and constructs canonical command/environment/current-directory values. The result maps native qualification stages to loader failure phases, serializes the production plan, binds it into the wire outcome and checks consistency before returning `LoaderReadyQualificationV1`. Outcome persistence failure is explicitly secondary diagnostic output, not a change to the primary qualification result.

The broader module names creator-arm request/consume, user-object association preflight and fail-stop handling for uncertain creation. These phases cannot safely become independently retryable helpers: uncertainty about a consumed creation capability is not equivalent to a pre-creation failure. The phase graph is token/namespace preflight → arm/desktop custody → prepared launch → resume/ready/containment → exit/drain → bound outcome.

## Compatibility and evidence gates

Preserve exact desktop/environment identities, one-use arm semantics, native error/phase mapping and serialized plan/outcome binding. Existing `_for_test` transitions expose creation/failure phase rules. Native gates must test impersonation restoration, cross-session namespace binding, uncertain creator acknowledgement, failed association drain, loader readiness and handle closure. Do not substitute loader-lab model results for production qualification. No changes to the partial scenario test or native scenario implementation are part of this decision. Independent review remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
