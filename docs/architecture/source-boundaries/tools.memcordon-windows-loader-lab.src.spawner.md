# tools.memcordon-windows-loader-lab.src.spawner

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `tools/memcordon-windows-loader-lab/src/spawner.rs`  
Registry owner: `loader-lab`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-06`, `WIN-03`

## Decision

Split SCM/service entry, scenario preparation, native creation variants, observation and cleanup behind one lab-run coordinator. Keep diagnostic authority explicit: this lab must not become an alternative production launcher or certification authority.

## Observed phases and custody

`windows::run_scenario` (line 282) derives the requested token, captures its envelope, generates a nonce-bound endpoint, prepares the ready pipe and constructs the scenario plan. Native resources include token, profile, parent-process, desktop and observer leases plus production job handles. `cleanup_after_create_failure` (line 900) waits for job emptiness before merging desktop/profile retirement; `merge_cleanup` requires all cleanup components to succeed and preserves specific failures. Result construction deliberately keeps the full schema at one boundary to make omitted evidence visible.

The phase graph is token/plan/endpoint preparation → native creation → suspended/readiness/containment observation → exit/job drain → desktop/profile/observer retirement → one result. Pure plan/environment preparation is an early extraction seam. Native lease Drop and explicit retirement behavior must move with their resource wrappers, not behind unrelated report helpers.

## Compatibility and evidence gates

Preserve scenario/result schemas, native status/phase mappings, prepared-plan identity and cleanup outcomes. Require native Windows smoke cases for each creation/environment/desktop variant and failed-create/failed-observer cleanup; model consistency does not prove an OS scenario ran. Production-equivalent cases must retain parity with shared launch-core plans and production qualification. The excluded partial `tests/scenario_contract.rs` was not inspected or used as evidence, and no scenario implementation is added here. Independent review remains pending.

## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
