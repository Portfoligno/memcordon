# tools.memcordon-ci.src.policy

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `tools/memcordon-ci/src/policy.rs`  
Registry owner: `ci`  
Design disposition: High-priority decomposition candidate  
Work packages: `CI-05`, `CI-08`, `GOV-01`, `GOV-06`

## Decision

Split repository/source, workflow/cache, build-context, packaging/release and Rust-source validators behind the current policy entrypoint. Introduce domain diagnostics only with an adapter preserving existing error ordering and messages.

## Observed phases and custody

`run` (line 4170) validates checkout identity, source registry and fuzz governance before loading policy/release configuration and inventory. It rejects nonstatic allowed workflow commands, then performs file/workflow/Rust/Cargo/manifests checks. The file combines YAML structure helpers, workflow-specific credential/cache constraints, Rust syntax checks and workspace metadata checks. Their common output is a failure, not a runtime resource lease.

The phase graph is trusted configuration/identity → tracked inventory → domain validation → first diagnostic. Split along input/authority domain, not arbitrary helper count. Workflow rules must continue to inspect exact structures and credential transitions; a generic permissive parser cannot replace release-specific checks. No domain may silently skip unsupported syntax.

## Compatibility and evidence gates

Preserve failure precedence, diagnostic text relied on by tests, allowed command semantics and fail-closed unknown structures. Existing workflow/rust-policy/mutation tests are the evidence surface; their presence is not a current pass claim. Characterize minimal invalid mutations per domain before extraction and compare diagnostics from old and new routes. Preserve source registry and fuzz validation at entry. Native gates concern tool/discovery integration; pure policy mutation tests should stay platform-independent. Existing inline test organization is outside this documentation unit's edit scope. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
