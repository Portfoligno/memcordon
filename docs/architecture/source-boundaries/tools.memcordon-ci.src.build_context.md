# tools.memcordon-ci.src.build_context

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `tools/memcordon-ci/src/build_context.rs`  
Registry owner: `ci`  
Design disposition: Keep behavior; high-priority decomposition candidate  
Work packages: `CI-01`, `CI-08`, `GOV-01`, `GOV-06`

## Decision

Split manifest/value schema, input traversal, platform/tool discovery and audit policy, preserving `ValidatedBuildContext` as the only owner that admits a build environment. Keep enrollment derived from live invocation/configuration rather than recorded declarations.

## Observed phases and custody

`prepare`/`prepare_inner` (line 952) enroll then measure. `enroll` canonicalizes the workspace, closes the ambient environment, admits Windows tooling when applicable, rejects ambient Cargo configuration and establishes managed Cargo home/toolchain input roots. `audit_with_discovery` first remeasures recorded inputs before executing selectors, then `audit_enrollment` compares root, environment, toolchains and discovery/input roots and remeasures afterward.

The phase graph is invocation-derived enrollment → input measurement → serialized context → pre-discovery drift check → rediscovery → exact enrollment/post-measurement check → command admission. The authority seam is between untrusted cached bytes and live executable selection. Traversal may become a separate component, but a manifest cannot supply its own authoritative tool/environment inventory.

## Compatibility and evidence gates

Preserve native path encoding, serialized input identity, cache digests, denied Cargo configuration and pre/post discovery order. Existing build-context, native-device, symlink and discovery tests should be mapped by invariant before moving code. Required mutation gates replace a selector/input, alter environment/toolchain/root, or change symlink/device identity and prove no unmeasured selector runs. Windows native compiler discovery and Unix filesystem identity need their platform gates. This record does not certify cached artifacts or execute managed builds. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
