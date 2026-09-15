# tools.memcordon-ci.tests.release_evidence

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `tools/memcordon-ci/tests/release_evidence.rs`  
Registry owner: `tests`  
Design disposition: Likely decomposition candidate  
Work packages: `CI-06`, `GOV-01`, `GOV-02`, `GOV-06`, `TEST-01`, `TEST-02`

## Decision

Split standard/macOS, Linux sealed, Windows sealed and cross-report identity mutation tests behind the current integration target. Preserve a shared fixture vocabulary without allowing generated complete-looking reports to stand in for runtime evidence.

## Observed fixture and assertion boundaries

The file constructs `ExpectedCertificationOrigin` with repository/run/workflow/commit identity, wraps production `collect_certification`, and builds typed standard reports plus native JSON fixtures. Tests mutate individual required fields, identities, artifact cardinality/size, package convergence, token representations and promoted inventories. Temporary input/output directories isolate artifact-copy and digest-binding behavior.

The phase graph is valid baseline fixture → controlled invalid mutation → production collector → rejection or digest-bound copied artifact assertion. The protected seam is between syntactically valid JSON and evidence authorized for release. A per-platform split must keep cross-report consistency cases together so independently plausible reports cannot evade identity binding.

## Compatibility and evidence gates

Preserve current report schemas, required-field sets, promoted selectors and negative cases for missing/contradictory evidence. Existing cases such as `windows_cross_report_identity_mutations_fail_closed`, `artifact_path_cardinality_and_size_fail_closed` and `valid_reports_are_copied_and_digest_bound` identify distinct obligations. A complete fixture is test input, never a certification result. Native report production and commit-bound hosted attestations are separate gates. Compare exact integration-test inventory after any split. Independent review remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
