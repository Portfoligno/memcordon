# crates.memcordon-platform.src.macos_launch

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-platform/src/macos_launch.rs`  
Registry owner: `platform`  
Design disposition: Keep behavior; urgent staged decomposition  
Work packages: `GOV-01`, `GOV-06`, `MAC-01`

## Decision

Proceed with staged protocol/channel and child-custody extraction, then launcher/guardian/inspector roles, retaining `launch_configured` as startup transaction coordinator. Do not equate helper exit with confirmed reaping or transfer child custody implicitly.

## Observed phases and custody

`Child::retire` (line 194) repeatedly observes exit and returns timeout while explicitly retaining an owned reaping obligation. `Drop for Child` marks unresolved local children for recovery rather than declaring them reaped. `Message` is a tagged, unknown-field-rejecting wire enum; `Channel` and `Frame` own protocol mechanics. `launch_inner` delegates to `launch_configured` (line 1440), which assembles phased native startup diagnostics and coordinates guardian/launcher startup with deadline, cleanup deadline and optional signal state.

The phase graph is protocol/resource preparation → guardian spawn/readiness → launcher/group binding → target execution witness → owned running handles → stop/inventory → authenticated disarm/reap. `Guardian::disarm`, child retirement and inventory lanes form distinct protocols but share custody obligations. Pure encoding is the first seam; ownership wrappers must move as whole units with their Drop/retirement behavior.

## Compatibility and evidence gates

Preserve message tags/sequences/run binding, native startup diagnostic phases, envelope/descriptor identity and deadline arithmetic. Existing protocol fixtures and named fault hooks cover partial frames, expired control, guardian loss, flood, timer mutation and resource recovery. Native macOS arm64/x64 gates must confirm bounded reap, signal behavior, partial-control invalidation and retained cleanup obligations before each extraction. No protocol or native fault execution was performed in this documentation unit. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
