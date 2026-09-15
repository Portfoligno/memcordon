# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.token.derivation

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/token/derivation.rs`  
Registry owner: `sealed-provider`  
Design disposition: Keep cohesive pending evidence  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-02`

## Decision

Keep privileged token derivation and scoped impersonation restoration together. Pure SID inventory and privilege-snapshot comparison helpers may move; installation/reversion of thread authority must retain one lexical owner.

## Observed phases and custody

`derive_launcher_holder_primary` (line 1665) rejects a preexisting thread token, opens the launcher source token with explicit query/source/duplicate access, adopts it into `OwnedHandle`, then captures source attestation. `ScopedPrivilegeThreadToken` (line 923) checks absence before `SetThreadToken`; explicit `revert` invokes `RevertToSelf` and verifies absence afterward. Its `Drop` path terminates/aborts the process if restoration or absence verification fails.

The phase graph is thread-authority preflight → source token/attestation → scoped privilege carrier → derivation/session adjustment → readback → explicit restoration → return owned result. Failing restoration is a fail-stop boundary, not a recoverable diagnostic. Moving privileged work into callbacks that outlive the scope would invalidate that guarantee.

## Compatibility and evidence gates

Preserve exact access masks, session and token-instance equality, restriction/privilege inventories and staged native diagnostic codes. Value-only validators include `exact_enabled_privilege_transition` and canonical restricting-SID validation. Native gates must show no residual thread token on each fallible path, no unintended source-token mutation, correct cross-session carriers and fail-stop restoration behavior. Tests should distinguish derivation failure from restoration failure. This record does not authorize altering privilege acquisition or downgrading fail-stop cleanup. Independent review remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
