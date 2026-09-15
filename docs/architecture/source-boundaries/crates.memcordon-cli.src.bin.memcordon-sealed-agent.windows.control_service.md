# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.control_service

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/control_service.rs`  
Registry owner: `sealed-provider`  
Design disposition: Keep cohesive pending evidence  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-02`

## Decision

Keep caller authentication, launcher-local handle transfer and relay ownership cohesive. Permit pure replay-binding/error classification helpers to move; the private-frame ownership-transfer point remains in one function.

## Observed phases and custody

`launch_client_inner` (line 882) obtains the pipe client's PID and authenticated token/envelope, checks qualification admission, derives the attempt/request binding, and acquires durable admission while serialized with package mutation. It authenticates the launcher before duplicating process-relative handles. `LauncherTransferRollback` records partial duplicates; every failed duplication or frame write invokes its abort path. Only a complete private `Launch` frame disarms that guard, after which `relay_protocol` owns the public/private exchange.

The phase graph is peer authentication → durable admission → authenticated destination namespace → incremental duplicate inventory → complete-frame handoff → bound relay/terminal recovery. Source and destination handle namespaces are not interchangeable. Splitting transfer construction from rollback would obscure which process owns each partial duplicate.

## Compatibility and evidence gates

Preserve public/private frame versions, attempt/nonce/request hashes, qualification admission semantics and terminal replay classifications. Hooks such as `bound_public_replay_failure_response_for_test` and authenticated-frontend duplication are characterization surfaces, not proof of execution. Required native Windows tests inject failure at every duplicate and truncated private write, then prove remote copies are revoked before handoff and launcher-owned afterward. Frontend loss, forged launcher identity and replay recovery must preserve rejection codes. No privilege or cleanup delegation is authorized by this record; independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
