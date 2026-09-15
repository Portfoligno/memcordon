# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.launcher_service

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/launcher_service.rs`  
Registry owner: `sealed-provider`  
Design disposition: Keep cohesive pending evidence  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-02`

## Decision

Retain `launch_attempt` and `AttemptCleanup` as the transaction authority. Pure terminal-candidate projection and diagnostic mapping are possible seams, but transferred-handle adoption, target release and retirement must remain coordinated.

## Observed phases and custody

`launch_attempt` (line 1593) adopts the transferred token, frontend and canary handles into `OwnedHandle` before fallible identity validation. It validates inheritance flags and recomputes request/attempt hashes rather than trusting the broker. The later `AttemptCleanup` (line 4288) ties job, disarm event, guardian process and mutable durable record to one armed owner; its `Drop` implementation is an emergency cleanup path. Monitoring, terminal candidate/receipt construction and acknowledgement are separate named operations but share the same attempt's custody.

The phase graph is adopt/validate → token and job setup → guardian/relay readiness → target release → monitoring → job/guardian retirement → terminal staging/acknowledgement. A split that lets evidence production outlive the job/record owner is unsafe. Terminal success must remain contingent on complete boundary evidence; fallback cleanup failures cannot become a successful terminal receipt.

## Compatibility and evidence gates

Preserve `WindowsLaunchBrokerRequestV1`, terminal candidates/receipts, phase diagnostics and durable state transitions. Existing hooks expose guardian startup, policy revocation and dropped-attempt cleanup. Required Windows x64/arm64 evidence covers forged binding, partial adopted inventories, guardian exit/live timeout, revoked policy, empty-job failure, relay retirement and missing terminal acknowledgement. Test selectors and actual executions must be bound by the coverage pipeline; this document does not certify them. Independent review remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
