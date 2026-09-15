# crates.memcordon-cli.src.bin.memcordon-sealed-agent.linux.launch

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs`  
Registry owner: `sealed-provider`  
Design disposition: Keep cohesive pending evidence  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-02`

## Decision

Retain the launch transaction in this module. Extract bounded packet encoders/decoders only after byte-vector parity; do not move cgroup or process custody into independent phase owners.

## Observed phases and custody

`execute_inner` (line 854) checks the exact five-descriptor inventory, creates or adopts `AttemptRecord`, records caller-envelope capture, installs `AttemptCleanupGuard`, binds policy admission, then creates `AttemptCgroup`. The end of that function requires cgroup emptiness plus init and guardian reap before recording retirement and disarming cleanup. Thus the phase graph is descriptor/admission validation → boundary creation → gated namespace/guardian startup → authorization/execution → kill/drain/reap → durable retirement.

The cleanup guard holds the attempt record, cgroup and init-process obligations. `Drop for AttemptCleanupGuard` is a fallback, while `finalize_failure` participates in the returned result. A primary error combined with cleanup failure becomes `MCSEALED-BOUNDARY-NOT-RETIRED`; successful target exit cannot erase incomplete retirement. This cross-phase locality is the reason to retain the transaction, independently of its item count.

## Compatibility and evidence gates

Preserve namespace-startup, exec-failure and guardian-terminal packet bytes, descriptor inventory, record transitions and terminal error precedence. Existing hooks include `receive_exec_status_for_test`, `decode_namespace_startup_record_for_test` and `verified_guardian_observed_provider_retirement_for_test`; their presence is source evidence, not execution evidence. Required characterization covers every early return after guard installation, provider/frontend loss, failed disarm, pidfd errors and incomplete reap. Native Linux PID/mount/cgroup namespace and cgroup-v2 runs must demonstrate the same retirement and error ordering before helper extraction is accepted. Reviewer confirmation remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
