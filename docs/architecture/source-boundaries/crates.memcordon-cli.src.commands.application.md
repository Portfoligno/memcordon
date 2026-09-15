# crates.memcordon-cli.src.commands.application

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/commands/application.rs`  
Registry owner: `cli`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-06`, `MAC-05`

## Decision

Split report construction, terminal/error projection and platform-specific delivery settlement from command orchestration. Preserve `execute`, `plan`, `doctor` and `clean` as command entrypoints, with one owner of each execution context and final exit decision.

## Observed phases and custody

`execute` (line 39) builds structured argv, captures the macOS run origin, resolves policy, owns `MacosExecutionContext`, resolves the helper, builds `SupervisorRequest`, and dispatches successful/error completion. Non-macOS `finish_execution` (line 231) preserves wrapper exit status unless report construction/write fails, which returns 125. The macOS counterpart (line 338) collects diagnostics in memory, derives a delivery expiry from runtime evidence and invokes bounded result delivery.

The phase graph is resolution/context → helper admission → supervision → outcome projection → delivery settlement → exit. The platform-specific delivery boundary is already observable; forcing one generic writer would erase deadline and custody differences. Report builders can accept immutable values, while context restoration and final exit precedence remain orchestration responsibilities.

## Compatibility and evidence gates

Preserve CLI exit codes, warning/summary behavior, report schemas, helper errors, quiet mode and macOS return/deadline semantics. Characterize report-construction and write failures against successful/failed supervision, signal restoration errors, and exhausted delivery expiry. Existing result-delivery module and CLI regression suites are consumers; no new suite execution is claimed here. Native macOS blocked sink, helper reap and interrupted-delivery gates remain required before moving settlement ownership. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
