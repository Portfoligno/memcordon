# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.record

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/record.rs`  
Registry owner: `sealed-provider`  
Design disposition: Keep cohesive pending evidence  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-02`

## Decision

Keep durable attempt mutation, replay reservations and recovery cohesive. Extract pure shared DTO validation/canonical encoding only where inputs and outputs are complete values; file publication and record reservations remain together.

## Observed phases and custody

`stage_terminal_response` (line 2094) resolves the attempt path, performs bounded read, distinguishes genuine missing file from other I/O failures, decodes and authenticates before staging. `LeasedTerminalResponse` retains a `RecordReaderReservation` alongside its optional payload; releasing the payload does not silently release the reader reservation, and acknowledgement uses the reserved path. The file also owns admission/writer reservations, create-once publication, replay retirement, quarantine and recovery.

The phase graph is reserve/authenticate → bounded durable mutation → staged terminal outbox → leased delivery → acknowledgement/retirement, with quarantine/recovery for ambiguity. Cross-phase locality protects against deleting a record while a terminal reader still depends on it. A generic storage split that treats missing/inaccessible/corrupt as the same state would invalidate recovery authority.

## Compatibility and evidence gates

Preserve authenticated record bytes/revisions, create-once semantics, nonce/request/provider binding, outbox disposition and retained diagnostics. Existing hooks expose atomic create-once and replay-unstaged classification. Characterize concurrent reader/writer/admission reservations, missing versus access-denied records, duplicate publication, response delivery before ack, interrupted retirement and restart quarantine. Native Windows filesystem identity/security and process-liveness gates remain necessary. No storage method may infer successful cleanup from an empty or unreadable inventory. Independent review is pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
