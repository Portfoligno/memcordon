# crates.memcordon-core.src.windows_sealed

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-core/src/windows_sealed.rs`  
Registry owner: `core`  
Design disposition: Keep cohesive pending evidence  
Work packages: `GOV-01`, `GOV-05`, `GOV-06`, `WIN-02`

## Decision

Keep the versioned Windows contract and consistency relations cohesive pending a dedicated compatibility map. Extract only self-contained codecs with shared vectors; do not fork durable-state or terminal-binding rules between provider and tooling consumers.

## Observed phases and custody

`WindowsDurableAttemptRecordV1` (line 1302) binds attempt/provider/boot/request/token/job identities, process identities, authorization and cleanup state, terminal outbox, diagnostics, workload checkpoint and revision. `authenticate_decoded_windows_attempt_record` (line 1375) validates expected identity shape, hashes bounded canonical serialization with the integrity field removed, restores the field and validates schema and cross-field evidence. The same file defines relay/certification transitions and public/private request/response DTOs.

The phase graph is bounded decode → canonical-integrity/binding checks → state/evidence consistency → shared transition decision → encode. Resources are owned bytes and typed values, not service handles. Cohesion protects the relation between states, terminal receipts and the canonical integrity representation; file size alone does not justify dispersing that relation.

## Compatibility and evidence gates

Preserve schema versions, bounded string/frame decoding, enum spellings, canonical hash input and transition acceptance tables across provider, core tests and fuzz targets. Pure argv/environment codecs may move only with byte-identical vectors and unchanged root exports. Required gates include tampered integrity/provider/request bindings, illegal transitions, malformed outboxes and cross-consumer serialized parity. Native certification validates the producers separately and cannot be inferred from DTO consistency. Independent review remains pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
