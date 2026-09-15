# Source remediation execution ledger

This ledger tracks the September 2026 source-justification design. A source
declaration or successful compilation is not native execution evidence. Hosted
gates must name the commit containing the relevant change; the design baseline's
successful runs cannot satisfy gates for later changes.

| Package | Current state | Remaining acceptance |
|---|---|---|
| GOV-01 | Strict inventory, syntax/Cargo routes, cfg/visibility and Cargo feature drift checks, stable history and mutation tests implemented | Review provisional per-source invariants and semantic platform applicability |
| GOV-02 | Pending | Exact test listing, execution records, signed-off lane merge and release gate |
| GOV-03 | In progress | Charters, seed/artifact ownership, manifest parity, stable shard identity |
| GOV-04 | Pending | API tiers, narrow CI exports, downstream stable API fixtures |
| GOV-05 | Windows launch DTO vectors implemented | Remaining versioned contract vectors and compatibility decisions |
| GOV-06 | Pending | Structural/co-change metrics and reviewed split/retention ADRs |
| GOV-07 | Pending | Pure build identity selection, provenance fixtures and release inventory |
| PROV-01 | In progress | Shared provider contracts, normal crate imports, helper parity |
| PROV-02 | Stale model removed; real transition checks implemented | Hosted production scenario evidence |
| PROV-03 | Certification naming and runtime/test scope corrected | Consumer policy and native certification evidence |
| PROV-04 | Eight private tests have ownership headers | Exact listed/executed Windows x64 and ARM64 records |
| PROV-05 | Evidence-gated; duplicate retained | Corpus/artifact/triage migration, cmin/replay, replacement Deep CI success before deletion |
| PROV-06 | Shared typed Linux inventory and parity tests implemented | Privileged native scenario execution and attestation |
| PROV-07 | In progress | Fixture command registry, owned handlers and exact release exclusion |
| MAC-01 | Characterization pending | Both architectures after each extraction stage; oracle, delivery, stress and mutation gates |
| MAC-02 | Pending | Admission extraction, signal restoration and race characterization |
| MAC-03 | Pending | Native facts/inventory/coordinator boundaries and process-tree cases |
| MAC-04 | Pending | Pure evidence projection and pairwise terminal precedence table |
| MAC-05 | Pending | Bounded delivery leases, digest-bound acknowledgement and confirmed reap |
| MAC-06 | Pending | Deadline/envelope/evidence vectors, cross-layer checks and fuzz target |
| MAC-07 | Pending | Independent oracle modules and shared-data-only parity on both architectures |
| CI-01 | Characterization pending | Golden V3 capture and mutation parity before managed-context decomposition |
| CI-02 | Native inspection crate and direct boundary tests implemented | Hosted Windows x64/ARM64 and Linux/macOS boundary execution |
| CI-03 | Pending | Immutable bootstrap/controller vectors and cold/warm hosted cache evidence |
| CI-04 | Pending | Typed command authority, credential isolation and process tests |
| CI-05 | Pending | Policy domain decomposition with preserved exact diagnostics/mutations |
| CI-06 | Pending | Suite/transaction phase ownership, failure injection and exact scenario plans |
| CI-07 | Native inspection boundary tests expanded | Remaining worker panic/poison, memory ceiling and native tool admission cases |
| CI-08 | Pending | Narrow nonpublishable CI API and removal of empty facades |
| WIN-01 | Characterization pending | Metrics and native error/handle/rollback vectors before domain splits |
| WIN-02 | Pending | Seven cohesive transaction ADRs and phase/cleanup mutation tests |
| WIN-03 | Pending | Lab spawner ownership, versioned records and native smoke parity |
| WIN-04 | DTO identity rename, ownership comments, vectors and consumer matrix implemented | Hosted consumer compatibility evidence |
| TEST-01 | Pending | Root-preserving suite decomposition and exact route comparison |
| TEST-02 | Focused provider/native/DTO/governance mutations added | Remaining cross-layer, differential and native mutation matrix |

Source records retain the design's proposed disposition. They describe required
behavior and intended boundaries; they do not declare the corresponding work
package complete. `target/ci/source-presence.json` explicitly sets
`execution_attested` to `false`.
