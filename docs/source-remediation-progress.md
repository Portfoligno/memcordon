# Source remediation execution ledger

This ledger tracks the September 2026 source-justification design. A source
declaration or successful compilation is not native execution evidence. Hosted
gates must name the commit containing the relevant change; the design baseline's
successful runs cannot satisfy gates for later changes.

| Package | Current state | Remaining acceptance |
|---|---|---|
| GOV-01 | Strict inventory, syntax/Cargo routes, cfg/visibility and Cargo feature drift checks, stable history and mutation tests implemented | Review provisional per-source invariants and semantic platform applicability |
| GOV-02 | Native execution records and authenticated CI/Deep/Backend artifact merge implemented; exact-commit completed-run release admission implemented for declared lanes | Hosted execution of the admission path; full declaration coverage, fuzz/scenario/delegated evidence, baseline ingestion and release-only routes remain required |
| GOV-03 | 53 charters, seed/artifact ownership, manifest parity and stable shard identity implemented | Complete changed-commit Deep CI evidence and retained crash/corpus accounting |
| GOV-04 | Pending | API tiers, narrow CI exports, downstream stable API fixtures |
| GOV-05 | Windows launch DTO vectors implemented | Remaining versioned contract vectors and compatibility decisions |
| GOV-06 | Structural/co-change metrics and provenance-bound collector implemented; collector corrections under review | Final independent review, source registry integration and substantive review of split/retention decisions |
| GOV-07 | Pure build identity selection, provenance fixtures and strict release identity checks implemented | Hosted package/archive verification on the changed commit |
| PROV-01 | Shared pure contracts and Linux parsers extracted; linked helper fingerprints tested; all three empty production adapters retired with explicit history | Native packaged-helper fingerprint and cross-context parity evidence |
| PROV-02 | Stale model removed; real transition checks implemented | Hosted production scenario evidence |
| PROV-03 | Certification naming and runtime/test scope corrected | Consumer policy and native certification evidence |
| PROV-04 | Eight private tests have ownership headers | Exact listed/executed Windows x64 and ARM64 records |
| PROV-05 | Corpus replay/cmin prerequisite runner implemented; duplicate retained | Hosted immutable corpus/artifact/triage migration and replacement Deep CI success before deletion |
| PROV-06 | Shared typed Linux inventory and parity tests implemented | Privileged native scenario execution and attestation |
| PROV-07 | Fixture command registries, domain handlers and exact inventory/release exclusion tests implemented | Hosted fixture and archive verification on the changed commit |
| MAC-01 | Fixed protocol vectors and native channel characterization implemented; no codec extraction | Both architectures on changed commit and after each extraction stage; oracle, delivery, stress and mutation gates |
| MAC-02 | Pending | Admission extraction, signal restoration and race characterization |
| MAC-03 | Pending | Native facts/inventory/coordinator boundaries and process-tree cases |
| MAC-04 | Pending | Pure evidence projection and pairwise terminal precedence table |
| MAC-05 | Nonblocking private delivery diagnostics and saturation/failure tests implemented; original stress cause remains unproven | Bounded delivery leases, digest-bound acknowledgement and confirmed reap redesign |
| MAC-06 | Deadline/envelope/runtime-evidence vectors, strict decoders and runtime-evidence fuzz target implemented | Both native architectures and Deep CI evidence on the changed commit |
| MAC-07 | Pending | Independent oracle modules and shared-data-only parity on both architectures |
| CI-01 | Golden V3 characterization, independent root closure, pre/post measurement, managed Miri parity and authenticated MSVC rediscovery implemented | Native gates and managed-context decomposition |
| CI-02 | Native inspection crate and direct boundary tests implemented | Hosted Windows x64/ARM64 and Linux/macOS boundary execution |
| CI-03 | Pending | Immutable bootstrap/controller vectors and cold/warm hosted cache evidence |
| CI-04 | Pending | Typed command authority, credential isolation and process tests |
| CI-05 | Pending | Policy domain decomposition with preserved exact diagnostics/mutations |
| CI-06 | Pending | Suite/transaction phase ownership, failure injection and exact scenario plans |
| CI-07 | Native inspection boundary tests expanded | Remaining worker panic/poison, memory ceiling and native tool admission cases |
| CI-08 | Pending | Narrow nonpublishable CI API and removal of empty facades |
| WIN-01 | Native implementation follow-up rejected by automatic approval review; no completion claimed | Authorized resolution, metrics and native error/handle/rollback vectors before domain splits |
| WIN-02 | Pending | Seven cohesive transaction ADRs and phase/cleanup mutation tests |
| WIN-03 | Initial versioned contract vectors implemented; later scenario work rejected by automatic approval review and partial file preserved outside committed source inventory | Authorized resolution, lab spawner ownership and native smoke parity |
| WIN-04 | DTO identity rename, ownership comments, vectors and consumer matrix implemented | Hosted consumer compatibility evidence |
| TEST-01 | Pending | Root-preserving suite decomposition and exact route comparison |
| TEST-02 | Focused provider/native/DTO/governance mutations added | Remaining cross-layer, differential and native mutation matrix |

Source records retain the design's proposed disposition. They describe required
behavior and intended boundaries; they do not declare the corresponding work
package complete. `target/ci/source-presence.json` explicitly sets
`execution_attested` to `false`.

Conservative acceptance accounting: no package is formally closed with every
required acceptance record. Eight packages principally await hosted gates
(GOV-03, GOV-07, PROV-02, PROV-06, PROV-07, MAC-06, CI-02, WIN-04); the other
27 still require implementation as well as evidence. Prior native successes are
useful evidence for their exact commits, not automatic closure of later changes.

Next independent partitions after the current GOV-02/GOV-06 units are GOV-04
API tier declarations and downstream stable-surface compile fixtures; CI-08
direct core runtime-manifest imports with relocation of its substantive fuzz
property; and CI-03 a std-only bootstrap/controller parity harness using immutable
vectors. These do not require waiting for unrelated native refactoring gates.
MAC-01's first extraction follows both architecture characterization,
oracle, delivery, stress and mutation gates for the accepted characterization
commit. PROV-05 duplicate retirement follows immutable corpus/triage migration,
replay/cmin and replacement Deep CI success. Neither gate can be substituted by
source declarations or a successful compile.

Cancelled predecessor runs, including the cancelled Deep run for `daf6c8b`,
provide no acceptance evidence. Its collector correctly rejected absent stress
archives. Local commits newer than the active hosted SHA likewise have no native
acceptance until their own required runs complete.
