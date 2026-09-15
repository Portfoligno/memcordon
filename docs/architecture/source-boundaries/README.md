# Source boundary accounting

Status: source-grounded proposed decisions; independent architecture review and characterization acceptance remain pending.

The remediation design's GOV-06 paragraph says 14 split candidates, two urgent monoliths and seven cohesive transactions (23). Its per-file appendix actually names 24 distinct GOV-06 paths: 15 ordinary split candidates, two urgent monoliths and seven cohesive transactions. This inventory preserves all 24; no candidate is silently dropped to match the prose total.

The records use current source-registry stable ids. Each now identifies inspected functions and concrete phase/custody relationships, proposes an authority seam or cohesive owner, and names compatibility and native gates. They preserve the design's intended disposition and distinguish authored analysis from independent review. They do not certify rollback safety or native tests merely by existing.

| Stable id | Current source | Disposition |
|---|---|---|
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.linux.launch](crates.memcordon-cli.src.bin.memcordon-sealed-agent.linux.launch.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs` | Keep cohesive pending evidence |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.control_service](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.control_service.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/control_service.rs` | Keep cohesive pending evidence |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.launcher_service](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.launcher_service.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/launcher_service.rs` | Keep cohesive pending evidence |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.loader_access](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.loader_access.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/loader_access.rs` | Likely decomposition candidate |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.package](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.package.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/package.rs` | Likely decomposition candidate |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.process_impl.desktop_loader](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.process_impl.desktop_loader.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process_impl/desktop_loader.rs` | Keep cohesive pending evidence |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.qualification](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.qualification.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/qualification.rs` | Likely decomposition candidate |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.record](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.record.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/record.rs` | Keep cohesive pending evidence |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.security](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.security.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/security.rs` | Likely decomposition candidate |
| [crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.token.derivation](crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.token.derivation.md) | `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/token/derivation.rs` | Keep cohesive pending evidence |
| [crates.memcordon-cli.src.commands.application](crates.memcordon-cli.src.commands.application.md) | `crates/memcordon-cli/src/commands/application.rs` | Likely decomposition candidate |
| [crates.memcordon-cli.tests.sealed_agent.windows_security](crates.memcordon-cli.tests.sealed_agent.windows_security.md) | `crates/memcordon-cli/tests/sealed_agent/windows_security.rs` | Likely decomposition candidate |
| [crates.memcordon-core.src.supervision](crates.memcordon-core.src.supervision.md) | `crates/memcordon-core/src/supervision.rs` | Likely decomposition candidate |
| [crates.memcordon-core.src.windows_sealed](crates.memcordon-core.src.windows_sealed.md) | `crates/memcordon-core/src/windows_sealed.rs` | Keep cohesive pending evidence |
| [crates.memcordon-platform.src.macos_launch](crates.memcordon-platform.src.macos_launch.md) | `crates/memcordon-platform/src/macos_launch.rs` | Keep behavior; urgent staged decomposition |
| [crates.memcordon-platform.src.supervisor](crates.memcordon-platform.src.supervisor.md) | `crates/memcordon-platform/src/supervisor.rs` | Likely decomposition candidate |
| [tools.memcordon-ci.src.build_context](tools.memcordon-ci.src.build_context.md) | `tools/memcordon-ci/src/build_context.rs` | Keep behavior; high-priority decomposition candidate |
| [tools.memcordon-ci.src.policy](tools.memcordon-ci.src.policy.md) | `tools/memcordon-ci/src/policy.rs` | High-priority decomposition candidate |
| [tools.memcordon-ci.src.release](tools.memcordon-ci.src.release.md) | `tools/memcordon-ci/src/release.rs` | Likely decomposition candidate |
| [tools.memcordon-ci.src.sealed_linux](tools.memcordon-ci.src.sealed_linux.md) | `tools/memcordon-ci/src/sealed_linux.rs` | Likely decomposition candidate |
| [tools.memcordon-ci.src.sealed_windows](tools.memcordon-ci.src.sealed_windows.md) | `tools/memcordon-ci/src/sealed_windows.rs` | Likely decomposition candidate |
| [tools.memcordon-ci.tests.release.unit](tools.memcordon-ci.tests.release.unit.md) | `tools/memcordon-ci/tests/release/unit.rs` | Likely decomposition candidate |
| [tools.memcordon-ci.tests.release_evidence](tools.memcordon-ci.tests.release_evidence.md) | `tools/memcordon-ci/tests/release_evidence.rs` | Likely decomposition candidate |
| [tools.memcordon-windows-loader-lab.src.spawner](tools.memcordon-windows-loader-lab.src.spawner.md) | `tools/memcordon-windows-loader-lab/src/spawner.rs` | Likely decomposition candidate |

## Measurement contract

Function identities include deterministic source-traversal occurrence ordinals. A separate lexical-name map supports approximate call matching. Same-named cfg alternatives remain separate occurrences and ambiguous calls create no edge. Nested function names include their enclosing free function or implementation method. The call graph covers free functions and implementation methods; trait and foreign declarations are excluded from that graph. Unsafe-signature counts visit all signatures, including trait and foreign declarations, independently of graph membership.

`memcordon_ci::boundary_metrics::analyze_source` parses Rust with syn and counts declared items, visibility categories, unsafe blocks/functions and cfg/cfg_attr attributes without evaluating cfg or expanding macros. Item counts include Rust Item nodes and implementation methods; they exclude fields, enum variants and other associated items. Public means syntactic `pub`, not effective visibility through enclosing modules. Function calls record direct path calls; dynamic dispatch, method-call expressions and macro-generated calls are excluded.

`analyze_files` accepts explicit source text and commit path sets. Import edges match import segments to unique supplied file stems; ambiguous stems remain unresolved. These are lexical hints, not Cargo/module/name resolution. Test references mean such imports from a tests directory or a file declaring a test function, not observed execution. Call clusters are undirected connected components of uniquely matched direct local calls, including isolated functions. Cochanges count supplied commits touching both paths; callers must state the history range and shallow-history limitations. No operating-system probes, subprocesses or CI queries occur in this library.

## Tracked-source report command

Run `memcordon-ci source boundaries --output /tmp/source-boundaries.json --history-limit 32` from the repository. The history limit accepts 1 through 1000 commits and defaults to 32. The output contains all current registry entries tagged GOV-06, measured against tracked registered Rust sources only. The command never reads untracked source or registry files. It lists tracked unregistered sources and deleted or untracked registry sources explicitly; a missing GOV-06 candidate fails collection. These disclosures do not replace source-registry policy validation.

The JSON binds HEAD, tracked dirty status, tracked inventory, registry-file SHA-256 digests and source-content SHA-256 digests. Untracked files are excluded from dirty status. Measurements describe current working-tree content, so dirty reports must not be attributed to HEAD content alone. Before/after checks reject observed HEAD, tracked status, inventory, content or shallow-boundary changes; they are not an atomic filesystem snapshot.

History records exact commit ids from bounded topological ancestry, whether more commits were available, and shallow-repository boundaries. Per-commit changed paths use the union of parent comparisons for merges, without following renames. Unavailable shallow-parent comparisons are explicitly marked and contribute no cochange counts. Empty change sets in those records do not prove absence of changes. Cochanges remain pair counts rather than statistical clusters.

The producer identity embeds hashes of the compiled collector source, metrics source and Cargo.lock alongside package and algorithm versions. Git replacement objects are disabled and graft metadata is rejected. Publication rejects tracked output paths and uses atomic replacement at the guarded canonical destination, preserving a tracked source even when an output hardlink exists.

Eight focused collector tests cover hashes and dirty-state changes, ignored invalid untracked files, deterministic output, bounded history, tracked unregistered files, deleted-source accounting, missing required candidates, shallow-parent omissions, symlink rejection, replacement/graft behavior and tracked/hardlinked output protection. The five library measurement tests separately cover syntax and lexical-graph behavior. Generated reports belong in an artifact path; they are not automatically committed. Final source-registry integration and actual per-candidate architecture acceptance remain separate work.
