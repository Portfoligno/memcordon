# Source presence

`memcordon-ci source validate` checks one declaration for each nonignored Rust
source under `crates/`, `tools/`, and `fuzz/fuzz_targets/`. Pending additions and
deletions are included so the same check works before commit. The policy suite
runs the check automatically.

The eight TOML domains use schema 1 and reject unknown fields. Each source has a
stable id, current path, owner, kind, visibility tier, protected invariant,
consumer, platform, source route and reviewed disposition. Routes are compared
with Cargo target metadata and a `syn` module graph containing every cfg branch.
Cargo roots retain their required features; module edges retain cfg and visibility.
Each record also pins its source's cfg/cfg_attr declarations and item visibility
to qualified owners, including imports, methods and fields. Moving a gate to an
unrelated declaration or widening an item requires an explicit record edit.
The independent fuzz workspace's explicit targets are included. Standalone Rust
entrypoints require an observed rustc input in a workflow job. These compile
declarations are not proof of hosted execution.

For a move, retain the id and change the path and routes. For a replacement,
record the old id in `replaces`. Add new identities to `ci/source-history.toml`;
never remove historical identities. A retired source needs an explicit reason in
that history. Active and retired identities must be disjoint. This preserves the
375-file design baseline while accounting for new implementation files.

`memcordon-ci source routes --output PATH` emits the observed source graph to aid
review. It does not generate ownership or justification. After editing a source
record, run validation and review the declarations as part of the same change.

The JSON diagnostic at `target/ci/source-presence.json` names the checkout commit
and explicitly says `execution_attested: false`. A consumer declaration does not
claim a test ran. Exact execution attestations, semantic platform applicability and
review of provisional per-file invariants remain separate acceptance work in
[the execution ledger](../../docs/source-remediation-progress.md).
