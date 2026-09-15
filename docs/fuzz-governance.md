# Fuzz ownership and evidence

`fuzz/targets.toml` is the managed fuzz plan. Each Cargo binary has exactly one
charter with a stable ordinal ID, production contract, property, input class,
corpus owner, seed directory, supported hosts, and retention requirement.
Odd IDs select the first shard and even IDs the second; rename a binary without
changing its ID. New targets receive new IDs. The Cargo manifest remains the
compiled binary inventory and must agree with the charter registry exactly.
PROV-05 reserves the named `agent-package-inspection` ID in its original first
shard, so historical triage has a permanent canonical survivor name.

The controller validates source-inclusion declarations against Rust syntax.
Direct imports use the production package APIs. Any `#[path]` or `include!`
compilation requires an explicit shared-source declaration and parity obligation;
the source registry owns the corresponding route evidence. A declaration does
not itself prove native execution or authorize a binary-source exception.

All targets retain a 30-second smoke interval and the five-minute outer command
bound. Ordinary inputs are limited to 4 KiB, policy/workflow documents to 64 KiB,
and workload inputs to 1 MiB. The larger document class admits the real checked-in
policy and workflow rather than excluding their accepted-input paths.

Checked-in seeds include reviewed parser records, real configuration documents,
and workload JSON examples. Shared lexical bootstrap seeds exercise rejection
paths for schemas without a checked-in positive example. These are not claimed
as accepted schema coverage. Existing generated workload seeds and historical
`fuzz/corpus/<binary>` directories are also retained and merged. Lexical harnesses
exercise the original bytes and, where documented, a newline-terminated seed
record with its final newline removed; production parsers remain unchanged.

The working corpus lives under `target/ci/fuzz-corpus/<stable-id>`. Merge reads
bounded regular files, rejects symbolic links, verifies pre-existing digest
paths, and copies by SHA-256 without deleting source files. Restored corpus
contents are included in the input inventory. The cache includes all charter,
seed, harness, dependency, and managed-build inputs.

Before each phase, the controller writes
`target/ci/reports/fuzz/<stable-id>/evidence.json`. It records the charter, latest
phase, input corpus digests, resulting crash-artifact digests, and any command
failure. A target left as `planned` or `built` has not completed execution. The
report is a latest-phase record, not a full event history or GOV-02 commit-bound
execution attestation. Crash files are copied under their content digest in the
same stable-ID directory; the original cargo-fuzz artifact remains intact.
The workflow always uploads these reports/artifacts with 90-day retention, and
report paths are excluded from restored build caches.

An alias may name only a removed binary and cannot collide with another alias.
The package-inspection duplicate remains an active target, with its own charter,
until PROV-05 records historical artifact ownership, both-corpus replay,
content-preserving migration, minimization, and survivor replay. Merely copying
corpora or passing a smoke lane does not satisfy that retirement gate.
