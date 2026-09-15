# Package inspection fuzz migration

`agent-package-inspection` is the canonical stable charter id. Both it and
`windows-package-inspection` remain active until the following gates are met.

The canonical Deep CI shard runs a prerequisite route using the pinned,
measured cargo-fuzz version. It copies and content-deduplicates both targets'
checked-in seeds, restored stable corpora, legacy corpora, legacy crashes and
restored content-addressed crashes. Evidence JSON files are not fuzz inputs.
It replays each corpus input and each crash explicitly on both active targets,
runs `cargo fuzz cmin` on a disposable copy, and replays the minimized corpus
plus every original crash on the canonical target. Failure stops the route.
Original inputs are preserved even when minimization or replay fails.

The existing always-upload fuzz artifact route retains copies and stage evidence
under `target/ci/reports/fuzz/agent-package-inspection/migration/`. Each report
records the checkout commit, measured cargo-fuzz version, selected nightly and
host, searched paths, content hashes, exact argv, completion and failures.
The report explicitly leaves historical discovery, native acceptance and
retirement authorization false. A successful run covers only inputs present on
that runner; an empty local directory is not evidence of historical completeness.

Before retirement, audit checked-in corpora, historical CI crash/corpus artifacts,
issues, dashboards and triage scripts for the old target name. Record every
source and immutable artifact/run identity in a reviewed migration manifest,
including unavailable or expired artifacts. Restore all recovered inputs into
the old target's corpus/artifact directories and execute the route on the exact
candidate commit. Preserve the resulting reports and all original crashes.
Resolve missing historical evidence explicitly; do not silently declare it empty.

After the full replay, cmin and required native acceptance gates pass, add the
old-name mapping to `fuzz/target-aliases.toml`, update shards and dashboards, and
only then remove the duplicate bin and harness. No alias or retirement is
performed by the prerequisite route itself.
