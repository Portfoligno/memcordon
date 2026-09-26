# Managed preparation and concurrency

The cold launcher requires an explicit `--profile`: `stable`, `msrv`, `miri`,
`fuzz`, `supply-chain`, or `release-preflight`. Job identity remains provenance
metadata and does not select preparation. Context schema 4 binds the profile,
resolved toolchains, auxiliary executables, sources, and native inputs. A managed
suite verifies that measured closure before executing restored tools, then retains
the existing post-suite audit and cache publication guards.

Deep CI partitions complete Miri harnesses into two jobs and sorted fuzz targets
into four jobs. Targets remain serial within each job. Per-shard plans are uploaded
as diagnostic evidence. Source/tool cache publishers have an explicit first-shard
owner, and source keys distinguish Miri, fuzz, and stress purposes.

Bootstrap supports two scoped lanes with independent task journals, one immutable
group deadline, deterministic controller-before-auxiliary failures, and joining
both started lanes on failure or panic. Auxiliary installations use per-tool
staging/build paths. Pinned identities and executable digests are checked before
promotion; an incomplete attempt cannot publish a usable context. Managed suites
bypass installation-receipt checks and execute only enrolled final binaries.

Production bootstrap scheduling remains sequential while collecting group and
task timing. Enabling overlap requires current runner measurements showing a
preparation improvement without increased timeout/failure rates. The tested lane
engine provides the scheduling support; this change makes no elapsed-time claim.

Stress exposes combined, packages, and lifecycle suites. Combined jobs retain
their existing platform inventory until phase timing, duplicated setup, lost
incremental reuse, and queue delay justify a split. Phase evidence records package
completion, elapsed time, failures, and the distinct Linux backend-unavailable
disposition. The child seed/report paths and single lifecycle process are retained.
