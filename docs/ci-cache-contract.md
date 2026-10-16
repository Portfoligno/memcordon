# CI cache recipes

Source downloads and compilation products have separate identities. The
`mc-download-bootstrap-v5` entry is explicitly a partial bootstrap seed. It
never establishes workspace, fuzz, audit, deny or cargo-fuzz completeness.
Postbootstrap source contexts resolve the actual Cargo home and emit only its
registry archives and Git databases. Credentials, extracted sources and installed
state are excluded. A different home suppresses the default-home bootstrap save.

Complete workspace and fuzz entries require their actual locked fetch recipe.
Each auxiliary tool has its own source family, native installation target and
pin. Actual successful locked installation and staged version validation record
population; a restored executable's version check does not. Missing or malformed
packaged lockfiles suppress source publication. Custom registry/source selection
and target overrides remain unavailable until their exact recipes are modeled.
Population outputs belong to the current process and remain separate from writer
settlement. A source save rechecks its acquisition identity and retains its
original requested key, exact-hit exclusion and trusted-event guards.

Auxiliary compilation transports `target/debug`, `target/release` and the genuine
`target/CACHEDIR.TAG`, using layout revision 5 for both exact and compatible
identities. Only the two profile directories may be discarded. Before native
driver bootstrap creates `target/ci`, a package-scoped Cargo clean initializes
the genuine parent target marker without compilation. Save probes require the
marker and both populated profiles; a single settled profile can instead supply
an explicitly partial compiled seed. Probe failure suppresses saving. Unsafe restore
sanitation still blocks subsequent work. Local packages are cleaned even on an
exact hit, while external dependency products remain reusable.

Windows contexts observe the selected MSVC compiler, linker, librarian and
effective SDK/UCRT searches through the locked native resolver. Missing legacy
developer variables alone do not disable reuse. Conflicting selectors, unknown
search roots, redirected paths and unidentified native inputs still disable the
affected compiled entry. Synchronous native discovery has a finite optional
workflow-step timeout; it never activates a shell developer environment.

A service hit, a dependency seed retained by sanitation and actual Cargo reuse
are different observations. The local auxiliary regression transports the real
member list, preserves an external registry artifact and observes Cargo freshness
after sanitation. Native Windows correspondence and hosted cold/save/warm results
must be measured on their actual runners; cross-target typechecking does not
establish them. No cache outcome replaces native tests, readiness cleanup,
diagnostic ownership or release rehearsal.

Layout 6 separates native tests, selected product compilation, private native
tests and fuzz targets. Matching optimized source-test recipes share dependency
prefixes across producer roles; fuzz shard selection remains exact content while
its instrumentation remains compatible. Tool executables stay exact-version;
only their build directories gain compatible dependency fallback. Typed Cargo
configuration ignores comments and scheduling settings while refusing unknown
compiler, source, credential and precedence inputs for the affected family.

Ordinary native and fuzz jobs compile before executing their complete selected
tests. A bounded independent staged copy can retain settled compilation before
execution, including dependencies from a failed compilation. Complete entries
are preferred; at most one staged seed is imported into an empty owned target
and current local packages are cleaned again. Snapshots preserve actual modes
and modification times, hash actual bytes, reject redirected paths and active
writers, and never copy test outcomes or hardlink live compiler output.

Public crates.io archive seeds and sparse-index snapshots have content-derived
keys and separate bounded staging roots. They make no complete acquisition
claim. Each selected job restores at most one of each, performs ordinary online
Cargo work, and probes the observed content key before an optional save. A
same-name archive collision preserves the current file and rejects the seed.
Unsupported source scope remains cold; unsafe paths and unresolved owners block
mutation. No registry settings, remote caches or paid storage limits are changed.

Generated Miri sysroots and stable ordinary packaged consumers have separate
native acceptance gates. The Miri gate requires the exact pinned nightly's real
setup/transport/interpretation regression. The consumer gate requires actual
four-package compilation, external Cargo freshness, local rebuilding and fresh
installation at identical canonical coordinates. Gates are source-reviewed
target/toolchain tuples, never restored readiness files or environment switches.
The corresponding ignored native regressions document their explicit commands.
Existing readiness/public/capture workflow consumers remain ephemeral; the
current workflow inventory contains no eligible ordinary consumer caller.
