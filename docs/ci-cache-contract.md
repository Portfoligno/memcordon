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
marker and a populated profile; their failure suppresses saving. Unsafe restore
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
