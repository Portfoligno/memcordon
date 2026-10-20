# CI cache recipes

Source downloads and compilation products have separate identities. The
`mc-ci-public-source-v1` entry is explicitly a partial public source seed. It
never establishes workspace, fuzz, audit, deny or cargo-fuzz completeness.
Postbootstrap source contexts resolve the actual Cargo home and emit only its
registry archives and Git databases. Credentials, extracted sources and installed
state are excluded. Eligible jobs select the owned standard Cargo home explicitly.

Complete workspace and fuzz entries require their actual locked fetch recipe.
Each auxiliary tool has its own source family, native installation target and
pin. Actual successful locked installation and staged version validation record
population; a restored executable's version check does not. Missing or malformed
packaged lockfiles suppress source publication. Custom registry/source selection
and target overrides remain unavailable until their exact recipes are modeled.
Population outputs belong to the current process and remain separate from writer
settlement. A source save rechecks its acquisition identity and retains its
original requested key, exact-hit exclusion and trusted-event guards.

Retention is independent of the job's aggregate success. Public source seeds save
after independent successful native acquisition; complete workspace downloads
save after the locked fetch. Release compilation retention precedes readiness
and uploads. Required tests, cleanup, rehearsal and publication still fail on
their actual errors. A save-action conclusion proves an attempt, not durable
storage: a later real restore is required to establish service retention.

Completed compilation entries require the selected producer's completion fact.
A later assertion failure preserves that fact only if no subsequent compilation
mutated the same scope. A failed or incomplete compiler recipe uses a content-keyed
partial seed. Every started writer must settle; only a declared skipped step
counts as never started. Empty outputs and cancellation never prove settlement.
The native owner reports settlement before semantic error formatting, retaining
timeout, output-cap, callback, reader and logger failures independently. Population,
settlement and completion outputs are attempted separately without replacing the
first work failure. Miri setup readiness remains distinct from writer settlement.

Revision 7 extends partial snapshots to the finite existing default compilation
layouts, Miri target outputs, and each pinned tool's build root. It excludes Miri
sysroots and installed tool images. Earlier unchanged explicit partition snapshots
retain their revision 6 namespace. Imports validate the selected index, every
member and Cargo markers before ordinary work; restored bytes never skip that
work. Tool download contexts use the source-only family API independently of
compiler/SDK probing, while binary and build caches retain native identities.

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
# Rust workflow authoring and cache transport

The source of the four checked-in workflow adapters is
`tools/memcordon-ci/src/workflow_definitions/`. Run
`memcordon-ci ci workflows --write` after editing; `--check` compares exact UTF-8
LF output. Fixed literal native invocations include explicit Windows executable
names. GitHub retains scheduling, event and credential boundaries, pinned action
transport and actual dependency results.

`ci cache-requests <recipe>`, `ci segment <recipe>` and
`ci cleanup-transfers <recipe>` select finite source-controlled recipes. Requests
contain cache identities and bounded paths. Settlement and compilation facts
come from current native owners; they cannot be restored from a request or
manifest. Save actions consume only the corresponding producer's validated
`*-save`, `*-key` and `*-path` outputs and use explicit `always()` guards.
Completed and partial compiler transfers stay distinct, with a new envelope
namespace and safe inbox validation before any live-root import. Unsafe paths or
unresolved ownership remain failures. Optional malformed cache data can be
discarded for a clean build.

Acquisition and compilation checkpoints remain before later test, readiness and
required upload failures. Finalizers attempt independent outputs before returning
the primary work error. Compiler/execution segments do not duplicate the earlier
source-family checkpoint; tool preparation retains its own actual source family.
Execution after a compile checkpoint does not reimport an older compilation
inbox over newly compiled work.

The driver has separate cold/build/runtime/inbox/transfer roots. Its executable
cache reuse is active for every supported native host, subject to actual input
compatibility and bounded image validation. Cold source compilation remains
the fallback; a failed first cold compilation cannot fabricate native settlement
or a ready image. Executable cache data is ordinary trusted-scope cache material,
not authentication or source approval. Credential-bearing publishers and actual
rehearsal do not execute cached bootstrap/current images.

An independent three-OS `source-seed` job acquires locked public crates.io
archives and sparse-index data with native Cargo. Release owns branch-push
production and Deep owns tag-push production; standalone branch dispatches own
their acquisition, except publication-only recovery. Consumers never depend on
this job. Successful acquisition can save even when an unrelated first driver
compilation fails. Its finite raw source paths contain no compiler output,
credentials, extracted sources, or readiness fact. Managed source transfers keep
their ordinary envelope checks and actual settled-owner requirements.

Eligible build jobs use standard `CARGO_HOME` at `target/ci-cargo-home` and
normalize checkout bytes before source-key hashing. A compatible source restore
never replaces current Cargo work. Driver images and compilation transfers have
independent eligibility: missing exact-image metadata does not disable usable
dependency outputs. Supported generated Miri sysroots use actual setup identity,
without a host/nightly rollout whitelist; explicit setup and interpreted tests
still execute. Backend branch supersession stops work admission and attempts
bounded native retirement; forceful runner termination is never reported clean.

Portable structural and mutation tests do not demonstrate hosted cache storage,
Windows rename/share behavior, Linux/macOS cold/warm native operation, or measured
transfer/build performance. Those outcomes require their actual native/service
acceptance. Report cache eligibility, an attempted transfer and verified later
retrieval separately.
