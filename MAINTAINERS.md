# Maintaining MemCordon

Public behavior belongs in README.md, docs/reference.md, generated CLI help, and
Rust API documentation. Historical proposals in Git history are not current
contracts.

The workspace separates core policy, state, outcomes and reports from native
execution. memcordon-windows-launch-core shares the typed Windows launch model;
memcordon-platform owns native backends; the memcordon facade and CLI own public
execution and report assembly. memcordon-testkit supplies process-test support,
and memcordon-ci runs repository policy and ordinary build, package and native
behavior checks. The independent macOS deadline oracle observes clocks, process
identity, streams and teardown without production supervision dependencies.

Containment must be established before target instructions run. Linux uses its
native cgroup and launcher boundary, Windows creates a suspended target before
Job Object assignment, and macOS establishes a process group under its native
owner. Native owners retain their actual child handles until reaping. Process-table
presence is not proof of direct-child ownership or retirement.

Retain ordinary exit precedence: deadline 123, confirmed memory limit 124, and
wrapper or cleanup failure 125. A failed cleanup remains visible. Privileged
optional services retain actual local authentication, administrator grants,
protected file checks, cancellation and cleanup. Saved observations cannot
replace live admission or native resource checks.

CI keeps pinned toolchains and action revisions, read-only contents permission,
credential-free builds, and complete native matrix and Miri/fuzz shard coverage.
On covered branch/version-filter tag pushes, Release owns common preparation;
ordinary CI retains six debug-native cells, Deep CI retains stress, and Native
backend tests retains optional Windows sealed and Linux private installed work.
Release's CLI-only public selection does not cover those optional runtimes.
PR and merge-group CI, explicit standalone dispatches and uncovered-tag common
checks retain their existing work. The event classifier only schedules jobs; it
does not establish Release success or publication permission. Ref deletions do
not schedule work for the deleted ref.
Every workflow run step invokes one executable with arguments.
CI orchestration reads standard GitHub context and explicit command arguments;
custom environment variables are confined to workflow files and never introduce
a source, target, phase or timeout protocol in Rust or build scripts. Cargo source
caches use the actual Cargo home and split restore/save steps. Compiled-cache
reuse is disabled while the selected native inputs lack an ordinary safe cache
identity; restoring a cache never proves that a test ran.
Debug-native and optimized-native owners use separate cache purposes and actual
test recipes. Release additionally identifies selected product features and
binaries. Preserve split restore/save, valid-context and quiescence conditions;
do not cache reports, installed state or prepared release bytes.

Native CI executes the selected test binaries on matching hosts. Installed
consumers exercise the selected package and archive bytes and report execution,
collection and cleanup failures separately. Special loader experiments remain
optional and do not enter distribution inputs.

Release tooling prepares selected source and artifact bytes, exercises native and
installed consumers, and reconciles publication state. See RELEASING.md for the
operating procedure. A portable test or an unavailable native host does not
establish completed native release validation.
Required checks and dashboards must distinguish actual branch preparation from
PR/merge-group checks and skipped duplicate jobs. Their settings are a maintainer
operation and are not changed by workflow edits. Confirm the enabled Release
candidate path and representative event outcomes before relying on suppression;
see RELEASING.md for migration, measurement and rollback guidance.
