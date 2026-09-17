# Managed CI compilation

Shared compiled caches use the `managed-v2` namespace. Each job freshly compiles
the standard-library-only seed, then builds the CI controller from source in
`target/ci/control-bootstrap`. Neither executable is restored from a cache.
Dependency archives and locked Git objects use the isolated
`target/ci/source-home`; Cargo verifies registry checksums during extraction.

Before restoring compilation outputs, the controller records materialized source
bytes, modes and symlinks; the actual installed compiler sysroots; native SDK,
header, library and tool trees; approved environment-selected native roots; and
the complete closed child environment. SHA-256 identifies file contents. The
manifest also binds the workflow/job/revision and the source of all operation
recipes. Ignored build outputs and generated fuzz corpora are explicitly outside
the compilation-source tree; the generator and fuzz inputs remain source inputs.

Nightly/Miri setup and pinned auxiliary tools run before measurement. Auxiliary
tool preparation is intentionally cold at the compiled-output boundary in this
initial migration, as is controller preparation. Their dependency sources and
build outputs are retained separately. Candidate dependency/object/incremental
outputs remain cached, and every suite executes after a hit. No pass record or
acceptance evidence is a cache input.

Cargo and Cargo-fuzz commands use explicit managed invocation types. They select
absolute compiler paths, place that sysroot first on PATH, and receive a frozen
environment. Compiler/wrapper/configuration overrides are rejected; unknown
ambient variables and credentials are not inherited by compilation. Workload
execution and publication credentials retain their separate policies. Ordinary
candidate compilation is offline after dependency acquisition. Both Cargo
configuration filenames are rejected in the working-directory ancestry and
unapproved Cargo homes.

Windows compilation admits a positive native-tool PATH before seed compilation,
controller measurement and standalone generated-package compilation. It retains
the selected MSVC tools, rustup, Git, LLVM and versioned Windows SDK tools; managed
Cargo invocations also prepend their enrolled compiler sysroot. Discovery selects
explicit executables, and their installation/support trees are measured alongside
the existing SDK and compiler roots. Other ambient PATH directories are not
inherited, and missing required tools fail admission without an ambient fallback.
Unsupported entries in an admitted input tree still fail measurement.

This tool selection includes ARM Clang for the current ring build recipe and
rustup for compilation tests. Windows implicit executable search and system DLL
loading remain part of the declared native platform baseline, including the
enrolled system tools used by tests. PATH admission is not a general process
sandbox and does not prevent absolute-path execution or package activation APIs.
New build recipes or generated consumers that need another external helper must
enroll it and its inputs before entering this profile. Non-compilation workload
and publication commands retain their separate environment policy.

Generated consumer crates and extracted package sources use a separate measured
route with fresh Cargo homes and compilation directories. Their source snapshots
are audited, install destinations are explicitly declared, and recorded evidence
marks these builds ineligible for shared caches. A local package patch configuration
may reference only canonical paths inside the measured source tree; ancestor
configuration and command-line configuration overrides remain forbidden.

Preflight and postflight content audits reject drift. Partial compilation from a
failed test may be saved only after a successful audit, with the original nonempty
exact cache key, on the trusted default branch. Release jobs consume those cache
rules without publishing new trusted entries from a tag. The workflow validator
checks this managed envelope before applying the existing exact suite, artifact
and publication contracts.

This is a trusted-worker, declared-input boundary. An arbitrary build script can
read undeclared host state; it must not be added to this profile without enrolling
its inputs and reviewing its acquisition behavior. Missing, unreadable or
unsupported input trees fail planning rather than produce a partial key. Local
regressions cover environment exclusion, compiler/SDK/source content drift,
configuration discovery, native byte preservation, managed commands, seed
compilation and unsafe cache-route mutations. Cold/warm hosted workflow execution
and native Windows SDK discovery still require CI qualification; local macOS
tests do not establish those results or downstream installed-package acceptance.

The separate [native profile qualification tool](native-profile-qualification.md)
can construct and audit a staged candidate with complete selected support trees.
It does not admit that candidate to this production contract or emit a cache key;
full installation enrollment remains in place pending native closure and
relocation qualification.

The seed now owns final context admission. It revokes the old context and its
`native-inputs.admission.json` sidecar before journal creation, supervises each
child under the existing 1800-second ceiling, and requires successful, timely,
observed termination before publishing. A suspended Windows child joins a
kill-on-close Job Object before it can execute; surviving descendants prevent
success. Termination gets a separate bounded five-second observation window.
Failure to observe cleanup remains failure, even if the child wrote a complete
candidate. Progress never extends the deadline.

The parent synchronizes a provisional admission record, publishes the candidate,
then atomically links the sidecar as its last fallible publication operation.
Admission binds the context SHA-256, a unique parent journal nonce, and the current
GitHub run, attempt and job. Restore and audit require successful preparation;
save additionally requires the existing successful audit and trusted-key gates.
Both context and sidecar are excluded from compiled caches. Failed revocation
cannot physically invalidate an unwritable old pair: the explicit preparation
outcome gates therefore remain authoritative. A sidecar alone is not proof that
the current invocation succeeded, especially locally where GitHub identifiers
are absent. This remains a trusted-worker boundary, not protection against a
process authorized to rewrite the context and admission together.

Bounded failure journals are uploaded even when preparation fails. See
[inventory observations and experiments](inventory-observation.md) for schemas,
storage bounds, command interfaces and Windows qualification limits.
