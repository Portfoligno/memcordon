# ADR 0001: Windows loader qualification is unobserved

Status: accepted

The shared production plan/create boundary and typed result transport are the
loader-qualification contract. Legacy in-band diagnostic modules and portable
source-shape tests have been removed. Production process behavior is split by
responsibility, raw native creation is centralized in the shared launch core,
and semantic contract tests exercise the same factory, attestor, and channel
driver used by the shipped package path.

MemCordon certifies exactly one unobserved production loader launch. The
production plan contains no debugger, loader-snap, ETW, passive-observer, or
restricted-token controls. Its creation flags, exact inherited-handle list,
Job-at-creation requirement, executable, command, environment, current
directory, desktop, object descriptors, and caller-token identity are validated
and hashed before process creation.

The shipped LoaderControl helper uses production plan schema 2, whose fixed
creation policy is consoleless (`DETACHED_PROCESS`). It has an empty inherited
handle list and attests the selected helper image, token and desktop through
the authenticated protocol. The plan version and fixed creation flags are
included in the plan digest. Schema 1 retains its original console policy and
exact digest interpretation for historical evidence and laboratory inputs.

This helper qualification does not assert that the workload image initialized.
The workload retains its separate process-group and standard-stream policy and
must satisfy its own creation, containment, readback, release and retirement
checks. Holder policy is separate and unchanged. A detached-console
diagnostic is explicitly not applicable to a schema-2 consoleless baseline; it
creates no alternative child and supplies no qualification authority.

The separate Probe helper also uses an explicit consoleless creation policy.
Its typed policy fixes the Probe role, creation flags, atomic Job assignment and
empty inherited-handle list before native creation. The identical policy enters
Probe binding schema 4 and its digest; child admission rejects role, schema or
policy mismatch. Holder bindings remain schema 3 with their original bytes and
digest domain. Probe still requires its actual token lineage, USER security and
noninteractive/live binding evidence, admitted AccessCheck, normal child exit
and empty Job. These are helper attestation claims, not workload initialization
or diagnostic authority, and workload console/stdIO policy is unchanged.

Debugger, loader-snap, ETW/WPR, Process Monitor, and synthetic token variants
belong only to the standalone Windows loader laboratory. A diagnostic outcome
is evidence and cannot replace or fail the production result. The laboratory
uses a separate namespace and reports scenario failures as structured data;
only an incomplete harness or failed cleanup produces a nonzero harness exit.
External Procmon/WPR evidence is attached in a second phase without changing
the original scenario and result artifacts. The augmented manifest is
digest-bound to the selected pair, PID, time window, build, symbols, and
restricted raw trace.

Provider failures preserve the first native production stage and status.
Cleanup is a secondary typed outcome. Rendering is terminal: no decision may
be made by parsing diagnostic prose.

The production sealed-agent build must not link debugger event-pump or lab-only
ETW/session-control imports. CI verifies the binary import boundary and runs
loader production, provider lifecycle, package/channel, and explicit diagnostic
lab work as separate jobs.
