# Windows causal diagnostics acceptance after 0.5.5-rc.1

This acceptance map supplements [the V1 contract](windows-causal-diagnostics-v1.md).
The rc.32 baseline execution report is schema 10; an implementation release
must use its exact validated compatibility schema. Diagnostic projections remain
V1, and the Windows public/private protocols remain 2/2. A diagnostic never supplies a
missing terminal receipt, acknowledgment, retirement proof or restart authority.

## Executable regression map

The portable tests below are in `crates/memcordon-core/tests/diagnostics.rs`.
Native tests are in `crates/memcordon-cli/tests/sealed_agent/`. Names identify
executable assertions, not an assertion that this document ran them.

| Requirement | Executable test | Evidence scope |
| --- | --- | --- |
| Original event is immutable; overflow is explicit | `original_is_immutable_and_secondary_overflow_is_explicit` | Portable journal model |
| Native codes retain domain and bits | `native_domains_preserve_bits_and_reject_unknown_fields` | Portable public projection |
| Provider, attempt, request and digest must match | `projection_requires_exact_provider_attempt_request_and_digest` | Portable binding and independent digest vector |
| Expiry cannot alter terminal or ACK authority | `diagnostic_expiry_does_not_change_terminal_authority_or_ack_bytes` | Portable protocol commitment |
| Capture precedes cleanup; unwind preserves the original | `windows_causal_capture::source_capture_and_record_cleanup_share_one_ordered_journal`, `windows_causal_capture::unwinding_and_reentrant_capture_preserve_original_and_expose_loss` | Native attempt-local capture |
| Receiptless Posttarget response remains refused and retains original cause | `windows_postauthorization_retirement::receiptless_posttarget_rejection_cannot_bypass_terminal_binding` | Native record/rejection path |
| Later outbox failure does not replace primary failure | `windows_replay_retention::final_outbox_store_failure_preserves_primary_and_bounds_secondary_diagnostics` | Native terminal publication |
| Storage faults preserve original and truthful durability | `windows_record_faults::native_publication_fault_matrix_preserves_original_and_honest_commit_boundary` | Native write/flush/rename/readback fault injection |
| Stalled storage cannot own Job cleanup | `windows_record_faults::frozen_native_publication_does_not_own_workload_job_cleanup` | Native writer and guardian ownership |
| Bound retained response survives record reread failure | `windows_replay_retention::bound_launch_retention_survives_record_reread_failure` | Native retained-failure response |
| Accounting conversion retains its native code and monitor classification | `windows::launcher_service::job_conversion_tests::job_accounting_conversion_preserves_monitor_classification` | Native wrapper through launch conversion and journal |
| Every emitted Job/target/guardian operation has one typed mapping | `windows::launcher_service::job_conversion_tests::job_observation_mapping_covers_emitted_operations` | Native conversion inventory and semantic errors |
| String-returning wrappers cannot replace the typed original | `windows::launcher_service::job_conversion_tests::job_string_conversion_preserves_semantics` | Native legacy conversion |
| Later observation reconstruction retains the original operation | `windows::launcher_service::job_conversion_tests::job_diagnostic_reconstruction_preserves_operation` | Native cleanup conversion |

These source-file names are navigation labels. The authoritative fully qualified
test names live in `tools/memcordon-ci/src/workload_qualification.rs` and the
sealed-agent test module declarations. The certification driver requires exactly
one successful named test for each selected native case; zero matches cannot
produce a qualified result. x64 and ARM64 certificates remain separate, tied to
their source and component provenance. Portable success does not certify Windows.

## Installed-provider acceptance

The installed acceptance driver runs after a successful public launch and before
active package mutation, once for each native-bundle and Cargo-package channel
on each MSVC architecture. It runs a source-built, bounded fixture as workload
input through the installed public CLI. The fixture creates at most 256 direct
leaves plus its root, with a 120-second MemCordon deadline, a 180-second runner
deadline, a 240-second fixture safety expiry, and a 4 GiB preflight memory
budget. An insufficient runner is a failed required case, not a skip. The
fixture does not alter privileged provider behavior or increase the production
inventory ceiling.

The accepted report must use the exact release-selected execution schema and
remain a failed/error envelope. Its immutable original is
`Monitor / AccumulateProcessInventory / ProcessInventoryCapacity`, with
`observed = limit + 1`, no invented native number, and a later ordered
`ValidateTerminalResponse / TerminalBinding` refusal. The projection remains
bound to the qualified provider, attempt and request. Cleanup and recovery are
independently observed; neither supplies a missing receipt, terminal ACK,
restart authority or success. Native process enumeration checks the uniquely
staged fixture image and creation identities, rather than trusting PID absence
or parsing `tasklist` output. Raw public report bytes are retained before
supported package recovery.

Four separate acceptance files are required:
`windows-x64-installed-causal-native.json`,
`windows-x64-installed-causal-cargo.json`,
`windows-arm64-installed-causal-native.json`, and
`windows-arm64-installed-causal-cargo.json`. Each binds the channel, target,
source, package version, fixture and nine raw artifacts, and requires all
twelve named assertions in `windows_causal_acceptance.rs`. Release ingestion
hashes and reparses the raw files; source-native diagnostic tests remain a
different evidence class. Only a measured published native archive may produce
release acceptance. The local-build fallback is explicitly a development
evaluation and cannot publish any of these four certificates.

The source regression map is not a claim that this installed-provider sequence
or the unchanged downstream Windows Nightly workload passed. Those need fresh
native evidence. Keep private-state ACLs unchanged: no ownership takeover,
privilege escalation, raw-state reader or alternate diagnostic endpoint is part
of this acceptance path. Explicit unavailable/loss evidence remains a failure
observation; a secondary event never becomes an unavailable original.

## Downstream closure

Source candidate regression, isolated installed-package qualification and the
approved bare-PATH downstream verifier are distinct evidence classes. This patch
does not upgrade an installation, select a release artifact or authorize a grant.
Closing the installer incident requires a fresh ordered suite in the original
execution context: exact installed identity/version, active probe, smoke,
installer compilation, direct executable installer invocation and the project's
remaining required gates. Preserve the reviewed workload and its budgets; a
source build or a tool-version check alone cannot replace the functional gate.

The Linux baseline continues to reject genuine TCP requirements before release.
Required TCP tests remain blocked in that context, never counted as passing
negative application tests. A private TCP profile or coverage partition requires
its own explicit approval and native qualification.
