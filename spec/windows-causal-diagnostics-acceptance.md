# Windows causal diagnostics acceptance after 0.5.5-rc.1

This acceptance map supplements [the V1 contract](windows-causal-diagnostics-v1.md).
Live Windows execution uses `memcordon.result` revision 1, public/private
protocol 3/3, terminal receipt V2, and durable attempt record V4. Numeric execution
report schema 11 remains a compatibility format. Diagnostic projections remain
V1. A diagnostic never supplies a
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

These source-file names are navigation labels. Fully qualified test names follow
the sealed-agent test module declarations. Native CI executes the selected Cargo
test binaries on their matching hosts. Portable success does not establish native
Windows behavior.

## Installed-provider acceptance

The installed consumer in `tools/memcordon-ci/src/windows_installed_cases.rs`
uses the selected native archive or exact packaged crates on each matching MSVC
architecture. Its two cases are `sampling-population` and
`guardian-loss-after-release`. The population fixture holds the root and 256
children while the driver independently retains their PID/birth identities. It
requires a deadline result with complete retirement. The guardian-loss case
terminates an authenticated, held guardian after release and requires the
original monitor failure, a provider-failure result and complete retirement.
A bounded sample with explicit omissions is valid; a fabricated complete history
is not. Preflight requires 4 GiB available memory; insufficient capacity is a
failed requirement.

The consumer verifies the named result's provider association, native exit status,
authorization and cleanup. It retains bounded report/stdout/stderr hashes and
keeps behavior, collection, workload cleanup and package cleanup outcomes
separate. Public smoke runs before and after the cases; retained-state recovery,
package upgrade and uninstall must also complete. Assessments are written to
`windows-assessment.json` and `installed-assessment.json`. The release workflow
runs native-bundle and Cargo-package channels on separate fresh hosts and waits
for successful installed jobs before assembly. These checks do not grant a local
launch permission or substitute for the provider's live native checks.

The source regression map does not establish successful installed-consumer
execution or downstream workload validation. Those need fresh
native evidence. Keep private-state ACLs unchanged: no ownership takeover,
privilege escalation, raw-state reader or alternate diagnostic endpoint is part
of this acceptance path. Explicit unavailable/loss evidence remains a failure
observation; a secondary event never becomes an unavailable original.

## Downstream closure

Source regression, selected installed-consumer execution and downstream workload
verification exercise distinct inputs. Downstream validation requires the original
execution context: exact installed identity/version, active probe, smoke,
installer compilation, direct executable installer invocation and the project's
remaining required gates. Preserve the reviewed workload and its budgets; a
source build or a tool-version check alone cannot replace the functional gate.

The Linux baseline continues to reject genuine TCP requirements before release.
Required TCP tests remain blocked in that context, never counted as passing
negative application tests. The optional private TCP provider uses its own local
grants and native checks as described in the
[V2 workload contract](../docs/spec-workload-contract-v2.md).
