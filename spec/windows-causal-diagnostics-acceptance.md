# Windows causal diagnostics acceptance after 0.5.5-rc.1

This acceptance map supplements [the V1 contract](windows-causal-diagnostics-v1.md).
Execution reports remain schema 10, diagnostic projections remain V1, and the
Windows public/private protocols remain 2/2. A diagnostic never supplies a
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

These source-file names are navigation labels. The authoritative fully qualified
test names live in `tools/memcordon-ci/src/workload_qualification.rs` and the
sealed-agent test module declarations. The certification driver requires exactly
one successful named test for each selected native case; zero matches cannot
produce a qualified result. x64 and ARM64 certificates remain separate, tied to
their source and component provenance. Portable success does not certify Windows.

## Installed-provider acceptance

An installed-package test must observe the original monitor event through the
supported authenticated failure channel and schema-10 frontend report after a
later receiptless terminal-binding refusal. Compare the original typed operation,
native domain/value and ordering, preserve later secondary events, and require
the operation to remain failed. Observed cleanup must not manufacture a receipt,
ACK, policy retirement, restart or success. Record exact package/component
identity and retain public evidence before supported package recovery.

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
