# Windows launch contract ownership and compatibility

`memcordon-windows-launch-core` is the observer-free contract between installed
provider qualification and the diagnostic loader lab. Its root exports remain
the supported API; private module names are not public import paths.

`environment_identity.rs` records the identity of already prepared environment
bytes. `prepared.rs` constructs those bytes. Neither an identity DTO nor successful
JSON decoding grants native authority. `ProductionLoaderPlanV1::new` and native
attestation own semantic validation and binding to actual objects.

The small DTO modules remain separate because their audit domains differ:
environment byte identity, exact handle roles, desktop/security binding, and token
snapshot identity. Their V1 field names, role spellings, and integer widths are
pinned by `spec/vectors/windows-launch/dto-v1.json`. A change to those bytes or
meaning requires a reviewed version/compatibility decision rather than silently
regenerating the fixture. Tests use only public root exports.

## DTO matrix

Production below means
`crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process_impl/desktop_loader.rs`
and its qualification caller. Lab means
`tools/memcordon-windows-loader-lab/src/spawner.rs` unless stated otherwise.
Test names are in `memcordon-windows-launch-core/tests/dto_vectors.rs` unless a
different target is named. These are declared coverage routes, not execution
attestations; changed-SHA native evidence is tracked separately.

| Public type | Production consumer | Lab consumer | Round-trip/compatibility test | Invalid-input test | Vector version |
|---|---|---|---|---|---|
| `PreparedEnvironmentIdentityV1` | Prepared environment identity enters production plan | Prepared scenario environment identity enters diagnostic plan | `launch_dto_v1_golden_round_trips_are_exact` | `launch_dto_v1_rejects_unknown_missing_and_mistyped_fields`; `decoded_dtos_do_not_bypass_production_plan_admission` | launch DTO V1 |
| `DesktopBindingV1` | Exact desktop and security material enter plan/attestation | Selected scenario desktop enters plan | Same golden test | Same strict-decoding and plan-admission tests | launch DTO V1 |
| `TargetTokenIdentityV1` | Qualified token envelope, authentication and session identity | Selected diagnostic token identity | Same golden test | Same strict-decoding and plan-admission tests | launch DTO V1 |
| `ExactHandleListV1` | Empty production inherited-role list | Empty diagnostic plan inherited-role list | Same golden test | Same strict-decoding and plan-admission tests (decoded nonempty list rejected) | launch DTO V1 |
| `HandleRoleV1` | Role vocabulary in exact-list contract; production forbids all inherited roles | Same exact-list contract | Same golden test covers every current variant | Same strict-decoding test rejects unknown roles | launch DTO V1 |

## Remaining public API matrix

This section maps the rest of the root API without pretending that native handles,
traits or preparation objects have a serde representation. `production_contract`
means the launch-core test target; `lab_contract` means the loader-lab target.
V1/V2 here identifies the existing contract, not an additional newly generated
golden file. Broader GOV-05 vector expansion remains separately tracked.

| Public types | Production consumer | Lab consumer | Round-trip or non-serde compatibility route | Invalid-input / failure route | Contract version |
|---|---|---|---|---|---|
| `ArtifactRefV1`, `RedactionClassV1` | No direct CLI consumer; diagnostic artifact boundary | `artifact.rs`, scenario evidence | `dto_vectors::diagnostic_artifact_and_native_call_records_keep_strict_contracts`; `lab_contract::external_capture_summary_is_bound_to_side_trace_plan_package_and_target` | Same strict-contract test; `lab_contract::artifact_references_reject_parent_traversal` | V1 |
| `ArtifactRefError` | No direct CLI consumer | Artifact construction error mapping | Non-serde error returned by shared constructor | Same traversal rejection | Rust error API for V1 |
| `ProductionLoaderPlanInputV1`, `ProductionLoaderPlanV1` | Production package loader plan | Scenario plan and controller plan input | `production_contract::ephemeral_marker_does_not_change_production_plan`; DTO admission test constructs shared plan | `production_contract::production_plan_cannot_enable_debugger`; DTO admission mutation cases | V1 |
| `ProductionPlanError` | Typed plan construction failure | Scenario plan error mapping | Non-serde shared error API | DTO admission mutation cases | Rust error API for V1 |
| `PreparedLoaderCommandV1`, `PreparedLoaderEnvironmentV1`, `PreparedCurrentDirectoryV1` | Prepared native command/environment/directory | Scenario prepared inputs | Non-serde owned byte buffers; `desktop_material::pre_resume_desktop_material_is_exact_nul_terminated_and_plan_bound` exercises plan-bound prepared material on Windows | `dto_vectors::prepared_material_rejects_invalid_encodings_before_native_creation` | V1 |
| `LoaderReadyEndpointV1` | Production ready-channel binding | Prepared scenario ready channel | Shared endpoint material, exercised by `desktop_material` | `dto_vectors::prepared_material_rejects_invalid_encodings_before_native_creation` | V1 |
| `HandshakeOutcomeV1` | Authenticated loader readiness evidence | Scenario handshake result | Nested in `production_contract::failure_payload_is_bounded_and_typed`; lab run evidence | `production_contract::production_failure_is_not_replaced` | V1 |
| `NativeStatusV1`, `WindowsLoaderQualificationStageV2` | Typed native failure identity and phase | Scenario failure status/phase | `production_contract::failure_payload_is_bounded_and_typed` | `production_contract::production_failure_is_not_replaced` | V1 status / V2 phase |
| `CleanupOutcomeV1`, `CleanupStatusV1` | Loader cleanup proof | Scenario cleanup observation | Nested failure evidence in `failure_payload_is_bounded_and_typed` | `production_contract::cleanup_is_secondary`; `lab_contract::harness_rejects_failed_cleanup_even_when_scenario_failure_is_observational` | V1 |
| `LoaderReadyEvidenceV1`, `WindowsLoaderQualificationFailureV2`, `WindowsLoaderQualificationOutcomeV2` | Package qualification result | Shared evidence/production comparison | `dto_vectors::ready_evidence_round_trip_rejects_unreviewed_version_and_handshake`; `production_contract::failure_payload_is_bounded_and_typed` | Same ready-evidence test; `production_contract::suspended_attestation_rejects_unproven_desktop_and_handles` | V1 ready / V2 result |
| `NativeCallOutcomeV1` | No direct CLI consumer; diagnostic call observation | `scenario.rs` process creation observation | `dto_vectors::diagnostic_artifact_and_native_call_records_keep_strict_contracts` | Same strict-contract test; `lab_contract::harness_accepts_preplan_failure_as_scenario_data` | V1 |
| `ProcessCreateFailure`, `PackageLoaderProbeError` | Shared loader creation/probe failure | Native factory/attestation adapters | Non-serde transaction errors | `production_contract::production_failure_is_not_replaced` | Rust transaction API |
| `SuspendedProcessEvidenceV1` | Suspended process attestation | Scenario native process inspection | `production_contract::qualification_runs_one_loader_probe`; Windows desktop material | `production_contract::suspended_attestation_rejects_unproven_desktop_and_handles` | V1 |
| `SuspendedProcessFactory`, `SuspendedProcessAttestor`, `LoaderReadyChannel`, `ProductionQualificationDriver` | One production create/attest/handshake owner | Shared factory and native operations in lab adapters | Non-serde traits/coordinator; `production_contract::qualification_runs_one_loader_probe` | `production_contract::diagnostic_failure_cannot_fail_qualification`; `cleanup_is_secondary` | Rust transaction API |
| `NativeSecurityDescriptorV1`, `NativeKernelObjectKindV1` | Exact native object security attestation | Lab selected security material | Non-serde native descriptors; `native_security::job_readback_normalizes_generic_all_and_omitted_group` | `native_security::kernel_security_mismatches_name_the_actual_object_kind` | V1, Windows only |
| `ProductionNativeCreateRequestV1`, `SuspendedNativeProcessV1`, `ProductionJobV1` | Handle-owning native creation transaction | Native scenario creation and cleanup | Non-serde native values; `desktop_material::pre_resume_desktop_material_is_exact_nul_terminated_and_plan_bound` | Same test's exact request/attestation checks; `native_security` object mismatches | V1, Windows only |
| `NativeCreateErrorV1` | Native create error mapping | `spawner.rs` native status mapping | Non-serde native error | `native_security::kernel_security_mismatches_name_the_actual_object_kind` | V1, Windows only |

Native-only rows must execute on both Windows architectures. Compilation on macOS
or a cross-target check is API/type evidence only. No native test is converted into
an unconditional success or silently omitted from its applicable runner route.
