#![cfg(feature = "test-fixtures")]
#[path = "../src/bin/consumer_readiness_windows/descriptor.rs"]
pub mod descriptor;
#[path = "../src/bin/consumer_readiness_windows/matched_control_input_record.rs"]
pub mod matched_control_input_record;
#[path = "../src/bin/consumer_readiness_windows/matched_control_report.rs"]
mod report;
use descriptor::{
    matched as record,
    matched_plan::{Directory, DirectoryRole, Plan},
};
use matched_control_input_record as input;
use report::*;
use sha2::{Digest, Sha256};
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn token() -> input::TokenDetails {
    input::TokenDetails {
        envelope: memcordon_core::WindowsCallerTokenEnvelopeV1 {
            user_sid: "S-1-5-21-1".into(),
            owner_sid: "S-1-5-21-1".into(),
            primary_group_sid: "S-1-5-32-545".into(),
            groups_sha256: memcordon_core::hash_bytes(b"groups").into(),
            privileges_sha256: memcordon_core::hash_bytes(b"privileges").into(),
            restricted_sids_sha256: memcordon_core::hash_bytes(b"restricted").into(),
            integrity_level: "S-1-16-8192".into(),
            mandatory_policy: 1,
            session_id: 1,
            elevation_type: 3,
            elevated: false,
            virtualization_allowed: false,
            virtualization_enabled: false,
            ui_access: false,
            appcontainer: false,
            authentication_id: 9,
            token_type: 1,
            impersonation_level: 0,
        },
        token_id: 10,
        expiration: -1,
        group_count: 2,
        privilege_count: 3,
        modified_id: 11,
        default_acl_bytes: 40,
        default_acl_sha256: [8; 32],
    }
}
fn fixture(protected: bool) -> (Report, Plan, Expected) {
    fixture_for(
        if protected {
            record::Scope::Envelope
        } else {
            record::Scope::BinaryFiles
        },
        protected,
    )
}
fn fixture_for(scope: record::Scope, protected: bool) -> (Report, Plan, Expected) {
    let root = std::env::temp_dir().join("memcordon-matched-report-model");
    let token = token();
    let token_hash = hash(&serde_json::to_vec(&token.envelope).unwrap());
    let environment = vec![memcordon_core::WindowsEnvironmentEntryV1 {
        name: "SystemRoot".encode_utf16().collect(),
        value: "C:\\Windows".encode_utf16().collect(),
    }];
    let mut plan = Plan {
        revision: 1,
        pair_sha256: [1; 32],
        input_sha256: [2; 32],
        scope,
        restricted: protected,
        fixture_sha256: memcordon_core::hash_bytes(b"fixture").into(),
        cli_sha256: memcordon_core::hash_bytes(b"cli").into(),
        direct_descriptor: root.join("direct.json"),
        installed_descriptor: root.join("installed.json"),
        cwd: root.clone(),
        work_clock: descriptor::ControlClock {
            revision: 1,
            work_cutoff_qpc: 100,
            qpc_frequency: 1000,
        },
        cleanup_cutoff_qpc: 200,
        record: root.join("broker.json"),
        environment: environment.clone(),
        directories: vec![Directory {
            role: DirectoryRole::Cwd,
            path: root.clone(),
            volume_serial: 1,
            file_index: 10,
            attributes: 0x10,
            security_information: 23,
            security_bytes: 80,
            security_sha256: [5; 32],
        }],
        provider: None,
    };
    for (role, path, file_index) in [
        (DirectoryRole::DirectOutput, root.join("direct"), 11),
        (DirectoryRole::InstalledOutput, root.join("installed"), 12),
    ] {
        let mut directory = plan.directories[0].clone();
        directory.role = role;
        directory.path = path;
        directory.file_index = file_index;
        plan.directories.push(directory);
    }
    if scope == record::Scope::ProviderListenerSelection {
        use descriptor::matched_plan::{ProviderControl, ProviderInput};
        use memcordon_platform::windows_private_fixture_binding::{
            DotLocalInput, PrivateFixtureAncestor, PrivateFixtureBinding,
        };
        let chain = |path: &std::path::Path| {
            path.ancestors()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .enumerate()
                .map(|(index, path)| PrivateFixtureAncestor {
                    path: path.to_owned(),
                    volume_serial: 1,
                    file_index: index as u64 + 100,
                    attributes: 0x10,
                })
                .collect::<Vec<_>>()
        };
        let parent = root.join("inputs");
        let fixture = parent.join("fixture.exe");
        let local = parent.join("fixture.exe.local");
        let provider = local.join("provider.dll");
        let direct = PrivateFixtureBinding {
            revision: 2,
            fixture: fixture.clone(),
            volume_serial: 1,
            file_index: 1000,
            attributes: 0x20,
            links: 1,
            bytes: 4096,
            sha256: plan.fixture_sha256.clone(),
            native_path_utf16: "\\Device\\Model\\inputs\\fixture.exe"
                .encode_utf16()
                .collect(),
            ancestors: chain(&parent),
            local_input: DotLocalInput::Directory(PrivateFixtureAncestor {
                path: local,
                volume_serial: 1,
                file_index: 1001,
                attributes: 0x10,
            }),
            output_ancestors: chain(&root.join("direct")),
        };
        let mut installed = direct.clone();
        installed.output_ancestors = chain(&root.join("installed"));
        // Separate leaves have separate identities even though their root-first
        // chains share the same prefix paths.
        installed.output_ancestors.last_mut().unwrap().file_index = 2002;
        let mut direct = direct;
        direct.output_ancestors.last_mut().unwrap().file_index = 2001;
        plan.provider = Some(ProviderControl {
            direct,
            installed,
            paths: vec![fixture, provider.clone()],
            providers: vec![ProviderInput {
                path: provider,
                original_path: "C:\\Windows\\provider.dll".encode_utf16().collect(),
                private_native_path: "\\Device\\Model\\inputs\\fixture.exe.local\\provider.dll"
                    .encode_utf16()
                    .collect(),
                volume_serial: 1,
                file_index: 1002,
                bytes: 8192,
                sha256: "ab".repeat(32),
            }],
        });
        for directory in &mut plan.directories {
            let control = plan.provider.as_ref().unwrap();
            let native = control
                .direct
                .output_ancestors
                .iter()
                .chain(&control.installed.output_ancestors)
                .find(|native| native.path == directory.path)
                .unwrap();
            directory.volume_serial = u64::from(native.volume_serial);
            directory.file_index = native.file_index;
        }
    }
    let denied = if protected {
        for (role, path, file_index) in [
            (DirectoryRole::DriverParent, root.join("driver"), 13),
            (DirectoryRole::ProviderParent, root.join("provider"), 14),
        ] {
            let mut directory = plan.directories[0].clone();
            directory.role = role;
            directory.path = path;
            directory.file_index = file_index;
            plan.directories.push(directory);
        }
        vec![
            root.join("driver/probe.bin"),
            root.join("provider/probe.bin"),
        ]
    } else {
        vec![]
    };
    let mut declared: descriptor::Descriptor = serde_json::from_value(serde_json::json!({
        "matched_control":record::Binding{pair_sha256:plan.pair_sha256,lane:record::Lane::Installed,scope,input_sha256:plan.input_sha256},
        "format":"memcordon.fixture-workload","revision":descriptor::DESCRIPTOR_REVISION,
        "case":match scope {record::Scope::Envelope=>descriptor::Case::Envelope,record::Scope::BinaryFiles=>descriptor::Case::BinaryFiles,record::Scope::JointListenerPrefix|record::Scope::ProviderListenerSelection=>descriptor::Case::Joint},
        "output_root":root.join("installed"),"transcript":root.join("installed/fixture-events.bin"),
        "challenge":[0,255,1],"stdout_base64":"","stderr_base64":"","arguments":[],"application_status":0,
        "churn_creations":descriptor::CHURN_CREATIONS,"churn_live":descriptor::CHURN_LIVE,
        "denied_write_paths":denied,"sentinel_handles":[],"descendant_gate":null,"start_gate":"Local\\report-model",
        "start_transport":{"transport":"controller-stdin","version":if scope==record::Scope::ProviderListenerSelection {descriptor::controller_start::PRIVATE_VERSION}else if scope==record::Scope::JointListenerPrefix {descriptor::controller_start::REGISTRY_VERSION}else{descriptor::controller_start::VERSION}},
        "winsock_registry":matches!(scope,record::Scope::JointListenerPrefix|record::Scope::ProviderListenerSelection).then_some(descriptor::winsock_registry::Declaration{version:descriptor::winsock_registry::VERSION,view:descriptor::winsock_registry::View::Native,sha256:[9;32]}),
        "provider_input_experiment":plan.provider.is_some(),"provider_input_paths":plan.provider.as_ref().map(|value|value.paths.clone()).unwrap_or_default(),"provider_input_binding":plan.provider.as_ref().map(|value|value.installed.clone()),
        "control_clock":plan.work_clock,"completion_gate":null,"cohort_gate":null,"generation_gate":null,"toolchain":null
    })).unwrap();
    let direct = plan.direct_descriptor_for(&declared).unwrap();
    plan.input_sha256 = plan.input_digest(&direct).unwrap();
    declared.matched_control.as_mut().unwrap().input_sha256 = plan.input_sha256;
    let direct = plan.direct_descriptor_for(&declared).unwrap();
    plan.validate(&direct, &declared).unwrap();
    let direct_digest = hash(&serde_json::to_vec(&direct).unwrap());
    let installed_digest = hash(&serde_json::to_vec(&declared).unwrap());
    let observations = |lane, pid, digest| {
        let binding = record::Binding {
            pair_sha256: plan.pair_sha256,
            lane,
            scope,
            input_sha256: plan.input_sha256,
        };
        let readback = input::Readback {
            revision: 1,
            binding: binding.clone(),
            descriptor_sha256: digest,
            pid,
            birth: 50 + u64::from(pid),
            token_sha256: token_hash,
            partial_token_sha256: [4; 32],
            token: token.clone(),
            cwd_utf16: root.to_str().unwrap().encode_utf16().collect(),
            cwd_identity: input::CwdIdentity {
                volume_serial: 1,
                file_index: plan.directories[0].file_index,
                attributes: 0x10,
            },
            environment: environment.clone(),
            streams: [(-10i32) as u32, (-11i32) as u32, (-12i32) as u32]
                .into_iter()
                .map(|role| input::Stream {
                    role,
                    file_type: 3,
                    security: input::Security {
                        security_information: 23,
                        bytes: 80,
                        sha256: [5; 32],
                    },
                })
                .collect(),
            started_qpc: 1,
            finished_qpc: 10,
            qpc_frequency: 1000,
            cutoff_qpc: 100,
        };
        let mut operations = vec![
            record::Operation::CreateNestedDirectory,
            record::Operation::WriteEmptyFile,
            record::Operation::WriteAllBytesTemporary,
            record::Operation::RenameAllBytes,
            record::Operation::ReadAllBytes,
            record::Operation::VerifyAllBytes,
            record::Operation::WriteChallenge,
        ];
        if protected {
            operations.extend([
                record::Operation::ProtectedWrite {
                    role: record::ProtectedRole::Driver,
                },
                record::Operation::ProtectedWrite {
                    role: record::ProtectedRole::Provider,
                },
            ]);
        }
        if matches!(
            scope,
            record::Scope::JointListenerPrefix | record::Scope::ProviderListenerSelection
        ) {
            operations = vec![
                record::Operation::WinsockStartup,
                record::Operation::ListenerConstruct,
                record::Operation::ListenerLocalAddress,
                record::Operation::CompetingBind,
            ];
        }
        let observation = record::Observation {
            revision: record::REVISION,
            native_status_domain: if matches!(
                scope,
                record::Scope::JointListenerPrefix | record::Scope::ProviderListenerSelection
            ) {
                record::NativeStatusDomain::PerOperation
            } else {
                record::NativeStatusDomain::Win32
            },
            binding,
            descriptor_sha256: digest,
            pid,
            birth: readback.birth,
            cutoff_qpc: 100,
            qpc_frequency: 1000,
            token_sha256: token_hash,
            started_qpc: 20,
            finished_qpc: 80,
            operations: operations
                .into_iter()
                .enumerate()
                .map(|(index, op)| record::OperationRecord {
                    ordinal: index as u32 + 1,
                    op,
                    arguments_sha256: [index as u8; 32],
                    before_qpc: 20 + index as u64 * 2,
                    after_qpc: 21 + index as u64 * 2,
                    outcome: if matches!(
                        scope,
                        record::Scope::JointListenerPrefix
                            | record::Scope::ProviderListenerSelection
                    ) {
                        match op {
                            record::Operation::WinsockStartup
                            | record::Operation::ListenerConstruct => {
                                record::Outcome::Completed { data_sha256: None }
                            }
                            record::Operation::ListenerLocalAddress => {
                                record::Outcome::LocalEndpoint {
                                    ipv4: [127, 0, 0, 1],
                                    port: 40000 + pid as u16,
                                }
                            }
                            record::Operation::CompetingBind => {
                                record::Outcome::HeldEndpointRefusal {
                                    ipv4: [127, 0, 0, 1],
                                    port: 40000 + pid as u16,
                                    code: 10048,
                                    calls: 1,
                                }
                            }
                            _ => unreachable!(),
                        }
                    } else if matches!(op, record::Operation::ProtectedWrite { .. }) {
                        record::Outcome::NativeFailure { code: 5 }
                    } else {
                        record::Outcome::Completed {
                            data_sha256: Some([7; 32]),
                        }
                    },
                })
                .collect(),
            terminal: record::Terminal::CompletedScope,
        };
        (readback, observation)
    };
    let (direct_input, direct_record) = observations(record::Lane::Direct, 20, direct_digest);
    let (installed_input, installed_record) =
        observations(record::Lane::Installed, 21, installed_digest);
    let expected = Expected {
        direct_target: (scope == record::Scope::ProviderListenerSelection).then_some((20, 70)),
        broker: (19, 69),
        direct_descriptor_sha256: direct_digest,
        installed_descriptor_sha256: installed_digest,
        installed_target: (21, 71),
        frontend: (22, 72),
        direct_stdout: StreamEvidence {
            bytes: 0,
            sha256: hash(&[]),
        },
        direct_stderr: StreamEvidence {
            bytes: 0,
            sha256: hash(&[]),
        },
    };
    let report = Report {
        revision: REVISION,
        claim_scope: if scope == record::Scope::ProviderListenerSelection {
            ClaimScope::ProviderListenerPrefixWithSharedInputs
        } else if scope == record::Scope::JointListenerPrefix {
            ClaimScope::ListenerPrefix
        } else {
            ClaimScope::OwnedFileOperationsAndSelectedToken
        },
        physical_stream_security_equal: true,
        paired_stdio: PairedStdioCoverage::NotAssessed,
        positive_coverage: PositiveCoverage::Complete,
        validation: ScopeValidation::MatchedSuccess,
        native_availability: NativeAvailability::Available,
        scope,
        pair_sha256: plan.pair_sha256,
        broker: Actor { pid: 19, birth: 69 },
        caller: Caller {
            source: token.clone(),
            selected: token,
        },
        direct: Direct {
            pid: 20,
            birth: 70,
            native_status: 0,
            job_active_processes: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_sha256: hash(&[]),
            stderr_sha256: hash(&[]),
        },
        installed_frontend: Frontend {
            pid: 22,
            birth: 72,
            native_status: 0,
        },
        comparison: ReportComparison {
            outcome: ReportOutcome::ScopeSuccess,
            scope,
            native_status_domain: if matches!(
                scope,
                record::Scope::JointListenerPrefix | record::Scope::ProviderListenerSelection
            ) {
                record::NativeStatusDomain::PerOperation
            } else {
                record::NativeStatusDomain::Win32
            },
        },
        direct_input,
        installed_input,
        direct_record,
        installed_record,
    };
    (report, plan, expected)
}
fn failed(observation: &mut record::Observation) {
    observation.operations.truncate(3);
    observation.operations[2].outcome = record::Outcome::NativeFailure { code: 5 };
    observation.terminal = record::Terminal::FirstFailure { ordinal: 3 };
}

#[test]
fn listener_refusal_validates_only_limited_comparison_and_never_positive_availability() {
    let (mut observed, plan, expected) = fixture_for(record::Scope::JointListenerPrefix, false);
    validate(
        &decode(&serde_json::to_vec(&observed).unwrap()).unwrap(),
        &plan,
        &expected,
    )
    .unwrap();
    for record in [&mut observed.direct_record, &mut observed.installed_record] {
        record.operations.truncate(2);
        record.operations[1].outcome = record::Outcome::NativeCallFailure {
            boundary: record::NativeBoundary::WsaSocket,
            domain: record::NativeStatusDomain::Winsock,
            code: 12345,
            calls: 1,
        };
        record.terminal = record::Terminal::FirstFailure { ordinal: 2 };
    }
    observed.direct.native_status = 2;
    observed.installed_frontend.native_status = 2;
    observed.comparison.outcome = ReportOutcome::SameObservedFailure;
    observed.positive_coverage = PositiveCoverage::Unestablished;
    observed.validation = ScopeValidation::MatchedNativeRefusal;
    observed.native_availability = NativeAvailability::Unavailable;
    assert_eq!(
        validate(&observed, &plan, &expected).unwrap().outcome,
        record::ComparisonOutcome::SameObservedFailure
    );
    for field in [
        "available",
        "positive",
        "claim",
        "validation",
        "status",
        "job",
        "stage",
        "opaque",
        "late",
        "token",
    ] {
        let mut altered = observed.clone();
        match field {
            "available" => altered.native_availability = NativeAvailability::Available,
            "positive" => altered.positive_coverage = PositiveCoverage::Complete,
            "claim" => altered.claim_scope = ClaimScope::OwnedFileOperationsAndSelectedToken,
            "validation" => altered.validation = ScopeValidation::MatchedSuccess,
            "status" => altered.installed_frontend.native_status = 0,
            "job" => altered.direct.job_active_processes = 1,
            "stage" => {
                altered.installed_record.operations[1].outcome =
                    record::Outcome::NativeCallFailure {
                        boundary: record::NativeBoundary::Bind,
                        domain: record::NativeStatusDomain::Winsock,
                        code: 12345,
                        calls: 1,
                    }
            }
            "opaque" => {
                altered.installed_record.operations[1].outcome = record::Outcome::NonNativeFailure
            }
            "late" => altered.installed_record.finished_qpc = altered.installed_record.cutoff_qpc,
            "token" => altered.installed_input.token.privilege_count += 1,
            _ => unreachable!(),
        }
        assert!(validate(&altered, &plan, &expected).is_err(), "{field}");
    }
    let (mut files, file_plan, file_expected) = fixture(false);
    files.claim_scope = ClaimScope::ListenerPrefix;
    assert!(validate(&files, &file_plan, &file_expected).is_err());
}

#[test]
fn provider_report_requires_shared_input_claim_and_independent_original_direct_identity() {
    let (original, plan, expected) = fixture_for(record::Scope::ProviderListenerSelection, false);
    let decoded = decode(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(
        validate(&decoded, &plan, &expected).unwrap().scope,
        record::Scope::ProviderListenerSelection
    );
    assert_eq!(
        decoded.claim_scope,
        ClaimScope::ProviderListenerPrefixWithSharedInputs
    );
    for field in [
        "claim",
        "old_revision",
        "missing_direct",
        "wrong_direct",
        "forged_direct",
        "missing_provider",
    ] {
        let mut observed = original.clone();
        let mut expectation = fixture_for(record::Scope::ProviderListenerSelection, false).2;
        let mut declaration = plan.clone();
        match field {
            "claim" => observed.claim_scope = ClaimScope::ListenerPrefix,
            "old_revision" => observed.revision = 3,
            "missing_direct" => expectation.direct_target = None,
            "wrong_direct" => expectation.direct_target = Some((999, 999)),
            "forged_direct" => {
                observed.direct.pid = 999;
                observed.direct.birth = 999;
                observed.direct_input.pid = 999;
                observed.direct_input.birth = 999;
                observed.direct_record.pid = 999;
                observed.direct_record.birth = 999;
            }
            "missing_provider" => declaration.provider = None,
            _ => unreachable!(),
        }
        assert!(
            validate(&observed, &declaration, &expectation).is_err(),
            "{field}"
        );
    }
    let (files, file_plan, mut file_expected) = fixture(false);
    file_expected.direct_target = Some((files.direct.pid, files.direct.birth));
    assert!(validate(&files, &file_plan, &file_expected).is_err());
}

#[test]
fn original_application_refusal_report_requires_actual_failure_and_never_native_or_positive_claims()
{
    for scope in [
        record::Scope::JointListenerPrefix,
        record::Scope::ProviderListenerSelection,
    ] {
        let (mut observed, plan, expected) = fixture_for(scope, false);
        for lane in [&mut observed.direct_record, &mut observed.installed_record] {
            lane.operations.truncate(2);
            lane.operations[1].outcome = record::Outcome::OriginalApplicationIoFailure {
                api: record::ApplicationIoApi::TcpListenerBind,
                domain: record::ApplicationIoDomain::RustIoRawOsErrorOnWindows,
                raw_os_error: 10106,
            };
            lane.terminal = record::Terminal::FirstFailure { ordinal: 2 };
        }
        observed.direct.native_status = 2;
        observed.installed_frontend.native_status = 2;
        observed.comparison.outcome = ReportOutcome::SameOriginalApplicationFailure;
        observed.positive_coverage = PositiveCoverage::Unestablished;
        observed.validation = ScopeValidation::MatchedApplicationRefusal;
        observed.native_availability = NativeAvailability::Unavailable;
        let decoded = decode(&serde_json::to_vec(&observed).unwrap()).unwrap();
        assert_eq!(
            validate(&decoded, &plan, &expected).unwrap().outcome,
            record::ComparisonOutcome::SameOriginalApplicationFailure
        );
        assert_eq!(decoded.paired_stdio, PairedStdioCoverage::NotAssessed);
        for field in [
            "native_claim",
            "positive",
            "available",
            "direct_status",
            "installed_status",
            "job",
            "raw_code",
            "opaque",
            "binding",
            "clock",
            "revision",
        ] {
            let mut altered = observed.clone();
            match field {
                "native_claim" => altered.validation = ScopeValidation::MatchedNativeRefusal,
                "positive" => altered.positive_coverage = PositiveCoverage::Complete,
                "available" => altered.native_availability = NativeAvailability::Available,
                "direct_status" => altered.direct.native_status = 0,
                "installed_status" => altered.installed_frontend.native_status = 0,
                "job" => altered.direct.job_active_processes = 1,
                "raw_code" => {
                    altered.installed_record.operations[1].outcome =
                        record::Outcome::OriginalApplicationIoFailure {
                            api: record::ApplicationIoApi::TcpListenerBind,
                            domain: record::ApplicationIoDomain::RustIoRawOsErrorOnWindows,
                            raw_os_error: 5,
                        }
                }
                "opaque" => {
                    altered.installed_record.operations[1].outcome =
                        record::Outcome::NonNativeFailure
                }
                "binding" => altered.installed_record.binding.pair_sha256 = [99; 32],
                "clock" => {
                    altered.installed_record.finished_qpc = altered.installed_record.cutoff_qpc
                }
                "revision" => altered.revision = REVISION - 1,
                _ => unreachable!(),
            }
            assert!(
                validate(&altered, &plan, &expected).is_err(),
                "{scope:?} {field}"
            );
        }
        for field in ["validation", "native_availability", "positive_coverage"] {
            let mut wire = serde_json::to_value(&observed).unwrap();
            wire.as_object_mut().unwrap().remove(field);
            assert!(
                decode(&serde_json::to_vec(&wire).unwrap()).is_err(),
                "{field}"
            );
        }
    }
}

#[test]
fn complete_scope_and_retained_application_failure_remain_distinct() {
    for protected in [false, true] {
        let (report, plan, expected) = fixture(protected);
        let decoded = decode(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(
            validate(&decoded, &plan, &expected).unwrap().outcome,
            record::ComparisonOutcome::ScopeSuccess
        );
    }
    let (mut report, plan, mut expected) = fixture(false);
    failed(&mut report.direct_record);
    failed(&mut report.installed_record);
    report.direct.native_status = 2;
    report.installed_frontend.native_status = 2;
    report.comparison.outcome = ReportOutcome::SameObservedFailure;
    report.positive_coverage = PositiveCoverage::Unestablished;
    report.validation = ScopeValidation::Mismatch;
    report.native_availability = NativeAvailability::Unestablished;
    let stderr = b"actual application failure";
    expected.direct_stderr = StreamEvidence {
        bytes: stderr.len() as u64,
        sha256: hash(stderr),
    };
    report.direct.stderr_bytes = expected.direct_stderr.bytes;
    report.direct.stderr_sha256 = expected.direct_stderr.sha256;
    assert_eq!(
        validate(&report, &plan, &expected).unwrap().outcome,
        record::ComparisonOutcome::SameObservedFailure
    );
    report.installed_record = fixture(false).0.installed_record;
    report.installed_frontend.native_status = 0;
    report.comparison.outcome = ReportOutcome::DifferentOutcome;
    assert_eq!(
        validate(&report, &plan, &expected).unwrap().outcome,
        record::ComparisonOutcome::DifferentOutcome
    );
}
#[test]
fn broker_proof_is_complete_strict_and_bounded() {
    let (report, _, _) = fixture(false);
    let wire = serde_json::to_value(&report).unwrap();
    for field in [
        "direct_record",
        "installed_record",
        "caller",
        "direct_input",
        "installed_input",
        "comparison",
        "claim_scope",
        "physical_stream_security_equal",
        "paired_stdio",
        "positive_coverage",
        "validation",
        "native_availability",
    ] {
        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            decode(&serde_json::to_vec(&missing).unwrap()).is_err(),
            "{field}"
        );
    }
    for field in ["outer", "caller", "operation", "comparison"] {
        let mut extra = wire.clone();
        match field {
            "outer" => extra["extra"] = true.into(),
            "caller" => extra["caller"]["selected"]["extra"] = true.into(),
            "operation" => extra["direct_record"]["operations"][0]["op"]["extra"] = true.into(),
            "comparison" => extra["comparison"]["extra"] = true.into(),
            _ => unreachable!(),
        }
        assert!(
            decode(&serde_json::to_vec(&extra).unwrap()).is_err(),
            "{field}"
        );
    }
    assert!(decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    let mut duplicate = serde_json::to_string(&report).unwrap();
    duplicate.insert_str(1, "\"revision\":1,");
    assert!(decode(duplicate.as_bytes()).is_err());
}

#[test]
fn scoped_report_retains_physical_difference_and_rejects_forged_claim_or_coverage() {
    for protected in [false, true] {
        let (mut report, plan, expected) = fixture(protected);
        report.installed_input.streams[0].security.sha256[0] ^= 1;
        report.installed_input.streams[0].security.bytes += 4;
        report.physical_stream_security_equal = false;
        let bytes = serde_json::to_vec(&report).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert!(!decoded.physical_stream_security_equal);
        assert_eq!(
            decoded.installed_input.streams,
            report.installed_input.streams
        );
        assert_eq!(
            validate(&decoded, &plan, &expected).unwrap().outcome,
            record::ComparisonOutcome::ScopeSuccess
        );
        report.physical_stream_security_equal = true;
        assert!(validate(&report, &plan, &expected).is_err());
    }
    let (original, plan, expected) = fixture(false);
    for field in [
        "old_revision",
        "claim_scope",
        "paired_stdio",
        "positive_coverage",
        "scope",
    ] {
        let mut wire = serde_json::to_value(&original).unwrap();
        match field {
            "old_revision" => wire["revision"] = 1.into(),
            "claim_scope" => wire["claim_scope"] = "all-native-inputs-identical".into(),
            "paired_stdio" => wire["paired_stdio"] = "complete".into(),
            "positive_coverage" => wire["positive_coverage"] = "invented".into(),
            "scope" => wire["scope"] = "joint".into(),
            _ => unreachable!(),
        }
        let result = decode(&serde_json::to_vec(&wire).unwrap());
        assert!(
            result.is_err() || validate(&result.unwrap(), &plan, &expected).is_err(),
            "{field}"
        );
    }
    let mut stopped = original;
    failed(&mut stopped.direct_record);
    failed(&mut stopped.installed_record);
    stopped.direct.native_status = 2;
    stopped.installed_frontend.native_status = 2;
    stopped.comparison.outcome = ReportOutcome::SameObservedFailure;
    assert!(
        validate(&stopped, &plan, &expected).is_err(),
        "stopped operations cannot claim complete coverage"
    );
    stopped.positive_coverage = PositiveCoverage::Unestablished;
    stopped.validation = ScopeValidation::Mismatch;
    stopped.native_availability = NativeAvailability::Unestablished;
    assert_eq!(
        validate(&stopped, &plan, &expected).unwrap().outcome,
        record::ComparisonOutcome::SameObservedFailure
    );
}
#[test]
fn missing_native_retirement_or_inconsistent_native_exit_never_validates() {
    let (original, plan, expected) = fixture(false);
    for field in [
        "job",
        "broker",
        "directstatus",
        "frontendstatus",
        "frontendpid",
        "frontendbirth",
        "directpid",
        "scope",
        "pair",
    ] {
        let mut report = original.clone();
        match field {
            "job" => report.direct.job_active_processes = 1,
            "broker" => report.broker.birth += 1,
            "directstatus" => report.direct.native_status = 2,
            "frontendstatus" => report.installed_frontend.native_status = 125,
            "frontendpid" => report.installed_frontend.pid += 1,
            "frontendbirth" => report.installed_frontend.birth += 1,
            "directpid" => report.direct.pid += 1,
            "scope" => report.scope = record::Scope::Envelope,
            "pair" => report.pair_sha256[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(validate(&report, &plan, &expected).is_err(), "{field}");
    }
}
#[test]
fn actual_capture_hashes_lengths_and_complete_bounds_are_required() {
    let (original, plan, expected) = fixture(false);
    for field in [
        "stdoutbytes",
        "stderrbytes",
        "stdouthash",
        "stderrhash",
        "overflow",
    ] {
        let mut report = original.clone();
        match field {
            "stdoutbytes" => report.direct.stdout_bytes = 1,
            "stderrbytes" => report.direct.stderr_bytes = 1,
            "stdouthash" => report.direct.stdout_sha256[0] ^= 1,
            "stderrhash" => report.direct.stderr_sha256[0] ^= 1,
            "overflow" => report.direct.stdout_bytes = MAX_BYTES as u64 + 1,
            _ => unreachable!(),
        }
        assert!(validate(&report, &plan, &expected).is_err(), "{field}");
    }
}
#[test]
fn selected_caller_inputs_are_independent_of_mutual_target_agreement() {
    let (original, plan, expected) = fixture(true);
    for field in ["acl", "expiry", "groups", "privileges", "envelope"] {
        let mut report = original.clone();
        for token in [
            &mut report.direct_input.token,
            &mut report.installed_input.token,
        ] {
            match field {
                "acl" => token.default_acl_sha256[0] ^= 1,
                "expiry" => token.expiration += 1,
                "groups" => token.group_count += 1,
                "privileges" => token.privilege_count += 1,
                "envelope" => token.envelope.session_id += 1,
                _ => unreachable!(),
            }
        }
        assert!(validate(&report, &plan, &expected).is_err(), "{field}");
    }
    let mut report = original;
    report.direct_input.token.token_id += 1;
    report.installed_input.token.modified_id += 1;
    validate(&report, &plan, &expected).unwrap();
}
#[test]
fn records_are_bound_to_actual_plan_identity_inputs_and_recomputed_comparison() {
    let (original, plan, expected) = fixture(false);
    for field in [
        "binding",
        "descriptor",
        "identity",
        "clock",
        "token",
        "beforestart",
        "outcome",
        "environment",
        "cwd",
    ] {
        let mut report = original.clone();
        match field {
            "binding" => report.direct_record.binding.input_sha256[0] ^= 1,
            "descriptor" => report.direct_record.descriptor_sha256[0] ^= 1,
            "identity" => report.installed_record.pid += 1,
            "clock" => report.direct_record.cutoff_qpc += 1,
            "token" => report.direct_record.token_sha256[0] ^= 1,
            "beforestart" => report.direct_record.started_qpc = 1,
            "outcome" => report.comparison.outcome = ReportOutcome::SameObservedFailure,
            "environment" => {
                report.direct_input.environment[0]
                    .value
                    .push(u16::from(b'X'));
                report.installed_input.environment[0]
                    .value
                    .push(u16::from(b'X'));
            }
            "cwd" => {
                report.direct_input.cwd_identity.file_index += 1;
                report.installed_input.cwd_identity.file_index += 1;
            }
            _ => unreachable!(),
        }
        assert!(validate(&report, &plan, &expected).is_err(), "{field}");
    }
}
