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
    let root = std::env::temp_dir().join("memcordon-matched-report-model");
    let scope = if protected {
        record::Scope::Envelope
    } else {
        record::Scope::BinaryFiles
    };
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
        "case":if protected {descriptor::Case::Envelope}else{descriptor::Case::BinaryFiles},
        "output_root":root.join("installed"),"transcript":root.join("installed/fixture-events.bin"),
        "challenge":[0,255,1],"stdout_base64":"","stderr_base64":"","arguments":[],"application_status":0,
        "churn_creations":descriptor::CHURN_CREATIONS,"churn_live":descriptor::CHURN_LIVE,
        "denied_write_paths":denied,"sentinel_handles":[],"descendant_gate":null,"start_gate":"Local\\report-model",
        "start_transport":{"transport":"controller-stdin","version":descriptor::controller_start::VERSION},
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
                file_index: 10,
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
        let observation = record::Observation {
            revision: 1,
            native_status_domain: record::NativeStatusDomain::Win32,
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
                    outcome: if matches!(op, record::Operation::ProtectedWrite { .. }) {
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
        revision: 1,
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
            native_status_domain: record::NativeStatusDomain::Win32,
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
