#[path = "../src/bin/consumer_readiness_windows/matched_control_record.rs"]
mod record;
use record::*;

fn observation(lane: Lane, protected: bool) -> Observation {
    let mut ops = vec![
        Operation::CreateNestedDirectory,
        Operation::WriteEmptyFile,
        Operation::WriteAllBytesTemporary,
        Operation::RenameAllBytes,
        Operation::ReadAllBytes,
        Operation::VerifyAllBytes,
        Operation::WriteChallenge,
    ];
    if protected {
        ops.extend([
            Operation::ProtectedWrite {
                role: ProtectedRole::Driver,
            },
            Operation::ProtectedWrite {
                role: ProtectedRole::Provider,
            },
        ]);
    }
    Observation {
        revision: REVISION,
        native_status_domain: NativeStatusDomain::Win32,
        binding: Binding {
            pair_sha256: [1; 32],
            lane,
            scope: if protected {
                Scope::Envelope
            } else {
                Scope::BinaryFiles
            },
            input_sha256: [2; 32],
        },
        descriptor_sha256: if lane == Lane::Direct {
            [3; 32]
        } else {
            [4; 32]
        },
        pid: if lane == Lane::Direct { 10 } else { 11 },
        birth: 20,
        cutoff_qpc: 100,
        qpc_frequency: 1000,
        token_sha256: [5; 32],
        started_qpc: 1,
        finished_qpc: 30,
        operations: ops
            .into_iter()
            .enumerate()
            .map(|(index, op)| OperationRecord {
                ordinal: index as u32 + 1,
                op,
                arguments_sha256: [index as u8; 32],
                before_qpc: index as u64 * 2 + 2,
                after_qpc: index as u64 * 2 + 3,
                outcome: if matches!(op, Operation::ProtectedWrite { .. }) {
                    Outcome::NativeFailure { code: 5 }
                } else {
                    Outcome::Completed {
                        data_sha256: Some([6; 32]),
                    }
                },
            })
            .collect(),
        terminal: Terminal::CompletedScope,
    }
}

fn refuse(value: &mut Observation, index: usize, outcome: Outcome) {
    value.operations.truncate(index + 1);
    value.operations[index].outcome = outcome;
    value.terminal = Terminal::FirstFailure {
        ordinal: index as u32 + 1,
    };
}

fn prefix(lane: Lane, port: u16) -> Observation {
    let mut value = observation(lane, false);
    value.binding.scope = Scope::JointListenerPrefix;
    value.native_status_domain = NativeStatusDomain::PerOperation;
    value.operations.truncate(4);
    for (record, (op, outcome)) in value.operations.iter_mut().zip([
        (
            Operation::WinsockStartup,
            Outcome::Completed { data_sha256: None },
        ),
        (
            Operation::ListenerConstruct,
            Outcome::Completed { data_sha256: None },
        ),
        (
            Operation::ListenerLocalAddress,
            Outcome::LocalEndpoint {
                ipv4: [127, 0, 0, 1],
                port,
            },
        ),
        (
            Operation::CompetingBind,
            Outcome::HeldEndpointRefusal {
                ipv4: [127, 0, 0, 1],
                port,
                code: 10048,
                calls: 1,
            },
        ),
    ]) {
        record.op = op;
        record.outcome = outcome;
    }
    value
}

fn application_failure(code: i32) -> Outcome {
    Outcome::OriginalApplicationIoFailure {
        api: ApplicationIoApi::TcpListenerBind,
        domain: ApplicationIoDomain::RustIoRawOsErrorOnWindows,
        raw_os_error: code,
    }
}

#[test]
fn original_application_refusal_has_distinct_semantics_and_preserves_exact_raw_result() {
    for scope in [Scope::JointListenerPrefix, Scope::ProviderListenerSelection] {
        for code in [0, -1, 5, 10106] {
            let mut direct = prefix(Lane::Direct, 41001);
            let mut installed = prefix(Lane::Installed, 42002);
            direct.binding.scope = scope;
            installed.binding.scope = scope;
            refuse(&mut direct, 1, application_failure(code));
            refuse(&mut installed, 1, application_failure(code));
            let decoded = decode(&encode(&direct).unwrap()).unwrap();
            assert_eq!(decoded.operations[1].outcome, application_failure(code));
            assert_eq!(
                compare(&decoded, &installed, false).unwrap().outcome,
                ComparisonOutcome::SameOriginalApplicationFailure
            );
            installed.operations[1].outcome = application_failure(code.wrapping_add(1));
            assert_eq!(
                compare(&direct, &installed, false).unwrap().outcome,
                ComparisonOutcome::DifferentOutcome
            );
            installed.operations[1].outcome = Outcome::NativeCallFailure {
                boundary: NativeBoundary::WsaSocket,
                domain: NativeStatusDomain::Winsock,
                code: 10106,
                calls: 1,
            };
            assert_eq!(
                compare(&direct, &installed, false).unwrap().outcome,
                ComparisonOutcome::DifferentOutcome
            );
            assert_eq!(
                compare(&direct, &prefix_for_scope(scope, Lane::Installed), false)
                    .unwrap()
                    .outcome,
                ComparisonOutcome::DifferentOutcome
            );
        }
    }
}

fn prefix_for_scope(scope: Scope, lane: Lane) -> Observation {
    let mut value = prefix(lane, 42002);
    value.binding.scope = scope;
    value
}

#[test]
fn application_refusal_rejects_wrong_operation_opaque_binding_clock_and_wire_forgery() {
    let mut direct = prefix(Lane::Direct, 41001);
    let mut installed = prefix(Lane::Installed, 42002);
    refuse(&mut direct, 1, application_failure(10106));
    refuse(&mut installed, 1, application_failure(10106));
    let mutations: &[fn(&mut Observation)] = &[
        |o| o.operations[1].arguments_sha256 = [99; 32],
        |o| o.binding.pair_sha256 = [99; 32],
        |o| o.token_sha256 = [99; 32],
        |o| o.finished_qpc = o.cutoff_qpc,
        |o| {
            o.pid = 10;
            o.birth = 20;
        },
        |o| o.operations[1].outcome = Outcome::NonNativeFailure,
    ];
    for mutate in mutations {
        let mut altered = installed.clone();
        mutate(&mut altered);
        assert!(!matches!(
            compare(&direct, &altered, false),
            Ok(Comparison {
                outcome: ComparisonOutcome::SameOriginalApplicationFailure,
                ..
            })
        ));
    }
    let mut wrong_operation = installed.clone();
    refuse(&mut wrong_operation, 0, application_failure(10106));
    assert!(compare(&direct, &wrong_operation, false).is_err());
    let mut files = observation(Lane::Direct, false);
    refuse(&mut files, 1, application_failure(10106));
    assert!(validate(&files, &files.binding, false).is_err());
    for field in ["api", "domain", "calls", "revision"] {
        let mut wire = serde_json::to_value(&direct).unwrap();
        match field {
            "api" => wire["operations"][1]["outcome"][field] = "tcp-stream-connect".into(),
            "domain" => wire["operations"][1]["outcome"][field] = "winsock".into(),
            "calls" => wire["operations"][1]["outcome"][field] = 1.into(),
            "revision" => wire[field] = (REVISION - 1).into(),
            _ => unreachable!(),
        }
        assert!(
            decode(&serde_json::to_vec(&wire).unwrap()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn listener_prefix_compares_declared_endpoint_roles_without_fabricating_equal_ports() {
    let direct = prefix(Lane::Direct, 41001);
    let installed = prefix(Lane::Installed, 42002);
    let bytes = encode(&installed).unwrap();
    assert_eq!(decode(&bytes).unwrap(), installed);
    let result = compare(&direct, &installed, false).unwrap();
    assert_eq!(result.scope, Scope::JointListenerPrefix);
    assert_eq!(
        result.native_status_domain,
        NativeStatusDomain::PerOperation
    );
    assert_eq!(result.outcome, ComparisonOutcome::ScopeSuccess);
    assert_ne!(
        direct.operations[2].outcome,
        installed.operations[2].outcome
    );
    assert!(compare(&direct, &installed, true).is_err());
}

#[test]
fn provider_root_record_covers_only_the_same_bounded_original_listener_operations() {
    let mut direct = prefix(Lane::Direct, 41001);
    let mut installed = prefix(Lane::Installed, 42002);
    direct.binding.scope = Scope::ProviderListenerSelection;
    installed.binding.scope = Scope::ProviderListenerSelection;
    let compared = compare(&direct, &installed, false).unwrap();
    assert_eq!(compared.scope, Scope::ProviderListenerSelection);
    assert_eq!(compared.outcome, ComparisonOutcome::ScopeSuccess);
    assert_eq!(direct.operations.len(), 4);
    let refused = Outcome::NativeCallFailure {
        boundary: NativeBoundary::WsaSocket,
        domain: NativeStatusDomain::Winsock,
        code: 12345,
        calls: 1,
    };
    refuse(&mut direct, 1, refused.clone());
    refuse(&mut installed, 1, refused);
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::SameObservedFailure
    );
    installed.operations[1].outcome = Outcome::NativeFailure { code: 12345 };
    assert!(compare(&direct, &installed, false).is_err());
}

#[test]
fn precise_refusal_requires_exact_original_stage_boundary_domain_code_and_single_call() {
    for (index, boundary, domain) in [
        (0, NativeBoundary::WsaStartup, NativeStatusDomain::Winsock),
        (1, NativeBoundary::WsaSocket, NativeStatusDomain::Winsock),
        (
            1,
            NativeBoundary::SetHandleInformation,
            NativeStatusDomain::Win32,
        ),
        (1, NativeBoundary::Bind, NativeStatusDomain::Winsock),
        (1, NativeBoundary::Listen, NativeStatusDomain::Winsock),
    ] {
        let mut direct = prefix(Lane::Direct, 41001);
        let mut installed = prefix(Lane::Installed, 42002);
        let failure = Outcome::NativeCallFailure {
            boundary,
            domain,
            code: 12345,
            calls: 1,
        };
        refuse(&mut direct, index, failure.clone());
        refuse(&mut installed, index, failure);
        assert_eq!(
            compare(&direct, &installed, false).unwrap().outcome,
            ComparisonOutcome::SameObservedFailure
        );
        installed.operations[index].outcome = Outcome::NativeCallFailure {
            boundary,
            domain,
            code: 12346,
            calls: 1,
        };
        assert_eq!(
            compare(&direct, &installed, false).unwrap().outcome,
            ComparisonOutcome::DifferentOutcome
        );
        for calls in [0, 2] {
            installed.operations[index].outcome = Outcome::NativeCallFailure {
                boundary,
                domain,
                code: 12345,
                calls,
            };
            assert!(compare(&direct, &installed, false).is_err());
        }
        installed.operations[index].outcome = Outcome::NativeCallFailure {
            boundary,
            domain,
            code: 0,
            calls: 1,
        };
        assert!(compare(&direct, &installed, false).is_err());
        installed.operations[index].outcome = Outcome::NativeCallFailure {
            boundary,
            domain: NativeStatusDomain::PerOperation,
            code: 12345,
            calls: 1,
        };
        assert!(compare(&direct, &installed, false).is_err());
        installed.operations[index].outcome = Outcome::NativeCallFailure {
            boundary,
            domain: if domain == NativeStatusDomain::Winsock {
                NativeStatusDomain::Win32
            } else {
                NativeStatusDomain::Winsock
            },
            code: 12345,
            calls: 1,
        };
        assert!(compare(&direct, &installed, false).is_err());
        assert_eq!(
            compare(&direct, &prefix(Lane::Installed, 42002), false)
                .unwrap()
                .outcome,
            ComparisonOutcome::DifferentOutcome
        );
    }
    let mut direct = prefix(Lane::Direct, 41001);
    let mut installed = prefix(Lane::Installed, 42002);
    refuse(
        &mut direct,
        1,
        Outcome::NativeCallFailure {
            boundary: NativeBoundary::WsaSocket,
            domain: NativeStatusDomain::Winsock,
            code: 12345,
            calls: 1,
        },
    );
    refuse(
        &mut installed,
        1,
        Outcome::NativeCallFailure {
            boundary: NativeBoundary::Bind,
            domain: NativeStatusDomain::Winsock,
            code: 12345,
            calls: 1,
        },
    );
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::DifferentOutcome
    );
    assert_eq!(
        compare(&prefix(Lane::Direct, 41001), &installed, false)
            .unwrap()
            .outcome,
        ComparisonOutcome::DifferentOutcome
    );
}

#[test]
fn listener_prefix_refuses_opaque_stopped_partial_or_wrong_endpoint_history() {
    let direct = prefix(Lane::Direct, 41001);
    for field in [
        "opaque",
        "generic",
        "wrong_boundary",
        "local_failure",
        "endpoint",
        "port",
        "competitor_endpoint",
        "competitor_code",
        "competitor_calls",
        "partial",
        "late",
        "arguments",
        "domain",
    ] {
        let mut installed = prefix(Lane::Installed, 42002);
        match field {
            "opaque" => refuse(&mut installed, 1, Outcome::NonNativeFailure),
            "generic" => refuse(&mut installed, 1, Outcome::NativeFailure { code: 12345 }),
            "wrong_boundary" => refuse(
                &mut installed,
                0,
                Outcome::NativeCallFailure {
                    boundary: NativeBoundary::Bind,
                    domain: NativeStatusDomain::Winsock,
                    code: 12345,
                    calls: 1,
                },
            ),
            "local_failure" => refuse(
                &mut installed,
                2,
                Outcome::NativeCallFailure {
                    boundary: NativeBoundary::Bind,
                    domain: NativeStatusDomain::Winsock,
                    code: 12345,
                    calls: 1,
                },
            ),
            "endpoint" => {
                installed.operations[2].outcome = Outcome::LocalEndpoint {
                    ipv4: [0, 0, 0, 0],
                    port: 42002,
                }
            }
            "port" => {
                installed.operations[2].outcome = Outcome::LocalEndpoint {
                    ipv4: [127, 0, 0, 1],
                    port: 0,
                }
            }
            "competitor_endpoint" => {
                installed.operations[3].outcome = Outcome::HeldEndpointRefusal {
                    ipv4: [127, 0, 0, 1],
                    port: 42003,
                    code: 10048,
                    calls: 1,
                }
            }
            "competitor_code" => {
                installed.operations[3].outcome = Outcome::HeldEndpointRefusal {
                    ipv4: [127, 0, 0, 1],
                    port: 42002,
                    code: 5,
                    calls: 1,
                }
            }
            "competitor_calls" => {
                installed.operations[3].outcome = Outcome::HeldEndpointRefusal {
                    ipv4: [127, 0, 0, 1],
                    port: 42002,
                    code: 10048,
                    calls: 2,
                }
            }
            "partial" => {
                installed.operations.remove(0);
                installed.operations[0].ordinal = 1;
            }
            "late" => installed.finished_qpc = installed.cutoff_qpc,
            "arguments" => installed.operations[0].arguments_sha256[0] ^= 1,
            "domain" => installed.native_status_domain = NativeStatusDomain::Win32,
            _ => unreachable!(),
        }
        if field == "arguments" {
            assert_eq!(
                compare(&direct, &installed, false).unwrap().outcome,
                ComparisonOutcome::DifferentOutcome
            );
        } else {
            assert!(compare(&direct, &installed, false).is_err(), "{field}");
        }
    }
    let mut file = observation(Lane::Direct, false);
    file.native_status_domain = NativeStatusDomain::PerOperation;
    assert!(validate(&file, &file.binding, false).is_err());
    file.native_status_domain = NativeStatusDomain::Win32;
    refuse(
        &mut file,
        0,
        Outcome::NativeCallFailure {
            boundary: NativeBoundary::WsaStartup,
            domain: NativeStatusDomain::Winsock,
            code: 12345,
            calls: 1,
        },
    );
    assert!(validate(&file, &file.binding, false).is_err());
}

#[test]
fn exact_stage1_success_roundtrips_with_explicit_scope_and_status_domain() {
    for protected in [false, true] {
        let direct = observation(Lane::Direct, protected);
        let installed = observation(Lane::Installed, protected);
        let decoded = decode(&encode(&direct).unwrap()).unwrap();
        assert_eq!(decoded, direct);
        validate(&decoded, &direct.binding, protected).unwrap();
        let result = compare(&direct, &installed, protected).unwrap();
        assert_eq!(result.outcome, ComparisonOutcome::ScopeSuccess);
        assert_eq!(result.scope, direct.binding.scope);
        assert_eq!(result.native_status_domain, NativeStatusDomain::Win32);
    }
    let mut direct = observation(Lane::Direct, false);
    let mut installed = observation(Lane::Installed, false);
    direct.binding.scope = Scope::Envelope;
    installed.binding.scope = Scope::Envelope;
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::ScopeSuccess
    );
}

#[test]
fn exact_native_failure_requires_same_stage_status_count_arguments_and_data() {
    let mut direct = observation(Lane::Direct, false);
    let mut installed = observation(Lane::Installed, false);
    refuse(&mut direct, 3, Outcome::NativeFailure { code: 5 });
    refuse(&mut installed, 3, Outcome::NativeFailure { code: 5 });
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::SameObservedFailure
    );
    installed.operations[3].outcome = Outcome::NativeFailure { code: 2 };
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::DifferentOutcome
    );
    installed = observation(Lane::Installed, false);
    refuse(&mut installed, 2, Outcome::NativeFailure { code: 5 });
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::DifferentOutcome
    );
    installed = observation(Lane::Installed, false);
    refuse(&mut installed, 3, Outcome::NativeFailure { code: 5 });
    installed.operations[0].arguments_sha256[0] ^= 1;
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::DifferentOutcome
    );
    installed.operations[0].arguments_sha256 = direct.operations[0].arguments_sha256;
    installed.operations[0].outcome = Outcome::Completed {
        data_sha256: Some([9; 32]),
    };
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::DifferentOutcome
    );
}

#[test]
fn every_equal_stopped_positive_operation_remains_failure_not_coverage() {
    for protected in [false, true] {
        for index in 0..7 {
            let mut direct = observation(Lane::Direct, protected);
            let mut installed = observation(Lane::Installed, protected);
            refuse(&mut direct, index, Outcome::NativeFailure { code: 5 });
            refuse(&mut installed, index, Outcome::NativeFailure { code: 5 });
            let compared = compare(&direct, &installed, protected).unwrap();
            assert_eq!(compared.outcome, ComparisonOutcome::SameObservedFailure);
            assert_eq!(direct.operations.len(), index + 1);
            assert_eq!(
                direct.operations[index].outcome,
                Outcome::NativeFailure { code: 5 }
            );
            direct.terminal = Terminal::CompletedScope;
            installed.terminal = Terminal::CompletedScope;
            assert!(compare(&direct, &installed, protected).is_err());
        }
    }
}

#[test]
fn mixed_inputs_tokens_lanes_clocks_and_reused_process_are_invalid() {
    let direct = observation(Lane::Direct, false);
    for field in [
        "pair",
        "input",
        "token",
        "lane",
        "frequency",
        "cutoff",
        "process",
    ] {
        let mut other = observation(Lane::Installed, false);
        match field {
            "pair" => other.binding.pair_sha256[0] ^= 1,
            "input" => other.binding.input_sha256[0] ^= 1,
            "token" => other.token_sha256[0] ^= 1,
            "lane" => other.binding.lane = Lane::Direct,
            "frequency" => other.qpc_frequency += 1,
            "cutoff" => other.cutoff_qpc += 1,
            "process" => {
                other.pid = direct.pid;
                other.birth = direct.birth;
            }
            _ => unreachable!(),
        }
        assert!(compare(&direct, &other, false).is_err(), "{field}");
    }
    let mut wrong = direct.binding.clone();
    wrong.input_sha256[0] ^= 1;
    assert!(validate(&direct, &wrong, false).is_err());
}

#[test]
fn incomplete_reordered_duplicate_or_postfailure_operations_are_invalid() {
    let valid = observation(Lane::Direct, false);
    for field in [
        "empty",
        "missing",
        "order",
        "duplicate",
        "postfailure",
        "terminal",
        "prematurefailure",
        "extra",
        "missingdata",
    ] {
        let mut value = valid.clone();
        match field {
            "empty" => value.operations.clear(),
            "missing" => {
                value.operations.pop();
            }
            "order" => value.operations.swap(1, 2),
            "duplicate" => value.operations[1].ordinal = 1,
            "postfailure" => value.operations[0].outcome = Outcome::NativeFailure { code: 5 },
            "terminal" => value.terminal = Terminal::FirstFailure { ordinal: 1 },
            "prematurefailure" => {
                refuse(&mut value, 3, Outcome::NativeFailure { code: 5 });
                value.terminal = Terminal::FirstFailure { ordinal: 3 };
            }
            "extra" => value.operations.push(value.operations[6].clone()),
            "missingdata" => value.operations[4].outcome = Outcome::Completed { data_sha256: None },
            _ => unreachable!(),
        }
        assert!(validate(&value, &valid.binding, false).is_err(), "{field}");
    }
}

#[test]
fn protected_envelope_requires_both_exact_roles_and_observed_access_denials() {
    let valid = observation(Lane::Direct, true);
    validate(&valid, &valid.binding, true).unwrap();
    assert!(validate(&valid, &valid.binding, false).is_err());
    for field in ["missing", "duplicate", "wrongerror", "success"] {
        let mut value = valid.clone();
        match field {
            "missing" => {
                value.operations.pop();
            }
            "duplicate" => {
                value.operations[8].op = Operation::ProtectedWrite {
                    role: ProtectedRole::Driver,
                }
            }
            "wrongerror" => value.operations[7].outcome = Outcome::NativeFailure { code: 2 },
            "success" => value.operations[7].outcome = Outcome::Completed { data_sha256: None },
            _ => unreachable!(),
        }
        assert!(validate(&value, &valid.binding, true).is_err(), "{field}");
    }
    let binary = observation(Lane::Direct, false);
    assert!(validate(&binary, &binary.binding, true).is_err());
}

#[test]
fn backwards_late_or_missing_native_clock_and_identity_are_invalid() {
    let valid = observation(Lane::Direct, false);
    for field in [
        "frequency",
        "pid",
        "birth",
        "late",
        "backwards",
        "beforestart",
        "overlap",
        "afterfinish",
    ] {
        let mut value = valid.clone();
        match field {
            "frequency" => value.qpc_frequency = 0,
            "pid" => value.pid = 0,
            "birth" => value.birth = 0,
            "late" => value.finished_qpc = value.cutoff_qpc,
            "backwards" => value.finished_qpc = 0,
            "beforestart" => value.operations[0].before_qpc = 0,
            "overlap" => value.operations[1].before_qpc = value.operations[0].before_qpc,
            "afterfinish" => value.operations[6].after_qpc = value.finished_qpc + 1,
            _ => unreachable!(),
        }
        assert!(validate(&value, &valid.binding, false).is_err(), "{field}");
    }
}

#[test]
fn wire_rejects_unknown_fields_versions_duplicates_bounds_and_partial_capture() {
    let valid = observation(Lane::Direct, false);
    let bytes = encode(&valid).unwrap();
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
    for field in [
        "outer",
        "binding",
        "operation",
        "outcome",
        "terminal",
        "revision",
        "domain",
    ] {
        let mut value = serde_json::to_value(&valid).unwrap();
        match field {
            "outer" => value["extra"] = true.into(),
            "binding" => value["binding"]["extra"] = true.into(),
            "operation" => value["operations"][0]["op"]["extra"] = true.into(),
            "outcome" => value["operations"][0]["outcome"]["extra"] = true.into(),
            "terminal" => value["terminal"]["extra"] = true.into(),
            "revision" => value["revision"] = (REVISION - 1).into(),
            "domain" => value["native_status_domain"] = "Wsa".into(),
            _ => unreachable!(),
        }
        assert!(
            decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut too_many = valid.clone();
    too_many.operations = vec![valid.operations[0].clone(); MAX_OPERATIONS + 1];
    assert!(encode(&too_many).is_err());
    assert!(decode(&serde_json::to_vec(&too_many).unwrap()).is_err());
    let mut duplicate = String::from_utf8(bytes).unwrap();
    duplicate.insert_str(1, "\"revision\":1,");
    assert!(decode(duplicate.as_bytes()).is_err());
}

#[test]
fn semantic_and_unavailable_errors_remain_distinct_from_native_application_status() {
    let mut direct = observation(Lane::Direct, false);
    let mut installed = observation(Lane::Installed, false);
    refuse(
        &mut direct,
        5,
        Outcome::SemanticFailure {
            kind: SemanticFailure::ReadbackMismatch,
        },
    );
    refuse(&mut installed, 5, Outcome::NativeFailure { code: 5 });
    assert_eq!(
        compare(&direct, &installed, false).unwrap().outcome,
        ComparisonOutcome::DifferentOutcome
    );
    installed.operations[5].outcome = Outcome::NonNativeFailure;
    assert!(compare(&direct, &installed, false).is_err());
    direct.operations[5].outcome = Outcome::NonNativeFailure;
    assert!(compare(&direct, &installed, false).is_err());
    for kind in [
        SemanticFailure::ProtectedWriteSucceeded,
        SemanticFailure::ProtectedWriteWrongError,
    ] {
        let mut value = observation(Lane::Direct, true);
        refuse(&mut value, 7, Outcome::SemanticFailure { kind });
        validate(&value, &value.binding, true).unwrap();
    }
    let mut wrong_stage = observation(Lane::Direct, false);
    refuse(
        &mut wrong_stage,
        0,
        Outcome::SemanticFailure {
            kind: SemanticFailure::ReadbackMismatch,
        },
    );
    assert!(validate(&wrong_stage, &wrong_stage.binding, false).is_err());
    let mut direct = observation(Lane::Direct, true);
    let mut installed = observation(Lane::Installed, true);
    refuse(
        &mut direct,
        7,
        Outcome::SemanticFailure {
            kind: SemanticFailure::ProtectedWriteWrongError,
        },
    );
    refuse(
        &mut installed,
        7,
        Outcome::SemanticFailure {
            kind: SemanticFailure::ProtectedWriteWrongError,
        },
    );
    assert!(compare(&direct, &installed, true).is_err());
}
