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
            "revision" => value["revision"] = 2.into(),
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
