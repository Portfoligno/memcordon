#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_lifecycle_case.rs"]
mod linux_lifecycle_case;
#[path = "support/linux_prepared_case.rs"]
mod linux_prepared_case;
#[path = "support/original_fixture_recovery_case.rs"]
mod original_fixture_recovery_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;
#[path = "../../../crates/memcordon-cli/src/bin/original_native_recovery_delivery.rs"]
mod native_delivery;

#[test]
fn original_recovery_delivery_contract_remains_the_prepared_admission() {
    let case = linux_lifecycle_case::delivery_case();
    case.validate().unwrap();
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
    let read =
        |name: &str| std::fs::read(case.root.path().join(format!("{prefix}/{name}"))).unwrap();
    let prepared: memcordon_core::mixed_observation::MixedPreparedObservationV2 =
        serde_json::from_slice(&read("prepared.json")).unwrap();
    let contract = read("original-contract.json");
    let source = prepared.provider.source_commit.as_str();
    native_delivery::validate_contract(&contract, &prepared, source).unwrap();
    let command: serde_json::Value =
        serde_json::from_slice(&read("frontend-invocation.json")).unwrap();
    let destination = serde_json::from_slice(&read("report-destination.json")).unwrap();
    let failure = serde_json::from_slice(&read("report-delivery-failure.json")).unwrap();
    native_delivery::validate(
        &command,
        &contract,
        &destination,
        &failure,
        prepared.caller.pid,
        prepared.admission.caller_uid,
    )
    .unwrap();
    assert!(
        native_delivery::validate(
            &command,
            &contract,
            &destination,
            &failure,
            prepared.caller.pid + 1,
            prepared.admission.caller_uid
        )
        .is_err()
    );
    assert!(native_delivery::validate_contract(&contract, &prepared, "different-source").is_err());
    let mut forged = serde_json::to_value(&prepared.admission.request).unwrap();
    forged["expected_epoch"]["revision"] =
        json!(prepared.admission.request.expected_epoch.revision.get() + 1);
    let forged = serde_json::to_vec(&forged).unwrap();
    memcordon_core::workload_contract_v3::WorkloadContractV3::parse(&forged).unwrap();
    assert!(native_delivery::validate_contract(&forged, &prepared, source).is_err());
}

#[test]
fn original_frontend_lifetime_rejects_coherently_rehashed_wrong_or_moved_options() {
    use sha2::{Digest, Sha256};
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
    for phase in ["allocation", "drain", "delivery"] {
        for mutation in ["wrong", "missing", "duplicate", "moved"] {
            let mut case = if phase == "delivery" {
                linux_lifecycle_case::delivery_case()
            } else {
                linux_lifecycle_case::loss_case("frontend", phase)
            };
            case.validate().unwrap();
            let command_path = format!("{prefix}/frontend-invocation.json");
            let mut command: serde_json::Value = serde_json::from_slice(
                &std::fs::read(case.root.path().join(&command_path)).unwrap(),
            )
            .unwrap();
            let mut args: Vec<Vec<u8>> =
                serde_json::from_value(command["arguments"].clone()).unwrap();
            let mode = args.iter().position(|arg| arg == b"--wait-for").unwrap();
            match mutation {
                "wrong" => {
                    args[mode + 1] = if phase == "drain" {
                        b"command".to_vec()
                    } else {
                        b"workload".to_vec()
                    }
                }
                "missing" => {
                    args.drain(mode..mode + ["--wait-for", "command"].len());
                }
                "duplicate" => {
                    let pair = args[mode..mode + ["--wait-for", "command"].len()].to_vec();
                    args.splice(mode..mode, pair);
                }
                "moved" => {
                    let pair: Vec<_> = args
                        .drain(mode..mode + ["--wait-for", "command"].len())
                        .collect();
                    args.extend(pair);
                }
                _ => unreachable!(),
            }
            command["arguments"] = json!(args);
            let bytes = serde_json::to_vec(&command).unwrap();
            let digest = hex::encode(Sha256::digest(&bytes));
            case.write(&command_path, &bytes);
            case.mutate(&format!("{prefix}/frontend-preinput.json"), |raw| {
                raw["invocation_sha256"] = json!(digest)
            });
            case.mutate(&format!("{prefix}/frontend-wait.json"), |raw| {
                raw["invocation_sha256"] = json!(digest)
            });
            case.mutate(&format!("{prefix}/lifecycle-loss-raw.json"), |raw| {
                raw["observations"][0]["frontend_invocation"] = command;
                raw["frontend_wait"]["invocation_sha256"] = json!(digest);
            });
            let error = case.validate().unwrap_err();
            assert!(
                error == "lifecycle actual frontend command/selected image differs"
                    || error == "lifecycle original frontend paths/target arguments differ",
                "{phase}/{mutation} failed outside the exact argv grammar: {error}"
            );
        }
    }
}

#[test]
fn control_shutdown_requires_original_authenticated_two_hop_chain() {
    fn mutate_action(
        case: &mut persisted_case::PersistedCase,
        edit: impl FnOnce(&mut serde_json::Value),
    ) {
        let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
        let action_path = format!("{prefix}/controller-action.json");
        case.mutate(&action_path, edit);
        let action: serde_json::Value =
            serde_json::from_slice(&std::fs::read(case.root.path().join(&action_path)).unwrap())
                .unwrap();
        case.mutate(&format!("{prefix}/lifecycle-loss-raw.json"), |raw| {
            let observation = raw["observations"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|observation| {
                    observation["format"] == "memcordon.linux-lifecycle-intervention"
                })
                .unwrap();
            observation["action"] = action;
        });
    }
    for phase in ["allocation", "release", "drain"] {
        for field in [
            "control",
            "control_status_bytes",
            "control_endpoint",
            "caller_status_bytes",
            "caller_image",
            "worker_image_check",
            "control_image_check",
            "caller_image_check",
            "current_image_check",
        ] {
            let mut case = linux_lifecycle_case::loss_case("control", phase);
            case.validate().unwrap();
            mutate_action(&mut case, |value| value[field] = json!(null));
            assert!(
                case.validate().is_err(),
                "accepted missing {field} at {phase}"
            );
        }
        for (field, replacement) in [
            ("peer_pid", json!(102)),
            ("peer_uid", json!(65534)),
            ("peer_gid", json!(65534)),
            ("peer_gid", json!(0)),
            ("peer_gid", json!(1235)),
            ("revision", json!(1)),
        ] {
            let mut case = linux_lifecycle_case::loss_case("control", phase);
            case.validate().unwrap();
            mutate_action(&mut case, |value| value[field] = replacement);
            assert!(
                case.validate().is_err(),
                "accepted substituted {field} at {phase}"
            );
        }
        for field in ["pid", "birth", "journal_sha256", "native_image"] {
            let mut case = linux_lifecycle_case::loss_case("control", phase);
            case.validate().unwrap();
            mutate_action(&mut case, |value| value["control"][field] = json!(null));
            assert!(
                case.validate().is_err(),
                "accepted substituted control {field} at {phase}"
            );
        }
        let mut case = linux_lifecycle_case::loss_case("control", phase);
        case.validate().unwrap();
        mutate_action(&mut case, |value| {
            value["peer_gid"] = json!(1235);
            value["control_endpoint"]["gid"] = json!(1235);
            value["control_endpoint"]["supplementary_groups"] = json!([1235]);
            value["control_endpoint"]["group_argument"] = json!(b"--groups=1235".as_slice());
            value["control_status_bytes"] =
                json!(b"Uid:\t0\t0\t0\t0\nGid:\t1235\t1235\t1235\t1235\n".as_slice());
        });
        assert!(
            case.validate().is_err(),
            "accepted coherent foreign endpoint group at {phase}"
        );
    }
}

#[test]
fn retiring_witness_rejects_rehashed_original_owner_and_journal_substitution() {
    use sha2::{Digest, Sha256};
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
    for field in [
        "guardian",
        "worker",
        "journal",
        "binding",
        "enrollment_sha256",
        "observation_deadline_monotonic_millis",
        "authorizes_launch",
        "retirement_completed",
    ] {
        let mut case = linux_lifecycle_case::loss_case("guardian", "drain");
        case.validate().unwrap();
        case.mutate(&format!("{prefix}/retirement-prepared.json"), |value| {
            value[field] = json!(null);
        });
        assert!(
            case.validate().is_err(),
            "accepted substituted retiring witness {field}"
        );
    }
    let mut case = linux_lifecycle_case::loss_case("guardian", "drain");
    case.validate().unwrap();
    case.mutate(&format!("{prefix}/controller-intent.json"), |value| {
        value["retirement_barrier"]["journal"]["sha256"] =
            json!(hex::encode(Sha256::digest(b"substituted original journal")));
    });
    assert!(case.validate().is_err());
}

#[test]
fn lifecycle_derived_image_budget_preserves_headroom_and_rejects_rehashed_changes() {
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
    let receipt = format!("{prefix}/fixture-memory-budget.json");
    for field in [
        "headroom_bytes",
        "image_bytes",
        "rounded_image_bytes",
        "limit_bytes",
        "page_bytes",
    ] {
        let mut case = linux_lifecycle_case::allocation_case("frontend");
        case.validate().unwrap();
        case.mutate(&receipt, |value| value["budget"][field] = json!(1));
        assert!(case.validate().is_err(), "accepted altered {field}");
    }
    for field in ["source", "cell", "lease_id", "key"] {
        let mut case = linux_lifecycle_case::allocation_case("frontend");
        case.mutate(&receipt, |value| value[field] = json!("unrelated"));
        assert!(case.validate().is_err(), "accepted altered {field}");
    }
}

#[test]
fn lifecycle_native_memory_limit_and_budget_peer_are_required() {
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
    for field in ["memory_max", "cgroup_inode", "attempt_id", "budget_sha256"] {
        let mut case = linux_lifecycle_case::allocation_case("guardian");
        case.mutate(&format!("{prefix}/fixture-memory-max.json"), |value| {
            value[field] = json!(0)
        });
        assert!(case.validate().is_err(), "accepted altered native {field}");
    }
    let mut case = linux_lifecycle_case::allocation_case("control");
    case.mutate("case-evidence.json", |value| {
        value["artifacts"]
            .as_array_mut()
            .unwrap()
            .retain(|peer| peer["role"] != "fixture-memory-budget.json");
    });
    assert!(case.validate().is_err());
}

#[test]
fn lifecycle_descriptor_cannot_reuse_headroom_as_the_total_limit() {
    let mut case = linux_lifecycle_case::allocation_case("worker");
    case.mutate(
        "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0/fixture-input.json",
        |value| {
            value["memory_bytes"] = json!(512 * 1024 * 1024_u64);
        },
    );
    assert!(case.validate().is_err());
}

#[test]
fn measured_recovery_joins_the_complete_original_lifecycle_graph() {
    use memcordon_readiness_verifier::original_fixture_recovery_contract as contract;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    for delivery in [false, true] {
        let mut case = if delivery {
            linux_lifecycle_case::delivery_case()
        } else {
            linux_lifecycle_case::allocation_case("frontend")
        };
        let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
        let read =
            |leaf: &str| std::fs::read(case.root.path().join(format!("{prefix}/{leaf}"))).unwrap();
        let owner: serde_json::Value =
            serde_json::from_slice(&read("lifecycle-owner.json")).unwrap();
        let lease: serde_json::Value =
            serde_json::from_slice(&read("original-lease-owner.json")).unwrap();
        let old: serde_json::Value =
            serde_json::from_slice(&read("native-recovery-invocation.json")).unwrap();
        let cwd: Vec<u8> = serde_json::from_value(old["cwd_native_bytes"].clone()).unwrap();
        let root = String::from_utf8(cwd).unwrap();
        let admin = lease["admin_root"].as_str().unwrap();
        let mut originals = BTreeMap::new();
        let mut record = |role: &str, leaf: &str| {
            let bytes = read(leaf);
            originals.insert(
                role.into(),
                if role == "lease_owner" {
                    format!("{root}/lease-owner.json")
                } else {
                    format!("{root}/{leaf}")
                },
            );
            contract::Record {
                path: format!("{admin}/recovery-stage/input-{role}.bin").into(),
                length: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
            }
        };
        let context = if delivery {
            contract::Context::Delivery {
                lease_owner: record("lease_owner", "original-lease-owner.json"),
                prepared: record("prepared", "prepared.json"),
                allocation_journal: record("allocation_journal", "allocation-phase-journal.bin"),
                frontend_invocation: record("frontend_invocation", "frontend-invocation.json"),
                original_contract: record("original_contract", "original-contract.json"),
                report_destination: record("report_destination", "report-destination.json"),
                report_delivery_failure: record(
                    "report_delivery_failure",
                    "report-delivery-failure.json",
                ),
            }
        } else {
            contract::Context::Lifecycle {
                lease_owner: record("lease_owner", "original-lease-owner.json"),
                prepared: record("prepared", "prepared.json"),
                allocation_journal: record("allocation_journal", "allocation-phase-journal.bin"),
                phase_journal: record("phase_journal", "phase-journal.bin"),
                controller_intent: record("controller_intent", "controller-intent.json"),
                controller_action: record("controller_action", "controller-action.json"),
            }
        };
        let family = original_fixture_recovery_case::Family {
            identity: owner["identity"].clone(),
            cell: owner["cell"].clone(),
            scope: owner["lease_id"].as_str().unwrap().into(),
            work: owner["work_deadline_unix_millis"].as_u64().unwrap(),
            cleanup: owner["cleanup_deadline_unix_millis"].as_u64().unwrap(),
            admin: admin.into(),
            original_root: root,
            context,
            originals,
        };
        let (mut invocation, process, _, records) =
            original_fixture_recovery_case::family(family.clone());
        let mut references = serde_json::Map::new();
        for (leaf, bytes) in records {
            let path = format!("recovery-acquisition/{leaf}");
            case.write(&path, &bytes);
            references.insert(leaf, json!(path));
        }
        invocation["original_fixture"]["acquisition_artifacts"] = references.into();
        case.json(
            &format!("{prefix}/native-recovery-invocation.json"),
            &invocation,
        );
        case.json(&format!("{prefix}/native-recovery-process.json"), &process);
        case.write(&format!("{prefix}/native-recovery-stdout.bin"), b"");
        case.write(&format!("{prefix}/native-recovery-stderr.bin"), b"");
        case.validate().unwrap();
        if delivery {
            for role in ["frontend_invocation", "original_contract"] {
                let mut forged = family.clone();
                let (_, record) = forged
                    .context
                    .records_mut()
                    .into_iter()
                    .find(|(name, _)| *name == role)
                    .unwrap();
                record.sha256 = hex::encode(Sha256::digest(b"different retained original bytes"));
                let (mut replacement, process, _, records) =
                    original_fixture_recovery_case::family(forged);
                replacement["original_fixture"]["acquisition_artifacts"] =
                    invocation["original_fixture"]["acquisition_artifacts"].clone();
                for (leaf, bytes) in records {
                    case.write(&format!("recovery-acquisition/{leaf}"), &bytes);
                }
                case.json(
                    &format!("{prefix}/native-recovery-invocation.json"),
                    &replacement,
                );
                case.json(&format!("{prefix}/native-recovery-process.json"), &process);
                assert_eq!(
                    case.validate().unwrap_err(),
                    "lifecycle fixture recovery original intervention differs",
                    "accepted coherently rehashed foreign {role}"
                );
            }
        }
        let (mut unrelated, process, _, records) =
            original_fixture_recovery_case::family(original_fixture_recovery_case::Family {
                scope: "unrelated-original-lease".into(),
                ..family
            });
        unrelated["original_fixture"]["acquisition_artifacts"] =
            invocation["original_fixture"]["acquisition_artifacts"].clone();
        for (leaf, bytes) in records {
            case.write(&format!("recovery-acquisition/{leaf}"), &bytes);
        }
        case.json(
            &format!("{prefix}/native-recovery-invocation.json"),
            &unrelated,
        );
        case.json(&format!("{prefix}/native-recovery-process.json"), &process);
        assert_eq!(
            case.validate().unwrap_err(),
            "lifecycle fixture recovery crosses original source/lifetime"
        );
    }
}

#[test]
fn original_frontend_scope_rejects_rehashed_alias_and_sibling_paths() {
    for mutation in ["windows-separators", "sibling", "parent-traversal"] {
        let mut case = linux_lifecycle_case::allocation_case("frontend");
        case.validate().unwrap();
        let path = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0/frontend-invocation.json";
        case.mutate(path, |raw| {
            let mut arguments: Vec<Vec<u8>> =
                serde_json::from_value(raw["arguments"].clone()).unwrap();
            for index in [11, 15, 17] {
                let original = std::str::from_utf8(&arguments[index]).unwrap();
                let changed = match mutation {
                    "windows-separators" => original.replace("/recipe-0/", "/recipe-0\\"),
                    "sibling" => original.replace("/recipe-0/", "/recipe-0-sibling/"),
                    "parent-traversal" => original.replace("/recipe-0/", "/recipe-0/../recipe-0/"),
                    _ => unreachable!(),
                };
                arguments[index] = changed.into_bytes();
            }
            raw["arguments"] = json!(arguments);
        });
        let command: serde_json::Value =
            serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap()).unwrap();
        case.mutate("x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0/lifecycle-loss-raw.json", |raw| {
            raw["observations"][0]["frontend_invocation"] = command;
        });
        assert_eq!(
            case.validate().unwrap_err(),
            "lifecycle frontend observation/contract scope crosses original result directory",
            "{mutation} escaped original Linux frontend scope"
        );
    }
}

#[test]
fn persisted_report_delivery_keeps_completed_provider_terminal_separate_from_native_write_failure()
{
    let mut case = linux_lifecycle_case::delivery_case();
    case.validate().unwrap();
    let path = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0/report-delivery-failure.json";
    let original = std::fs::read(case.root.path().join(path)).unwrap();
    case.mutate(path, |raw| raw["native_errno"] = json!(13));
    assert!(
        case.validate().is_err(),
        "accepted unrelated native report failure instead of actual EISDIR"
    );
    case.write(path, &original);
    case.validate().unwrap();
    case.mutate(path, |raw| raw["destination"]["inode"] = json!(801));
    assert!(
        case.validate().is_err(),
        "accepted report destination replacement across actual failed write"
    );
    case.write(path, &original);
    case.mutate(path, |raw| {
        let bytes: Vec<u8> = serde_json::from_value(raw["submitted_report"].clone()).unwrap();
        let mut result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        result["wrapper_status"] = json!(125);
        raw["submitted_report"] = json!(serde_json::to_vec(&result).unwrap());
    });
    assert!(
        case.validate().is_err(),
        "accepted rewriting original completed provider status to local frontend failure"
    );
}

#[test]
fn prepared_lifecycle_rejects_obsolete_checkpoint_claims() {
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
    for phase in ["allocation", "release"] {
        let mut case = linux_lifecycle_case::loss_case("frontend", phase);
        case.validate().unwrap();
        case.mutate(&format!("{prefix}/lifecycle-loss-raw.json"), |raw| {
            raw["observations"][0]["phase"] = json!("checkpoint-committed");
            raw["observations"][0]["release_knowledge"] = json!("not-released");
        });
        assert!(
            case.validate().is_err(),
            "accepted obsolete {phase} checkpoint tuple"
        );
    }
}

#[test]
fn persisted_twelve_losses_require_original_phase_transport_and_descendant_custody() {
    for actor in ["frontend", "worker", "guardian", "control"] {
        for phase in ["allocation", "release", "drain"] {
            let mut case = linux_lifecycle_case::loss_case(actor, phase);
            case.validate()
                .unwrap_or_else(|error| panic!("{actor}/{phase} original baseline: {error}"));
            let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
            if actor == "control" {
                let path = format!("{prefix}/controller-action.json");
                case.mutate(&path, |raw| raw["peer_uid"] = json!(65534));
                let action: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap())
                        .unwrap();
                case.mutate(&format!("{prefix}/lifecycle-loss-raw.json"), |raw| {
                    raw["observations"][1]["action"] = action
                });
                assert!(
                    case.validate().is_err(),
                    "{phase} accepted unrelated control peer credential"
                );
            } else if phase == "drain" {
                case.mutate(&format!("{prefix}/native-family-retirement.json"), |raw| {
                    raw["descendants"][0]["identity"]["parent_pid"] = json!(999)
                });
                assert!(
                    case.validate().is_err(),
                    "{actor} accepted unrelated drain descendant ancestry"
                );
            } else if phase == "release" {
                let path = format!("{prefix}/release-prepared.json");
                case.mutate(&path, |raw| raw["authorizes_launch"] = json!(true));
                let barrier: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap())
                        .unwrap();
                case.mutate(&format!("{prefix}/controller-intent.json"), |raw| {
                    raw["release_barrier"] = barrier.clone()
                });
                case.mutate(&format!("{prefix}/lifecycle-loss-raw.json"), |raw| {
                    raw["observations"][1]["intent"]["release_barrier"] = barrier
                });
                assert!(
                    case.validate().is_err(),
                    "{actor} accepted authorizing final release observation"
                );
            }
        }
    }
}

#[test]
fn persisted_allocation_loss_requires_original_native_exit_and_family() {
    for actor in ["frontend", "worker", "guardian"] {
        let mut case = linux_lifecycle_case::allocation_case(actor);
        case.validate()
            .unwrap_or_else(|error| panic!("{actor} original allocation baseline: {error}"));
        let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
        let path = format!("{prefix}/native-family-retirement.json");
        case.mutate(&path, |raw| raw["namespace_init"]["birth"] = json!(999));
        assert!(
            case.validate().is_err(),
            "{actor} accepted unrelated retired namespace init"
        );
    }
}

#[test]
fn persisted_worker_loss_rejects_rehashed_shell_exit_and_renewed_cutoffs() {
    let mut case = linux_lifecycle_case::allocation_case("worker");
    case.validate().unwrap();
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
    let wait = format!("{prefix}/frontend-wait.json");
    let raw = format!("{prefix}/lifecycle-loss-raw.json");
    let original = std::fs::read(case.root.path().join(&wait)).unwrap();
    case.mutate(&wait, |value| {
        value["raw_wait_status"] = json!(137 * 256);
        value["native_exit"] = json!(137);
    });
    let changed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(case.root.path().join(&wait)).unwrap()).unwrap();
    case.mutate(&raw, |value| value["frontend_wait"] = changed);
    assert!(
        case.validate().is_err(),
        "accepted shell137 for genuine missing-report infrastructure failure"
    );
    case.write(&wait, &original);
    let restored: serde_json::Value = serde_json::from_slice(&original).unwrap();
    case.mutate(&raw, |value| value["frontend_wait"] = restored);
    case.validate().unwrap();
    let invocation = format!("{prefix}/native-recovery-invocation.json");
    case.mutate(&invocation, |value| {
        value["cleanup_deadline_unix_millis"] = json!(201)
    });
    let updated = memcordon_readiness_verifier::sha256(
        &std::fs::read(case.root.path().join(invocation)).unwrap(),
    );
    case.mutate(&format!("{prefix}/native-recovery-process.json"), |value| {
        value["invocation_sha256"] = json!(updated)
    });
    assert!(
        case.validate().is_err(),
        "accepted renewed original cleanup cutoff"
    );
}
