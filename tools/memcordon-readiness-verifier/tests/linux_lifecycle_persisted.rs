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

#[test]
fn measured_recovery_joins_the_complete_original_lifecycle_graph() {
    use memcordon_readiness_verifier::original_fixture_recovery_contract as contract;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    let mut case = linux_lifecycle_case::allocation_case("frontend");
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
    let read =
        |leaf: &str| std::fs::read(case.root.path().join(format!("{prefix}/{leaf}"))).unwrap();
    let owner: serde_json::Value = serde_json::from_slice(&read("lifecycle-owner.json")).unwrap();
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
    let context = contract::Context::Lifecycle {
        lease_owner: record("lease_owner", "original-lease-owner.json"),
        prepared: record("prepared", "prepared.json"),
        allocation_journal: record("allocation_journal", "allocation-phase-journal.bin"),
        phase_journal: record("phase_journal", "phase-journal.bin"),
        controller_intent: record("controller_intent", "controller-intent.json"),
        controller_action: record("controller_action", "controller-action.json"),
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
fn persisted_twelve_losses_require_original_phase_transport_and_descendant_custody() {
    for actor in ["frontend", "worker", "guardian", "control"] {
        for phase in ["allocation", "release", "drain"] {
            let mut case = linux_lifecycle_case::loss_case(actor, phase);
            case.validate()
                .unwrap_or_else(|error| panic!("{actor}/{phase} original baseline: {error}"));
            let prefix = "x86_64-unknown-linux-gnu/candidate-native/linux-mixed/recipe-0";
            if actor == "control" {
                let path = format!("{prefix}/controller-action.json");
                case.mutate(&path, |raw| raw["peer_uid"] = json!(0));
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
