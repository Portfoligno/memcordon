#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_lifecycle_case.rs"]
mod linux_lifecycle_case;
#[path = "support/linux_prepared_case.rs"]
mod linux_prepared_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;

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
