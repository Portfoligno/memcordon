#[path = "support/linux_image_entrypoint_case.rs"]
mod linux_image_entrypoint_case;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_lifecycle_case.rs"]
mod linux_lifecycle_case;
#[path = "support/linux_limits_case.rs"]
mod linux_limits_case;
#[path = "support/linux_prepared_case.rs"]
mod linux_prepared_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;

fn mutate_memory_journal(
    case: &mut persisted_case::PersistedCase,
    change: impl FnOnce(&mut serde_json::Value),
) {
    case.mutate("controller.json", |actions| {
        let source = &mut actions[1]["selected_worker_source"];
        let bytes: Vec<u8> = serde_json::from_value(source["journal_bytes"].clone()).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let payload = text
            .lines()
            .find_map(|line| line.strip_prefix("payload="))
            .unwrap();
        let mut journal = serde_json::from_str(payload).unwrap();
        change(&mut journal);
        let rebuilt = linux_prepared_case::durable_journal(&journal);
        source["journal_sha256"] = json!(memcordon_readiness_verifier::sha256(&rebuilt));
        source["journal_bytes"] = json!(rebuilt);
    });
}

#[test]
fn both_memory_families_reject_rehashed_other_execution_barriers() {
    for family in ["C-STATUS", "L-LIFE-03"] {
        for (phase, knowledge) in [
            ("target-gated", "not-released"),
            ("target-gated", "possibly-released"),
            ("release-intent", "possibly-released"),
            ("execution-observed", "not-released"),
            ("execution-observed", "possibly-released"),
            ("retiring", "exec-observed"),
            ("retired", "exec-observed"),
        ] {
            let mut case = linux_limits_case::baseline(family, "memory");
            case.validate().unwrap();
            mutate_memory_journal(&mut case, |journal| {
                journal["phase"] = json!(phase);
                journal["release_knowledge"] = json!(knowledge);
            });
            let error = case.validate().unwrap_err();
            assert!(
                error.contains("selected executing memory family"),
                "{family}/{phase}/{knowledge}: {error}"
            );
        }
    }
}

#[test]
fn both_memory_families_reject_rehashed_original_journal_identity_changes() {
    for family in ["C-STATUS", "L-LIFE-03"] {
        for field in [
            "attempt_id",
            "mixed_admission_metadata",
            "mixed_worker",
            "target",
        ] {
            let mut case = linux_limits_case::baseline(family, "memory");
            case.validate().unwrap();
            mutate_memory_journal(&mut case, |journal| match field {
                "attempt_id" => journal[field] = json!("a".repeat(32)),
                "mixed_admission_metadata" => {
                    journal[field]["request_sha256"] = json!("a".repeat(64))
                }
                _ => journal[field]["start_time"] = json!(999),
            });
            let error = case.validate().unwrap_err();
            assert!(
                !error.contains("checksum") && !error.contains("measurement differs"),
                "{family}/{field} failed only hashing: {error}"
            );
        }
    }
}

#[test]
fn eight_original_limit_and_stream_routes() {
    for (family, scenario) in [
        ("C-STATUS", "deadline"),
        ("C-STATUS", "memory"),
        ("L-LIFE-03", "deadline"),
        ("L-LIFE-03", "memory"),
        ("L-LIFE-03", "cancellation"),
        ("L-LIFE-03", "reserved-target-exit"),
        ("C-IO", "bounded-large-output"),
        ("L-MIX-05", "bounded-large-output"),
    ] {
        let case = linux_limits_case::baseline(family, scenario);
        case.validate()
            .unwrap_or_else(|error| panic!("{family}/{scenario}: {error}"));
    }
}

#[test]
fn original_relay_backpressure_route_and_rehashed_pipe_hostile() {
    let mut case = linux_limits_case::baseline("L-LIFE-05", "relay-backpressure");
    case.validate().unwrap();
    case.mutate("controller.json", |actions| {
        actions[0]["pipes"][0]["source_link"] = json!(b"pipe:[999]")
    });
    assert!(case.validate().is_err());
}

#[test]
fn original_memory_source_and_cancellation_rehashed_hostiles() {
    let mut case = linux_limits_case::baseline("C-STATUS", "memory");
    case.validate().unwrap();
    case.mutate("controller.json", |actions| {
        actions[1]["stopped"]["birth"] = json!(301)
    });
    assert!(case.validate().is_err());
    let mut case = linux_limits_case::baseline("L-LIFE-03", "cancellation");
    case.validate().unwrap();
    case.mutate("controller.json", |actions| {
        actions[0]["held_frontend"]["birth"] = json!(302)
    });
    assert!(case.validate().is_err());
}

#[test]
fn original_deadline_population_rehashed_namespace_and_child_hostiles() {
    let mut case = linux_limits_case::baseline("C-STATUS", "deadline");
    case.validate().unwrap();
    case.mutate("controller.json", |actions| {
        actions[0]["root"]["pid"]["inode"] = json!(999);
        for member in actions[0]["members"].as_array_mut().unwrap() {
            member["native"]["pid"]["inode"] = json!(999);
        }
    });
    assert!(case.validate().is_err());
    let mut case = linux_limits_case::baseline("C-STATUS", "deadline");
    case.validate().unwrap();
    case.mutate("controller.json", |actions| {
        actions[0]["members"][1]["native"]["namespace_pids"][1] = json!(3)
    });
    assert!(case.validate().is_err());
}
