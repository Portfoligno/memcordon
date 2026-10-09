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
