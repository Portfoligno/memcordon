#[path = "../src/release/native_execution_association.rs"]
mod native_execution_association;

use native_execution_association::{Allocation, matches};

#[test]
fn execution_verifies_scoped_allocation_without_changing_component_recipe() {
    let component_recipe = "original-native-components-v1";
    let scoped_recipe = format!("{component_recipe}:native-linux-x64:2");
    let expected = Allocation {
        run_id: "run-42",
        recipe_id: &scoped_recipe,
        target: "x86_64-unknown-linux-gnu",
        artifact_prefix: "target/candidate-native/components",
        work_deadline: 100,
        cleanup_deadline: 900_100,
    };
    let intent = serde_json::json!({
        "identity":{"run_id":expected.run_id}, "recipe_id":scoped_recipe,
        "target":expected.target, "artifact_prefix":expected.artifact_prefix,
        "work_deadline_unix_millis":expected.work_deadline,
        "cleanup_deadline_unix_millis":expected.cleanup_deadline
    });
    assert!(matches(&intent, &expected));
    for recipe in [
        component_recipe,
        "original-native-components-v1:native-linux-x64:1",
        "original-native-components-v1:native-linux-arm64:2",
    ] {
        let mut wrong = intent.clone();
        wrong["recipe_id"] = recipe.into();
        assert!(!matches(&wrong, &expected));
    }
    for (field, value) in [
        ("target", serde_json::json!("aarch64-unknown-linux-gnu")),
        ("artifact_prefix", serde_json::json!("other/components")),
        ("work_deadline_unix_millis", serde_json::json!(101)),
        ("cleanup_deadline_unix_millis", serde_json::json!(900_101)),
    ] {
        let mut wrong = intent.clone();
        wrong[field] = value;
        assert!(!matches(&wrong, &expected));
    }
    let mut wrong = intent.clone();
    wrong["identity"]["run_id"] = "another-run".into();
    assert!(!matches(&wrong, &expected));
    let invalid = Allocation {
        cleanup_deadline: 100,
        ..expected
    };
    let mut wrong = intent;
    wrong["cleanup_deadline_unix_millis"] = 100.into();
    assert!(!matches(&wrong, &invalid));
}
