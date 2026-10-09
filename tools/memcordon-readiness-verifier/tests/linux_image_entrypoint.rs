#[path = "support/linux_image_entrypoint_case.rs"]
mod linux_image_entrypoint_case;
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
fn image_entrypoint_full_original_build_result_and_native_custody() {
    let mut case = linux_image_entrypoint_case::baseline();
    case.validate().unwrap();
    case.mutate("entrypoint.json", |raw| {
        raw["source"]["host_stat_errno"] = json!(0)
    });
    assert!(case.validate().is_err());
    let mut case = linux_image_entrypoint_case::baseline();
    case.validate().unwrap();
    case.mutate("entrypoint.json", |raw| {
        raw["executable"]["inode"] = json!(0)
    });
    assert!(case.validate().is_err());
}

#[test]
fn image_entrypoint_rehashed_original_admission_and_build_hostiles() {
    let mut case = linux_image_entrypoint_case::baseline();
    case.validate().unwrap();
    case.mutate("entrypoint.json", |raw| {
        raw["target"]["mount"] = raw["source"]["host_mount"].clone()
    });
    assert!(case.validate().is_err());
    let mut case = linux_image_entrypoint_case::baseline();
    case.validate().unwrap();
    case.mutate("created.json", |raw| raw["parent_birth"] = json!(1));
    assert!(case.validate().is_err());
    let mut case = linux_image_entrypoint_case::baseline();
    case.validate().unwrap();
    case.mutate("result.json", |raw| {
        raw["runtime"]["outcome"]["execution"]["native_wait_status"] = json!(256)
    });
    assert!(case.validate().is_err());
}
