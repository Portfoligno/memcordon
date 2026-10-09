#[path = "support/linux_image_entrypoint_case.rs"]
mod linux_image_entrypoint_case;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_lifecycle_case.rs"]
mod linux_lifecycle_case;
#[path = "support/linux_positive_case.rs"]
mod linux_positive_case;
#[path = "support/linux_prepared_case.rs"]
mod linux_prepared_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;

#[test]
fn original_separate_positive_admission_route() {
    let case = linux_positive_case::baseline();
    case.validate().unwrap();
}
