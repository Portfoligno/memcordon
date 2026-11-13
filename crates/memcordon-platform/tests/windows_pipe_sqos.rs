#![cfg(all(windows, feature = "test-support"))]

#[path = "../src/sealed/windows_client_input_observation.rs"]
pub mod client_input;
#[path = "../src/sealed/windows_client_input_observation_native.rs"]
mod client_input_native;
#[path = "../src/sealed/windows_control_pipe_flags.rs"]
mod current_control_pipe;
#[path = "private/windows_pipe_sqos_native.rs"]
mod native;
#[path = "private/windows_pipe_sqos_record.rs"]
pub mod record;

#[test]
fn owned_pipe_sqos_rows_measure_authenticated_inventory_without_policy_changes() {
    // Exercise the actual production policy through both measured native
    // dynamic-full cases below. Baseline 0x80 remains a historical control,
    // along with static/effective alternatives; it is not current policy.
    assert_eq!(current_control_pipe::FLAGS, 0x0016_0080);
    assert_eq!(
        current_control_pipe::FLAGS,
        record::Case::DynamicFull.flags()
    );
    assert_eq!(
        current_control_pipe::FLAGS,
        record::TrackingCase::DynamicFull.flags()
    );
    for historical in [
        record::Case::Baseline,
        record::Case::StaticFull,
        record::Case::StaticEffective,
        record::Case::DynamicEffective,
    ] {
        assert_ne!(current_control_pipe::FLAGS, historical.flags());
    }
    native::run().expect("owned native SQOS fixture and cleanup");
}
