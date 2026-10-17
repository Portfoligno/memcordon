use super::*;
use crate::work_outcome::WriterSettlement;

fn child() -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--ignored",
        "--exact",
        "command::native_observation_tests::observed_child",
        "--nocapture",
    ]);
    command
}

#[test]
fn failed_logger_adapter_never_claims_quiescence_after_a_real_child() {
    let result = memcordon_testkit::run_with_deadline(&mut child(), Duration::from_secs(5));
    assert!(result.is_ok());
    let outcome = finish_native_observation(result, false);
    assert_eq!(outcome.writers(), WriterSettlement::Unknown);
    assert!(
        outcome
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("logger panicked")
    );
}

#[test]
fn callback_failure_is_failed_but_actual_capture_settles() {
    let result =
        memcordon_testkit::run_with_deadline_after(&mut child(), Duration::from_secs(5), |_| {
            Err(std::io::Error::other("callback fixture failure"))
        });
    let outcome = finish_native_observation(result, true);
    assert_eq!(outcome.writers(), WriterSettlement::Settled);
    assert!(
        outcome
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("callback fixture failure")
    );
}

#[test]
fn uncertain_reader_adapter_retains_failure_and_blocks_reading() {
    let result = memcordon_testkit::run_with_deadline(&mut child(), Duration::from_secs(5));
    assert!(result.is_ok());
    let outcome = finish_native_observation(
        Err(memcordon_testkit::ProcessTestError::Output(
            std::io::Error::other("reader fixture uncertainty"),
        )),
        true,
    );
    assert_eq!(outcome.writers(), WriterSettlement::Unknown);
    assert!(
        outcome
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("reader fixture uncertainty")
    );
}

#[test]
#[ignore = "native argv child fixture"]
fn observed_child() {}
