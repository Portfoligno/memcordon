#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/pipe_connect_observation.rs"]
mod observation;

use observation::ConnectObservation;

fn value<'a>(summary: &'a str, name: &str) -> &'a str {
    summary
        .split_whitespace()
        .find_map(|field| {
            field
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
        })
        .unwrap()
}

#[test]
fn mixed_connection_results_preserve_absent_busy_and_wait_observations() {
    let mut observed = ConnectObservation::default();
    observed.record_create_failure(Some(2));
    observed.record_create_failure(Some(231));
    observed.record_wait(Err(Some(121)));
    observed.record_create_failure(Some(231));
    observed.record_wait(Ok(()));
    observed.record_create_failure(Some(2));

    let summary = observed.timeout_error();
    assert!(summary.starts_with("timed out waiting for the sealed provider pipe;"));
    assert_eq!(value(&summary, "observed_create_failures"), "4");
    assert_eq!(value(&summary, "file_not_found"), "2");
    assert_eq!(value(&summary, "pipe_busy"), "2");
    assert_eq!(value(&summary, "last_create_error"), "Some(2)");
    assert_eq!(value(&summary, "wait_successes"), "1");
    assert_eq!(value(&summary, "wait_failures"), "1");
    // A successful wait cannot supply a meaningful new last-error value.
    assert_eq!(value(&summary, "last_wait_error"), "Some(121)");
}

#[test]
fn unavailable_native_error_is_not_replaced_by_an_older_failure() {
    let mut observed = ConnectObservation::default();
    observed.record_create_failure(Some(231));
    observed.record_wait(Err(Some(121)));
    observed.record_create_failure(None);
    observed.record_wait(Err(None));
    let summary = observed.timeout_error();
    assert_eq!(value(&summary, "observed_create_failures"), "2");
    assert_eq!(value(&summary, "file_not_found"), "0");
    assert_eq!(value(&summary, "pipe_busy"), "1");
    assert_eq!(value(&summary, "last_create_error"), "None");
    assert_eq!(value(&summary, "wait_failures"), "2");
    assert_eq!(value(&summary, "last_wait_error"), "None");
}

#[test]
fn complete_existing_retry_budget_has_a_fixed_small_failure_summary() {
    let mut observed = ConnectObservation::default();
    for _ in 0..100 {
        observed.record_create_failure(Some(231));
        observed.record_wait(Err(Some(u32::MAX)));
    }
    let summary = observed.timeout_error();
    assert_eq!(value(&summary, "observed_create_failures"), "100");
    assert_eq!(value(&summary, "pipe_busy"), "100");
    assert_eq!(value(&summary, "wait_failures"), "100");
    assert_eq!(value(&summary, "last_wait_error"), "Some(4294967295)");
    assert!(summary.len() < 512);
    assert!(std::mem::size_of::<ConnectObservation>() <= 64);
}
