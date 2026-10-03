use memcordon_ci::{
    CiError,
    performance_plan::Layout,
    preparation::{complete_lanes, remaining},
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[test]
fn both_owners_finish_after_failure_or_panic_in_fixed_result_order() {
    for layout in [Layout::Serial, Layout::Parallel] {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let first = Arc::clone(&observed);
        let second = Arc::clone(&observed);
        let error = complete_lanes(
            layout,
            move || {
                first.lock().unwrap().push("first");
                Err(CiError::Message("first failure".into()))
            },
            move || {
                second.lock().unwrap().push("second");
                Err(CiError::Message("second failure".into()))
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.find("first failure").unwrap() < error.find("second failure").unwrap());
        let mut completed = observed.lock().unwrap().clone();
        completed.sort();
        assert_eq!(completed, ["first", "second"]);
        let done = Arc::new(Mutex::new(false));
        let second = Arc::clone(&done);
        assert!(
            complete_lanes(
                layout,
                || panic!("actual injected owner failure"),
                move || {
                    *second.lock().unwrap() = true;
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(*done.lock().unwrap());
    }
}

#[test]
fn original_group_deadline_caps_each_command_without_renewal() {
    let end = Instant::now() + Duration::from_secs(2);
    assert!(remaining(end, Duration::from_secs(30)).unwrap() <= Duration::from_secs(2));
    assert!(remaining(Instant::now(), Duration::from_secs(30)).is_err());
}
