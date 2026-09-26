pub use memcordon_ci::{CiError, Result};

#[path = "../src/private_kernel_observer.rs"]
mod private_kernel_observer;
#[path = "../src/private_kernel_replay.rs"]
mod private_kernel_replay;
#[path = "../src/private_probe_bundle.rs"]
mod private_probe_bundle;
#[path = "../src/private_process_clock.rs"]
mod private_process_clock;

use private_process_clock::parse_clock_inputs_for_test;

#[test]
fn proc_reader_clock_inputs_are_exact_and_bounded() {
    let fields = vec!["S"; 20].join(" ");
    let stat = format!("42 (worker with spaces) {fields}");
    // Field 22 is index 19 after the command's closing parenthesis.
    assert!(parse_clock_inputs_for_test(&stat, "time:[88]", "boottime 0 0\n").is_err());
    let mut fields = vec!["S".to_owned(); 20];
    fields[19] = "420".into();
    let stat = format!("42 (worker with spaces) {}", fields.join(" "));
    assert_eq!(
        parse_clock_inputs_for_test(&stat, "time:[88]", "monotonic 0 0\nboottime -2 1\n").unwrap(),
        (420, 88, -1_999_999_999)
    );
    assert!(parse_clock_inputs_for_test(&stat, "time:[88]", "boottime 0 1000000000\n").is_err());
    assert!(
        parse_clock_inputs_for_test(&stat, "time:[88]", "boottime 0 0\nboottime 0 0\n").is_err()
    );
}
