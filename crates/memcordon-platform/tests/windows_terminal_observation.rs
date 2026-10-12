#![cfg(windows)]

#[path = "../src/sealed/windows_terminal_observation.rs"]
mod observation;

use observation::WindowsTerminalObservationScope;

#[test]
fn local_probe_failure_does_not_supply_terminal_or_request_authority() {
    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::retain_probe_failure("OpenProcess(provider): raw-os-error=Some(5)");
    observation::retain_probe_failure("later failure must not replace original");
    let error = scope.finish().unwrap_err();
    assert!(error.contains("unavailable"));
    assert!(error.contains("OpenProcess(provider): raw-os-error=Some(5)"));
    assert!(!error.contains("later failure"));

    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::retain_probe_failure("CreateFileW(control pipe): raw-os-error=Some(5)");
    let error = scope.finish_request().unwrap_err();
    assert!(error.contains("unavailable"));
    assert!(error.contains("CreateFileW(control pipe)"));
}

#[test]
fn local_probe_failure_is_bounded_and_cannot_escape_its_scope() {
    observation::retain_probe_failure("outside explicit observation scope");
    let scope = WindowsTerminalObservationScope::begin().unwrap();
    let error = scope.finish().unwrap_err();
    assert!(!error.contains("probe failure"));

    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::retain_probe_failure(&"界".repeat(4096));
    let error = scope.finish().unwrap_err();
    let detail = error
        .split_once("first local provider probe failure: ")
        .unwrap()
        .1;
    assert!(detail.len() <= 2048);
    assert!(!detail.is_empty());
    assert!(detail.chars().all(|character| character == '界'));

    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::retain_probe_failure("dropped scope failure");
    drop(scope);
    let scope = WindowsTerminalObservationScope::begin().unwrap();
    assert!(!scope.finish().unwrap_err().contains("probe failure"));
}
