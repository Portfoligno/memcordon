use super::*;
use std::time::{Duration, Instant};

fn worker_selector() -> &'static str {
    concat!(module_path!(), "::fatal_restoration_policy_worker")
        .split_once("::")
        .expect("guard tests are nested below their embedding crate")
        .1
}

#[test]
fn sacrificial_worker_selector_names_one_registered_test_without_running_it() {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", worker_selector(), "--ignored", "--list"]);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(20),
        8 * 1024,
    )
    .unwrap();
    assert!(output.status.success());
    let listing = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(
        listing
            .lines()
            .filter_map(|line| {
                line.strip_suffix(": test")
                    .or_else(|| line.strip_suffix(": benchmark"))
            })
            .collect::<Vec<_>>(),
        [worker_selector()]
    );
    assert!(!listing.contains("original-gate-failure-before-control "));
}

fn primary() -> OwnedHandle {
    let mut raw = ptr::null_mut();
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | windows_sys::Win32::Security::TOKEN_DUPLICATE,
                &mut raw,
            )
        },
        0
    );
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

#[test]
fn real_installed_guard_restores_original_no_thread_token_during_unwind() {
    no_thread_token()
        .map_err(|_| "guard fixture requires original no-thread-token context")
        .unwrap();
    let source = primary();
    let before =
        memcordon_windows_launch_core::query_token_envelope(source.as_raw_handle()).unwrap();
    let reached = std::cell::Cell::new(false);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = install(source.as_raw_handle())
            .map_err(|_| "same-identity primary installation refused")
            .unwrap();
        reached.set(true);
        assert!(no_thread_token().is_err());
        panic!("bounded installed-control unwind fixture");
    }));
    assert!(unwind.is_err() && reached.get());
    no_thread_token()
        .map_err(|_| "original no-thread-token restoration failed")
        .unwrap();
    assert_eq!(
        memcordon_windows_launch_core::query_token_envelope(source.as_raw_handle()).unwrap(),
        before
    );
}

#[test]
#[ignore = "sacrificial child invoked only by fatal policy parent"]
fn fatal_restoration_policy_worker() {
    use std::io::Write;
    let mut output = std::io::stdout().lock();
    output.write_all(b"\n").unwrap();
    let _permit = super::super::controller_gate_control_publication::publish(
        &std::io::Error::from_raw_os_error(5),
        &json!({"test_role":"fatal-policy-worker"}),
        &mut output,
    )
    .unwrap();
    drop(output);
    let mut guard = Restore {
        armed: true,
        _thread: PhantomData,
    };
    // This tests the source-used fail-closed policy, not a native RevertToSelf failure.
    guard.restored(false);
    panic!("fatal restoration policy unexpectedly returned");
}

#[test]
fn fatal_restoration_policy_exits_only_its_sacrificial_process() {
    let work = Instant::now() + Duration::from_secs(20);
    let cleanup = work + Duration::from_secs(10);
    let selector = worker_selector();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", selector, "--ignored", "--nocapture"]);
    let remaining = work.saturating_duration_since(Instant::now());
    assert!(!remaining.is_zero());
    let output =
        memcordon_testkit::run_with_deadline_output_limit(&mut command, remaining, 8 * 1024)
            .unwrap();
    let record = output
        .stdout
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(b"original-gate-failure-before-control "))
        .expect("actual sacrificial worker must publish original failure before fatal policy");
    let record: Value = serde_json::from_slice(record).unwrap();
    assert_eq!(record["original_raw_os_error"], 5);
    assert_eq!(record["control"], "pending");
    assert_eq!(record["binding"]["test_role"], "fatal-policy-worker");
    assert!(!output.status.success());
    assert_ne!(
        output.status.code(),
        Some(101),
        "test panic is not fatal restoration policy proof"
    );
    assert!(Instant::now() < cleanup);
}
