use memcordon_testkit::{ProcessTestError, run_with_deadline_output_limit};
use std::{
    io::{self, Write},
    process::Command,
    time::{Duration, Instant},
};

#[test]
fn output_cap_preserves_first_bytes_and_settles_without_waiting_for_guard() {
    let started = Instant::now();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["output_limit_child", "--exact", "--ignored", "--nocapture"]);
    let error = run_with_deadline_output_limit(&mut command, Duration::from_secs(30), 128 * 1024)
        .unwrap_err();
    let ProcessTestError::OutputLimit {
        stdout, cleanup, ..
    } = error
    else {
        panic!("expected actual output cap failure");
    };
    let text = String::from_utf8_lossy(&stdout);
    assert!(text.contains("output-limit-sentinel"));
    assert_eq!(stdout.len(), 128 * 1024);
    assert!(cleanup.is_ok());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "output cap waited for whole guard"
    );
}

#[test]
#[ignore = "native argv subprocess helper"]
fn output_limit_child() {
    let mut output = io::stdout().lock();
    output.write_all(b"output-limit-sentinel\n").unwrap();
    output.flush().unwrap();
    let bytes = vec![b'x'; 16 * 1024];
    loop {
        if output.write_all(&bytes).is_err() {
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
    }
}
