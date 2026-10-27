use memcordon_ci::{command::CommandSpec, producer_failure_forwarding as forwarding};
use std::io::Write;
use std::time::{Duration, Instant};

fn record() -> Vec<u8> {
    let value = serde_json::json!({
        "format":"memcordon.original-export-producer-failure",
        "revision":1,
        "diagnostic_only":true,
        "original_evidence":"x".repeat(70 * 1024)
    });
    let mut record = forwarding::MARKER.to_vec();
    record.extend(serde_json::to_vec(&value).unwrap());
    record.push(b'\n');
    record
}

#[test]
#[ignore = "finite original-output child selected by the boundary regression"]
fn original_privileged_output_worker() {
    let mut stderr = std::io::stderr().lock();
    stderr.write_all(&vec![b'h'; 80 * 1024]).unwrap();
    stderr.write_all(b"\n").unwrap();
    stderr.write_all(&record()).unwrap();
    stderr.write_all(&record()).unwrap();
    stderr
        .write_all(b"export-original-producer-failure {\n")
        .unwrap();
    stderr.write_all(forwarding::MARKER).unwrap();
    stderr
        .write_all(&vec![b'x'; forwarding::RECORD_BOUND])
        .unwrap();
    stderr.write_all(b"\n").unwrap();
    stderr.write_all(&vec![b't'; 80 * 1024]).unwrap();
    stderr.write_all(b"\n").unwrap();
    stderr.write_all(forwarding::MARKER).unwrap();
    stderr.write_all(b"{").unwrap();
    stderr.flush().unwrap();
    std::process::exit(23);
}

#[test]
fn real_privilege_hop_preserves_exact_record_and_original_native_failure() {
    let directory = tempfile::tempdir().unwrap();
    let work = Instant::now() + Duration::from_secs(20);
    let command = CommandSpec::new(
        std::env::current_exe().unwrap(),
        directory.path(),
        Duration::from_secs(20),
    )
    .args([
        "--exact",
        "original_privileged_output_worker",
        "--ignored",
        "--nocapture",
    ])
    .bounded_until(work);
    let mut intermediate_stderr = Vec::new();
    let failure = command
        .run_with_producer_failure_forwarding(&mut intermediate_stderr)
        .unwrap_err();
    assert!(matches!(
        failure,
        memcordon_ci::CiError::SettledCommandFailure(_)
    ));
    assert!(failure.to_string().contains("23"));
    let expected = record();
    assert!(expected.len() > 64 * 1024);
    assert!(intermediate_stderr.starts_with(&expected));
    let outer = forwarding::inspect(Some(&intermediate_stderr));
    assert_eq!(outer.record, Some(expected.as_slice()));
    assert_eq!(outer.counts.matching_records, 1);
    let summary: serde_json::Value = serde_json::from_slice(
        intermediate_stderr
            .split(|byte| *byte == b'\n')
            .find_map(|line| line.strip_prefix(b"export-producer-forwarding "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(summary["counts"]["matching_records"], 5);
    assert_eq!(summary["counts"]["omitted_valid_records"], 1);
    assert_eq!(summary["counts"]["invalid_records"], 1);
    assert_eq!(summary["counts"]["oversized_records"], 1);
    assert_eq!(summary["counts"]["incomplete_records"], 1);
    assert!(Instant::now() < work);
    // The process observer has already settled/reaped the finite failed child;
    // forwarding is not a second execution or a replacement for native failure.
}

#[test]
fn broken_diagnostic_sink_preserves_the_settled_child_failure() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("record forwarding does not flush the diagnostic sink")
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let failure = CommandSpec::new(
        std::env::current_exe().unwrap(),
        directory.path(),
        Duration::from_secs(20),
    )
    .args([
        "--exact",
        "original_privileged_output_worker",
        "--ignored",
        "--nocapture",
    ])
    .run_with_producer_failure_forwarding(&mut Broken)
    .unwrap_err();
    assert!(matches!(
        failure,
        memcordon_ci::CiError::SettledCommandFailure(_)
    ));
    assert!(failure.to_string().contains("23"));
}
