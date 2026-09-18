#[allow(dead_code)]
#[path = "../../ci-bounded-command.rs"]
mod bounded;
#[allow(dead_code)]
#[path = "../../ci-inventory-trace.rs"]
mod trace;

use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use trace::Recording;

#[test]
fn formatter_uses_owned_drive_operand_and_rejects_other_spellings() {
    use std::ffi::OsStr;
    let volume = OsStr::new("X:");
    let arguments = trace::formatter_arguments(volume).unwrap();
    let mut command = std::process::Command::new("format.com");
    command.args(&arguments);
    assert_eq!(command.get_args().next(), Some(volume));
    assert_eq!(arguments.len(), 6);
    assert_eq!(
        &arguments[1..],
        &["/FS:NTFS", "/Q", "/Y", "/X", "/V:MemCordonTrace"]
    );
    for mount in [
        r"C:\a\memcordon\target/ci/reports/inventory-observation/v1\owned\mount",
        r"C:\workspace with spaces\target\ci\owned\mount",
        "XX:",
        "X:/",
        "x:",
        "X:\0",
        r"\\?\Volume{126da3c0-ec83-4670-b78c-284a7abc2d22}\",
        r"\\?\Volume{untrusted/ci}\",
    ] {
        assert!(
            trace::formatter_arguments(OsStr::new(mount)).is_err(),
            "{mount}"
        );
    }
}

#[test]
fn formatter_capture_drains_excess_and_retains_failure_provenance() {
    let input = vec![b'x'; 200_000];
    let mut reader = io::Cursor::new(input);
    let stdout = bounded::drain_prefix(&mut reader, 65536);
    assert_eq!(reader.position(), 200_000);
    assert_eq!(stdout.prefix.len(), 65536);
    assert_eq!(stdout.bytes, 200_000);
    assert!(stdout.truncated);
    assert!(stdout.error.is_none());
    let stderr = bounded::drain_prefix(io::Cursor::new(b"format rejected"), 65536);
    let capture = bounded::CapturedCompletion {
        completion: bounded::Completion {
            outcome: bounded::Outcome::ExitFailure,
            elapsed: std::time::Duration::from_millis(42),
            exit_code: Some(7),
            kill_error: None,
            termination_observed: true,
        },
        stdout,
        stderr,
    };
    let directory = tempfile::tempdir().unwrap();
    let record: serde_json::Value = serde_json::from_str(&bounded::retain_capture(
        directory.path(),
        "format",
        &capture,
    ))
    .unwrap();
    assert_eq!(record["completion"]["exit_code"], 7);
    assert_eq!(record["completion"]["outcome"], "ExitFailure");
    assert_eq!(record["completion"]["elapsed_ms"], 42);
    assert_eq!(record["streams"][0]["truncated"], true);
    assert_eq!(
        std::fs::read(directory.path().join("inventory-wpr-format-stderr.log")).unwrap(),
        b"format rejected"
    );
    assert!(
        capture
            .completion
            .result()
            .unwrap_err()
            .to_string()
            .contains("exit_code=Some(7)")
    );
    let repeated: serde_json::Value = serde_json::from_str(&bounded::retain_capture(
        directory.path(),
        "format",
        &capture,
    ))
    .unwrap();
    assert_eq!(
        repeated["streams"][0]["retention_error"]["kind"],
        "AlreadyExists"
    );
    assert_eq!(
        std::fs::read(directory.path().join("inventory-wpr-format-stderr.log")).unwrap(),
        b"format rejected"
    );
}

#[test]
fn formatter_capture_preserves_partial_read_failure_and_os_error() {
    struct Fails(bool);
    impl io::Read for Fails {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fixture read failure",
                ));
            }
            self.0 = true;
            bytes[0] = b'x';
            Ok(1)
        }
    }
    let stream = bounded::drain_prefix(Fails(false), 65536);
    assert_eq!(stream.prefix, b"x");
    assert_eq!(stream.bytes, 1);
    assert!(!stream.truncated);
    assert_eq!(
        stream.error.as_ref().unwrap().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        stream.error.as_ref().unwrap().to_string(),
        "fixture read failure"
    );
    let error: serde_json::Value =
        serde_json::from_str(&bounded::error_json(&io::Error::from_raw_os_error(5))).unwrap();
    assert_eq!(error["os_code"], 5);
}

#[test]
fn recorder_handshake_is_bounded_owned_and_published_complete() {
    let directory = tempfile::tempdir().unwrap();
    let ready = directory.path().join("ready");
    assert!(!trace::ready(&ready, b"owned").unwrap());
    trace::signal(&ready, b"owned").unwrap();
    assert!(trace::ready(&ready, b"owned").unwrap());
    assert!(trace::ready(&ready, b"different").is_err());
    assert!(trace::signal(&ready, b"replacement").is_err());
    let large = directory.path().join("large");
    std::fs::write(&large, vec![b'x'; 1024]).unwrap();
    assert!(trace::ready(&large, b"owned").is_err());
    let unpublished = directory.path().join("unpublished");
    std::fs::write(unpublished.with_extension("pending"), b"own").unwrap();
    assert!(!trace::ready(&unpublished, b"owned").unwrap());
    assert!(trace::signal(&unpublished, b"owned").is_err());
    assert!(!unpublished.exists());
}

struct Recorder {
    calls: Rc<RefCell<Vec<String>>>,
    fail_start: bool,
    fail_finish: bool,
    fail_cancel: bool,
}
impl Recorder {
    fn operation(&self, name: &str, fails: bool) -> io::Result<()> {
        self.calls.borrow_mut().push(name.into());
        if fails {
            Err(io::Error::other(name.to_owned()))
        } else {
            Ok(())
        }
    }
}
impl Recording for Recorder {
    fn start(&mut self) -> io::Result<()> {
        self.operation("start", self.fail_start)
    }
    fn finish(&mut self) -> io::Result<()> {
        self.operation("finish", self.fail_finish)
    }
    fn cancel(&mut self) -> io::Result<()> {
        self.operation("cancel", self.fail_cancel)
    }
    fn observe(&mut self, phase: &str, result: &io::Result<()>) {
        self.calls
            .borrow_mut()
            .push(format!("{phase}:{}", result.is_ok()));
    }
}

#[test]
fn recording_failure_never_repeats_or_replaces_authoritative_workload() {
    for (fail_start, fail_finish, fail_cancel) in [
        (false, false, false),
        (true, false, false),
        (true, false, true),
        (false, true, false),
        (false, true, true),
    ] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut recording = Recorder {
            calls: calls.clone(),
            fail_start,
            fail_finish,
            fail_cancel,
        };
        let result = trace::around(&mut recording, || {
            calls.borrow_mut().push("workload".into());
            Err::<(), _>(io::Error::new(
                io::ErrorKind::TimedOut,
                "original child deadline",
            ))
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let calls = calls.borrow();
        assert_eq!(calls.iter().filter(|name| *name == "workload").count(), 1);
        assert_eq!(
            calls.iter().filter(|name| *name == "finish").count(),
            usize::from(!fail_start)
        );
        assert_eq!(
            calls.iter().filter(|name| *name == "cancel").count(),
            usize::from(fail_start || fail_finish)
        );
        let work = calls.iter().position(|name| name == "workload").unwrap();
        if fail_start {
            assert!(calls.iter().position(|name| name == "cancel").unwrap() < work);
        } else {
            assert!(calls.iter().position(|name| name == "finish").unwrap() > work);
        }
    }
}

#[test]
fn unavailable_diagnostics_preserve_success() {
    let mut recording = Recorder {
        calls: Rc::default(),
        fail_start: true,
        fail_finish: false,
        fail_cancel: true,
    };
    assert_eq!(trace::around(&mut recording, || 42), 42);
}

#[test]
fn export_admission_is_bounded_and_never_clobbers_existing_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.etl");
    let destination = directory.path().join("retained.etl");
    std::fs::write(&source, b"12345").unwrap();
    assert!(trace::copy_bounded(&source, &destination, 4, true).is_err());
    assert!(!destination.exists());
    assert_eq!(
        trace::copy_bounded(&source, &destination, 4, false).unwrap(),
        4
    );
    assert_eq!(std::fs::read(&destination).unwrap(), b"1234");
    assert!(trace::copy_bounded(&source, &destination, 5, true).is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"1234");
    let complete = directory.path().join("complete.etl");
    assert_eq!(trace::copy_bounded(&source, &complete, 5, true).unwrap(), 5);
    std::fs::write(&source, b"").unwrap();
    assert!(trace::copy_bounded(&source, &directory.path().join("empty.etl"), 5, true).is_err());
}

#[test]
fn every_wpr_operation_is_scoped_to_the_owned_instance_without_shell_arguments() {
    use std::ffi::OsStr;
    use trace::WprOperation;
    assert!(WprOperation::Cancel.arguments(OsStr::new("")).is_err());
    let instance = OsStr::new("owned-session-guid");
    let directory = std::path::PathBuf::from("recording path with spaces");
    for operation in [
        WprOperation::Start(directory.clone()),
        WprOperation::Status,
        WprOperation::Stop(directory.clone()),
        WprOperation::Cancel,
    ] {
        let arguments = operation.arguments(instance).unwrap();
        assert_eq!(arguments[arguments.len() - 2], "-instancename");
        assert_eq!(arguments.last().unwrap(), instance);
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| *argument == "-instancename")
                .count(),
            1
        );
    }
    let start = WprOperation::Start(directory.clone())
        .arguments(instance)
        .unwrap();
    assert_eq!(start[1], "ci/inventory.wprp!Inventory.Verbose");
    assert_eq!(start[3], directory.as_os_str());
    assert!(!start.iter().any(|argument| argument == "-filemode"));
}
