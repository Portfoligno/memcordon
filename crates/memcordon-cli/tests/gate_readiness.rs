#![cfg(feature = "test-fixtures")]

use std::fs;
use std::io;
use std::process::Command;
use std::time::{Duration, Instant};

use memcordon_testkit::run_with_deadline_after_output_limit;

#[test]
fn gate_publishes_complete_readable_readiness_before_waiting() {
    let directory = tempfile::tempdir().unwrap();
    // Exercise the relative-path consumer as well as repeated concurrent reads.
    for _ in 0..16 {
        let ready = directory.path().join("ready");
        let finish = directory.path().join("finish");
        let observed_ready = ready.clone();
        let observed_finish = finish.clone();
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-test-fixture"));
        command
            .current_dir(directory.path())
            .args(["gate-wait", "ready", "finish"]);
        let output = run_with_deadline_after_output_limit(
            &mut command,
            Duration::from_secs(10),
            64 * 1024,
            move |_| {
                let deadline = Instant::now() + Duration::from_secs(5);
                let result = loop {
                    match fs::read(&observed_ready) {
                        Ok(bytes) if bytes == b"authorized\n" => break Ok(()),
                        Ok(bytes) => {
                            break Err(io::Error::other(format!(
                                "partial readiness marker: {bytes:?}"
                            )));
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => break Err(error),
                    }
                    if Instant::now() >= deadline {
                        break Err(io::Error::new(io::ErrorKind::TimedOut, "readiness"));
                    }
                    std::thread::yield_now();
                };
                fs::write(observed_finish, b"finish\n")?;
                result
            },
        )
        .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(output.stderr.is_empty(), "{:?}", output.stderr);
        assert_eq!(fs::read(&ready).unwrap(), b"authorized\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                fs::metadata(&ready).unwrap().permissions().mode() & 0o044,
                0
            );
        }
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
        fs::remove_file(ready).unwrap();
        fs::remove_file(finish).unwrap();
    }
}
