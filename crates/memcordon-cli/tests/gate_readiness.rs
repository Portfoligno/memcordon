#![cfg(feature = "test-fixtures")]

use std::fs;
use std::io::{self, Read};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use memcordon_testkit::run_with_deadline_after_output_limit;

const GATE_PREFIX_BYTES: usize = 1024;

fn gate_observation(path: &std::path::Path, elapsed: Duration) -> io::Result<serde_json::Value> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(
                serde_json::json!({"state":"absent", "phase":"before-finish", "clock-domain":"harness-monotonic", "elapsed-ms":elapsed.as_millis(), "errno":error.raw_os_error()}),
            );
        }
        Err(error) => return Err(error),
    };
    let byte_count = file.metadata()?.len();
    let mut prefix = Vec::new();
    file.by_ref()
        .take(GATE_PREFIX_BYTES as u64)
        .read_to_end(&mut prefix)?;
    let truncated = byte_count > prefix.len() as u64;
    Ok(
        serde_json::json!({"state":"observed", "phase":"before-finish", "clock-domain":"harness-monotonic", "elapsed-ms":elapsed.as_millis(), "byte-count":byte_count, "prefix":prefix, "truncated":truncated}),
    )
}

#[test]
fn gate_publishes_complete_readable_readiness_before_waiting() {
    let directory = tempfile::tempdir().unwrap();
    // Exercise the relative-path consumer as well as repeated concurrent reads.
    for _ in 0..16 {
        let ready = directory.path().join("ready");
        let finish = directory.path().join("finish");
        let observed_ready = ready.clone();
        let observed_finish = finish.clone();
        let failure_observation = Arc::new(Mutex::new(None));
        let retained = failure_observation.clone();
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-test-fixture"));
        command
            .current_dir(directory.path())
            .args(["gate-wait", "ready", "finish"]);
        let outcome = run_with_deadline_after_output_limit(
            &mut command,
            Duration::from_secs(10),
            64 * 1024,
            move |_| {
                let started = Instant::now();
                let deadline = Instant::now() + Duration::from_secs(5);
                let result = loop {
                    match gate_observation(&observed_ready, started.elapsed()) {
                        Ok(observation) if observation["state"] == "absent" => {
                            *retained.lock().unwrap() = Some(observation);
                        }
                        Ok(observation)
                            if observation["prefix"]
                                == serde_json::json!(b"authorized\n".to_vec())
                                && observation["truncated"] == false =>
                        {
                            break Ok(());
                        }
                        Ok(observation) => {
                            *retained.lock().unwrap() = Some(observation.clone());
                            break Err(io::Error::other(format!(
                                "partial readiness marker: {observation}"
                            )));
                        }
                        Err(error) => {
                            *retained.lock().unwrap() = Some(
                                serde_json::json!({"state":"unavailable", "phase":"before-finish", "reason":error.to_string(), "errno":error.raw_os_error()}),
                            );
                            break Err(error);
                        }
                    }
                    if Instant::now() >= deadline {
                        break Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "readiness absent before finish",
                        ));
                    }
                    std::thread::yield_now();
                };
                fs::write(observed_finish, b"finish\n")?;
                result
            },
        );
        // The owner settles the child before diagnostic file I/O can run.
        if let Err(error) = &outcome {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/ci/deadline-evidence/gate-readiness.json");
            let retained = failure_observation.lock().unwrap();
            let error = error.to_string();
            let error_bytes = error.as_bytes();
            let prefix = &error_bytes[..error_bytes.len().min(64 * 1024)];
            let value = serde_json::json!({"phase":"gate-readiness", "observation":*retained, "result":String::from_utf8_lossy(prefix), "result-truncated":prefix.len() != error_bytes.len()});
            let write = || -> io::Result<()> {
                fs::create_dir_all(path.parent().unwrap())?;
                let mut bytes = serde_json::to_vec_pretty(&value).map_err(io::Error::other)?;
                bytes.push(b'\n');
                fs::write(&path, bytes)
            };
            if let Err(secondary) = write() {
                eprintln!("gate diagnostic retention incomplete: {secondary}");
            }
        }
        let output = outcome.unwrap();
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

#[test]
fn gate_failure_observations_preserve_absence_and_bounded_actual_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("marker");
    let absent = gate_observation(&path, Duration::from_millis(1)).unwrap();
    assert_eq!(absent["state"], "absent");
    assert!(absent.get("prefix").is_none());
    let bytes = vec![b'x'; GATE_PREFIX_BYTES + 37];
    fs::write(&path, &bytes).unwrap();
    let malformed = gate_observation(&path, Duration::from_millis(2)).unwrap();
    assert_eq!(malformed["byte-count"], bytes.len());
    assert_eq!(
        malformed["prefix"].as_array().unwrap().len(),
        GATE_PREFIX_BYTES
    );
    assert_eq!(malformed["truncated"], true);
    assert_eq!(malformed["phase"], "before-finish");
    assert_eq!(
        malformed["prefix"],
        serde_json::json!(bytes[..GATE_PREFIX_BYTES])
    );
}
