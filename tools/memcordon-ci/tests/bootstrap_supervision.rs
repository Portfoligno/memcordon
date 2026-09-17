#[allow(dead_code)]
#[path = "../../ci-bounded-command.rs"]
mod bounded;
use bounded::{Clock, Outcome, Process};
use std::io;
use std::process::ExitStatus;
use std::time::Duration;
struct FakeClock(Duration);
impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        self.0
    }
    fn tick(&mut self) {
        self.0 += Duration::from_secs(1);
    }
}
struct Stuck {
    killed: bool,
    kill_fails: bool,
}
impl Process for Stuck {
    fn status(&mut self) -> io::Result<Option<ExitStatus>> {
        Ok(None)
    }
    fn terminate(&mut self) -> io::Result<()> {
        self.killed = true;
        if self.kill_fails {
            Err(io::Error::other("denied"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn deadline_and_cleanup_are_finite_even_when_termination_is_not_observed() {
    let mut child = Stuck {
        killed: false,
        kill_fails: true,
    };
    let mut clock = FakeClock(Duration::ZERO);
    let result = bounded::supervise(
        &mut child,
        &mut clock,
        Duration::from_secs(3),
        Duration::from_secs(2),
    );
    assert_eq!(result.outcome, Outcome::Deadline);
    assert_eq!(clock.0, Duration::from_secs(5));
    assert!(child.killed);
    assert!(!result.admitted());
    assert!(!result.termination_observed);
    assert_eq!(result.kill_error.as_deref(), Some("denied"));
}
#[test]
fn equality_with_deadline_does_not_admit_late_success() {
    let mut child = Stuck {
        killed: false,
        kill_fails: false,
    };
    let mut clock = FakeClock(Duration::from_secs(3));
    let result = bounded::supervise(
        &mut child,
        &mut clock,
        Duration::from_secs(3),
        Duration::ZERO,
    );
    assert_eq!(result.outcome, Outcome::Deadline);
    assert!(!result.admitted());
}

#[test]
fn successful_status_observed_after_budget_is_rejected() {
    use std::cell::Cell;
    use std::rc::Rc;
    struct SharedClock(Rc<Cell<Duration>>);
    impl Clock for SharedClock {
        fn elapsed(&self) -> Duration {
            self.0.get()
        }
        fn tick(&mut self) {
            self.0.set(self.0.get() + Duration::from_secs(1));
        }
    }
    struct LateSuccess(Rc<Cell<Duration>>);
    impl Process for LateSuccess {
        fn status(&mut self) -> io::Result<Option<ExitStatus>> {
            self.0.set(Duration::from_secs(3));
            Ok(Some(ExitStatus::default()))
        }
        fn terminate(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let shared = Rc::new(Cell::new(Duration::ZERO));
    let result = bounded::supervise(
        &mut LateSuccess(shared.clone()),
        &mut SharedClock(shared),
        Duration::from_secs(3),
        Duration::from_secs(1),
    );
    assert_eq!(result.outcome, Outcome::Deadline);
    assert!(!result.admitted());
}
#[test]
fn failed_spawn_admission_observes_cleanup_or_reports_unknown_with_bound() {
    let mut child = Stuck {
        killed: false,
        kill_fails: true,
    };
    let mut clock = FakeClock(Duration::ZERO);
    let error = bounded::abort_spawn(
        &mut child,
        &mut clock,
        &io::Error::other("job assignment denied"),
    );
    assert!(child.killed);
    assert_eq!(clock.0, bounded::TERMINATION_BUDGET);
    assert!(error.to_string().contains("termination_observed=false"));
    assert!(error.to_string().contains("job assignment denied"));
}
#[test]
fn std_only_digest_matches_independent_sha256_for_padding_boundaries() {
    use sha2::{Digest, Sha256};
    for length in [0, 1, 55, 56, 63, 64, 65, 65535, 65536, 65537] {
        let data = vec![b'x'; length];
        assert_eq!(
            bounded::sha256::digest(&mut data.as_slice()).unwrap(),
            hex::encode(Sha256::digest(&data))
        );
    }
}
#[test]
fn parent_publication_and_content_admission_reject_tampering() {
    let temporary = tempfile::tempdir().unwrap();
    let journal = bounded::Journal::create(temporary.path()).unwrap();
    let candidate = journal.directory().join("candidate");
    let output = temporary.path().join("context.json");
    std::fs::write(&candidate, b"verified context\n").unwrap();
    let mut completion = bounded::Completion {
        outcome: Outcome::Deadline,
        elapsed: Duration::ZERO,
        exit_code: Some(0),
        kill_error: None,
        termination_observed: true,
    };
    assert!(bounded::publish(&candidate, &output, &journal, &completion).is_err());
    assert!(!output.exists());
    completion.outcome = Outcome::Success;
    bounded::publish(&candidate, &output, &journal, &completion).unwrap();
    memcordon_ci::inventory_benchmark::require_admission(&output).unwrap();
    let admission_path = bounded::admission_path(&output);
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&admission_path).unwrap()).unwrap();
    for field in ["run_id", "run_attempt", "job"] {
        let mut changed = original.clone();
        let mut different = original[field].as_str().unwrap().to_owned();
        different.push('\0');
        changed[field] = serde_json::Value::String(different);
        std::fs::write(&admission_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            memcordon_ci::inventory_benchmark::require_admission(&output).is_err(),
            "{field}"
        );
    }
    std::fs::write(&admission_path, serde_json::to_vec(&original).unwrap()).unwrap();
    std::fs::write(&output, b"changed context\n").unwrap();
    assert!(memcordon_ci::inventory_benchmark::require_admission(&output).is_err());
    bounded::revoke(&output).unwrap();
    assert!(!output.exists());
    assert!(!bounded::admission_path(&output).exists());
}
#[test]
fn revoked_previous_pair_cannot_survive_early_journal_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("context.json");
    std::fs::write(&output, b"old").unwrap();
    std::fs::write(bounded::admission_path(&output), b"old admission").unwrap();
    bounded::revoke(&output).unwrap();
    let unavailable = temporary.path().join("not-a-directory");
    std::fs::write(&unavailable, b"file").unwrap();
    assert!(bounded::Journal::create(&unavailable).is_err());
    assert!(!output.exists());
    assert!(!bounded::admission_path(&output).exists());
}
#[test]
fn publication_destination_failures_never_create_eligible_pair() {
    for conflict in ["output", "admission", "provisional"] {
        let temporary = tempfile::tempdir().unwrap();
        let journal = bounded::Journal::create(temporary.path()).unwrap();
        let candidate = journal.directory().join("candidate");
        let output = temporary.path().join("context.json");
        std::fs::write(&candidate, b"context").unwrap();
        let path = match conflict {
            "output" => output.clone(),
            "admission" => bounded::admission_path(&output),
            _ => journal.directory().join("parent-admission.json"),
        };
        std::fs::write(path, b"occupied").unwrap();
        let completion = bounded::Completion {
            outcome: Outcome::Success,
            elapsed: Duration::ZERO,
            exit_code: Some(0),
            kill_error: None,
            termination_observed: true,
        };
        assert!(bounded::publish(&candidate, &output, &journal, &completion).is_err());
        assert!(memcordon_ci::inventory_benchmark::require_admission(&output).is_err());
    }
}
