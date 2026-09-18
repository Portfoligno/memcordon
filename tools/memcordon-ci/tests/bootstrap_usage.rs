#[allow(dead_code)]
#[path = "../../ci-bounded-command.rs"]
mod bounded;

use bounded::usage::{Counters, History, Io, RETAINED, Times};
use bounded::{Clock, Outcome, Process};
use std::cell::Cell;
use std::io;
use std::process::ExitStatus;
use std::rc::Rc;
use std::time::Duration;

fn counters() -> Counters {
    Counters {
        pid: 42,
        times: Ok(Times {
            creation_100ns: u64::MAX,
            kernel_100ns: 11,
            user_100ns: 13,
        }),
        io: Ok(Io {
            read_operations: 17,
            write_operations: 19,
            other_operations: 23,
            read_bytes: u64::MAX,
            write_bytes: 29,
            other_bytes: 31,
        }),
    }
}

#[test]
fn history_preserves_first_sample_and_bounded_tail_at_finished_query_cadence() {
    let mut history = History::default();
    assert!(history.due(Duration::ZERO));
    history.observe(Duration::ZERO, Duration::from_millis(250), Some(counters()));
    assert!(!history.due(Duration::from_millis(1249)));
    assert!(history.due(Duration::from_millis(1250)));
    for second in 2..40 {
        let instant = Duration::from_secs(second);
        history.observe(instant, instant, Some(counters()));
    }
    assert_eq!(history.samples, 39);
    assert_eq!(history.first.as_ref().unwrap().elapsed, Duration::ZERO);
    assert_eq!(history.recent.len(), RETAINED);
    assert_eq!(
        history.recent.front().unwrap().elapsed,
        Duration::from_secs(24)
    );
    assert_eq!(
        history.recent.back().unwrap().elapsed,
        Duration::from_secs(39)
    );
}

#[test]
fn logical_counters_and_independent_errors_are_lossless_and_phase_bound() {
    let mut history = History::default();
    history.observe(Duration::ZERO, Duration::ZERO, Some(counters()));
    let mut failed_times = counters();
    failed_times.times = Err(5);
    history.observe(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Some(failed_times),
    );
    let mut failed_io = counters();
    failed_io.io = Err(87);
    history.observe(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Some(failed_io),
    );
    let directory = tempfile::tempdir().unwrap();
    let mut journal = bounded::Journal::create(directory.path()).unwrap();
    journal.start("prepare \"context\"").unwrap();
    journal
        .process_usage("prepare \"context\"", &history)
        .unwrap();
    let bytes = std::fs::read(journal.directory().join("phase-process-usage.json")).unwrap();
    assert!(bytes.len() < 64 * 1024);
    let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["sequence"], 1);
    assert_eq!(document["phase"], "prepare \"context\"");
    let usage = &document["process_usage"];
    assert_eq!(usage["scope"], "direct_child_process");
    assert_eq!(usage["first"]["pid"], 42);
    assert_eq!(
        usage["first"]["times"]["creation_100ns"].as_u64(),
        Some(u64::MAX)
    );
    assert_eq!(usage["first"]["io"]["read_bytes"].as_u64(), Some(u64::MAX));
    assert_eq!(usage["recent"][1]["times"]["os_error"], 5);
    assert_eq!(usage["recent"][1]["io"]["read_operations"], 17);
    assert_eq!(usage["recent"][2]["io"]["os_error"], 87);
    assert_eq!(usage["recent"][2]["times"]["user_100ns"], 13);
}

struct TestClock {
    now: Rc<Cell<Duration>>,
    ticks: usize,
}
impl Clock for TestClock {
    fn elapsed(&self) -> Duration {
        self.now.get()
    }
    fn tick(&mut self) {
        self.ticks += 1;
        self.now.set(self.now.get() + Duration::from_secs(1));
    }
}
struct Child {
    now: Rc<Cell<Duration>>,
    killed: bool,
    queries: usize,
    query_delay: Duration,
    supported: bool,
}
impl Process for Child {
    fn status(&mut self) -> io::Result<Option<ExitStatus>> {
        Ok(self.killed.then(ExitStatus::default))
    }
    fn terminate(&mut self) -> io::Result<()> {
        self.killed = true;
        Ok(())
    }
    fn usage(&mut self) -> Option<Counters> {
        assert!(!self.killed, "no metric query during termination/reaping");
        self.queries += 1;
        self.now.set(self.now.get() + self.query_delay);
        self.supported.then(counters)
    }
}

#[test]
fn telemetry_does_not_renew_deadline_or_sample_during_termination() {
    for (supported, query_delay, expected_queries, expected_ticks) in [
        (true, Duration::ZERO, 3, 3),
        (false, Duration::ZERO, 1, 3),
        (true, Duration::from_secs(3), 1, 0),
    ] {
        let now = Rc::new(Cell::new(Duration::ZERO));
        let mut clock = TestClock {
            now: now.clone(),
            ticks: 0,
        };
        let mut child = Child {
            now,
            killed: false,
            queries: 0,
            query_delay,
            supported,
        };
        let (completion, history) = bounded::supervise_with_usage(
            &mut child,
            &mut clock,
            Duration::from_secs(3),
            Duration::from_secs(1),
        );
        assert_eq!(completion.outcome, Outcome::Deadline);
        assert!(!completion.admitted());
        assert!(completion.termination_observed);
        assert_eq!(completion.elapsed, Duration::from_secs(3));
        assert_eq!(child.queries, expected_queries);
        assert_eq!(clock.ticks, expected_ticks);
        if !supported {
            let document: serde_json::Value = serde_json::from_str(&history.json()).unwrap();
            assert_eq!(document["unsupported"], true);
            assert_eq!(document["samples"], 0);
            assert!(document["first"].is_null());
        }
    }
}

#[test]
fn optional_usage_write_failure_is_recorded_without_rejecting_timely_child_success() {
    for block_error_record in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = bounded::Journal::create(directory.path()).unwrap();
        std::fs::create_dir(journal.directory().join("phase-process-usage.json")).unwrap();
        let error_path = journal.directory().join("phase-process-usage-error.json");
        if block_error_record {
            std::fs::create_dir(&error_path).unwrap();
        }
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("--list")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let completion = bounded::run(&mut command, "list test names", &mut journal).unwrap();
        assert!(completion.admitted());
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(journal.directory().join("phase-end.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(document["outcome"], "Success");
        assert_eq!(document["cache_eligible"], false);
        if !block_error_record {
            let error: serde_json::Value =
                serde_json::from_slice(&std::fs::read(error_path).unwrap()).unwrap();
            assert_eq!(error["sequence"], document["sequence"]);
            assert_eq!(error["phase"], document["phase"]);
            assert!(!error["process_usage_error"].as_str().unwrap().is_empty());
        }
    }
}
