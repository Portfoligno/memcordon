use super::super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

pub(super) fn launch(mode: &str) -> (FrontendOwner, PathBuf, PathBuf) {
    let directory = Path::new("/tmp").join(format!(
        "memcordon-cleanup-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory).unwrap();
    let marker = directory.join("target-identity.json");
    let report = directory.join("execution.json");
    let test_exe = std::env::current_exe().unwrap();
    let binary = test_exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("memcordon-deadline-oracle");
    assert!(
        binary.exists(),
        "cargo test must build the native oracle binary"
    );
    let child = Command::new(&binary)
        .arg("--session-exec-confirmed")
        .arg(&binary)
        .args(["--native-fixture", mode])
        .arg(&marker)
        .arg(if mode == "children" {
            Path::new("1")
        } else {
            &report
        })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let session_id = i32::try_from(child.id()).unwrap();
    (
        FrontendOwner {
            child,
            session_id,
            session_confirmed: false,
            known: BTreeSet::new(),
            native_observations: BTreeMap::new(),
            reaped: false,
            teardown_done: false,
        },
        marker,
        directory,
    )
}

fn await_marker(owner: &mut FrontendOwner, marker: &Path) {
    owner
        .confirm_session(clock().unwrap() + 2_000_000_000)
        .unwrap();
    let boundary = Instant::now() + Duration::from_secs(2);
    while !marker.exists() && Instant::now() < boundary {
        owner.snapshot().unwrap();
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(marker.exists());
    owner.snapshot().unwrap();
}

#[test]
fn report_read_and_decode_errors_still_retire_live_fixture_identities() {
    for mode in ["missing-report", "malformed-report"] {
        let (mut owner, marker, directory) = launch(mode);
        let mut spec = SCENARIOS[0];
        spec.outer_bound = Duration::from_millis(500);
        let started = clock().unwrap();
        let mut observation = Observation::new(spec);
        let result = run_frontend(
            &mut owner,
            started,
            started + 500_000_000,
            spec,
            &marker,
            &directory.join("execution.json"),
            &mut observation,
        );
        if mode == "missing-report" {
            assert!(result.is_err());
        } else {
            assert!(
                observation
                    .failure_reasons
                    .iter()
                    .any(|failure| failure.kind == "report-invalid")
            );
        }
        assert!(!observation.pre_intervention_retirement_confirmed);
        assert!(owner.teardown().0);
        assert!(owner.reaped);
        for identity in &owner.known {
            assert!(!inventory::same_identity(&NativeProcessApi, *identity).unwrap());
        }
        fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn malformed_marker_and_outer_expiry_use_explicit_bounded_teardown() {
    for malformed in [true, false] {
        let (mut owner, marker, directory) = launch("children");
        await_marker(&mut owner, &marker);
        if malformed {
            fs::write(&marker, b"{broken\n").unwrap();
        } else {
            fs::remove_file(&marker).unwrap();
        }
        let spec = SCENARIOS[0];
        let started = clock().unwrap();
        let mut observation = Observation::new(spec);
        run_frontend(
            &mut owner,
            started,
            started + 50_000_000,
            spec,
            &marker,
            &directory.join("execution.json"),
            &mut observation,
        )
        .unwrap();
        assert!(
            observation
                .failure_reasons
                .iter()
                .any(|failure| failure.kind
                    == if malformed {
                        "marker-malformed"
                    } else {
                        "outer-deadline-expired"
                    })
        );
        assert!(!observation.pre_intervention_retirement_confirmed);
        assert!(owner.teardown().0);
        assert!(owner.reaped);
        fs::remove_dir_all(directory).unwrap();
    }
}

struct InventoryFailure;
impl ProcessApi for InventoryFailure {
    fn all_pids(&self) -> io::Result<Vec<i32>> {
        Err(io::Error::other("injected incomplete inventory"))
    }
    fn session_id(&self, pid: i32) -> io::Result<Option<i32>> {
        NativeProcessApi.session_id(pid)
    }
    fn observation(&self, pid: i32) -> io::Result<Option<inventory::ProcessObservation>> {
        NativeProcessApi.observation(pid)
    }
}

#[test]
fn failed_inventory_teardown_still_signals_known_identities_and_waits_frontend() {
    let (mut owner, marker, directory) = launch("children");
    await_marker(&mut owner, &marker);
    let known = owner.known.clone();
    let (complete, failures) = owner.teardown_with(&InventoryFailure);
    assert!(!complete, "failed native inventory cannot certify teardown");
    assert!(
        failures
            .iter()
            .any(|failure| failure.kind == "teardown-inventory")
    );
    assert!(owner.reaped);
    for identity in known {
        assert!(!inventory::same_identity(&NativeProcessApi, identity).unwrap());
    }
    assert!(owner.teardown().0);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn stopped_frontend_is_resumed_and_waited_during_error_cleanup() {
    let (mut owner, marker, directory) = launch("children");
    await_marker(&mut owner, &marker);
    let frontend = NativeProcessApi
        .observation(owner.session_id)
        .unwrap()
        .unwrap();
    owner.signal(frontend.identity, libc::SIGSTOP).unwrap();
    let boundary = Instant::now() + Duration::from_secs(1);
    while NativeProcessApi
        .observation(owner.session_id)
        .unwrap()
        .unwrap()
        .state
        != libc::SSTOP
        && Instant::now() < boundary
    {
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(owner.teardown().0);
    assert!(owner.reaped);
    fs::remove_dir_all(directory).unwrap();
}
