use super::*;

#[test]
fn observation_precedes_callback_settlement_and_preserves_original_status() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let peer_cancelled = cancelled.clone();
    let (progress_sender, progress_receiver) = mpsc::sync_channel(8);
    let peer = thread::spawn(move || {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "early_failure::waiting_peer",
            "--exact",
            "--ignored",
            "--nocapture",
        ]);
        run_with_deadline_controlled_output_limit(
            &mut command,
            Duration::from_secs(10),
            64 * 1024,
            Some(peer_cancelled),
            Some(ProgressOutput {
                sender: progress_sender,
                omitted: Arc::new(AtomicU64::new(0)),
            }),
        )
    });
    let mut progress = Vec::new();
    while !progress
        .windows(b"peer-ready".len())
        .any(|part| part == b"peer-ready")
    {
        progress.extend(
            progress_receiver
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .bytes,
        );
    }
    let (observed_sender, observed_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let owner = thread::spawn(move || {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "early_failure::nonzero_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ]);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        OuterTestBoundary::configure(&mut command).unwrap();
        let started = Instant::now();
        let child = command.spawn().unwrap();
        observe_deadline_child(
            child,
            started,
            started.elapsed(),
            Duration::from_secs(10),
            move |_, _, _| {
                release_receiver
                    .recv_timeout(Duration::from_secs(8))
                    .map_err(io::Error::other)
            },
            Some(64 * 1024),
            ProcessControl {
                cancelled: None,
                progress: None,
                failure: Some(Arc::new(move || {
                    cancelled.store(true, Ordering::Release);
                    let _ = observed_sender.try_send(());
                })),
            },
        )
    });
    observed_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    assert!(
        !owner.is_finished(),
        "failure notification must precede callback settlement"
    );
    let error = peer.join().unwrap().unwrap_err();
    assert!(matches!(
        error,
        ProcessTestError::Cancelled {
            cleanup: Ok(()),
            ..
        }
    ));
    assert!(
        !owner.is_finished(),
        "failing owner remains held after peer retirement"
    );
    release_sender.send(()).unwrap();
    let output = owner.join().unwrap().unwrap();
    assert_eq!(output.status.code(), Some(23));
}

#[test]
#[ignore = "native status fixture"]
fn nonzero_child() {
    std::process::exit(23);
}

#[test]
#[ignore = "native controlled peer fixture"]
fn waiting_peer() {
    use std::io::Write;
    std::io::stdout().write_all(b"peer-ready\n").unwrap();
    std::io::stdout().flush().unwrap();
    thread::sleep(Duration::from_secs(30));
}
