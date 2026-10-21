use crate::cancellation::{retirement_deadline, retirement_scope};
use std::time::{Duration, Instant};

#[test]
fn retirement_keeps_original_absolute_cutoff_and_restores_scope() {
    let original = Instant::now() + Duration::from_secs(1);
    assert_eq!(retirement_deadline(), None);
    {
        let _owner = retirement_scope(original);
        assert_eq!(retirement_deadline(), Some(original));
        {
            let _nested = retirement_scope(original + Duration::from_secs(5));
            assert_eq!(
                retirement_deadline(),
                Some(original),
                "nested cleanup cannot renew owner cutoff"
            );
        }
        let child_deadline = original - Duration::from_millis(100);
        {
            let _nested = retirement_scope(child_deadline);
            assert_eq!(retirement_deadline(), Some(child_deadline));
        }
        assert_eq!(retirement_deadline(), Some(original));
    }
    assert_eq!(retirement_deadline(), None);
}

#[cfg(unix)]
#[test]
fn isolated_signal_closes_admission_but_preserves_retirement_and_first_failure() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child.args([
        "cancellation::tests::signal_admission_child",
        "--exact",
        "--ignored",
        "--nocapture",
    ]);
    let output = memcordon_testkit::run_with_deadline(&mut child, Duration::from_secs(5)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
#[ignore = "native signal scenario isolated by the parent test"]
fn signal_admission_child() {
    use crate::{CiError, cancellation::Scope, command::CommandSpec, failure_mode::FailureMode};
    let scope = Scope::install().unwrap();
    let owner_cutoff = Instant::now() + Duration::from_secs(20);
    let expired_work = Instant::now() + Duration::from_millis(50);
    let result = crate::preparation::with_operation(FailureMode::CollectAll, expired_work, || {
        assert!(
            std::process::Command::new("kill")
                .args(["-INT", &std::process::id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let signal_cutoff = Instant::now() + Duration::from_secs(1);
        while crate::cancellation::observed()
            != Some(memcordon_platform::test_support::CiInterrupt::UnixInterrupt)
        {
            assert!(
                Instant::now() < signal_cutoff,
                "real SIGINT was not observed before the signal synchronization cutoff: {:?}",
                crate::cancellation::observed()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        while Instant::now() < expired_work {
            std::thread::sleep(Duration::from_millis(5));
        }
        crate::preparation::active_group()
            .unwrap()
            .requested
            .store(true, std::sync::atomic::Ordering::Release);
        let command = || {
            CommandSpec::new(
                std::env::current_exe().unwrap(),
                &std::env::current_dir().unwrap(),
                Duration::from_secs(2),
            )
            .peer_stop_policy(crate::command::PeerStopPolicy::CancelAndSettle)
            .args([
                "cancellation::tests::retirement_command_child",
                "--exact",
                "--ignored",
            ])
        };
        let refusal = command().output_quiet().unwrap_err();
        assert!(
            refusal.to_string().contains("external interruption"),
            "{refusal}"
        );
        {
            let _retirement = retirement_scope(owner_cutoff);
            assert!(
                command().output_quiet()?.status.success(),
                "expired work cutoff must not erase reserved retirement"
            );
        }
        assert!(command().output_quiet().is_err());
        Err::<(), _>(CiError::Message("original native assertion".into()))
    });
    assert_eq!(
        scope.finish(result).unwrap_err().to_string(),
        "original native assertion"
    );
    assert!(
        scope
            .finish(Ok(()))
            .unwrap_err()
            .to_string()
            .contains("external interruption")
    );
}

#[cfg(unix)]
#[test]
#[ignore = "one real native command admitted only during required retirement"]
fn retirement_command_child() {}
