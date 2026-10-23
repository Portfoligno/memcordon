use super::*;
use crate::command::CommandSpec;
use std::time::{Duration, Instant};

#[test]
fn duplicated_original_pidfd_retains_identity_and_refuses_action_after_exit() {
    let cutoff = Instant::now() + Duration::from_secs(15);
    let mut retained = None;
    let mut before = None;
    let result = CommandSpec::new(
        "/bin/sleep",
        std::path::Path::new("/"),
        Duration::from_secs(5),
    )
    .args(["30"])
    .bounded_until(cutoff)
    .output_quiet_with_exec_observation(|child| {
        let birth = process_birth(child.id()).map_err(crate::CiError::Message)?;
        let original =
            HeldLinuxProcess::acquire(child.id(), birth).map_err(crate::CiError::Message)?;
        let mut duplicate = original
            .duplicate_for_intervention(cutoff)
            .map_err(|error| crate::CiError::Message(format!("{error:?}")))?;
        before = Some((
            original
                .retirement_identity()
                .map_err(crate::CiError::Message)?,
            duplicate
                .retirement_identity()
                .map_err(crate::CiError::Message)?,
        ));
        duplicate
            .hold_executable_image(cutoff)
            .map_err(crate::CiError::Message)?;
        duplicate
            .verify_intervention_image(cutoff)
            .map_err(crate::CiError::Message)?;
        let killed = original.signal_kill().map_err(crate::CiError::Message)?;
        retained = Some((original, duplicate, killed));
        Ok(())
    });
    // The command adapter remains the sole native wait/cleanup owner, including
    // errors after an exec-stop signal. Assert only after it settles.
    let (original, duplicate, killed) =
        retained.expect("actual exec callback must retain original ownership");
    assert!(killed.is_ok(), "native kill={killed:?}; command={result:?}");
    assert!(
        original.exited().unwrap() && duplicate.exited().unwrap(),
        "command={result:?}"
    );
    let (a, b) = before.unwrap();
    assert_eq!(
        (a.pid, a.birth, a.parent_pid, a.parent_birth),
        (b.pid, b.birth, b.parent_pid, b.parent_birth)
    );
    assert!(!a.retirement_observed && !b.retirement_observed);
    assert!(duplicate.signal_kill().is_err());
    assert!(duplicate.verify_intervention_image(cutoff).is_err());
}

#[test]
fn current_executable_change_is_rejected_while_original_pidfd_remains_live() {
    let cutoff = Instant::now() + Duration::from_secs(15);
    let mut observer = None;
    // Native env performs an argv-based exec; no shell or custom environment.
    let result = CommandSpec::new(
        "/usr/bin/env",
        std::path::Path::new("/"),
        Duration::from_secs(5),
    )
    .args(["/bin/sleep", "30"])
    .bounded_until(cutoff)
    .output_quiet_with_exec_observation(|child| {
        let birth = process_birth(child.id()).map_err(crate::CiError::Message)?;
        let original =
            HeldLinuxProcess::acquire(child.id(), birth).map_err(crate::CiError::Message)?;
        let mut duplicate = original
            .duplicate_for_intervention(cutoff)
            .map_err(|error| crate::CiError::Message(format!("{error:?}")))?;
        duplicate
            .hold_executable_image(cutoff)
            .map_err(crate::CiError::Message)?;
        duplicate
            .verify_intervention_image(cutoff)
            .map_err(crate::CiError::Message)?;
        observer = Some(std::thread::spawn(move || -> Result<(), String> {
            let changed = loop {
                if Instant::now() >= cutoff {
                    break Err("original cutoff expired awaiting controlled exec".into());
                }
                if duplicate.exited()? {
                    break Err("controlled child exited before live exec observation".into());
                }
                match duplicate.verify_intervention_image(cutoff) {
                    Err(error)
                        if error.contains("executable changed after original measurement") =>
                    {
                        break Ok(());
                    }
                    Err(error) => break Err(error),
                    Ok(_) => std::thread::yield_now(),
                }
            };
            let killed = duplicate.signal_kill();
            changed?;
            match killed {
                Ok(Ok(())) => Ok(()),
                other => Err(format!(
                    "controlled child native retirement signal: {other:?}"
                )),
            }
        }));
        Ok(())
    });
    let observed = observer
        .expect("actual exec callback must retain observer")
        .join()
        .expect("native observer thread panicked");
    assert!(
        observed.is_ok(),
        "exec observation={observed:?}; owned command={result:?}"
    );
}
