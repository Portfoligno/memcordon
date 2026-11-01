use memcordon_ci::{
    CiError,
    terminal_capture::TerminalCapture,
    work_outcome::{WriterSettlement, has_unresolved_owner},
};

fn assert_unresolved(error: &CiError, description: &str) {
    assert!(has_unresolved_owner(error));
    assert!(matches!(
        error,
        CiError::OwnedWork {
            writers: WriterSettlement::Unknown,
            ..
        }
    ));
    assert!(error.to_string().contains(description));
    assert!(!error.to_string().contains("capture absent"));
}

#[test]
fn completed_original_output_remains_available_without_another_completion_or_replacement() {
    let mut capture = TerminalCapture::default();
    assert!(!capture.has_output());
    capture.complete(Ok(vec![0_u8, 255, 42])).unwrap();
    let first = capture.output().unwrap().as_ptr();
    assert_eq!(capture.output().unwrap(), &[0, 255, 42]);
    assert_eq!(capture.output().unwrap().as_ptr(), first);
    assert!(capture.has_output());
    assert!(capture.complete(Ok(vec![1, 2, 3])).is_err());
    assert_eq!(capture.output().unwrap(), &[0, 255, 42]);
    assert_unresolved(&capture.panicked(), "duplicate panic refused");
    assert_eq!(capture.output().unwrap().as_ptr(), first);
}

#[test]
fn failed_supervision_returns_the_original_typed_error_once_then_retains_failed_custody() {
    let mut capture = TerminalCapture::<Vec<u8>>::default();
    let original = CiError::LaneFailures {
        primary: Box::new(CiError::Io(std::io::Error::from_raw_os_error(5))),
        secondary: Box::new(CiError::Cancelled("original callback cleanup".into())),
    };
    let error = capture.complete(Err(original)).unwrap_err();
    let CiError::LaneFailures { primary, secondary } = error else {
        panic!("typed original causes lost")
    };
    assert!(matches!(*primary,CiError::Io(error) if error.raw_os_error()==Some(5)));
    assert!(matches!(*secondary,CiError::Cancelled(ref text) if text=="original callback cleanup"));
    assert!(!capture.has_output());
    for _ in 0..2 {
        assert_unresolved(&capture.output().unwrap_err(), "completed with failure");
    }
    assert!(capture.complete(Ok(vec![9])).is_err());
    assert_unresolved(&capture.output().unwrap_err(), "completed with failure");
}

#[test]
fn panicked_terminal_state_never_becomes_pending_absent_or_successful_output() {
    let mut capture = TerminalCapture::<()>::default();
    assert_unresolved(&capture.output().unwrap_err(), "pending");
    assert_unresolved(&capture.panicked(), "supervisor panicked");
    assert_unresolved(&capture.output().unwrap_err(), "supervisor panicked");
    let duplicate = capture
        .complete(Err(CiError::Io(std::io::Error::from_raw_os_error(6))))
        .unwrap_err();
    let CiError::LaneFailures { secondary, .. } = duplicate else {
        panic!("duplicate failure source lost")
    };
    assert!(matches!(*secondary,CiError::Io(error) if error.raw_os_error()==Some(6)));
    assert_unresolved(&capture.output().unwrap_err(), "supervisor panicked");
}
