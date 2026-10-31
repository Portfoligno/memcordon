use memcordon_ci::CiError;
use std::error::Error;

#[test]
fn context_preserves_owned_writer_settlement() {
    use memcordon_ci::work_outcome::{CompilationFacts, WorkOutcome, WriterSettlement};
    for writers in [WriterSettlement::Settled, WriterSettlement::Unknown] {
        let error = CiError::OwnedWork {
            source: Box::new(CiError::from(std::io::Error::from_raw_os_error(2))),
            writers,
            facts: CompilationFacts::default(),
        }
        .context("installed phase");
        assert!(
            matches!(&error, CiError::OwnedWork { writers: retained, .. } if *retained == writers)
        );
        let outcome = WorkOutcome::<()>::from_result(Err(error));
        assert_eq!(outcome.writers(), writers);
    }
}

#[test]
fn context_retains_original_io_cause_and_path() {
    let error = CiError::from(std::io::Error::from_raw_os_error(2))
        .context("phase=request-refusals scenario=version path=/tmp/request/input");
    assert!(error.to_string().contains("path=/tmp/request/input"));
    let mut cause: &dyn Error = &error;
    loop {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
            assert_eq!(io.raw_os_error(), Some(2));
            break;
        }
        cause = cause
            .source()
            .expect("original I/O cause remains available");
    }
}

#[test]
fn context_is_bounded_and_utf8_safe() {
    let label = format!("head{}tail", "界".repeat(4000));
    let error = CiError::Message("original".into()).context(label);
    let rendered = error.to_string();
    assert!(rendered.starts_with("head"));
    assert!(rendered.contains("context omitted"));
    assert!(rendered.ends_with("tail: original"));
    assert!(rendered.len() < 4200);
}

#[test]
fn context_preserves_cancellation_and_lane_error_priority() {
    assert!(matches!(
        CiError::Cancelled("stop".into()).context("phase"),
        CiError::Cancelled(_)
    ));
    assert!(matches!(
        CiError::NotStartedAfterFailure.context("phase"),
        CiError::NotStartedAfterFailure
    ));
    let error = CiError::LaneFailures {
        primary: Box::new(CiError::from(std::io::Error::from_raw_os_error(2))),
        secondary: Box::new(CiError::from(std::io::Error::from_raw_os_error(13))),
    }
    .context("retirement");
    let CiError::LaneFailures { primary, secondary } = error else {
        panic!("lane envelope lost")
    };
    assert!(primary.to_string().starts_with("retirement:"));
    assert!(secondary.to_string().starts_with("retirement:"));
    let CiError::Context { source, .. } = *primary else {
        panic!("primary context lost")
    };
    assert!(matches!(*source, CiError::Io(ref io) if io.raw_os_error() == Some(2)));
    let CiError::Context { source, .. } = *secondary else {
        panic!("secondary context lost")
    };
    assert!(matches!(*source, CiError::Io(ref io) if io.raw_os_error() == Some(13)));
}
