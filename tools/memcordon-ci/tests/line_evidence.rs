use memcordon_ci::line_evidence::{FramedLineError, unique_prefixed_line};

const PREFIX: &str = "MCSEALED-CONCURRENCY-EVIDENCE:";

#[test]
fn realistic_libtest_framing_requires_an_independent_evidence_line() {
    let inline = b"running 1 test\ntest sealed_simultaneous_attempts_have_disjoint_boundaries ... MCSEALED-CONCURRENCY-EVIDENCE:{}\nok\n";
    assert_eq!(
        unique_prefixed_line(inline, PREFIX, 32 * 1024),
        Err(FramedLineError::Missing)
    );

    let framed = b"running 1 test\ntest sealed_simultaneous_attempts_have_disjoint_boundaries ... \nMCSEALED-CONCURRENCY-EVIDENCE:{}\nok\n";
    assert_eq!(unique_prefixed_line(framed, PREFIX, 32 * 1024), Ok("{}"));
}

#[test]
fn framed_evidence_remains_unique_and_bounded() {
    let duplicate = b"MCSEALED-CONCURRENCY-EVIDENCE:{}\nMCSEALED-CONCURRENCY-EVIDENCE:{}\n";
    assert_eq!(
        unique_prefixed_line(duplicate, PREFIX, 32 * 1024),
        Err(FramedLineError::Duplicate)
    );

    let bounded = b"MCSEALED-CONCURRENCY-EVIDENCE:1234\n";
    assert_eq!(unique_prefixed_line(bounded, PREFIX, 4), Ok("1234"));
    assert_eq!(
        unique_prefixed_line(bounded, PREFIX, 3),
        Err(FramedLineError::TooLarge)
    );
}

#[test]
fn stderr_evidence_does_not_satisfy_an_empty_stdout_contract() {
    let stdout = b"test result: ok. 1 passed; 0 failed\n";
    let stderr = b"MCSEALED-CONCURRENCY-EVIDENCE:{}\n";
    assert_eq!(
        unique_prefixed_line(stdout, PREFIX, 32 * 1024),
        Err(FramedLineError::Missing)
    );
    assert_eq!(unique_prefixed_line(stderr, PREFIX, 32 * 1024), Ok("{}"));
}

#[test]
fn non_utf8_stdout_is_rejected_before_line_selection() {
    let error = unique_prefixed_line(&[0xff], PREFIX, 32 * 1024).unwrap_err();
    assert!(matches!(error, FramedLineError::InvalidUtf8(_)));
}
