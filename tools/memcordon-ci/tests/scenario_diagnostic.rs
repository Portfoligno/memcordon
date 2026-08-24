use memcordon_ci::line_evidence::{FramedLineError, unique_prefixed_line};
use memcordon_ci::scenario_diagnostic::{
    EvidenceDiagnosticError, EvidenceDiagnosticKind, MAXIMUM_CAPTURED_STREAM_BYTES,
    ScenarioFailureDiagnostic, observe_scenario_process,
};

const PREFIX: &str = "MCSEALED-FAULT-EVIDENCE:";

fn parse(output: &[u8]) -> Result<String, EvidenceDiagnosticError> {
    unique_prefixed_line(output, PREFIX, 64)
        .map(str::to_owned)
        .map_err(|error| match error {
            FramedLineError::Missing => EvidenceDiagnosticError::new(
                EvidenceDiagnosticKind::Missing,
                "typed evidence is missing",
            ),
            FramedLineError::Duplicate => EvidenceDiagnosticError::new(
                EvidenceDiagnosticKind::Duplicate,
                "typed evidence is duplicated",
            ),
            FramedLineError::TooLarge => EvidenceDiagnosticError::new(
                EvidenceDiagnosticKind::Oversized,
                "typed evidence is oversized",
            ),
            FramedLineError::InvalidUtf8(error) => {
                EvidenceDiagnosticError::new(EvidenceDiagnosticKind::InvalidUtf8, error.to_string())
            }
        })
}

fn process_failure<T>(
    observation: &memcordon_ci::scenario_diagnostic::ScenarioProcessObservation<T>,
) -> (&str, &str, EvidenceDiagnosticKind, Option<&str>) {
    match observation
        .failure
        .as_ref()
        .expect("observation should fail")
    {
        ScenarioFailureDiagnostic::Process {
            status,
            stdout: _,
            stderr,
            evidence_status,
            evidence_error,
        } => (
            status,
            &stderr.data,
            *evidence_status,
            evidence_error.as_deref(),
        ),
        ScenarioFailureDiagnostic::Setup { .. } => panic!("expected process failure"),
    }
}

#[test]
fn nonzero_missing_evidence_preserves_process_and_evidence_diagnostics() {
    let stdout = b"running 1 test\ntest selector ... FAILED\n";
    let stderr = b"thread 'selector' panicked at fixture.rs:80:5\n";
    let observation =
        observe_scenario_process(false, "exit status: 101", stdout, stderr, true, parse);
    let (status, captured_stderr, evidence_status, evidence_error) = process_failure(&observation);
    assert_eq!(status, "exit status: 101");
    assert_eq!(captured_stderr.as_bytes(), stderr);
    assert_eq!(evidence_status, EvidenceDiagnosticKind::Missing);
    assert_eq!(evidence_error, Some("typed evidence is missing"));
    assert!(observation.evidence.is_none());
}

#[test]
fn inline_evidence_remains_missing_instead_of_becoming_substring_evidence() {
    let output = b"test selector ... MCSEALED-FAULT-EVIDENCE:{\"schema_version\":1}\n";
    let observation = observe_scenario_process(true, "exit status: 0", output, b"", true, parse);
    let (_, _, evidence_status, _) = process_failure(&observation);
    assert_eq!(evidence_status, EvidenceDiagnosticKind::Missing);
}

#[test]
fn nonzero_valid_evidence_is_retained_but_never_accepted() {
    let output = b"\nMCSEALED-FAULT-EVIDENCE:{\"schema_version\":1}\n";
    let observation =
        observe_scenario_process(false, "exit status: 101", output, b"panic\n", true, parse);
    let (_, _, evidence_status, evidence_error) = process_failure(&observation);
    assert_eq!(evidence_status, EvidenceDiagnosticKind::Valid);
    assert_eq!(evidence_error, None);
    assert_eq!(
        observation.evidence.as_deref(),
        Some("{\"schema_version\":1}")
    );
}

#[test]
fn invalid_and_duplicate_evidence_are_explicit_failures() {
    let invalid = observe_scenario_process(true, "exit status: 0", &[0xff], b"", true, parse);
    let (_, _, invalid_status, invalid_error) = process_failure(&invalid);
    assert_eq!(invalid_status, EvidenceDiagnosticKind::InvalidUtf8);
    assert!(invalid_error.is_some());

    let duplicate_output = b"MCSEALED-FAULT-EVIDENCE:{}\nMCSEALED-FAULT-EVIDENCE:{}\n";
    let duplicate =
        observe_scenario_process(true, "exit status: 0", duplicate_output, b"", true, parse);
    let (_, _, duplicate_status, _) = process_failure(&duplicate);
    assert_eq!(duplicate_status, EvidenceDiagnosticKind::Duplicate);
}

#[test]
fn schema_decodable_contract_mismatch_remains_an_explicit_failure() {
    let output = b"MCSEALED-FAULT-EVIDENCE:{\"code\":\"actual\"}\n";
    let observation = observe_scenario_process(true, "exit status: 0", output, b"", true, |_| {
        Err::<String, _>(EvidenceDiagnosticError::new(
            EvidenceDiagnosticKind::ContractMismatch,
            "expected code did not match actual code",
        ))
    });
    let (_, _, evidence_status, evidence_error) = process_failure(&observation);
    assert_eq!(evidence_status, EvidenceDiagnosticKind::ContractMismatch);
    assert_eq!(
        evidence_error,
        Some("expected code did not match actual code")
    );
}

#[test]
fn captured_streams_are_exact_within_the_bound_and_bounded_above_it() {
    let exact = b"exact stdout\n";
    let exact_observation =
        observe_scenario_process(false, "signal: 9", exact, b"exact stderr\n", false, parse);
    let diagnostic = exact_observation.failure.expect("nonzero must fail");
    let ScenarioFailureDiagnostic::Process { stdout, stderr, .. } = diagnostic else {
        panic!("expected process failure");
    };
    assert_eq!(stdout.data.as_bytes(), exact);
    assert!(!stdout.truncated);
    assert_eq!(stderr.data, "exact stderr\n");
    assert!(!stderr.truncated);

    let oversized = vec![b'x'; MAXIMUM_CAPTURED_STREAM_BYTES + 1];
    let oversized_observation =
        observe_scenario_process(false, "exit status: 1", &oversized, b"", false, parse);
    let ScenarioFailureDiagnostic::Process { stdout, .. } =
        oversized_observation.failure.expect("nonzero must fail")
    else {
        panic!("expected process failure");
    };
    assert_eq!(stdout.data.len(), MAXIMUM_CAPTURED_STREAM_BYTES);
    assert_eq!(stdout.original_bytes, MAXIMUM_CAPTURED_STREAM_BYTES + 1);
    assert!(stdout.truncated);
}

#[test]
fn setup_failure_has_no_fabricated_process_or_attempt_evidence() {
    let diagnostic = ScenarioFailureDiagnostic::setup(
        "test-executable",
        "cargo omitted executable for linux_sealed",
    );
    assert_eq!(
        diagnostic,
        ScenarioFailureDiagnostic::Setup {
            phase: "test-executable",
            error: memcordon_ci::scenario_diagnostic::BoundedStream::capture(
                b"cargo omitted executable for linux_sealed",
            ),
        }
    );
}
