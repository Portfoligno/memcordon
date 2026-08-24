use serde::Serialize;

pub const MAXIMUM_CAPTURED_STREAM_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedStream {
    pub encoding: &'static str,
    pub data: String,
    pub original_bytes: usize,
    pub truncated: bool,
}

impl BoundedStream {
    pub fn capture(bytes: &[u8]) -> Self {
        let retained = bytes.len().min(MAXIMUM_CAPTURED_STREAM_BYTES);
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                let mut boundary = retained;
                while !text.is_char_boundary(boundary) {
                    boundary -= 1;
                }
                Self {
                    encoding: "utf-8",
                    data: text[..boundary].to_owned(),
                    original_bytes: bytes.len(),
                    truncated: boundary != bytes.len(),
                }
            }
            Err(_) => Self {
                encoding: "hex",
                data: bytes[..retained]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                original_bytes: bytes.len(),
                truncated: retained != bytes.len(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceDiagnosticKind {
    NotRequired,
    Missing,
    Duplicate,
    Oversized,
    InvalidUtf8,
    InvalidPayload,
    ContractMismatch,
    Valid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceDiagnosticError {
    pub kind: EvidenceDiagnosticKind,
    pub detail: String,
}

impl EvidenceDiagnosticError {
    pub fn new(kind: EvidenceDiagnosticKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ScenarioFailureDiagnostic {
    Setup {
        phase: &'static str,
        error: BoundedStream,
    },
    Process {
        status: String,
        stdout: BoundedStream,
        stderr: BoundedStream,
        evidence_status: EvidenceDiagnosticKind,
        evidence_error: Option<String>,
    },
}

impl ScenarioFailureDiagnostic {
    pub fn setup(phase: &'static str, error: impl Into<String>) -> Self {
        let error = error.into();
        Self::Setup {
            phase,
            error: BoundedStream::capture(error.as_bytes()),
        }
    }
}

#[derive(Debug)]
pub struct ScenarioProcessObservation<T> {
    pub evidence: Option<T>,
    pub failure: Option<ScenarioFailureDiagnostic>,
}

pub fn observe_scenario_process<T>(
    success: bool,
    status: impl Into<String>,
    stdout: &[u8],
    stderr: &[u8],
    evidence_required: bool,
    parse_evidence: impl FnOnce(&[u8]) -> Result<T, EvidenceDiagnosticError>,
) -> ScenarioProcessObservation<T> {
    let evidence_result = evidence_required.then(|| parse_evidence(stdout));
    let (evidence, evidence_status, evidence_error) = match evidence_result {
        None => (None, EvidenceDiagnosticKind::NotRequired, None),
        Some(Ok(evidence)) => (Some(evidence), EvidenceDiagnosticKind::Valid, None),
        Some(Err(error)) => (None, error.kind, Some(error.detail)),
    };
    let accepted = success && (!evidence_required || evidence.is_some());
    ScenarioProcessObservation {
        evidence,
        failure: (!accepted).then(|| ScenarioFailureDiagnostic::Process {
            status: status.into(),
            stdout: BoundedStream::capture(stdout),
            stderr: BoundedStream::capture(stderr),
            evidence_status,
            evidence_error,
        }),
    }
}
