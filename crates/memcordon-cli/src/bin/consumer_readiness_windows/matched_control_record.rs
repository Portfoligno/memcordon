//! Bounded application observations for an additional Stage1 measurement.
//! Native family settlement and installed ACK remain separate runtime checks.
use serde::{Deserialize, Serialize};

pub const REVISION: u32 = 1;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_OPERATIONS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lane {
    Direct,
    Installed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    BinaryFiles,
    Envelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeStatusDomain {
    Win32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub pair_sha256: [u8; 32],
    pub lane: Lane,
    pub scope: Scope,
    pub input_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectedRole {
    Driver,
    Provider,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Operation {
    CreateNestedDirectory,
    WriteEmptyFile,
    WriteAllBytesTemporary,
    RenameAllBytes,
    ReadAllBytes,
    VerifyAllBytes,
    WriteChallenge,
    ProtectedWrite { role: ProtectedRole },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticFailure {
    ReadbackMismatch,
    ProtectedWriteSucceeded,
    ProtectedWriteWrongError,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Outcome {
    Completed { data_sha256: Option<[u8; 32]> },
    NativeFailure { code: i32 },
    NonNativeFailure,
    SemanticFailure { kind: SemanticFailure },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub ordinal: u32,
    pub op: Operation,
    pub arguments_sha256: [u8; 32],
    pub before_qpc: u64,
    pub after_qpc: u64,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "terminal", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Terminal {
    CompletedScope,
    FirstFailure { ordinal: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub revision: u32,
    pub native_status_domain: NativeStatusDomain,
    pub binding: Binding,
    pub descriptor_sha256: [u8; 32],
    pub pid: u32,
    pub birth: u64,
    pub cutoff_qpc: u64,
    pub qpc_frequency: u64,
    pub token_sha256: [u8; 32],
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub operations: Vec<OperationRecord>,
    pub terminal: Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Invalid {}

fn operation_plan(scope: Scope, protected: bool) -> Result<Vec<Operation>, Invalid> {
    if protected && scope != Scope::Envelope {
        return Err(Invalid("protected roles require Envelope scope"));
    }
    let mut operations = vec![
        Operation::CreateNestedDirectory,
        Operation::WriteEmptyFile,
        Operation::WriteAllBytesTemporary,
        Operation::RenameAllBytes,
        Operation::ReadAllBytes,
        Operation::VerifyAllBytes,
        Operation::WriteChallenge,
    ];
    if protected {
        operations.extend([
            Operation::ProtectedWrite {
                role: ProtectedRole::Driver,
            },
            Operation::ProtectedWrite {
                role: ProtectedRole::Provider,
            },
        ]);
    }
    Ok(operations)
}

fn failed(record: &OperationRecord) -> bool {
    match (&record.op, &record.outcome) {
        (Operation::ProtectedWrite { .. }, Outcome::NativeFailure { code: 5 }) => false,
        (Operation::ProtectedWrite { .. }, _) => true,
        (_, Outcome::Completed { .. }) => false,
        _ => true,
    }
}

/// Validates application syntax/order and the supplied expected binding only.
/// The runtime must independently check held identities, inputs, token readbacks,
/// captures, direct Job settlement and installed product/ACK retirement.
pub fn validate(value: &Observation, expected: &Binding, protected: bool) -> Result<(), Invalid> {
    if value.revision != REVISION || &value.binding != expected {
        return Err(Invalid("observation revision or binding mismatch"));
    }
    let plan = operation_plan(expected.scope, protected)?;
    if value.pid == 0 || value.birth == 0 || value.qpc_frequency == 0 {
        return Err(Invalid("missing process identity or clock frequency"));
    }
    if value.started_qpc > value.finished_qpc || value.finished_qpc >= value.cutoff_qpc {
        return Err(Invalid("application observation outside original cutoff"));
    }
    if value.operations.is_empty()
        || value.operations.len() > MAX_OPERATIONS
        || value.operations.len() > plan.len()
    {
        return Err(Invalid("application operation count invalid"));
    }
    let mut previous = value.started_qpc;
    let mut failure = None;
    for (index, record) in value.operations.iter().enumerate() {
        if record.ordinal as usize != index + 1 || record.op != plan[index] {
            return Err(Invalid("application operation sequence mismatch"));
        }
        if failure.is_some() {
            return Err(Invalid("application operation follows first failure"));
        }
        if record.before_qpc < previous
            || record.after_qpc < record.before_qpc
            || record.after_qpc > value.finished_qpc
        {
            return Err(Invalid("application operation clock order invalid"));
        }
        previous = record.after_qpc;
        if let Outcome::SemanticFailure { kind } = record.outcome {
            let applicable = match kind {
                SemanticFailure::ReadbackMismatch => record.op == Operation::VerifyAllBytes,
                SemanticFailure::ProtectedWriteSucceeded
                | SemanticFailure::ProtectedWriteWrongError => {
                    matches!(record.op, Operation::ProtectedWrite { .. })
                }
            };
            if !applicable {
                return Err(Invalid(
                    "semantic failure does not match application operation",
                ));
            }
        }
        if matches!(
            record.op,
            Operation::ReadAllBytes | Operation::VerifyAllBytes
        ) && matches!(record.outcome, Outcome::Completed { data_sha256: None })
        {
            return Err(Invalid("completed readback lacks data digest"));
        }
        if failed(record) {
            failure = Some(record.ordinal);
        }
    }
    match (value.terminal, failure) {
        (Terminal::CompletedScope, None) if value.operations.len() == plan.len() => Ok(()),
        (Terminal::FirstFailure { ordinal }, Some(actual)) if ordinal == actual => Ok(()),
        _ => Err(Invalid(
            "application terminal does not match completed prefix",
        )),
    }
}

/// Wire bounds apply before decoding and after encoding; no truncation is valid.
pub fn decode(bytes: &[u8]) -> Result<Observation, Invalid> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Invalid("application record exceeds byte ceiling"));
    }
    let value: Observation =
        serde_json::from_slice(bytes).map_err(|_| Invalid("malformed application record"))?;
    // Serde's internally tagged unit variants can otherwise discard extra
    // fields despite deny_unknown_fields. Require the complete decoded shape,
    // including explicit nulls, rather than accepting an altered wire record.
    let wire: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Invalid("malformed application record"))?;
    let canonical = serde_json::to_value(&value)
        .map_err(|_| Invalid("application record shape unavailable"))?;
    if wire != canonical {
        return Err(Invalid(
            "application record contains an unexpected or missing field",
        ));
    }
    if value.revision != REVISION || value.operations.len() > MAX_OPERATIONS {
        return Err(Invalid(
            "application record revision or operation ceiling invalid",
        ));
    }
    Ok(value)
}

pub fn encode(value: &Observation) -> Result<Vec<u8>, Invalid> {
    if value.revision != REVISION || value.operations.len() > MAX_OPERATIONS {
        return Err(Invalid(
            "application record revision or operation ceiling invalid",
        ));
    }
    let bytes = serde_json::to_vec(value).map_err(|_| Invalid("application encoding failed"))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Invalid("application record exceeds byte ceiling"));
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonOutcome {
    ScopeSuccess,
    SameObservedFailure,
    DifferentOutcome,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Comparison {
    pub outcome: ComparisonOutcome,
    pub scope: Scope,
    pub native_status_domain: NativeStatusDomain,
}

/// Pure application comparison; runtime ownership checks are separate.
pub fn compare(
    direct: &Observation,
    installed: &Observation,
    protected: bool,
) -> Result<Comparison, Invalid> {
    validate(direct, &direct.binding, protected)?;
    validate(installed, &installed.binding, protected)?;
    if direct.binding.lane != Lane::Direct
        || installed.binding.lane != Lane::Installed
        || direct.binding.pair_sha256 != installed.binding.pair_sha256
        || direct.binding.scope != installed.binding.scope
        || direct.binding.input_sha256 != installed.binding.input_sha256
        || direct.token_sha256 != installed.token_sha256
        || direct.qpc_frequency != installed.qpc_frequency
        || direct.cutoff_qpc != installed.cutoff_qpc
        || (direct.pid == installed.pid && direct.birth == installed.birth)
    {
        return Err(Invalid(
            "matched application input, token, clock or lane mismatch",
        ));
    }
    if direct
        .operations
        .iter()
        .chain(&installed.operations)
        .any(|operation| {
            matches!(
                operation.outcome,
                Outcome::NonNativeFailure
                    | Outcome::SemanticFailure {
                        kind: SemanticFailure::ProtectedWriteWrongError
                    }
            )
        })
    {
        return Err(Invalid(
            "opaque application error cannot establish equivalence",
        ));
    }
    let equal = direct.terminal == installed.terminal
        && direct.operations.len() == installed.operations.len()
        && direct
            .operations
            .iter()
            .zip(&installed.operations)
            .all(|(left, right)| {
                left.ordinal == right.ordinal
                    && left.op == right.op
                    && left.arguments_sha256 == right.arguments_sha256
                    && left.outcome == right.outcome
            });
    let outcome = if !equal {
        ComparisonOutcome::DifferentOutcome
    } else if direct.terminal == Terminal::CompletedScope {
        ComparisonOutcome::ScopeSuccess
    } else {
        ComparisonOutcome::SameObservedFailure
    };
    Ok(Comparison {
        outcome,
        scope: direct.binding.scope,
        native_status_domain: NativeStatusDomain::Win32,
    })
}
