//! Factual components shared by current results and native attempt transports.
use serde::{Deserialize, Serialize};

pub const RESULT_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeKindV1 {
    Completed,
    Deadline,
    ConfirmedMemoryLimit,
    Interrupted,
    LaunchFailure,
    ProviderFailure,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupStateV1 {
    Complete,
    Incomplete,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalToolV1 {
    pub name: String,
    pub version: String,
    pub os: String,
    pub architecture: String,
    pub runtime_features: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeV1 {
    pub kind: OutcomeKindV1,
    pub native_termination: Option<crate::ChildTermination>,
    pub wrapper_status: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttemptAssociationV1 {
    pub provider: crate::PublicProviderBindingV1,
    pub attempt_id: crate::DiagnosticSha256,
    pub request_sha256: crate::DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeNamespaceV2 {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProcessV2 {
    pub pid: u32,
    pub birth: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedFilterAbiV2 {
    X86_64,
    Aarch64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReportFormat {
    #[default]
    Standard,
    ResultV3,
}

#[derive(Clone, Debug)]
pub enum ResultReport {
    Standard(Box<crate::MemcordonReport>),
    Current(Box<crate::result_v3::ResultV3>),
}

impl ResultReport {
    pub fn prepare_writer(&mut self, writer_pid: std::num::NonZeroU32) {
        if let Self::Current(report) = self {
            report.delivery = crate::result_v3::DeliveryStateV3::PreparedBy { writer_pid };
        }
    }

    pub fn write_bytes(&self, writer: &mut impl std::io::Write) -> Result<(), String> {
        match self {
            Self::Standard(report) => serde_json::to_writer_pretty(&mut *writer, report)
                .map_err(|error| error.to_string())?,
            Self::Current(report) => {
                report.validate()?;
                serde_json::to_writer_pretty(&mut *writer, report)
                    .map_err(|error| error.to_string())?;
            }
        }
        writer.write_all(b"\n").map_err(|error| error.to_string())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Standard(report) => {
                crate::bounded_json_bytes(report.as_ref(), RESULT_MAX_BYTES, true)
            }
            Self::Current(report) => {
                report.validate()?;
                crate::bounded_json_bytes(report.as_ref(), RESULT_MAX_BYTES, true)
            }
        }
        .map_err(|error| error.to_string())
    }
}
