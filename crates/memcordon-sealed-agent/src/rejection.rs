use serde::{Deserialize, Serialize};

const MAX_CODE_BYTES: usize = 128;
const MAX_DETAIL_BYTES: usize = 8 * 1024;
const MAX_CLEANUP_ERRORS: usize = 16;
const MAX_CLEANUP_ERROR_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectionPhaseV1 {
    RequestValidation,
    BoundaryCreation,
    GuardianStartup,
    TargetCreation,
    AssignmentVerification,
    ResourceVerification,
    Authorization,
    Monitoring,
    Retirement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectionCleanupV1 {
    pub attempted: bool,
    pub direct_child_reaped: bool,
    pub workload_empty: Option<bool>,
    pub helpers_reaped: bool,
    pub containment_removed: bool,
    pub sealed_boundary_retired: bool,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectionV1 {
    pub schema_version: u32,
    pub code: String,
    pub phase: RejectionPhaseV1,
    pub detail: String,
    pub os_code: Option<i32>,
    pub target_created: bool,
    pub target_released: bool,
    pub cleanup: RejectionCleanupV1,
}

impl RejectionV1 {
    pub fn from_launch_facts(
        code: &str,
        phase: RejectionPhaseV1,
        detail: &str,
        target_created: bool,
        target_released: bool,
        cleanup: RejectionCleanupV1,
    ) -> Result<Self, String> {
        let rejection = Self {
            schema_version: 1,
            code: if valid_code(code) {
                code.to_owned()
            } else {
                "MCSEALED-PROVIDER-REJECTION".to_owned()
            },
            phase,
            detail: bounded(detail, MAX_DETAIL_BYTES),
            os_code: None,
            target_created,
            target_released,
            cleanup,
        };
        rejection.validate()?;
        Ok(rejection)
    }

    pub fn from_launch_error(error: &str, attempt_id: [u8; 16]) -> Self {
        let code = stable_code(error);
        let phase = phase_for_code(&code);
        let target_created = target_was_observed(&code, phase);
        let target_released = code == "MCSEALED-AUTHORIZATION-RECORD"
            || code == "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION"
            || code == "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION"
            || code == "MCSEALED-TARGET-EXEC-STATUS"
            || matches!(
                phase,
                RejectionPhaseV1::Monitoring | RejectionPhaseV1::Retirement
            );
        let cleanup = cleanup_evidence(attempt_id, phase);
        Self {
            schema_version: 1,
            code,
            phase,
            detail: bounded(error, MAX_DETAIL_BYTES),
            os_code: None,
            target_created,
            target_released,
            cleanup,
        }
    }

    pub fn request_error(code: &str, detail: &str) -> Self {
        Self {
            schema_version: 1,
            code: if valid_code(code) {
                code.to_owned()
            } else {
                "MCSEALED-PROVIDER-REJECTION".to_owned()
            },
            phase: RejectionPhaseV1::RequestValidation,
            detail: bounded(detail, MAX_DETAIL_BYTES),
            os_code: None,
            target_created: false,
            target_released: false,
            cleanup: RejectionCleanupV1 {
                attempted: false,
                direct_child_reaped: false,
                workload_empty: None,
                helpers_reaped: false,
                containment_removed: false,
                sealed_boundary_retired: false,
                errors: Vec::new(),
            },
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut encoded = serde_json::to_vec(self)
            .map_err(|error| format!("MCSEALED-PROVIDER-REJECTION: {error}"))?;
        encoded.push(b'\n');
        if encoded.len() > crate::protocol::MAX_FRAME_LENGTH {
            return Err("MCSEALED-PROVIDER-REJECTION: receipt exceeds frame bound".to_owned());
        }
        Ok(encoded)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !valid_code(&self.code)
            || self.detail.len() > MAX_DETAIL_BYTES
            || self.detail.contains('\0')
            || self.target_released && !self.target_created
            || self.cleanup.errors.len() > MAX_CLEANUP_ERRORS
            || self
                .cleanup
                .errors
                .iter()
                .any(|error| error.len() > MAX_CLEANUP_ERROR_BYTES || error.contains('\0'))
        {
            return Err("MCSEALED-PROVIDER-REJECTION: invalid typed receipt".to_owned());
        }
        if !self.cleanup.attempted
            && (self.cleanup.direct_child_reaped
                || self.cleanup.workload_empty.is_some()
                || self.cleanup.helpers_reaped
                || self.cleanup.containment_removed
                || self.cleanup.sealed_boundary_retired
                || !self.cleanup.errors.is_empty())
        {
            return Err("MCSEALED-PROVIDER-REJECTION: contradictory cleanup receipt".to_owned());
        }
        if self.cleanup.sealed_boundary_retired
            && (!self.cleanup.direct_child_reaped
                || self.cleanup.workload_empty != Some(true)
                || !self.cleanup.helpers_reaped
                || !self.cleanup.containment_removed
                || !self.cleanup.errors.is_empty())
        {
            return Err("MCSEALED-PROVIDER-REJECTION: incomplete retirement receipt".to_owned());
        }
        let expected_fault = match self.code.as_str() {
            "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION"
            | "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION" => {
                Some((RejectionPhaseV1::Authorization, true, false))
            }
            "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION"
            | "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION" => {
                Some((RejectionPhaseV1::Monitoring, true, true))
            }
            _ => None,
        };
        if expected_fault.is_some_and(|expected| {
            expected != (self.phase, self.target_created, self.target_released)
                || !self.cleanup.sealed_boundary_retired
        }) {
            return Err("MCSEALED-PROVIDER-REJECTION: contradictory loss receipt".to_owned());
        }
        Ok(())
    }
}

fn stable_code(error: &str) -> String {
    let candidate = error.split_once(':').map_or(error, |(code, _)| code);
    if valid_code(candidate) {
        candidate.to_owned()
    } else {
        "MCSEALED-PROVIDER-REJECTION".to_owned()
    }
}

fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn phase_for_code(code: &str) -> RejectionPhaseV1 {
    if code == "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION"
        || code == "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION"
    {
        RejectionPhaseV1::Authorization
    } else if code == "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION"
        || code == "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION"
    {
        RejectionPhaseV1::Monitoring
    } else if matches!(
        code,
        "MCSEALED-CGROUP-KILL-FAILURE"
            | "MCSEALED-CGROUP-NOT-EMPTY"
            | "MCSEALED-NAMESPACE-INIT-REAP-DELAY"
            | "MCSEALED-GUARDIAN-REAP-FAILURE"
    ) {
        RejectionPhaseV1::Retirement
    } else if code == "MCSEALED-LAUNCH-DESCRIPTOR-SET" {
        RejectionPhaseV1::RequestValidation
    } else if code.starts_with("MCSEALED-NAMESPACE-INIT-") {
        RejectionPhaseV1::TargetCreation
    } else if code.contains("DESCRIPTOR")
        || code.contains("CGROUP-VIEW")
        || code.contains("TARGET-CREDENTIAL-READBACK")
        || code.contains("TARGET-CGROUP-READBACK")
        || code.contains("TARGET-NAMESPACE-READBACK")
        || code.contains("RECORD-RESOURCE")
    {
        RejectionPhaseV1::ResourceVerification
    } else if code.contains("TARGET-IDENTITY") || code.contains("RECORD-ASSIGNMENT") {
        RejectionPhaseV1::AssignmentVerification
    } else if code.contains("GUARDIAN") || code.contains("RECORD-GUARDIAN") {
        RejectionPhaseV1::GuardianStartup
    } else if code.contains("AUTHORIZATION") {
        RejectionPhaseV1::Authorization
    } else if code.contains("BOUNDARY-NOT-RETIRED") || code.contains("CGROUP-NOT-EMPTY") {
        RejectionPhaseV1::Retirement
    } else if code.contains("TARGET-CONTROL")
        || code.contains("TARGET-STATUS")
        || code.contains("FRONTEND-PIDFD")
        || code.contains("CGROUP")
        || code.contains("RECORD-ALLOCATE")
        || code.contains("RECORD-BOUNDARY")
        || code.contains("RECOVERY")
    {
        RejectionPhaseV1::BoundaryCreation
    } else if code.contains("MONITOR") || code.contains("DEADLINE") || code.contains("MEMORY") {
        RejectionPhaseV1::Monitoring
    } else if code.contains("TARGET") || code.contains("RECORD-TARGET") {
        RejectionPhaseV1::TargetCreation
    } else {
        RejectionPhaseV1::RequestValidation
    }
}

fn target_was_observed(code: &str, phase: RejectionPhaseV1) -> bool {
    if code == "MCSEALED-TARGET-WAIT"
        || (code.starts_with("MCSEALED-NAMESPACE-INIT-")
            && code != "MCSEALED-NAMESPACE-INIT-REAP-DELAY")
    {
        return false;
    }
    matches!(
        phase,
        RejectionPhaseV1::TargetCreation
            | RejectionPhaseV1::AssignmentVerification
            | RejectionPhaseV1::ResourceVerification
            | RejectionPhaseV1::Authorization
            | RejectionPhaseV1::Monitoring
            | RejectionPhaseV1::Retirement
    )
}

#[cfg(target_os = "linux")]
fn cleanup_evidence(attempt_id: [u8; 16], phase: RejectionPhaseV1) -> RejectionCleanupV1 {
    if phase == RejectionPhaseV1::RequestValidation {
        return RejectionCleanupV1 {
            attempted: false,
            direct_child_reaped: false,
            workload_empty: None,
            helpers_reaped: false,
            containment_removed: false,
            sealed_boundary_retired: false,
            errors: Vec::new(),
        };
    }
    let identity = attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record = std::path::Path::new(crate::linux::STATE_ROOT).join(&identity);
    let cgroup = std::path::Path::new(crate::linux::CGROUP_ROOT).join(&identity);
    let record_absent = path_absent_no_follow(&record);
    let containment_removed = path_absent_no_follow(&cgroup);
    let retired = record_absent && containment_removed;
    let errors = if retired {
        Vec::new()
    } else {
        vec!["MCSEALED-BOUNDARY-NOT-RETIRED: authenticated attempt residue remains".to_owned()]
    };
    RejectionCleanupV1 {
        attempted: true,
        direct_child_reaped: retired,
        workload_empty: Some(containment_removed),
        helpers_reaped: retired,
        containment_removed,
        sealed_boundary_retired: retired,
        errors,
    }
}

#[cfg(not(target_os = "linux"))]
fn cleanup_evidence(_attempt_id: [u8; 16], phase: RejectionPhaseV1) -> RejectionCleanupV1 {
    if phase == RejectionPhaseV1::RequestValidation {
        return RejectionCleanupV1 {
            attempted: false,
            direct_child_reaped: false,
            workload_empty: None,
            helpers_reaped: false,
            containment_removed: false,
            sealed_boundary_retired: false,
            errors: Vec::new(),
        };
    }
    RejectionCleanupV1 {
        attempted: true,
        direct_child_reaped: false,
        workload_empty: None,
        helpers_reaped: false,
        containment_removed: false,
        sealed_boundary_retired: false,
        errors: vec!["MCSEALED-PROVIDER-UNSUPPORTED: cleanup evidence is Linux-only".to_owned()],
    }
}

#[cfg(target_os = "linux")]
fn path_absent_no_follow(path: &std::path::Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

fn bounded(value: &str, maximum: usize) -> String {
    const SUFFIX: &str = "...[truncated]";
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut boundary = maximum - SUFFIX.len();
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}{SUFFIX}", &value[..boundary])
}
