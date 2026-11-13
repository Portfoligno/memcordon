//! Two read-only self-policy observations; no policy is changed or authorized.
use serde_json::{Value, json};

#[derive(Clone, Copy)]
pub enum Policy {
    ImageLoad,
    Signature,
}

#[derive(Default)]
pub struct Observation {
    pub attempted: bool,
    pub started_qpc: Option<u64>,
    pub finished_qpc: Option<u64>,
    pub success: Option<bool>,
    pub native_error: Option<u32>,
    pub flags: Option<u32>,
    pub clock_error: Option<u32>,
    pub cutoff_reached: bool,
}

pub fn diagnostic(policy: Policy, observation: &Observation) -> Value {
    let available = observation.attempted
        && observation.success == Some(true)
        && observation.flags.is_some()
        && observation.clock_error.is_none()
        && !observation.cutoff_reached
        && observation
            .started_qpc
            .zip(observation.finished_qpc)
            .is_some_and(|(start, finish)| start != 0 && finish >= start);
    let flags = observation.flags;
    let bit = |mask| flags.map(|flags| flags & mask != 0);
    let decoded = match policy {
        Policy::ImageLoad => {
            json!({"no_remote_images":bit(1),"no_low_mandatory_label_images":bit(2),
            "prefer_system32_images":bit(4),"audit_no_remote_images":bit(8),"audit_no_low_mandatory_label_images":bit(16)})
        }
        Policy::Signature => json!({"microsoft_signed_only":bit(1),"store_signed_only":bit(2),
            "mitigation_opt_in":bit(4),"audit_microsoft_signed_only":bit(8),"audit_store_signed_only":bit(16)}),
    };
    json!({"policy":match policy {Policy::ImageLoad=>"ProcessImageLoadPolicy",Policy::Signature=>"ProcessSignaturePolicy"},
        "attempted":observation.attempted,"available_before_original_cutoff":available,
        "started_qpc":observation.started_qpc,"finished_qpc":observation.finished_qpc,
        "query_succeeded":observation.success,"native_error":observation.native_error,
        "raw_flags":flags,"unknown_flag_bits":flags.map(|flags|flags&!31),"decoded":decoded,
        "clock_error":observation.clock_error,"original_cutoff_reached":observation.cutoff_reached,
        "acceptance_authority":false,"loader_policy_precedence_or_cause_proved":false})
}

pub fn bind(mut snapshot: Value, pid: u32, birth: u64) -> Value {
    snapshot["matches_authenticated_original_identity"] = json!(
        snapshot["actual_self"]["available_before_original_cutoff"] == true
            && snapshot["actual_self"]["pid"] == pid
            && snapshot["actual_self"]["creation_time_100ns"] == birth
    );
    snapshot
}
