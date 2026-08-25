use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::digest::OutputSizeUser;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReceipt {
    pub schema_version: u32,
    pub version: String,
    pub mechanism: String,
    pub provider_identity: String,
    pub control_service_identity: String,
    pub launcher_service_identity: String,
    pub receipt_digest: String,
    pub unified_cgroup_v2: bool,
    pub private_cgroup_subtree: bool,
    pub clone3: bool,
    pub clone3_into_cgroup: bool,
    pub pid_namespace: bool,
    pub mount_namespace: bool,
    pub cgroup_namespace: bool,
    pub pidfd: bool,
    pub close_range: bool,
    pub guardian_outside_boundary: bool,
    pub target_gated: bool,
    pub assignment_verified: bool,
    pub inherited_descriptors_verified: bool,
    pub spawn_error_reporting_verified: bool,
    pub frontend_loss_authority_verified: bool,
    pub cgroup_kill: bool,
    pub workload_empty: bool,
    pub helpers_reaped: bool,
    pub boundary_retired: bool,
    pub recovery_complete: bool,
    pub split_control_and_launcher_services: bool,
    pub launcher_no_new_privs_disabled: bool,
    pub caller_mount_namespace_reproduction_verified: bool,
    pub caller_no_new_privs_reproduction_verified: bool,
    pub caller_capability_bounding_set_reproduction_verified: bool,
    pub initial_provider_capabilities_absent: bool,
    pub credential_transition_disposition: String,
    pub setid_transition_certification_digest: String,
    pub sudo_transition_certification_digest: String,
    pub post_transition_cgroup_membership_verified: bool,
    pub post_transition_pid_namespace_verified: bool,
    pub post_transition_cleanup_verified: bool,
    pub recursive_provider_request_rejected: bool,
}

impl QualificationReceipt {
    pub fn complete(&self) -> bool {
        self.schema_version == 2
            && self.version == env!("CARGO_PKG_VERSION")
            && self.mechanism == "linux-pid-namespace-cgroup-v2"
            && self.provider_identity == "memcordon-sealed-agent-v2"
            && self.control_service_identity == "memcordon-sealed-agent.service:v2"
            && self.launcher_service_identity == "memcordon-sealed-launcher.service:v2"
            && valid_sha256(&self.receipt_digest)
            && self.unified_cgroup_v2
            && self.private_cgroup_subtree
            && self.clone3
            && self.clone3_into_cgroup
            && self.pid_namespace
            && self.mount_namespace
            && self.cgroup_namespace
            && self.pidfd
            && self.close_range
            && self.guardian_outside_boundary
            && self.target_gated
            && self.assignment_verified
            && self.inherited_descriptors_verified
            && self.spawn_error_reporting_verified
            && self.frontend_loss_authority_verified
            && self.cgroup_kill
            && self.workload_empty
            && self.helpers_reaped
            && self.boundary_retired
            && self.recovery_complete
            && self.split_control_and_launcher_services
            && self.launcher_no_new_privs_disabled
            && self.caller_mount_namespace_reproduction_verified
            && self.caller_no_new_privs_reproduction_verified
            && self.caller_capability_bounding_set_reproduction_verified
            && self.initial_provider_capabilities_absent
            && self.credential_transition_disposition == "preserve-caller-envelope"
            && valid_sha256(&self.setid_transition_certification_digest)
            && valid_sha256(&self.sudo_transition_certification_digest)
            && self.post_transition_cgroup_membership_verified
            && self.post_transition_pid_namespace_verified
            && self.post_transition_cleanup_verified
            && self.recursive_provider_request_rejected
    }

    pub fn render(&self) -> String {
        serde_json::to_string(self).expect("qualification receipt is serializable")
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == <Sha256 as OutputSizeUser>::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
