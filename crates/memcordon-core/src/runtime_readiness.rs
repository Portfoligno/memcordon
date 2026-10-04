use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::digest::OutputSizeUser;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// A factual self-test observation. Reading it grants no local permission.
pub struct ReadinessObservation {
    pub format: String,
    pub revision: u32,
    pub workload_profile: crate::workload_contract::ProfileRef,
    pub workload_profile_probe_verified: bool,
    pub version: String,
    pub mechanism: String,
    pub provider_identity: String,
    pub control_service_identity: String,
    pub launcher_service_identity: String,
    pub observation_digest: String,
    pub success_child_status: Option<i32>,
    pub missing_target_child_status: Option<i32>,
    pub profile_child_status: Option<i32>,
    pub caller_envelope_digest: Option<String>,
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
}

impl ReadinessObservation {
    pub fn complete(&self) -> bool {
        self.format == "memcordon.runtime-readiness"
            && self.revision == 1
            && self.workload_profile
                == crate::workload_registry::BaselineProfile::LinuxUnixCreate.reference()
            && self.workload_profile_probe_verified
            && self.version == env!("CARGO_PKG_VERSION")
            && self.mechanism == "linux-pid-namespace-cgroup-v2"
            && self.provider_identity == "memcordon-sealed-agent-v2"
            && self.control_service_identity == "memcordon-sealed-agent.service:v2"
            && self.launcher_service_identity == "memcordon-sealed-launcher.service:v2"
            && self.native_facts_complete()
    }

    /// Shared measured lifecycle facts, without accepting a service or profile.
    /// Callers must separately validate the exact selected readiness role.
    pub fn native_facts_complete(&self) -> bool {
        valid_sha256(&self.observation_digest)
            && self.success_child_status == Some(0)
            && self.missing_target_child_status == Some(127)
            && self.profile_child_status == Some(0)
            && self
                .caller_envelope_digest
                .as_deref()
                .is_some_and(valid_sha256)
            && self
                .digest_facts()
                .is_ok_and(|digest| digest == self.observation_digest)
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
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("readiness observation exceeds byte bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let observation: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if !observation.complete() {
            return Err("readiness observation is incomplete or differs".into());
        }
        Ok(observation)
    }

    pub fn digest_facts(&self) -> Result<String, String> {
        let mut object = serde_json::to_value(self).map_err(|error| error.to_string())?;
        object
            .as_object_mut()
            .expect("readiness is a struct")
            .remove("observation_digest");
        let bytes = serde_json::to_vec(&object).map_err(|error| error.to_string())?;
        Ok(crate::workload_codec::hash_bytes(&bytes).into())
    }

    pub fn render(&self) -> String {
        serde_json::to_string(self).expect("readiness observation is serializable")
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == <Sha256 as OutputSizeUser>::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
