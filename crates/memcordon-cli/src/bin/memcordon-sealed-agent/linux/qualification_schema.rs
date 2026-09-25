use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::digest::OutputSizeUser;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReceipt {
    pub schema_version: u32,
    pub workload_profile: memcordon_core::workload_contract::ProfileRef,
    pub workload_profile_probe_verified: bool,
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
        self.schema_version == 3
            && self.workload_profile
                == memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate.reference()
            && self.workload_profile_probe_verified
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

/// A V4 host receipt can be qualified only against independently observed
/// native probe completions and the protected installed byte identity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeQualificationProbeV4 {
    pub profile: memcordon_core::workload_contract::ProfileRef,
    pub name: String,
    pub native_executed: bool,
    pub passed: bool,
    pub completion_digest: memcordon_core::DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReceiptV4 {
    pub schema_version: u32,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub boot_id: String,
    pub installed_runtime_manifest_sha256: memcordon_core::DiagnosticSha256,
    pub installed_agent_sha256: memcordon_core::DiagnosticSha256,
    pub installed_units: memcordon_core::package_inspection_v6::LinuxUnitHashesV6,
    pub filter_abi: String,
    pub filter_instruction_sha256: memcordon_core::DiagnosticSha256,
    pub profile_catalog_sha256: memcordon_core::DiagnosticSha256,
    pub host_prerequisites_digest: memcordon_core::DiagnosticSha256,
    pub native_run_digest: memcordon_core::DiagnosticSha256,
    pub probes: Vec<NativeQualificationProbeV4>,
    pub receipt_digest: memcordon_core::DiagnosticSha256,
}

pub struct TrustedQualificationProbeV4<'a> {
    pub profile: &'a memcordon_core::workload_contract::ProfileRef,
    pub name: &'a str,
    pub native_executed: bool,
    pub completion_digest: &'a memcordon_core::DiagnosticSha256,
}

pub struct TrustedQualificationReceiptV4<'a> {
    pub source_commit: &'a str,
    pub target: &'a str,
    pub boot_id: &'a str,
    pub installed_runtime_manifest_sha256: &'a memcordon_core::DiagnosticSha256,
    pub installed_agent_sha256: &'a memcordon_core::DiagnosticSha256,
    pub installed_units: &'a memcordon_core::package_inspection_v6::LinuxUnitHashesV6,
    pub filter_instruction_sha256: &'a memcordon_core::DiagnosticSha256,
    pub host_prerequisites_digest: &'a memcordon_core::DiagnosticSha256,
    pub native_run_digest: &'a memcordon_core::DiagnosticSha256,
    pub probes: &'a [TrustedQualificationProbeV4<'a>],
    pub receipt_sha256: &'a memcordon_core::DiagnosticSha256,
}

/// The installed host canary is a closed inventory. Release qualification has
/// its own, larger native catalogue; a receipt with arbitrary successful probe
/// names cannot qualify this host.
pub const HOST_PROBE_CATALOG_V1: &[(memcordon_core::workload_registry_v2::ProfileKindV2, &str)] = &[
    (
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        "descriptor_identity_filter_namespace",
    ),
    (
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        "frontend_guardian_loss_retirement",
    ),
    (
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        "namespace_port_sysctl_isolation",
    ),
    (
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        "target_exec_failure_retirement",
    ),
    (
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        "tcp_listener_client_competitor",
    ),
    (
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        "unix_creation_socketpair_denial",
    ),
    (
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        "wrong_family_protocol_denial",
    ),
    (
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxUnixCreateV1,
        "baseline_unix_success_retirement",
    ),
];

impl QualificationReceiptV4 {
    pub fn parse_and_validate(
        bytes: &[u8],
        trusted: &TrustedQualificationReceiptV4<'_>,
    ) -> Result<Self, String> {
        if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("V4 qualification receipt exceeds byte limit".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        if &memcordon_core::workload_codec::hash_bytes(bytes) != trusted.receipt_sha256 {
            return Err("V4 qualification receipt bytes differ from protected readback".into());
        }
        let receipt: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        receipt.validate(trusted)?;
        Ok(receipt)
    }

    pub fn validate(&self, trusted: &TrustedQualificationReceiptV4<'_>) -> Result<(), String> {
        use memcordon_core::workload_registry_v2::ProfileKindV2;
        let expected_abi = match trusted.target {
            "x86_64-unknown-linux-gnu" => "x86_64",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => return Err("V4 qualification target is not a supported native GNU ABI".into()),
        };
        if self.schema_version != 4
            || self.version != env!("CARGO_PKG_VERSION")
            || self.source_commit != trusted.source_commit
            || self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.target != trusted.target
            || self.boot_id != trusted.boot_id
            || !valid_boot_id(&self.boot_id)
            || self.installed_runtime_manifest_sha256 != *trusted.installed_runtime_manifest_sha256
            || self.installed_agent_sha256 != *trusted.installed_agent_sha256
            || self.installed_units != *trusted.installed_units
            || self.filter_abi != expected_abi
            || self.filter_instruction_sha256 != *trusted.filter_instruction_sha256
            || self.profile_catalog_sha256
                != memcordon_core::workload_discovery_v2::profile_catalog_digest_v2()
            || self.host_prerequisites_digest != *trusted.host_prerequisites_digest
            || self.native_run_digest != *trusted.native_run_digest
            || self.probes.len() != trusted.probes.len()
            || self.probes.len() != HOST_PROBE_CATALOG_V1.len()
        {
            return Err("V4 qualification host, boot, image or native run differs".into());
        }
        let private = ProfileKindV2::LinuxTcp4PrivateV1.reference();
        let baseline = ProfileKindV2::LinuxUnixCreateV1.reference();
        let mut saw_private = false;
        let mut saw_baseline = false;
        let mut previous: Option<(&str, &str)> = None;
        for ((probe, expected), (kind, name)) in self
            .probes
            .iter()
            .zip(trusted.probes)
            .zip(HOST_PROBE_CATALOG_V1)
        {
            let key = (probe.profile.id.as_str(), probe.name.as_str());
            if probe.name.is_empty()
                || probe.name.len() > 256
                || !probe.name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
                || previous.is_some_and(|prior| prior >= key)
                || probe.profile != *expected.profile
                || probe.name != expected.name
                || probe.profile != kind.reference()
                || probe.name != *name
                || !probe.native_executed
                || !probe.passed
                || !expected.native_executed
                || probe.completion_digest != *expected.completion_digest
            {
                return Err("V4 qualification probe inventory or completion differs".into());
            }
            saw_private |= probe.profile == private;
            saw_baseline |= probe.profile == baseline;
            if probe.profile != private && probe.profile != baseline {
                return Err("V4 qualification contains an unknown profile".into());
            }
            previous = Some(key);
        }
        if !saw_private || !saw_baseline || self.receipt_digest != self.canonical_digest()? {
            return Err("V4 qualification is incomplete or receipt digest differs".into());
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<memcordon_core::DiagnosticSha256, String> {
        let mut content = self.clone();
        content.receipt_digest = memcordon_core::DiagnosticSha256::from_bytes([0; 32]);
        Ok(memcordon_core::workload_codec::hash_bytes(
            &serde_json::to_vec(&content).map_err(|error| error.to_string())?,
        ))
    }
}

fn valid_boot_id(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && parts.iter().zip([8, 4, 4, 4, 12]).all(|(part, length)| {
            part.len() == length
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}
