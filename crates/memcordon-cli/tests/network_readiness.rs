#[path = "../src/bin/memcordon-sealed-agent/network_readiness.rs"]
mod network_readiness;

use memcordon_core::runtime_readiness::ReadinessObservation;

fn measured_fixture() -> ReadinessObservation {
    let mut observation = ReadinessObservation {
        format: "memcordon.runtime-readiness".into(),
        revision: 1,
        workload_profile: memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate
            .reference(),
        workload_profile_probe_verified: true,
        version: env!("CARGO_PKG_VERSION").into(),
        mechanism: "linux-pid-namespace-cgroup-v2".into(),
        provider_identity: "memcordon-sealed-agent-v2".into(),
        control_service_identity: "memcordon-sealed-agent.service:v2".into(),
        launcher_service_identity: "memcordon-sealed-launcher.service:v2".into(),
        observation_digest: String::new(),
        success_child_status: Some(0),
        missing_target_child_status: Some(127),
        profile_child_status: Some(0),
        caller_envelope_digest: Some(
            memcordon_core::workload_codec::hash_bytes(b"caller envelope").into(),
        ),
        unified_cgroup_v2: true,
        private_cgroup_subtree: true,
        clone3: true,
        clone3_into_cgroup: true,
        pid_namespace: true,
        mount_namespace: true,
        cgroup_namespace: true,
        pidfd: true,
        close_range: true,
        guardian_outside_boundary: true,
        target_gated: true,
        assignment_verified: true,
        inherited_descriptors_verified: true,
        spawn_error_reporting_verified: true,
        frontend_loss_authority_verified: true,
        cgroup_kill: true,
        workload_empty: true,
        helpers_reaped: true,
        boundary_retired: true,
        recovery_complete: true,
        split_control_and_launcher_services: true,
        launcher_no_new_privs_disabled: true,
        caller_mount_namespace_reproduction_verified: true,
        caller_no_new_privs_reproduction_verified: true,
        caller_capability_bounding_set_reproduction_verified: true,
        initial_provider_capabilities_absent: true,
        credential_transition_disposition: "preserve-caller-envelope".into(),
    };
    observation.observation_digest = observation.digest_facts().unwrap();
    observation
}

fn network_fixture() -> ReadinessObservation {
    let mut observation = measured_fixture();
    observation.format = "memcordon.network-launcher-readiness".into();
    observation.workload_profile = network_readiness::profile();
    observation.launcher_service_identity = "memcordon-sealed-network-launcher.service:v2".into();
    observation.observation_digest = observation.digest_facts().unwrap();
    observation
}

#[test]
fn network_measurements_cannot_be_replayed_as_ordinary_readiness() {
    let ordinary = measured_fixture();
    assert!(ordinary.complete());
    assert!(ReadinessObservation::parse(ordinary.render().as_bytes()).is_ok());
    assert!(!network_readiness::complete(&ordinary));
    let network = network_fixture();
    assert!(network_readiness::complete(&network));
    assert!(!network.complete());
    assert!(ReadinessObservation::parse(network.render().as_bytes()).is_err());
    for field in ["format", "workload_profile", "launcher_service_identity"] {
        let mut value = serde_json::to_value(&network).unwrap();
        value[field] = serde_json::to_value(&ordinary).unwrap()[field].clone();
        let mut mutant: ReadinessObservation = serde_json::from_value(value).unwrap();
        mutant.observation_digest = mutant.digest_facts().unwrap();
        assert!(!network_readiness::complete(&mutant), "substituted {field}");
    }
}

#[test]
fn network_role_still_requires_every_native_fact_and_actual_profile_exit() {
    let network = network_fixture();
    let value = serde_json::to_value(&network).unwrap();
    for (field, fact) in value.as_object().unwrap() {
        if fact == &serde_json::Value::Bool(true) {
            let mut mutant = value.clone();
            mutant[field] = serde_json::Value::Bool(false);
            let mut mutant: ReadinessObservation = serde_json::from_value(mutant).unwrap();
            mutant.observation_digest = mutant.digest_facts().unwrap();
            assert!(
                !network_readiness::complete(&mutant),
                "missing native fact {field}"
            );
        }
    }
    let mut failed = network.clone();
    failed.profile_child_status = Some(125);
    failed.observation_digest = failed.digest_facts().unwrap();
    assert!(!network_readiness::complete(&failed));
    let mut copied = network;
    copied.caller_envelope_digest =
        Some(memcordon_core::workload_codec::hash_bytes(b"substituted caller envelope").into());
    assert!(
        !network_readiness::complete(&copied),
        "copied digest accepted"
    );
}

#[cfg(unix)]
#[test]
fn native_family_results_require_selected_allows_and_exact_ipv6_denial() {
    use network_readiness::{Family, validate_creation};
    for family in [Family::Unix, Family::Ipv4, Family::RouteNetlink] {
        assert!(validate_creation(family, Ok(()), libc::EAFNOSUPPORT).is_ok());
        for errno in [libc::EAFNOSUPPORT, libc::EPERM, libc::EACCES] {
            assert!(validate_creation(family, Err(errno), libc::EAFNOSUPPORT).is_err());
        }
    }
    assert!(validate_creation(Family::Ipv6, Err(libc::EAFNOSUPPORT), libc::EAFNOSUPPORT).is_ok());
    assert!(validate_creation(Family::Ipv6, Ok(()), libc::EAFNOSUPPORT).is_err());
    for errno in [libc::EPERM, libc::EACCES] {
        assert!(validate_creation(Family::Ipv6, Err(errno), libc::EAFNOSUPPORT).is_err());
    }
}
