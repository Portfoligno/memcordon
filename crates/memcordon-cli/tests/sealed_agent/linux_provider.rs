#[test]
fn qualification_fails_closed_without_root_provider() {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } != 0 {
        let error = crate::linux::qualification::qualify().unwrap_err();
        assert!(error.starts_with("MCSEALED-PROVIDER-IDENTITY:"));
    }
}

#[test]
fn qualification_receipt_requires_complete_retirement() {
    #[cfg(target_os = "linux")]
    {
        let digest = "0".repeat(64);
        let incomplete = crate::linux::qualification::QualificationReceipt {
            schema_version: 2,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
            provider_identity: "memcordon-sealed-agent-v2".to_owned(),
            control_service_identity: "memcordon-sealed-agent.service:v2".to_owned(),
            launcher_service_identity: "memcordon-sealed-launcher.service:v2".to_owned(),
            receipt_digest: digest.clone(),
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
            recovery_complete: false,
            split_control_and_launcher_services: true,
            launcher_no_new_privs_disabled: true,
            caller_mount_namespace_reproduction_verified: true,
            caller_no_new_privs_reproduction_verified: true,
            caller_capability_bounding_set_reproduction_verified: true,
            initial_provider_capabilities_absent: true,
            credential_transition_disposition: "preserve-caller-envelope".to_owned(),
            setid_transition_certification_digest: digest.clone(),
            sudo_transition_certification_digest: digest,
            post_transition_cgroup_membership_verified: true,
            post_transition_pid_namespace_verified: true,
            post_transition_cleanup_verified: true,
            recursive_provider_request_rejected: true,
        };
        assert!(!incomplete.complete());
    }
}

#[test]
fn gated_target_cgroup_readback_uses_mountinfo_filesystem_type() {
    #[cfg(target_os = "linux")]
    {
        let hidden = "36 25 0:32 / /sys rw,nosuid,nodev - tmpfs tmpfs rw\n";
        assert!(!crate::linux::launch::cgroup_mount_visible(hidden).unwrap());

        let exposed = "37 25 0:29 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw\n";
        assert!(crate::linux::launch::cgroup_mount_visible(exposed).unwrap());

        let malformed = "37 25 0:29 / /sys/fs/cgroup rw,nosuid,nodev cgroup2 cgroup rw\n";
        assert!(crate::linux::launch::cgroup_mount_visible(malformed).is_err());
    }
}
