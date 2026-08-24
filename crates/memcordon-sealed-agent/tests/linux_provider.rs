#[test]
fn qualification_fails_closed_without_root_provider() {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } != 0 {
        let error = memcordon_sealed_agent::linux::qualification::qualify().unwrap_err();
        assert!(error.starts_with("MCSEALED-PROVIDER-IDENTITY:"));
    }
}

#[test]
fn qualification_receipt_requires_complete_retirement() {
    #[cfg(target_os = "linux")]
    {
        let incomplete = memcordon_sealed_agent::linux::qualification::QualificationReceipt {
            schema_version: 1,
            mechanism: "linux-pid-namespace-cgroup-v1".to_owned(),
            provider_identity: "fixture".to_owned(),
            receipt_digest: "fixture".to_owned(),
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
        };
        assert!(!incomplete.complete());
    }
}

#[test]
fn gated_target_cgroup_readback_uses_mountinfo_filesystem_type() {
    #[cfg(target_os = "linux")]
    {
        let hidden = "36 25 0:32 / /sys rw,nosuid,nodev - tmpfs tmpfs rw\n";
        assert!(!memcordon_sealed_agent::linux::launch::cgroup_mount_visible(hidden).unwrap());

        let exposed = "37 25 0:29 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw\n";
        assert!(memcordon_sealed_agent::linux::launch::cgroup_mount_visible(exposed).unwrap());

        let malformed = "37 25 0:29 / /sys/fs/cgroup rw,nosuid,nodev cgroup2 cgroup rw\n";
        assert!(memcordon_sealed_agent::linux::launch::cgroup_mount_visible(malformed).is_err());
    }
}
