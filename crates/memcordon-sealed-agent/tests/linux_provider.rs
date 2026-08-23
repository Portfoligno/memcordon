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
