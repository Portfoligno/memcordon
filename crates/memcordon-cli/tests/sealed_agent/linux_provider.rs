#![cfg(target_os = "linux")]

#[test]
fn readiness_fails_closed_without_root_provider() {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } != 0 {
        let error = crate::linux::qualification::observe_readiness().unwrap_err();
        assert!(error.starts_with("MCSEALED-PROVIDER-IDENTITY:"));
    }
}

#[test]
#[cfg(feature = "test-support")]
fn readiness_observation_requires_complete_retirement() {
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    {
        let observation = super::linux_service::readiness();
        assert!(observation.complete());
        for field in [
            "recovery_complete",
            "workload_empty",
            "helpers_reaped",
            "boundary_retired",
        ] {
            let mut value = serde_json::to_value(&observation).unwrap();
            value[field] = false.into();
            let mut incomplete: memcordon_core::runtime_readiness::ReadinessObservation =
                serde_json::from_value(value).unwrap();
            incomplete.observation_digest = incomplete.digest_facts().unwrap();
            assert!(
                !incomplete.complete(),
                "{field} must remain a real observation"
            );
            assert!(
                memcordon_core::runtime_readiness::ReadinessObservation::parse(
                    incomplete.render().as_bytes()
                )
                .is_err()
            );
        }
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
