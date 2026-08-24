#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(cgroup) = std::str::from_utf8(data) {
        #[cfg(target_os = "linux")]
        let _ = memcordon_sealed_agent::linux::service::cgroup_membership_is_sealed(cgroup);
        #[cfg(not(target_os = "linux"))]
        let _ = cgroup.lines().count();
    }
});
