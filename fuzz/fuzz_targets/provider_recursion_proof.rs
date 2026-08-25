#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(target_os = "linux")]
#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/cgroup_membership.rs"]
mod cgroup_membership;

fuzz_target!(|data: &[u8]| {
    if let Ok(cgroup) = std::str::from_utf8(data) {
        #[cfg(target_os = "linux")]
        let _ = cgroup_membership::is_sealed(cgroup);
        #[cfg(not(target_os = "linux"))]
        let _ = cgroup.lines().count();
    }
});
