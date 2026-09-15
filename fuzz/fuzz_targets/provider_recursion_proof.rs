#![no_main]

use libfuzzer_sys::fuzz_target;

use memcordon_core::sealed_provider::cgroup_membership;

fuzz_target!(|data: &[u8]| {
    if let Ok(cgroup) = std::str::from_utf8(data) {
        if let Ok(sealed) = cgroup_membership::is_sealed(cgroup) {
            let unified = cgroup
                .lines()
                .find_map(|line| {
                    let (_, rest) = line.split_once(':')?;
                    let (controllers, path) = rest.split_once(':')?;
                    controllers.is_empty().then_some(path)
                })
                .expect("accepted membership has a unified hierarchy");
            assert_eq!(
                sealed,
                unified
                    .split('/')
                    .any(|component| component == "memcordon-sealed")
            );
            let duplicate = format!("{cgroup}0::/\n");
            assert!(cgroup_membership::is_sealed(&duplicate).is_err());
            assert!(cgroup_membership::is_sealed(cgroup.trim_end_matches('\n')).is_err());
        }
    }
});
