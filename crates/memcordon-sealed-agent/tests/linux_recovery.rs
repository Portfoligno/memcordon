#![cfg(target_os = "linux")]

use std::path::Path;

const STATE_ROOT: &str = "/var/lib/memcordon/sealed";
const CGROUP_ROOT: &str = "/sys/fs/cgroup/memcordon-sealed";

fn identity(byte: u8) -> String {
    format!("{:032x}", u128::from(byte) << 120)
}

#[test]
fn sealed_recovery_removes_authenticated_stale_record_without_cgroup() {
    let identity = identity(0xa1);
    let record =
        memcordon_sealed_agent::linux::attempt::AttemptRecord::create(identity.clone(), unsafe {
            libc::getpid()
        })
        .unwrap();
    record.transition("boundary-created").unwrap();
    let ambiguous = memcordon_sealed_agent::linux::recovery::recover().unwrap();
    assert!(ambiguous.is_empty());
    assert!(!Path::new(STATE_ROOT).join(identity).exists());
}

#[test]
fn sealed_recovery_quarantines_cgroup_without_authenticated_record() {
    let identity = identity(0xa2);
    let path = Path::new(CGROUP_ROOT).join(&identity);
    std::fs::create_dir(&path).unwrap();
    let ambiguous = memcordon_sealed_agent::linux::recovery::recover().unwrap();
    assert!(
        ambiguous.iter().any(|candidate| candidate == &identity),
        "an unauthenticated cgroup must be quarantined"
    );
    assert!(path.exists(), "recovery must not kill by cgroup name alone");
    std::fs::remove_dir(path).unwrap();
}

#[test]
fn sealed_recovery_blocks_capability_while_live_state_is_ambiguous() {
    let identity = identity(0xa3);
    let path = Path::new(CGROUP_ROOT).join(&identity);
    std::fs::create_dir(&path).unwrap();
    let error = memcordon_sealed_agent::linux::qualification::qualify()
        .expect_err("ambiguous state must suppress sealed capability");
    assert!(error.contains("AMBIGUOUS") || error.contains("UNAVAILABLE"));
    std::fs::remove_dir(path).unwrap();
}
