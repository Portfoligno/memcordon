#![cfg(target_os = "linux")]

use std::path::Path;

const STATE_ROOT: &str = "/var/lib/memcordon/sealed";
const CGROUP_ROOT: &str = "/sys/fs/cgroup/memcordon-sealed";

fn identity(byte: u8) -> String {
    format!("{:032x}", u128::from(byte) << 120)
}

fn root_entries(path: &Path) -> Vec<String> {
    let mut entries = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

#[test]
fn empty_recovery_inventory_allows_qualification_to_continue() {
    assert!(crate::linux::qualification::require_unambiguous_recovery(&[]).is_ok());
}

#[test]
fn ambiguous_recovery_inventory_is_reported_with_bounded_examples() {
    let ambiguous = (0_u8..18).map(identity).collect::<Vec<_>>();
    let error = crate::linux::qualification::require_unambiguous_recovery(&ambiguous)
        .expect_err("ambiguous recovery must block qualification");

    assert!(error.starts_with("MCSEALED-PROVIDER-UNAVAILABLE:"));
    assert!(error.contains("recovery-ambiguous-count=18"));
    for example in ambiguous.iter().take(16) {
        assert!(error.contains(example));
    }
    assert!(!error.contains(&ambiguous[16]));
    assert!(!error.contains(&ambiguous[17]));
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_recovery_removes_authenticated_stale_record_without_cgroup() {
    let identity = identity(0xa1);
    let record =
        crate::linux::attempt::AttemptRecord::create(identity.clone(), unsafe { libc::getpid() })
            .unwrap();
    record.transition("boundary-created").unwrap();
    let ambiguous = crate::linux::recovery::recover().unwrap();
    assert!(ambiguous.is_empty());
    assert!(!Path::new(STATE_ROOT).join(&identity).exists());
    assert!(!Path::new(CGROUP_ROOT).join(identity).exists());
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_recovery_quarantines_cgroup_without_authenticated_record() {
    let identity = identity(0xa2);
    let path = Path::new(CGROUP_ROOT).join(&identity);
    std::fs::create_dir(&path).unwrap();
    let ambiguous = crate::linux::recovery::recover().unwrap();
    assert!(
        ambiguous.iter().any(|candidate| candidate == &identity),
        "an unauthenticated cgroup must be quarantined"
    );
    assert!(path.exists(), "recovery must not kill by cgroup name alone");
    assert!(!Path::new(STATE_ROOT).join(&identity).exists());
    std::fs::remove_dir(path).unwrap();
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_recovery_blocks_capability_while_live_state_is_ambiguous() {
    let identity = identity(0xa3);
    let path = Path::new(CGROUP_ROOT).join(&identity);
    std::fs::create_dir(&path).unwrap();
    let state_before = root_entries(Path::new(STATE_ROOT));
    let cgroups_before = root_entries(Path::new(CGROUP_ROOT));
    let error = crate::linux::qualification::qualify_after_package_verification_for_test()
        .expect_err("ambiguous state must suppress sealed capability");
    assert!(
        error.starts_with("MCSEALED-PROVIDER-UNAVAILABLE:"),
        "unexpected qualification error: {error}"
    );
    assert!(
        error.contains(&identity),
        "ambiguous identity omitted: {error}"
    );
    assert_eq!(root_entries(Path::new(STATE_ROOT)), state_before);
    assert_eq!(root_entries(Path::new(CGROUP_ROOT)), cgroups_before);
    assert!(path.exists(), "qualification removed unauthenticated state");
    std::fs::remove_dir(path).unwrap();
}
