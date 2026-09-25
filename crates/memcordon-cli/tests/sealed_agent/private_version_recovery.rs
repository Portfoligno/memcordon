#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

const ATTEMPT: &str = "edededededededededededededededed";

#[test]
fn newer_unresolved_attempt_and_interrupted_transition_survive_recovery() {
    let temporary = TempDir::new().unwrap();
    let state = temporary.path().join("state");
    let cgroups = temporary.path().join("cgroups");
    std::fs::create_dir(&state).unwrap();
    std::fs::create_dir(&cgroups).unwrap();
    std::fs::create_dir(cgroups.join(ATTEMPT)).unwrap();

    let canonical = state.join(ATTEMPT);
    let body = format!("version=5\ncgroup={ATTEMPT}\nstate=release-intent\n");
    let digest: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(&canonical, format!("{body}digest={digest}\n")).unwrap();
    let ambiguous = crate::linux::recovery::recover_test_roots(&state, &cgroups).unwrap();
    assert_eq!(ambiguous, [ATTEMPT.to_owned()]);
    assert!(
        canonical.exists(),
        "unknown canonical journal must remain available"
    );
    assert!(
        cgroups.join(ATTEMPT).exists(),
        "owned boundary cannot be declared retired"
    );

    let interrupted = canonical.with_extension("new");
    std::fs::write(
        &interrupted,
        format!("version=5\ncgroup={ATTEMPT}\nstate=retiring\n"),
    )
    .unwrap();
    std::fs::set_permissions(&interrupted, std::fs::Permissions::from_mode(0o600)).unwrap();

    let ambiguous = crate::linux::recovery::recover_test_roots(&state, &cgroups).unwrap();
    assert!(ambiguous.contains(&ATTEMPT.to_owned()));
    assert!(ambiguous.contains(&format!("{ATTEMPT}.new")));
    assert!(
        canonical.exists(),
        "unknown canonical journal must remain available"
    );
    assert!(
        interrupted.exists(),
        "unknown transition must not be rolled back"
    );
    assert!(
        cgroups.join(ATTEMPT).exists(),
        "owned boundary cannot be declared retired"
    );
}

#[test]
fn version_axes_do_not_share_numbers_by_name() {
    assert_eq!(crate::protocol::PROTOCOL_VERSION, 3);
    assert_eq!(crate::protocol::NETWORK_PROTOCOL_VERSION, 4);
    assert_eq!(memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION, 10);
    assert_eq!(
        memcordon_core::report_v11::PRIVATE_EXECUTION_REPORT_SCHEMA_V11,
        11
    );
    assert_eq!(memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION, 2);
    assert_eq!(memcordon_core::WINDOWS_PRIVATE_PROTOCOL_VERSION, 2);
}

#[test]
fn private_probe_fixture_selector_is_closed_and_has_no_caller_arguments() {
    use crate::linux::private_qualification::ProbeFixtureKindV1;

    for (index, (_, name)) in crate::linux::qualification::HOST_PROBE_CATALOG_V1
        .iter()
        .enumerate()
    {
        let kind = ProbeFixtureKindV1::at(index).expect("catalogue case has a typed fixture");
        assert_eq!(ProbeFixtureKindV1::named(OsStr::new(name)), Some(kind));
        let command = crate::linux::private_target::PrivateExecArguments::for_probe_fixture(kind)
            .expect("typed fixture has fixed argv");
        let argv = command.argv();
        assert_eq!(argv.len(), 3);
        assert_eq!(argv[0].to_bytes(), b"/usr/libexec/memcordon-sealed-agent");
        assert_eq!(argv[1].to_bytes(), b"private-probe-fixture");
        assert_eq!(argv[2].to_bytes(), name.as_bytes());
        assert!(command.environment().is_empty());
    }
    assert!(
        ProbeFixtureKindV1::at(crate::linux::qualification::HOST_PROBE_CATALOG_V1.len()).is_none()
    );
    for invalid in ["../../bin/sh", "TCP-LISTENER", "", "unknown-fixture"] {
        assert!(ProbeFixtureKindV1::named(OsStr::new(invalid)).is_none());
    }
}

#[test]
fn private_probe_identity_never_selects_root_or_supplementary_groups() {
    use crate::linux::execution_identity::ResolvedTargetIdentity;

    assert!(ResolvedTargetIdentity::for_probe_account(0, 1001).is_err());
    assert!(ResolvedTargetIdentity::for_probe_account(1001, 0).is_err());
    let identity = ResolvedTargetIdentity::for_probe_account(1001, 1002).unwrap();
    assert_eq!(identity.uid(), 1001);
    assert_eq!(identity.gid(), 1002);
    assert!(identity.groups().is_empty());
    assert!(!identity.delegated());
}
