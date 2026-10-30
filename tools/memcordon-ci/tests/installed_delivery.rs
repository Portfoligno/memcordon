use memcordon_ci::release::installed_tests::{Delivery, InstalledTestArgs};
use std::path::PathBuf;

fn arguments(delivery: Delivery) -> InstalledTestArgs {
    InstalledTestArgs {
        delivery,
        target: Some(PathBuf::from("selected/target")),
        packages: Some(PathBuf::from("selected/packages")),
        prepared: None,
        diagnostics: PathBuf::from("diagnostics/installed"),
    }
}

#[test]
fn delivered_channels_cannot_relabel_candidate_inputs_as_public() {
    for delivery in [Delivery::CandidateNative, Delivery::CandidateCargo] {
        let mut args = arguments(delivery);
        args.validate().unwrap();
        args.prepared = Some("prepared".into());
        assert!(args.validate().is_err());
        args.prepared = None;
        args.packages = None;
        assert!(args.validate().is_err());
    }
    for delivery in [Delivery::PublicNative, Delivery::PublicCargo] {
        let mut args = arguments(delivery);
        assert!(args.validate().is_err());
        args.target = None;
        args.packages = None;
        assert!(args.validate().is_err());
        args.prepared = Some("prepared".into());
        args.validate().unwrap();
    }
}

#[test]
fn diagnostic_writes_cannot_enter_selected_payloads() {
    let mut args = arguments(Delivery::CandidateNative);
    args.diagnostics = "selected/target/diagnostics".into();
    assert!(args.validate().is_err());
    args.diagnostics = "selected".into();
    assert!(args.validate().is_err());
    args.diagnostics = "selected/reports/../target/diagnostics".into();
    assert!(args.validate().is_err());
}

#[cfg(unix)]
#[test]
fn diagnostic_parent_alias_cannot_enter_selected_payload() {
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("selected");
    std::fs::create_dir(&selected).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&selected, &alias).unwrap();
    let mut args = arguments(Delivery::CandidateNative);
    args.target = Some(selected);
    args.diagnostics = alias.join("diagnostics");
    assert!(args.validate().is_err());
}
