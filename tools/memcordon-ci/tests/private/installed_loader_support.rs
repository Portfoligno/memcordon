use super::*;
use crate::release::{artifacts, distribution::TargetDistribution};
use crate::windows_causal_acceptance::InstalledChannel;
use crate::windows_installed_cases::SelectedArtifact;
use std::time::{Duration, Instant};

#[cfg(windows)]
#[test]
fn retained_fixture_survives_original_temporary_payload_and_rejects_substitution() {
    let temporary = tempfile::tempdir().unwrap();
    let source_path = temporary.path().join("fixture.exe");
    let bytes = pe([0x64, 0x86], 23);
    std::fs::write(&source_path, &bytes).unwrap();
    let source = SelectedArtifact {
        path: source_path,
        sha256: artifacts::checksum(&bytes),
    };
    let durable = tempfile::tempdir().unwrap();
    let selected = durable.path().canonicalize().unwrap();
    let (fixture, held) = retain_fixture(&selected, &source).unwrap();
    assert_eq!(fixture.path, selected.join("memcordon-test-fixture.exe"));
    assert_eq!(fixture.sha256, source.sha256);
    drop(held);
    drop(temporary);
    let held = crate::windows_readiness_adapter::hold_artifact(
        &fixture.path,
        Some(&fixture.sha256),
        512 * 1024 * 1024,
    )
    .unwrap();
    assert_eq!(held.bytes, bytes);
    drop(held);
    std::fs::write(&fixture.path, b"substituted").unwrap();
    assert!(
        crate::windows_readiness_adapter::hold_artifact(
            &fixture.path,
            Some(&fixture.sha256),
            512 * 1024 * 1024
        )
        .is_err()
    );
}

fn pe(machine: [u8; 2], marker: u8) -> Vec<u8> {
    let mut bytes = vec![marker; 72];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
    bytes[64..68].copy_from_slice(b"PE\0\0");
    bytes[68..70].copy_from_slice(&machine);
    bytes
}
pub(crate) fn fixture() -> (
    tempfile::TempDir,
    BuildSourceIdentity,
    InstalledWindowsPayload,
    RuntimeManifest,
) {
    let directory = tempfile::tempdir().unwrap();
    let source = BuildSourceIdentity::Working {
        commit: "a".repeat(40),
        version: "0.5.8-dev".parse().unwrap(),
    };
    let distribution = TargetDistribution {
        target: "x86_64-pc-windows-msvc".into(),
        features: vec!["windows-sealed-runtime".into()],
        binaries: vec![
            "memcordon".into(),
            "memcordon-sealed-agent".into(),
            "memcordon-target-desktop-bootstrap".into(),
            "memcordon-session-broker".into(),
        ],
        units: vec![],
    };
    let bytes = pe([0x64, 0x86], 0);
    let mut components = vec![];
    for (name, role) in distribution.binaries.iter().zip([
        RuntimeComponentRole::PublicCli,
        RuntimeComponentRole::SealedAgent,
        RuntimeComponentRole::DesktopBootstrap,
        RuntimeComponentRole::SessionBroker,
    ]) {
        let path = format!("{name}.exe");
        std::fs::write(directory.path().join(&path), &bytes).unwrap();
        components.push(super::super::target::runtime_component(role, path, &bytes));
    }
    let manifest = RuntimeManifest::windows(
        source.version().to_string(),
        source.commit().into(),
        distribution.target.clone(),
        components,
    )
    .unwrap();
    std::fs::write(
        directory.path().join("runtime-manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let fixture = SelectedArtifact {
        path: directory.path().join("fixture.exe"),
        sha256: artifacts::checksum(&bytes),
    };
    std::fs::write(&fixture.path, &bytes).unwrap();
    let archive = SelectedArtifact {
        path: directory.path().join("original.zip"),
        sha256: artifacts::checksum(b"selected original"),
    };
    std::fs::write(&archive.path, b"selected original").unwrap();
    let payload = InstalledWindowsPayload::from_materialized(
        InstalledChannel::NativeBundle,
        &source,
        &distribution,
        vec![archive],
        directory.path(),
        fixture,
        &directory.path().join("installed"),
        directory.path().join("observations"),
    )
    .unwrap();
    (directory, source, payload, manifest)
}
fn assessment(payload: &InstalledWindowsPayload) -> InstalledWindowsAssessment {
    InstalledWindowsAssessment {
        channel: payload.channel,
        target: payload.target.clone(),
        source_commit: payload.source_commit.clone(),
        version: payload.version.clone(),
        artifacts: payload.artifacts.clone(),
        public_smoke_before: Ok(()),
        cases: vec![],
        positive_cases: vec![],
        positive_suite: Err("original restricted loader failed".into()),
        loss_cases: vec![],
        loss_suite: Ok(()),
        capacity_cases: vec![],
        capacity_suite: Ok(()),
        refusal_cases: vec![],
        refusal_suite: Ok(()),
        retained_state_recovery: Ok(()),
        public_smoke_after: Ok(()),
        package_upgrade: Ok(()),
        package_uninstall: Ok(()),
    }
}
fn deadlines() -> WindowsLeaseDeadlines {
    let now = Instant::now();
    WindowsLeaseDeadlines {
        work: now + Duration::from_secs(30),
        cleanup: now + Duration::from_secs(60),
        work_deadline_unix_millis: 30_000,
        cleanup_deadline_unix_millis: 60_000,
    }
}

#[test]
fn actual_source_original_retirement_and_catalog_are_required() {
    let (_owned, source, payload, _) = fixture();
    let original = assessment(&payload);
    admit(&source, &payload, &original, deadlines()).unwrap();
    assert!(!original.accepted());
    for mutation in [
        "source",
        "version",
        "target",
        "channel",
        "artifacts",
        "uninstall",
        "positive",
    ] {
        let mut changed = original.clone();
        match mutation {
            "source" => changed.source_commit = "b".repeat(40),
            "version" => changed.version = "0.0.1".into(),
            "target" => changed.target = "aarch64-pc-windows-msvc".into(),
            "channel" => changed.channel = InstalledChannel::CargoPackage,
            "artifacts" => changed.artifacts[0].sha256 = "b".repeat(64),
            "uninstall" => changed.package_uninstall = Err("retirement uncertain".into()),
            "positive" => changed.positive_suite = Ok(()),
            _ => unreachable!(),
        }
        assert!(
            admit(&source, &payload, &changed, deadlines()).is_err(),
            "{mutation}"
        );
    }
    let foreign = BuildSourceIdentity::Working {
        commit: "b".repeat(40),
        version: source.version().clone(),
    };
    assert!(admit(&foreign, &payload, &original, deadlines()).is_err());
    for mutation in ["work-expired", "crossed-monotonic", "crossed-wall"] {
        let mut clock = deadlines();
        match mutation {
            "work-expired" => clock.work = Instant::now(),
            "crossed-monotonic" => clock.work = clock.cleanup,
            "crossed-wall" => clock.work_deadline_unix_millis = clock.cleanup_deadline_unix_millis,
            _ => unreachable!(),
        }
        assert!(
            admit(&source, &payload, &original, clock).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn only_original_native_bootstrap_replaces_the_measured_support_role() {
    let (_owned, _, _, actor) = fixture();
    let original = pe([0x64, 0x86], 7);
    let mixed = mixed_manifest(&actor, &original).unwrap();
    assert_eq!(mixed.components.len(), actor.components.len());
    for (before, after) in actor.components.iter().zip(&mixed.components) {
        if before.role == RuntimeComponentRole::DesktopBootstrap {
            assert_eq!(after.sha256, artifacts::checksum(&original));
            assert_ne!(after.sha256, before.sha256);
            assert_eq!(after.path, before.path);
        } else {
            assert_eq!(
                serde_json::to_value(before).unwrap(),
                serde_json::to_value(after).unwrap()
            );
        }
    }
    assert_eq!(mixed.source_commit, actor.source_commit);
    assert_eq!(mixed.version, actor.version);
    assert_eq!(mixed.target, actor.target);
    assert!(mixed_manifest(&actor, &pe([0x64, 0xaa], 7)).is_err());
    assert!(mixed_manifest(&actor, b"not a native image").is_err());
    let mut missing = actor.clone();
    missing
        .components
        .retain(|component| component.role != RuntimeComponentRole::DesktopBootstrap);
    assert!(mixed_manifest(&missing, &original).is_err());
}

#[test]
fn persisted_cleanup_clock_cannot_renew_or_cross_boot_and_wall_cutoffs() {
    let clock = CleanupClock {
        domain: "original-boot".into(),
        observed_millis: 100,
        cleanup_millis: 1100,
        cleanup_unix_millis: 5000,
    };
    let read = |domain: &str, millis| crate::ci_operation_time::ClockReading {
        domain: domain.into(),
        millis,
    };
    assert_eq!(
        clock.remaining(read("original-boot", 200), 4500).unwrap(),
        Duration::from_millis(500)
    );
    assert_eq!(
        clock.remaining(read("original-boot", 1000), 4000).unwrap(),
        Duration::from_millis(100)
    );
    for (domain, boot, wall) in [
        ("foreign-boot", 200, 4000),
        ("original-boot", 99, 4000),
        ("original-boot", 1100, 4000),
        ("original-boot", 200, 5000),
    ] {
        assert!(clock.remaining(read(domain, boot), wall).is_err());
    }
    let acquired = CleanupClock::acquire(deadlines(), read("original-boot", 100)).unwrap();
    assert_eq!(acquired.cleanup_unix_millis, 60_000);
    assert!(acquired.cleanup_millis <= 60_100);
    let mut expired = deadlines();
    expired.cleanup = Instant::now();
    assert!(CleanupClock::acquire(expired, read("original-boot", 100)).is_err());
    assert!(CleanupClock::acquire(deadlines(), read("original-boot", u64::MAX)).is_err());
}
