use super::*;
use std::os::unix::fs::{chown, symlink};

const NATIVE_TEST_WAIT: Duration = Duration::from_secs(15);
const IMAGE_BYTES: &[u8] = b"original administrative image evidence";

fn require_root() {
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "native fixture requires original root authority"
    );
}

fn report(output: &Path, deadline: Instant) -> ImageCaseReport {
    ImageCaseReport {
        observations: Vec::new(),
        export_observations: Vec::new(),
        retained_images: Vec::new(),
        launches: Vec::new(),
        prepared_owners: Vec::new(),
        descendant_owners: Vec::new(),
        importer_owners: Vec::new(),
        export_worker_owners: Vec::new(),
        directory_custody: Vec::new(),
        file_custody: Vec::new(),
        image_custody: custody_fixture::custody(deadline),
        image_directory_witnesses: Vec::new(),
        image_file_witnesses: Vec::new(),
        image_partial_files: Vec::new(),
        administrative_export_handles: Vec::new(),
        export_helpers: Vec::new(),
        failures: Vec::new(),
        failure_diagnostic: None,
        failure_retention_error: None,
        first_failure_phase: None,
        first_failure_scenario: None,
        failure_journal: None,
        emergency_descriptors: Vec::new(),
        custody_phase: std::cell::Cell::new(CustodyPhase::Collecting),
        output: output.to_owned(),
        cleanup_deadline: deadline,
        cleanup_attempts: 0,
    }
}

fn definition() -> RuntimeImageDefinitionV1 {
    serde_json::from_value(serde_json::json!({
        "format":"memcordon.runtime-image", "revision":1, "image_id":"native-evidence-ancestry",
        "target": if cfg!(target_arch = "aarch64") { "aarch64-unknown-linux-gnu" } else { "x86_64-unknown-linux-gnu" },
        "entries":[{"kind":"regular", "path":"image.bin", "size":IMAGE_BYTES.len(), "sha256":hex(&Sha256::digest(IMAGE_BYTES)), "executable":true}],
        "entrypoints":[{"id":"owned-readiness", "path":"image.bin"}], "library_directories":[], "startup_environment":[]
    })).unwrap()
}

struct Fixture {
    _root: tempfile::TempDir,
    admin: PathBuf,
    evidence: PathBuf,
    output: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        require_root();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let admin = root.path().join("administrative");
        let evidence = root.path().join("external-evidence");
        let output = evidence.join("image-cases");
        std::fs::create_dir(&admin).unwrap();
        std::fs::create_dir(&evidence).unwrap();
        std::fs::create_dir(&output).unwrap();
        for directory in [&evidence, &output] {
            chown(directory, Some(65534), Some(65534)).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o750)).unwrap();
        }
        std::fs::write(admin.join("image.bin"), IMAGE_BYTES).unwrap();
        std::fs::set_permissions(
            admin.join("image.bin"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        Self {
            _root: root,
            admin,
            evidence,
            output,
        }
    }
}

#[test]
#[ignore = "requires Linux root and protected uid65534 external evidence custody"]
fn administrative_source_captures_into_original_external_owner_evidence_only() {
    let fixture = Fixture::new();
    let deadline = Instant::now() + NATIVE_TEST_WAIT;
    let destination = fixture.output.join("baseline-entrypoint.bin");
    let mut captured = report(&fixture.output, deadline);
    let digest = capture_manifest_member(
        &fixture.admin,
        &definition(),
        "image.bin",
        Some(&destination),
        true,
        &mut captured,
        deadline,
    )
    .unwrap();
    assert_eq!(digest, hex(&Sha256::digest(IMAGE_BYTES)));
    assert_eq!(std::fs::read(&destination).unwrap(), IMAGE_BYTES);
    let named = std::fs::symlink_metadata(&destination).unwrap();
    assert!(named.is_file());
    assert_eq!(named.nlink(), 1);
    assert_eq!(named.mode() & 0o222, 0);
    assert!(captured.file_custody.iter().any(|owner| {
        let metadata = owner.metadata().unwrap();
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            metadata.len(),
        ) == (
            named.dev(),
            named.ino(),
            named.uid(),
            named.gid(),
            named.mode(),
            IMAGE_BYTES.len() as u64,
        )
    }));
    let directory_witnesses: Vec<_> = captured
        .image_directory_witnesses
        .iter()
        .flatten()
        .cloned()
        .collect();
    assert!(directory_witnesses.iter().any(|owner| {
        captured
            .image_custody
            .borrow(owner, deadline)
            .unwrap()
            .metadata()
            .unwrap()
            .uid()
            == 65534
    }));
    assert!(captured.observations.is_empty());
    assert!(captured.failures.is_empty());

    // The same externally owned directory remains inadmissible as runtime
    // source authority, even with identical source bytes and a protected mode.
    std::fs::write(fixture.evidence.join("image.bin"), IMAGE_BYTES).unwrap();
    let rejected = fixture.output.join("external-source.bin");
    assert!(
        capture_manifest_member(
            &fixture.evidence,
            &definition(),
            "image.bin",
            Some(&rejected),
            true,
            &mut captured,
            deadline
        )
        .is_err()
    );
    assert!(!rejected.exists());
    assert!(hold_ancestry(&fixture.evidence).is_err());
    captured.finish_custody(deadline).unwrap();
}

#[test]
#[ignore = "requires Linux root and protected uid65534 external evidence custody"]
fn evidence_destinations_refuse_writable_symlink_outside_and_expired_paths() {
    let fixture = Fixture::new();
    let deadline = Instant::now() + NATIVE_TEST_WAIT;
    let writable = fixture.output.join("writable");
    let outside = fixture.evidence.join("outside");
    std::fs::create_dir(&writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let alias = fixture.output.join("alias");
    symlink(&outside, &alias).unwrap();
    for (destination, cutoff) in [
        (writable.join("baseline.bin"), deadline),
        (alias.join("baseline.bin"), deadline),
        (outside.join("baseline.bin"), deadline),
        (fixture.output.join("expired.bin"), Instant::now()),
    ] {
        let mut captured = report(&fixture.output, deadline);
        assert!(
            capture_manifest_member(
                &fixture.admin,
                &definition(),
                "image.bin",
                Some(&destination),
                true,
                &mut captured,
                cutoff
            )
            .is_err()
        );
        assert!(
            !destination.exists(),
            "rejected destination must not be created"
        );
        assert!(captured.observations.is_empty());
        captured.finish_custody(deadline).unwrap();
    }
    assert_eq!(
        std::fs::read(fixture.admin.join("image.bin")).unwrap(),
        IMAGE_BYTES
    );
}

#[test]
#[ignore = "requires Linux root and protected uid65534 external evidence custody"]
fn original_evidence_ancestry_rejects_same_mode_owner_replacement() {
    let fixture = Fixture::new();
    let deadline = Instant::now() + NATIVE_TEST_WAIT;
    let held = hold_evidence_ancestry(&fixture.output, deadline).unwrap();
    verify_evidence_ancestry(&fixture.output, &held, deadline).unwrap();
    let moved = fixture.evidence.join("held-original-output");
    std::fs::rename(&fixture.output, &moved).unwrap();
    std::fs::create_dir(&fixture.output).unwrap();
    chown(&fixture.output, Some(65534), Some(65534)).unwrap();
    std::fs::set_permissions(&fixture.output, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(verify_evidence_ancestry(&fixture.output, &held, deadline).is_err());
    assert!(held.last().unwrap().metadata().unwrap().is_dir());
    assert!(std::fs::read_dir(&fixture.output).unwrap().next().is_none());
}
