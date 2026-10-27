use super::*;

const FD_TEST_WAIT: Duration = Duration::from_secs(30);
const ORIGINAL_MEMBER: &[u8] = b"original owned runtime image member";

fn empty_report(output: &Path, deadline: Instant) -> ImageCaseReport {
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

fn selected_definition(members: &[String]) -> RuntimeImageDefinitionV1 {
    let entries: Vec<_> = members
        .iter()
        .map(|member| {
            serde_json::json!({
                "kind":"regular", "path":member, "size":ORIGINAL_MEMBER.len(),
                "sha256":hex(&Sha256::digest(ORIGINAL_MEMBER)), "executable":true,
            })
        })
        .collect();
    serde_json::from_value(serde_json::json!({
        "format":"memcordon.runtime-image", "revision":1, "image_id":"native-fd-custody",
        "target":if cfg!(target_arch = "aarch64") {"aarch64-unknown-linux-gnu"} else {"x86_64-unknown-linux-gnu"},
        "entries":entries, "entrypoints":[{"id":"owned-readiness", "path":members[0]}],
        "library_directories":[], "startup_environment":[],
    })).unwrap()
}

fn native_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, Vec<String>) {
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "native image custody requires original root authority"
    );
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let source = root.path().join("original-source");
    let output = root.path().join("evidence");
    std::fs::create_dir(&output).unwrap();
    let relative_parent = PathBuf::from("lib").join("native").join("selected");
    std::fs::create_dir_all(source.join(&relative_parent)).unwrap();
    let members: Vec<_> = (0..12)
        .map(|index| {
            let member = relative_parent.join(index.to_string());
            std::fs::write(source.join(&member), ORIGINAL_MEMBER).unwrap();
            std::fs::set_permissions(source.join(&member), std::fs::Permissions::from_mode(0o555))
                .unwrap();
            member.to_str().unwrap().to_owned()
        })
        .collect();
    (root, source, output, members)
}

#[test]
#[ignore = "requires Linux root and actual administrative image copy/capture custody"]
fn original_inventory_copy_and_repeated_capture_share_complete_native_witnesses() {
    let (root, source, output, members) = native_fixture();
    let deadline = Instant::now() + FD_TEST_WAIT;
    let mut report = empty_report(&output, deadline);
    let definition = selected_definition(&members);
    let diagnostic = output.join("original-diagnostic.json");
    let diagnostic_index = report.file_custody.len();
    retain(
        &diagnostic,
        b"retained original diagnostic",
        &mut report.file_custody,
    )
    .unwrap();
    let diagnostic_identity = report.file_custody[diagnostic_index].metadata().unwrap();
    let mut previous_count = 0;
    for case in ["neighbor-import", "distinct-case"] {
        let copied = root.path().join(case);
        copy_inventory(&source, &copied, &definition, &mut report, deadline).unwrap();
        let after_copy = report.image_custody.owner_count();
        assert!(
            after_copy > previous_count,
            "distinct case copies keep distinct original owners"
        );
        previous_count = after_copy;
        for _ in 0..4 {
            for member in &members {
                assert_eq!(
                    capture_manifest_member(
                        &copied,
                        &definition,
                        member,
                        None,
                        true,
                        &mut report,
                        deadline
                    )
                    .unwrap(),
                    hex(&Sha256::digest(ORIGINAL_MEMBER))
                );
            }
            assert_eq!(
                report.image_custody.owner_count(),
                after_copy,
                "inventory observations must not add physical owners for the same objects"
            );
        }
    }
    assert!(report.image_partial_files.iter().all(Option::is_none));
    let physical: std::collections::BTreeSet<_> = report
        .image_directory_witnesses
        .iter()
        .flatten()
        .chain(report.image_file_witnesses.iter())
        .map(|owner| (owner.role, owner.path.clone()))
        .collect();
    assert_eq!(physical.len(), report.image_custody.owner_count());
    let root_metadata = std::fs::metadata("/").unwrap();
    for chain in report.image_directory_witnesses.clone() {
        let first = report
            .image_custody
            .borrow(chain.first().unwrap(), deadline)
            .unwrap()
            .metadata()
            .unwrap();
        assert_eq!(
            (first.dev(), first.ino()),
            (root_metadata.dev(), root_metadata.ino())
        );
        for owner in &chain {
            assert!(
                report
                    .image_custody
                    .borrow(owner, deadline)
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .is_dir()
            );
        }
        assert!(chain.len() > root.path().components().count());
    }
    let still_original = report.file_custody[diagnostic_index].metadata().unwrap();
    assert_eq!(
        (still_original.dev(), still_original.ino()),
        (diagnostic_identity.dev(), diagnostic_identity.ino())
    );
    let mut bytes = Vec::new();
    image_custody::PositionalReader::new(&report.file_custody[diagnostic_index])
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"retained original diagnostic");
    assert_eq!(report.file_custody.len(), diagnostic_index + 1);
    assert!(
        report.observations.is_empty(),
        "no runtime import result is fabricated by custody tests"
    );
    report.finish_custody(deadline).unwrap();
}

#[test]
#[ignore = "requires Linux root and actual administrative image copy/capture custody"]
fn fresh_capture_measures_mutations_and_rejects_replaced_original_file_and_directory() {
    let (root, source, output, members) = native_fixture();
    let deadline = Instant::now() + FD_TEST_WAIT;
    let mut report = empty_report(&output, deadline);
    let definition = selected_definition(&members);
    let copied = root.path().join("selected-case");
    copy_inventory(&source, &copied, &definition, &mut report, deadline).unwrap();
    let after_copy = report.image_custody.owner_count();
    let selected = copied.join(&members[0]);
    let mut changed = ORIGINAL_MEMBER.to_vec();
    changed[0] ^= 0x20;
    std::fs::write(&selected, &changed).unwrap();
    std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o777)).unwrap();
    let observed = capture_manifest_member(
        &copied,
        &definition,
        &members[0],
        None,
        false,
        &mut report,
        deadline,
    )
    .unwrap();
    assert_eq!(observed, hex(&Sha256::digest(&changed)));
    assert_ne!(observed, hex(&Sha256::digest(ORIGINAL_MEMBER)));
    assert_eq!(report.image_custody.owner_count(), after_copy);
    assert!(
        capture_manifest_member(
            &copied,
            &definition,
            &members[0],
            None,
            true,
            &mut report,
            deadline
        )
        .is_err()
    );
    let original_owner = report
        .image_file_witnesses
        .iter()
        .find(|owner| owner.identity.inode == std::fs::metadata(&selected).unwrap().ino())
        .unwrap()
        .clone();
    let original_lease = report
        .image_custody
        .borrow(&original_owner, deadline)
        .unwrap();
    let saved = selected.with_extension("held-original");
    std::fs::rename(&selected, &saved).unwrap();
    std::fs::write(&selected, &changed).unwrap();
    assert!(
        capture_manifest_member(
            &copied,
            &definition,
            &members[0],
            None,
            false,
            &mut report,
            deadline
        )
        .is_err()
    );
    assert_eq!(
        original_lease.metadata().unwrap().ino(),
        std::fs::metadata(&saved).unwrap().ino()
    );
    assert_eq!(report.image_custody.owner_count(), after_copy);
    let moved = root.path().join("held-original-case");
    std::fs::rename(&copied, &moved).unwrap();
    std::fs::create_dir(&copied).unwrap();
    assert!(
        report
            .hold_image_ancestry(&copied, false, deadline)
            .is_err()
    );
    assert_eq!(report.image_custody.owner_count(), after_copy);
    let alias = root.path().join("symlink-case");
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    assert!(report.hold_image_ancestry(&alias, false, deadline).is_err());
    assert!(
        report
            .image_file_witnesses
            .iter()
            .all(|owner| owner.role
                == crate::release::linux_image_custodian::Role::AdministrativeFile)
    );
    report.finish_custody(deadline).unwrap();
}

#[test]
#[ignore = "requires Linux root and actual administrative image copy/capture custody"]
fn failed_manifest_copy_retains_original_source_and_exact_partial_output_owner() {
    let (root, source, output, members) = native_fixture();
    let deadline = Instant::now() + FD_TEST_WAIT;
    let mut report = empty_report(&output, deadline);
    let mut raw = serde_json::to_value(selected_definition(&members)).unwrap();
    raw["entries"][0]["sha256"] = hex(&Sha256::digest(b"different approved bytes")).into();
    let wrong_manifest: RuntimeImageDefinitionV1 = serde_json::from_value(raw).unwrap();
    let destination = root.path().join("failed-copy");
    assert!(
        copy_inventory(
            &source,
            &destination,
            &wrong_manifest,
            &mut report,
            deadline
        )
        .is_err()
    );
    let partial = destination.join(&members[0]);
    let named = std::fs::symlink_metadata(&partial).unwrap();
    let partials: Vec<_> = report
        .image_partial_files
        .iter()
        .filter_map(Option::as_ref)
        .collect();
    assert_eq!(partials.len(), 1);
    let held = partials[0].metadata().unwrap();
    assert!(held.is_file());
    assert_eq!(held.nlink(), 1);
    assert_eq!(
        (held.dev(), held.ino(), held.len()),
        (named.dev(), named.ino(), ORIGINAL_MEMBER.len() as u64)
    );
    assert_eq!(std::fs::read(&partial).unwrap(), ORIGINAL_MEMBER);
    let original = std::fs::metadata(source.join(&members[0])).unwrap();
    let original_witness = report
        .image_file_witnesses
        .iter()
        .find(|owner| {
            (owner.identity.device, owner.identity.inode) == (original.dev(), original.ino())
        })
        .unwrap()
        .clone();
    let original_lease = report
        .image_custody
        .borrow(&original_witness, deadline)
        .unwrap();
    assert_eq!(
        (
            original_lease.metadata().unwrap().dev(),
            original_lease.metadata().unwrap().ino()
        ),
        (original.dev(), original.ino())
    );
    assert!(report.image_custody.owner_count() > 0);
    assert!(report.observations.is_empty());
    assert!(
        report.file_custody.is_empty(),
        "a partial output is never accepted as a completed artifact"
    );
    report.finish_custody(deadline).unwrap();
}
