#![cfg(unix)]

use memcordon_ci::release::readiness_producer_seal::{
    Scope, publication_cutoff, publish_held, read_input, selected_paths,
};
use std::{
    fs::File,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
    time::{Duration, Instant},
};

#[test]
fn only_exact_selected_projection_paths_are_admitted() {
    let workspace = Path::new("/selected/workspace");
    let acquisition = workspace.join(".release/readiness-cell");
    let cell = acquisition.join("producer/cell.json");
    let output = acquisition.join("producer-packed/producer-manifest.json");
    selected_paths(workspace, &acquisition, &cell, &output).unwrap();
    for changed in [
        workspace.join("elsewhere"),
        workspace.join(".release/../readiness-cell"),
    ] {
        assert!(selected_paths(workspace, &changed, &cell, &output).is_err());
    }
    assert!(
        selected_paths(
            workspace,
            &acquisition,
            &cell,
            &acquisition.join("arbitrary.json")
        )
        .is_err()
    );
    assert!(
        selected_paths(
            workspace,
            &acquisition,
            &workspace.join("cell.json"),
            &output
        )
        .is_err()
    );
}

#[test]
fn held_publication_is_exact_readable_and_cannot_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let held = File::open(directory.path()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    publish_held(
        &held,
        b"{\"failed\":true}",
        held.metadata().unwrap().uid(),
        deadline,
        || Ok(()),
    )
    .unwrap();
    let output = directory.path().join("producer-manifest.json");
    assert_eq!(std::fs::read(&output).unwrap(), b"{\"failed\":true}\n");
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    assert!(
        publish_held(
            &held,
            b"replacement",
            held.metadata().unwrap().uid(),
            deadline,
            || Ok(())
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&output).unwrap(), b"{\"failed\":true}\n");
}

#[test]
fn failed_final_custody_check_removes_only_its_own_partial_output() {
    let directory = tempfile::tempdir().unwrap();
    let held = File::open(directory.path()).unwrap();
    let error = publish_held(
        &held,
        b"bounded failure report",
        held.metadata().unwrap().uid(),
        Instant::now() + Duration::from_secs(2),
        || Err("selected directory changed".into()),
    )
    .unwrap_err();
    assert!(error.contains("selected directory changed"));
    assert!(!directory.path().join("producer-manifest.json").exists());
    let output = directory.path().join("producer-manifest.json");
    let moved = directory.path().join("original-partial");
    assert!(
        publish_held(
            &held,
            b"original",
            held.metadata().unwrap().uid(),
            Instant::now() + Duration::from_secs(2),
            || {
                std::fs::rename(&output, &moved).unwrap();
                std::fs::write(&output, b"unrelated replacement").unwrap();
                Err("selected output replaced".into())
            }
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&output).unwrap(), b"unrelated replacement");
}

#[test]
fn source_reads_refuse_symlinks_hardlinks_and_oversized_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().canonicalize().unwrap();
    std::fs::create_dir(directory.path().join("inputs")).unwrap();
    let source = directory.path().join("inputs/identity.json");
    std::fs::write(&source, b"source-bound bytes").unwrap();
    assert_eq!(
        read_input(&workspace, Path::new("inputs/identity.json")).unwrap(),
        b"source-bound bytes"
    );
    symlink(&source, directory.path().join("inputs/alias.json")).unwrap();
    assert!(read_input(&workspace, Path::new("inputs/alias.json")).is_err());
    symlink(
        directory.path().join("inputs"),
        directory.path().join("linked"),
    )
    .unwrap();
    assert!(read_input(&workspace, Path::new("linked/identity.json")).is_err());
    std::fs::hard_link(&source, directory.path().join("inputs/second.json")).unwrap();
    assert!(read_input(&workspace, Path::new("inputs/identity.json")).is_err());
    let oversized = File::create(directory.path().join("inputs/oversized.json")).unwrap();
    oversized
        .set_len(memcordon_readiness_verifier::MAX_INDEX_BYTES as u64 + 1)
        .unwrap();
    assert!(read_input(&workspace, Path::new("inputs/oversized.json")).is_err());
}

#[test]
fn publication_cutoff_and_root_projection_custody_fail_closed() {
    assert!(publication_cutoff(0).is_err());
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(directory.path().join(".release/readiness-cell/producer")).unwrap();
    let acquisition = directory.path().join(".release/readiness-cell");
    let cell = acquisition.join("producer/cell.json");
    std::fs::write(&cell, b"{}").unwrap();
    let output = acquisition.join("producer-packed/producer-manifest.json");
    assert!(
        Scope::open(
            directory.path(),
            &acquisition,
            &cell,
            &output,
            u32::MAX,
            Instant::now() + Duration::from_secs(2)
        )
        .is_err()
    );
    let held = File::open(directory.path()).unwrap();
    assert!(
        publish_held(
            &held,
            b"late",
            held.metadata().unwrap().uid(),
            Instant::now(),
            || Ok(())
        )
        .is_err()
    );
    assert!(!directory.path().join("producer-manifest.json").exists());
}
