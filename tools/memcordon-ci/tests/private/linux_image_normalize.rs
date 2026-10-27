use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

fn retained(root: &Path, bytes: &[u8]) -> (PathBuf, std::fs::File) {
    let path = root.join("image.bin");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    (path, file)
}

#[test]
fn baseline_expected_bytes_follow_only_declared_finite_aliases() {
    let digest = hex::encode(Sha256::digest(b"baseline"));
    let raw = serde_json::json!({"format":"memcordon.runtime-image","revision":1,"image_id":"baseline","target":"x86_64-unknown-linux-gnu",
        "entries":[{"kind":"symlink","path":"bin/alias","target":"bin/image"},
        {"kind":"regular","path":"bin/image","size":b"baseline".len(),"sha256":digest,"executable":true}],
        "entrypoints":[{"id":"owned-readiness","path":"bin/alias"}],"library_directories":[],"startup_environment":[]});
    let image = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(
        baseline_regular(&image, "bin/alias").unwrap(),
        (b"baseline".len() as u64, digest)
    );
    assert!(baseline_regular(&image, "bin/absent").is_err());
    let mut cycle = raw;
    cycle["entries"][0]["target"] = "bin/alias".into();
    let image = serde_json::from_value(cycle).unwrap();
    assert!(baseline_regular(&image, "bin/alias").is_err());
}

#[test]
#[ignore = "requires original Linux root/65534 image-artifact custody"]
fn image_role_streams_above_ordinary_cap_without_materializing_bytes() {
    let root = tempfile::tempdir().unwrap();
    let (path, file) = retained(root.path(), &[]);
    let length = 128 * 1024 * 1024 + 1;
    file.set_len(length).unwrap();
    file.sync_all().unwrap();
    let mut hash = Sha256::new();
    let zeroes = [0u8; 64 * 1024];
    let mut remaining = length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(zeroes.len() as u64)).unwrap();
        hash.update(&zeroes[..count]);
        remaining -= count as u64;
    }
    let expected = hex::encode(hash.finalize());
    let mut artifacts = BTreeMap::new();
    assert!(capture(root.path(), &path, &mut artifacts).is_err());
    assert!(artifacts.is_empty());
    let reference = capture_image(
        root.path(),
        &path,
        &mut artifacts,
        (length, &expected),
        &[file],
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(artifacts[&reference].length, length);
    assert_eq!(artifacts[&reference].sha256, expected);
    assert!(length < memcordon_readiness_verifier::MAX_ARTIFACT_BYTES);
}

#[test]
#[ignore = "requires original Linux root/65534 image-artifact custody"]
fn image_capture_rejects_exact_size_digest_substitution_symlink_and_global_overflow() {
    let root = tempfile::tempdir().unwrap();
    let bytes = b"retained original image";
    let (path, held) = retained(root.path(), bytes);
    let digest = hex::encode(Sha256::digest(bytes));
    let mut artifacts = BTreeMap::new();
    let owner = [held];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    assert!(
        capture_image(
            root.path(),
            &path,
            &mut artifacts,
            (bytes.len() as u64 + 1, &digest),
            &owner,
            deadline
        )
        .is_err()
    );
    let wrong = hex::encode(Sha256::digest(b"different bytes"));
    assert!(
        capture_image(
            root.path(),
            &path,
            &mut artifacts,
            (bytes.len() as u64, &wrong),
            &owner,
            deadline
        )
        .is_err()
    );
    assert!(
        capture_image(
            root.path(),
            &path,
            &mut artifacts,
            (
                memcordon_readiness_verifier::MAX_ARTIFACT_BYTES + 1,
                &digest
            ),
            &owner,
            deadline
        )
        .is_err()
    );
    assert!(
        capture_image(
            root.path(),
            &path,
            &mut artifacts,
            (bytes.len() as u64, &digest),
            &owner,
            std::time::Instant::now()
        )
        .is_err()
    );
    let replacement = root.path().join("replacement.bin");
    std::fs::write(&replacement, bytes).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    assert!(
        capture_image(
            root.path(),
            &path,
            &mut artifacts,
            (bytes.len() as u64, &digest),
            &owner,
            deadline
        )
        .is_err()
    );
    let alias = root.path().join("alias.bin");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(
        capture_image(
            root.path(),
            &alias,
            &mut artifacts,
            (bytes.len() as u64, &digest),
            &owner,
            deadline
        )
        .is_err()
    );
    assert!(artifacts.is_empty());
}

#[test]
#[ignore = "requires original Linux root/65534 image-artifact custody"]
fn selected_mutation_and_original_baseline_keep_distinct_exact_hashes() {
    let source = tempfile::tempdir().unwrap();
    let baseline = tempfile::tempdir().unwrap();
    let (changed, changed_owner) = retained(source.path(), b"changed");
    let (original, original_owner) = retained(baseline.path(), b"initial");
    let changed_hash = hex::encode(Sha256::digest(b"changed"));
    let original_hash = hex::encode(Sha256::digest(b"initial"));
    let mut changed_artifacts = BTreeMap::new();
    let mut original_artifacts = BTreeMap::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    capture_image(
        source.path(),
        &changed,
        &mut changed_artifacts,
        (b"changed".len() as u64, &changed_hash),
        &[changed_owner],
        deadline,
    )
    .unwrap();
    capture_image(
        baseline.path(),
        &original,
        &mut original_artifacts,
        (b"initial".len() as u64, &original_hash),
        &[original_owner],
        deadline,
    )
    .unwrap();
    assert_ne!(
        changed_artifacts["image.bin"].sha256,
        original_artifacts["image.bin"].sha256
    );
}
