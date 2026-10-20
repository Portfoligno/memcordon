use super::*;
use crate::sha256;

fn origin(artifact: &Artifact) -> ProducerOrigin {
    ProducerOrigin {
        job: "native-windows-x64".into(),
        run_id: "1".into(),
        run_attempt: 1,
        artifact_id: "2".into(),
        artifact_sha256: artifact.sha256.clone(),
        bundle_artifact: artifact.path.clone(),
        source_commit: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        version: "0.5.8-dev".into(),
        manifest_sha256: "c".repeat(64),
        repository: Some("Portfoligno/memcordon".into()),
    }
}

fn artifact(root: &Path, name: &str, bytes: &[u8]) -> Artifact {
    std::fs::write(root.join(name), bytes).unwrap();
    Artifact {
        path: name.into(),
        length: bytes.len() as u64,
        sha256: sha256(bytes),
    }
}

#[test]
fn only_unique_indexed_producer_roles_receive_container_allowance() {
    let root = tempfile::tempdir().unwrap();
    let bundle = artifact(root.path(), "producer.zip", b"container");
    let raw = artifact(root.path(), "raw.bin", b"raw");
    let role = origin(&bundle);
    // Exercise the production admission algorithm with scaled finite limits.
    let custody = Custody::with_limits(
        root.path(),
        &[bundle.clone(), raw.clone()],
        std::slice::from_ref(&role),
        3,
        12,
    )
    .unwrap();
    assert!(!custody.bytes.contains_key(&bundle.path));
    assert!(custody.archives[&bundle.path].bytes.is_none());
    assert_eq!(custody.bytes(&raw.path).unwrap(), b"raw");
    let mut held = custody.archive(&bundle.path).unwrap();
    let mut actual = Vec::new();
    held.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, b"container");
    assert!(custody.archive(&raw.path).is_err());
    assert!(Custody::with_limits(root.path(), std::slice::from_ref(&bundle), &[], 3, 12).is_err());
    assert!(
        Custody::with_limits(
            root.path(),
            std::slice::from_ref(&bundle),
            &[role.clone(), role.clone()],
            3,
            12
        )
        .is_err()
    );
    assert!(Custody::with_limits(root.path(), &[], std::slice::from_ref(&role), 3, 12).is_err());
    let mut wrong = role.clone();
    wrong.artifact_sha256 = sha256(b"foreign");
    assert!(
        Custody::with_limits(root.path(), std::slice::from_ref(&bundle), &[wrong], 3, 12).is_err()
    );
    // The archive and raw member together remain charged to the same total.
    assert!(
        Custody::with_limits(
            root.path(),
            &[bundle.clone(), raw],
            std::slice::from_ref(&role),
            3,
            11
        )
        .is_err()
    );
    assert!(
        Custody::with_limits(root.path(), std::slice::from_ref(&bundle), &[role], 3, 8).is_err()
    );
    assert!(Custody::new(root.path(), &[bundle]).is_ok());
}

#[test]
fn held_container_rejects_mutation_and_named_replacement() {
    let root = tempfile::tempdir().unwrap();
    let bundle = artifact(root.path(), "producer.zip", b"container");
    let custody = Custody::for_evidence(
        root.path(),
        std::slice::from_ref(&bundle),
        &[origin(&bundle)],
    )
    .unwrap();
    #[cfg(unix)]
    {
        std::fs::write(root.path().join(&bundle.path), b"different").unwrap();
        assert!(custody.archive(&bundle.path).is_err());
        std::fs::write(root.path().join(&bundle.path), b"container").unwrap();
        std::fs::rename(root.path().join(&bundle.path), root.path().join("old.zip")).unwrap();
        std::fs::write(root.path().join(&bundle.path), b"container").unwrap();
        assert!(custody.archive(&bundle.path).is_err());
    }
    #[cfg(windows)]
    {
        // The held share mode prevents replacement or a new writer.
        assert!(std::fs::write(root.path().join(&bundle.path), b"different").is_err());
        assert!(custody.archive(&bundle.path).is_ok());
    }
}

#[test]
fn streaming_collection_enforces_observed_length_digest_and_no_aliases() {
    let root = tempfile::tempdir().unwrap();
    let bundle = artifact(root.path(), "producer.zip", b"container");
    assert!(collect_confined(root.path(), &bundle.path, 8, false).is_err());
    let mut wrong_length = bundle.clone();
    wrong_length.length += 1;
    assert!(
        Custody::for_evidence(
            root.path(),
            &[wrong_length.clone()],
            &[origin(&wrong_length)]
        )
        .is_err()
    );
    let mut wrong_digest = bundle.clone();
    wrong_digest.sha256 = sha256(b"foreign");
    assert!(
        Custody::for_evidence(
            root.path(),
            &[wrong_digest.clone()],
            &[origin(&wrong_digest)]
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            root.path().join(&bundle.path),
            root.path().join("alias.zip"),
        )
        .unwrap();
        let mut alias = bundle.clone();
        alias.path = "alias.zip".into();
        assert!(Custody::for_evidence(root.path(), &[alias.clone()], &[origin(&alias)]).is_err());
        std::fs::hard_link(root.path().join(&bundle.path), root.path().join("hard.zip")).unwrap();
        assert!(
            Custody::for_evidence(
                root.path(),
                std::slice::from_ref(&bundle),
                &[origin(&bundle)]
            )
            .is_err()
        );
    }
}
