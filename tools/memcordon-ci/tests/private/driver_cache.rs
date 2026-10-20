use super::*;

fn recipe() -> Recipe {
    Recipe {
        abi: ABI,
        image_format: FORMAT,
        package: "memcordon-ci".into(),
        binary: "memcordon-ci".into(),
        profile: "release".into(),
        toolchain: "1.97.1".into(),
        features: Vec::new(),
        companions: Vec::new(),
        hosts: vec![host_name().into()],
    }
}

#[test]
fn image_miss_still_discovers_and_emits_both_compilation_requests() {
    let mut requests = Vec::new();
    let mut outputs = std::collections::BTreeMap::new();
    context_requests(
        || Ok(None),
        |complete| {
            requests.push(complete);
            Ok(crate::cache_snapshot::TransferRequest {
                key: if complete {
                    "complete-key"
                } else {
                    "partial-key"
                }
                .into(),
                prefix: "compatible-prefix".into(),
                path: PathBuf::from(if complete {
                    "target/complete-inbox"
                } else {
                    "target/partial-inbox"
                }),
            })
        },
        |values| {
            outputs.extend(
                values
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), value.clone())),
            );
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(requests, [true, false]);
    assert_eq!(outputs["image-restore"], "false");
    assert_eq!(outputs["compiled-complete-restore"], "true");
    assert_eq!(outputs["compiled-partial-restore"], "true");
    assert_eq!(outputs["compiled-complete-key"], "complete-key");
    assert_eq!(outputs["compiled-partial-key"], "partial-key");
    assert_eq!(outputs["compiled-complete-inbox"], "target/complete-inbox");
    assert_eq!(outputs["compiled-partial-inbox"], "target/partial-inbox");
}

fn fixture(root: &Path, class: ImageClass, key: &str) -> Result<()> {
    let from = root.join("built");
    std::fs::create_dir_all(&from)?;
    std::fs::write(from.join(executable()), b"actual image bytes\n")?;
    copy_image(root, &from, IMAGE_IN, &recipe(), class, key)?;
    Ok(())
}

#[test]
fn exact_image_requires_class_source_host_recipe_and_member_bytes() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), ImageClass::Current, "current-source").unwrap();
    let validate = || {
        validate_image(
            root.path(),
            IMAGE_IN,
            &recipe(),
            ImageClass::Current,
            Some("current-source"),
        )
    };
    assert!(validate().is_ok());
    assert!(
        validate_image(
            root.path(),
            IMAGE_IN,
            &recipe(),
            ImageClass::Bootstrap,
            None
        )
        .is_err()
    );
    assert!(
        validate_image(
            root.path(),
            IMAGE_IN,
            &recipe(),
            ImageClass::Current,
            Some("different-source")
        )
        .is_err()
    );
    let manifest = root.path().join(IMAGE_IN).join(MANIFEST);
    let original = std::fs::read(&manifest).unwrap();
    for field in ["host", "recipe"] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value[field] = "different".into();
        std::fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(validate().is_err(), "mismatched {field} accepted");
    }
    std::fs::write(&manifest, original).unwrap();
    std::fs::write(
        root.path().join(IMAGE_IN).join(executable()),
        b"changed bytes\n",
    )
    .unwrap();
    assert!(validate().is_err());
}

#[test]
fn image_refuses_partial_extraction_extra_companion_and_duplicate_metadata() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), ImageClass::Current, "key").unwrap();
    let directory = root.path().join(IMAGE_IN);
    std::fs::write(directory.join("undeclared.dll"), b"extra\n").unwrap();
    assert!(
        validate_image(
            root.path(),
            IMAGE_IN,
            &recipe(),
            ImageClass::Current,
            Some("key")
        )
        .is_err()
    );
    std::fs::remove_file(directory.join("undeclared.dll")).unwrap();
    let manifest = directory.join(MANIFEST);
    let original = std::fs::read_to_string(&manifest).unwrap();
    let duplicate = original.replacen("{", "{\"abi\":1,", 1);
    std::fs::write(&manifest, duplicate).unwrap();
    assert!(
        validate_image(
            root.path(),
            IMAGE_IN,
            &recipe(),
            ImageClass::Current,
            Some("key")
        )
        .is_err()
    );
    std::fs::write(&manifest, original).unwrap();
    std::fs::remove_file(directory.join(executable())).unwrap();
    assert!(
        validate_image(
            root.path(),
            IMAGE_IN,
            &recipe(),
            ImageClass::Current,
            Some("key")
        )
        .is_err()
    );
}

#[test]
fn mutation_never_deletes_running_image_root() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let executable = std::env::current_exe().unwrap();
    let directory = executable.parent().unwrap().strip_prefix(root).unwrap();
    assert!(reset_directory(root, directory.to_str().unwrap()).is_err());
    assert!(executable.is_file());
}

#[cfg(unix)]
#[test]
fn image_member_and_ancestor_symlinks_are_never_followed() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), ImageClass::Current, "key").unwrap();
    let image = root.path().join(IMAGE_IN).join(executable());
    std::fs::remove_file(&image).unwrap();
    std::os::unix::fs::symlink(root.path().join("built").join(executable()), &image).unwrap();
    assert!(
        validate_image(
            root.path(),
            IMAGE_IN,
            &recipe(),
            ImageClass::Current,
            Some("key")
        )
        .is_err()
    );
    let other = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(other.path().join("target")).unwrap();
    std::os::unix::fs::symlink(
        root.path().join("target/ci-transfer"),
        other.path().join("target/ci-transfer"),
    )
    .unwrap();
    assert!(image_directory(other.path(), IMAGE_IN).is_err());
}

#[test]
fn actual_failed_managed_compiler_settles_and_selects_only_partial_work() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("src")).unwrap();
    std::fs::create_dir_all(root.path().join("seed/src")).unwrap();
    std::fs::write(root.path().join("Cargo.toml"),"[package]\nname=\"memcordon-ci\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ntiny-seed={path=\"seed\"}\n").unwrap();
    std::fs::write(
        root.path().join("seed/Cargo.toml"),
        "[package]\nname=\"tiny-seed\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("seed/src/lib.rs"),
        "pub fn seed() -> bool { true }\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("src/main.rs"),
        "fn main() { let _: u8 = tiny_seed::seed(); }\n",
    )
    .unwrap();
    std::fs::write(root.path().join("Cargo.lock"),"version = 4\n[[package]]\nname=\"memcordon-ci\"\nversion=\"0.1.0\"\ndependencies=[\"tiny-seed\"]\n[[package]]\nname=\"tiny-seed\"\nversion=\"0.1.0\"\n").unwrap();
    let outcome = managed_compilation(root.path(), &recipe());
    assert!(!outcome.is_ok());
    assert_eq!(
        outcome.writers(),
        crate::work_outcome::WriterSettlement::Settled
    );
    let target = root
        .path()
        .join("target/ci-driver-build")
        .join(host_name())
        .join("release/deps");
    assert!(
        std::fs::read_dir(target).unwrap().any(|entry| entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|extension| extension == "rlib")),
        "real dependency compilation left no reusable object"
    );
    assert_eq!(
        crate::segment_cache::compilation_retention(
            true,
            true,
            true,
            outcome.writers(),
            outcome.is_ok()
        ),
        crate::segment_cache::RetentionDecision::Partial
    );
}

#[test]
fn compiler_probe_uncertainty_does_not_invent_a_source_writer_or_hide_failure() {
    use crate::work_outcome::{WorkOutcome, WriterSettlement};
    let probe = WorkOutcome::observed(
        Err(error("native compiler probe unresolved")),
        WriterSettlement::Unknown,
    );
    let mut attempted = false;
    let result = finish_with_source(probe, WriterSettlement::NotStarted, |source| {
        attempted = true;
        assert_eq!(source.writers(), WriterSettlement::NotStarted);
        assert!(source.writers().permits_reading());
        Ok(())
    });
    assert!(attempted);
    let failure = result.unwrap_err();
    assert!(crate::work_outcome::has_unresolved_owner(&failure));
    assert!(
        failure
            .to_string()
            .contains("native compiler probe unresolved")
    );
    let result = finish_with_source(
        WorkOutcome::observed(Ok(()), WriterSettlement::Settled),
        WriterSettlement::Settled,
        |_| {
            WorkOutcome::<()>::observed(
                Err(error("source reader unresolved")),
                WriterSettlement::Unknown,
            )
            .into_result()
        },
    );
    assert!(crate::work_outcome::has_unresolved_owner(
        &result.unwrap_err()
    ));
}

#[test]
fn actual_startup_protocol_requires_exact_supported_abi_format_and_host() {
    let bytes = serde_json::to_vec(&Protocol {
        abi: ABI,
        image_format: FORMAT,
        host: host_name().into(),
    })
    .unwrap();
    assert!(validate_protocol(&bytes).is_ok());
    for field in ["abi", "image_format", "host"] {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value[field] = if field == "host" {
            serde_json::json!("wrong-host")
        } else {
            serde_json::json!(999)
        };
        assert!(validate_protocol(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(validate_protocol(b"memcordon-ci 0.1.0\n").is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["new-command-list"] = serde_json::json!([]);
    assert!(validate_protocol(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn cleanup_removes_only_finite_inboxes_and_transfers_preserving_live_driver_roots() {
    let root = tempfile::tempdir().unwrap();
    for relative in [
        IMAGE_IN,
        IMAGE_OUT,
        BOOTSTRAP_OUT,
        CANDIDATE,
        BOOTSTRAP,
        CURRENT,
        "target/ci-driver-cold",
        "target/ci-driver-build",
    ] {
        std::fs::create_dir_all(root.path().join(relative)).unwrap();
        std::fs::write(root.path().join(relative).join("sentinel"), b"owned data\n").unwrap();
    }
    cleanup(root.path()).unwrap();
    for relative in [IMAGE_IN, IMAGE_OUT, BOOTSTRAP_OUT, CANDIDATE] {
        assert!(!root.path().join(relative).exists());
    }
    for relative in [
        BOOTSTRAP,
        CURRENT,
        "target/ci-driver-cold",
        "target/ci-driver-build",
    ] {
        assert_eq!(
            std::fs::read(root.path().join(relative).join("sentinel")).unwrap(),
            b"owned data\n"
        );
    }
}
