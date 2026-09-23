use super::*;

fn record() -> CrateRecord {
    CrateRecord {
        name: "memcordon".into(),
        version: "1.2.3".into(),
        archive_sha256: "ab".repeat(32),
        canonical_tree_sha256: "cd".repeat(32),
        canonical_identity_sha256: "ef".repeat(32),
        vcs_commit: "a".repeat(40),
    }
}

#[test]
fn candidate_and_public_install_share_locked_child_topology() {
    let record = record();
    let consumer = Path::new("consumer");
    let install = consumer.join("install");
    let candidate = consumer.join("candidate").join("memcordon");
    let public = consumer_install_arguments(&record, None, &install);
    let local = consumer_install_arguments(&record, Some(&candidate), &install);
    assert_eq!(public.first(), local.first());
    let locked = |arguments: &[OsString]| {
        arguments
            .iter()
            .position(|argument| argument == "--locked")
            .unwrap()
    };
    assert_eq!(&public[locked(&public)..], &local[locked(&local)..]);
    assert!(
        public
            .windows(2)
            .any(|arguments| arguments == [OsString::from("--version"), OsString::from("1.2.3")])
    );
    assert!(local.windows(2).any(
        |arguments| arguments == [OsString::from("--path"), candidate.clone().into_os_string()]
    ));
    assert_eq!(install.parent(), Some(consumer));
}

#[test]
fn candidate_resolution_rejects_registry_wrong_version_and_unadmitted_paths() {
    let temporary = TempDir::new().unwrap();
    let candidate = temporary.path().join("candidate");
    let package = candidate.join("memcordon");
    fs::create_dir_all(&package).unwrap();
    fs::write(package.join("Cargo.toml"), "[package]\n").unwrap();
    let package = package.canonicalize().unwrap();
    let sources = CandidateSources {
        packages: BTreeMap::from([("memcordon".into(), ("1.2.3".into(), package.clone()))]),
        root: candidate.canonicalize().unwrap(),
    };
    let valid = serde_json::json!({"packages": [{"name":"memcordon", "version":"1.2.3", "source":null, "manifest_path":package.join("Cargo.toml")} ]});
    sources
        .validate_resolution(&serde_json::to_vec(&valid).unwrap(), "memcordon")
        .unwrap();
    for (field, value) in [
        (
            "source",
            serde_json::json!("registry+https://github.com/rust-lang/crates.io-index"),
        ),
        ("version", serde_json::json!("1.2.4")),
    ] {
        let mut invalid = valid.clone();
        invalid["packages"][0][field] = value;
        assert!(
            sources
                .validate_resolution(&serde_json::to_vec(&invalid).unwrap(), "memcordon")
                .is_err()
        );
    }
    let other = temporary.path().join("Cargo.toml");
    fs::write(&other, "[package]\n").unwrap();
    let mut invalid = valid.clone();
    invalid["packages"][0]["manifest_path"] = serde_json::to_value(other).unwrap();
    assert!(
        sources
            .validate_resolution(&serde_json::to_vec(&invalid).unwrap(), "memcordon")
            .is_err()
    );
    assert!(
        sources
            .validate_resolution(br#"{"packages":[]}"#, "memcordon")
            .is_err()
    );
}

#[test]
fn missing_bundle_retains_failure_evidence_with_trailing_newline() {
    let temporary = TempDir::new().unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let report = temporary.path().join("evidence").join("report.json");
    assert!(run(root, &temporary.path().join("missing"), &report).is_err());
    let bytes = fs::read(report).unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["passed"], false);
    assert_eq!(value["phase"], "bundle-admission");
    assert_eq!(value["native_qualified"], false);
}

#[test]
fn report_write_failure_preserves_primary_and_prevents_success() {
    let result = finish_report(
        Err(failure("qualification-primary")),
        Err(failure("report-secondary")),
    )
    .unwrap_err()
    .to_string();
    assert!(result.contains("primary=qualification-primary"));
    assert!(result.contains("report=report-secondary"));
    assert!(finish_report(Ok(()), Err(failure("cannot write evidence"))).is_err());
}

#[test]
fn bundle_admission_rejects_nonlocal_references_and_missing_files() {
    let temporary = TempDir::new().unwrap();
    fs::write(temporary.path().join("archive"), b"archive").unwrap();
    assert!(bundle_file(temporary.path(), Path::new("archive")).is_ok());
    for path in [
        Path::new("../archive"),
        Path::new("missing"),
        temporary.path(),
    ] {
        assert!(bundle_file(temporary.path(), path).is_err());
    }
}

#[cfg(unix)]
#[test]
fn bundle_admission_rejects_symlink_escape() {
    let temporary = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("archive"), b"archive").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("archive"),
        temporary.path().join("archive"),
    )
    .unwrap();
    assert!(bundle_file(temporary.path(), Path::new("archive")).is_err());
}

#[test]
fn bounded_admission_copy_rejects_oversize_archive() {
    let temporary = TempDir::new().unwrap();
    let input = temporary.path().join("input");
    fs::write(&input, b"oversized").unwrap();
    assert!(copy_bounded(&input, &temporary.path().join("output"), 2).is_err());
}

fn archive_fixture(directory: &Path, dirty: bool) -> (CrateRecord, PathBuf) {
    let path = directory.join("memcordon-core.crate");
    let vcs =
        serde_json::to_vec(&serde_json::json!({"git":{"sha1":"a".repeat(40), "dirty":dirty}}))
            .unwrap();
    let encoder = GzEncoder::new(File::create(&path).unwrap(), Compression::fast());
    let mut archive = tar::Builder::new(encoder);
    for (name, bytes) in [
        (
            "memcordon-core-1.2.3/Cargo.toml",
            b"[package]\nname = \"memcordon-core\"\nversion = \"1.2.3\"\nedition = \"2021\"\n"
                .as_slice(),
        ),
        ("memcordon-core-1.2.3/.cargo_vcs_info.json", vcs.as_slice()),
        (
            "memcordon-core-1.2.3/src/lib.rs",
            b"pub fn candidate() -> u8 { 42 }\n".as_slice(),
        ),
        (
            "memcordon-core-1.2.3/src/main.rs",
            b"fn main() { println!(\"candidate\"); }\n".as_slice(),
        ),
        (
            "memcordon-core-1.2.3/Cargo.lock",
            b"version = 4\n\n[[package]]\nname = \"memcordon-core\"\nversion = \"1.2.3\"\n"
                .as_slice(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, name, bytes).unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap();
    let identity = canonical_crate_identity(&path).unwrap();
    (
        CrateRecord {
            name: "memcordon-core".into(),
            version: "1.2.3".into(),
            archive_sha256: sha256_file(&path).unwrap(),
            canonical_tree_sha256: canonical_crate_tree(&path).unwrap(),
            canonical_identity_sha256: identity.sha256,
            vcs_commit: "a".repeat(40),
        },
        path,
    )
}

#[test]
fn candidate_archive_admission_rejects_identity_tree_digest_and_dirty_provenance() {
    let temporary = TempDir::new().unwrap();
    let (valid, archive) = archive_fixture(temporary.path(), false);
    validate_archive_identity(&archive, &valid).unwrap();
    let mut mutations = Vec::new();
    let mut wrong = valid.clone();
    wrong.archive_sha256 = "00".repeat(32);
    mutations.push(wrong);
    let mut wrong = valid.clone();
    wrong.canonical_tree_sha256 = "00".repeat(32);
    mutations.push(wrong);
    let mut wrong = valid.clone();
    wrong.canonical_identity_sha256 = "00".repeat(32);
    mutations.push(wrong);
    let mut wrong = valid.clone();
    wrong.name = "other-package".into();
    mutations.push(wrong);
    let mut wrong = valid.clone();
    wrong.version = "1.2.4".into();
    mutations.push(wrong);
    let mut wrong = valid.clone();
    wrong.vcs_commit = "b".repeat(40);
    mutations.push(wrong);
    for wrong in mutations {
        assert!(validate_archive_identity(&archive, &wrong).is_err());
    }
    let (dirty, archive) = archive_fixture(temporary.path(), true);
    assert!(validate_archive_identity(&archive, &dirty).is_err());
}

#[test]
fn candidate_staging_resolves_and_compiles_the_admitted_archive_offline() {
    let temporary = TempDir::new().unwrap();
    let (record, archive) = archive_fixture(temporary.path(), false);
    let packages = CandidatePackages {
        archives: BTreeMap::from([(record.name.clone(), (record, archive))]),
    };
    let consumer = temporary.path().join("consumer");
    fs::create_dir(&consumer).unwrap();
    let sources = packages.stage(&consumer).unwrap();
    fs::create_dir(consumer.join("src")).unwrap();
    fs::write(
        consumer.join("src/main.rs"),
        b"fn main() { assert_eq!(memcordon_core::candidate(), 42); }\n",
    )
    .unwrap();
    fs::write(consumer.join("Cargo.toml"), b"[package]\nname = \"memcordon-release-consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[dependencies]\nmemcordon-core = \"=1.2.3\"\n").unwrap();
    let config: toml::Value =
        toml::from_str(&fs::read_to_string(consumer.join(".cargo/config.toml")).unwrap()).unwrap();
    assert_eq!(config.as_table().unwrap().len(), 1);
    assert_eq!(config["patch"]["crates-io"].as_table().unwrap().len(), 1);
    assert_eq!(
        config["patch"]["crates-io"]["memcordon-core"]
            .as_table()
            .unwrap()
            .len(),
        1
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let stable = config::toolchains(root).unwrap().stable;
    let run = |arguments: &[&str]| {
        memcordon_ci::build_context::run_isolated_cargo(
            &consumer,
            &stable,
            arguments.iter().copied(),
            Duration::from_secs(60),
            None,
        )
        .unwrap()
    };
    run(&["generate-lockfile", "--offline"]);
    let metadata = run(&["metadata", "--locked", "--offline", "--format-version", "1"]);
    sources
        .validate_resolution(&metadata, "memcordon-core")
        .unwrap();
    run(&["check", "--locked", "--offline"]);
    let install = consumer.join("install");
    let (record, _) = packages.archives.get("memcordon-core").unwrap();
    let package = sources.package_root("memcordon-core").unwrap();
    let mut arguments = consumer_install_arguments(record, Some(&package), &install);
    arguments.push(OsString::from("--offline"));
    memcordon_ci::build_context::run_isolated_cargo_with_output_scope(
        &consumer,
        &stable,
        arguments,
        Duration::from_secs(60),
        Some(&install),
        memcordon_ci::build_context::IsolatedOutputScope::SourceChild,
    )
    .unwrap();
    assert!(
        install
            .join("bin")
            .join(installed_binary_name("memcordon-core"))
            .is_file()
    );
    fs::write(
        package.join("build.rs"),
        b"fn main() { std::fs::write(\"../../install-other\", b\"undeclared output\").unwrap(); }\n",
    ).unwrap();
    let mut arguments = consumer_install_arguments(record, Some(&package), &install);
    arguments.extend([OsString::from("--offline"), OsString::from("--force")]);
    let error = memcordon_ci::build_context::run_isolated_cargo_with_output_scope(
        &consumer,
        &stable,
        arguments,
        Duration::from_secs(60),
        Some(&install),
        memcordon_ci::build_context::IsolatedOutputScope::SourceChild,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("isolated package source changed during compilation")
    );
}

#[test]
fn provider_cleanup_is_attempted_on_partial_install_and_retained_with_primary_error() {
    for install_succeeded in [false, true] {
        for cleanup_succeeded in [false, true] {
            let cleanup_attempted = std::cell::Cell::new(false);
            let mut smoke = NativeSmokeReport::default();
            let result = run_provider_lifecycle(
                &mut smoke,
                |smoke| {
                    smoke.provider_install = Some(install_succeeded);
                    Err(failure("qualification-primary"))
                },
                || {
                    cleanup_attempted.set(true);
                    if cleanup_succeeded {
                        Ok(())
                    } else {
                        Err(failure("cleanup-secondary"))
                    }
                },
            );
            assert!(cleanup_attempted.get());
            assert_eq!(smoke.provider_uninstall, Some(cleanup_succeeded));
            let error = result.unwrap_err().to_string();
            assert!(error.contains("qualification-primary"));
            assert_eq!(error.contains("cleanup-secondary"), !cleanup_succeeded);
        }
    }
    let mut smoke = NativeSmokeReport::default();
    assert!(
        run_provider_lifecycle(&mut smoke, |_| Ok(()), || Err(failure("absence unknown"))).is_err()
    );
    assert_eq!(smoke.provider_uninstall, Some(false));
}

#[test]
fn candidate_manifest_admission_rejects_schema_and_package_inventory_changes() {
    let (temporary, release) = super::super::tests::release_fixture();
    let bundle = temporary.path().join(&release.assets.output_directory);
    let path = bundle.join(&release.assets.manifest);
    let (_, valid, _) = bundle_manifest_at(temporary.path(), &bundle).unwrap();
    let mut invalid = valid.clone();
    invalid.schema_version += 1;
    write_json(&path, &invalid).unwrap();
    assert!(bundle_manifest_at(temporary.path(), &bundle).is_err());
    let mut invalid = valid.clone();
    invalid.crates.push(invalid.crates[0].clone());
    write_json(&path, &invalid).unwrap();
    assert!(bundle_manifest_at(temporary.path(), &bundle).is_err());
    let mut invalid = valid.clone();
    invalid.crates.pop();
    write_json(&path, &invalid).unwrap();
    assert!(bundle_manifest_at(temporary.path(), &bundle).is_err());
    let mut invalid = valid;
    invalid.crates.swap(0, 1);
    write_json(&path, &invalid).unwrap();
    assert!(bundle_manifest_at(temporary.path(), &bundle).is_err());
}

#[test]
fn candidate_manifest_binds_the_checked_out_tag_commit_and_workspace_version() {
    let (temporary, release) = super::super::tests::release_fixture();
    let root = temporary.path();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\n[workspace.package]\nversion = \"1.2.3\"\n",
    )
    .unwrap();
    git(root, ["init", "--quiet"]).unwrap();
    git(
        root,
        [
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--allow-empty",
            "--no-verify",
            "-m",
            "Fixture",
        ],
    )
    .unwrap();
    git(root, ["tag", "1.2.3"]).unwrap();
    let (_, mut manifest, _) =
        bundle_manifest_at(root, &root.join(&release.assets.output_directory)).unwrap();
    manifest.source_commit = git_text(root, &["rev-parse", "HEAD"]).unwrap();
    manifest.rust_toolchain = config::toolchains(root).unwrap().stable;
    for record in &mut manifest.crates {
        record.vcs_commit = manifest.source_commit.clone();
    }
    validate_candidate_manifest(root, &release, &manifest).unwrap();
    let mut invalid = manifest.clone();
    invalid.source_commit = "f".repeat(40);
    for record in &mut invalid.crates {
        record.vcs_commit = invalid.source_commit.clone();
    }
    assert!(validate_candidate_manifest(root, &release, &invalid).is_err());
    let mut invalid = manifest.clone();
    invalid.project = "another-project".into();
    assert!(validate_candidate_manifest(root, &release, &invalid).is_err());
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\n[workspace.package]\nversion = \"1.2.4\"\n",
    )
    .unwrap();
    assert!(validate_candidate_manifest(root, &release, &manifest).is_err());
}
