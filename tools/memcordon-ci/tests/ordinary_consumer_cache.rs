use memcordon_ci::release::{
    distribution::native_target,
    ordinary_consumer_cache::{
        ConsumerBuildLayout, OrdinarySlot, native_reuse_validated, validate_selection,
    },
};

fn directory() -> tempfile::TempDir {
    if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

#[test]
fn stable_layout_is_closed_to_the_ordinary_prepublication_cargo_route() {
    for cargo in [false, true] {
        for ordinary in [false, true] {
            for external in [false, true] {
                assert_eq!(
                    validate_selection(
                        ConsumerBuildLayout::StableOrdinary,
                        cargo,
                        ordinary,
                        external
                    )
                    .is_ok(),
                    cargo && ordinary && !external
                );
                assert!(
                    validate_selection(ConsumerBuildLayout::Ephemeral, cargo, ordinary, external)
                        .is_ok()
                );
            }
        }
    }
    // Portable ownership tests do not stand in for actual packaged Cargo reuse.
    assert!(!native_reuse_validated("unvalidated-target"));
}

#[test]
fn owned_slot_has_stable_separate_coordinates_and_excludes_another_live_owner() {
    let checkout = directory();
    let temporary = directory();
    let temporary = temporary.path().canonicalize().unwrap();
    let target = native_target().unwrap();
    let slot = OrdinarySlot::open_at(checkout.path(), &temporary, target).unwrap();
    let source = slot.source().to_owned();
    let home = slot.cargo_home();
    let install = slot.install();
    let build = slot.build().to_owned();
    assert!(source.starts_with(&temporary));
    assert!(home.starts_with(&temporary));
    assert!(install.starts_with(&temporary));
    assert!(build.starts_with(checkout.path().canonicalize().unwrap()));
    assert!(!build.starts_with(&temporary));
    assert!(OrdinarySlot::open_at(checkout.path(), &temporary, target).is_err());
    drop(slot);
    let reopened = OrdinarySlot::open_at(checkout.path(), &temporary, target).unwrap();
    assert_eq!(reopened.source(), source);
    assert_eq!(reopened.cargo_home(), home);
    assert_eq!(reopened.install(), install);
    assert_eq!(reopened.build(), build);
}

#[test]
fn wrong_target_and_unknown_slot_contents_fail_before_mutation() {
    let checkout = directory();
    let temporary = directory();
    let temporary = temporary.path().canonicalize().unwrap();
    assert!(OrdinarySlot::open_at(checkout.path(), &temporary, "../../outside").is_err());
    assert!(!temporary.join("memcordon-ordinary-consumer").exists());
    let target = native_target().unwrap();
    let owned = temporary.join("memcordon-ordinary-consumer").join(target);
    std::fs::create_dir_all(&owned).unwrap();
    std::fs::write(owned.join("unknown-state"), "do not erase\n").unwrap();
    assert!(OrdinarySlot::open_at(checkout.path(), &temporary, target).is_err());
    assert_eq!(
        std::fs::read_to_string(owned.join("unknown-state")).unwrap(),
        "do not erase\n"
    );
}

#[cfg(unix)]
#[test]
fn redirected_source_and_temporary_ancestry_are_rejected() {
    let checkout = directory();
    let temporary = directory();
    let temporary = temporary.path().canonicalize().unwrap();
    let target = native_target().unwrap();
    let slot = OrdinarySlot::open_at(checkout.path(), &temporary, target).unwrap();
    let source = slot.source().to_owned();
    drop(slot);
    let outside = directory();
    std::fs::write(outside.path().join("sentinel"), "preserve\n").unwrap();
    std::os::unix::fs::symlink(outside.path(), &source).unwrap();
    assert!(OrdinarySlot::open_at(checkout.path(), &temporary, target).is_err());
    let link = temporary.join("redirected-temp");
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    assert!(OrdinarySlot::open_at(checkout.path(), &link, target).is_err());
    assert_eq!(
        std::fs::read_to_string(outside.path().join("sentinel")).unwrap(),
        "preserve\n"
    );
}

/// Heavy acceptance is deliberately opt-in. Passing portable ownership tests does
/// not activate transport on any target; review this test's native evidence first.
#[test]
#[ignore = "actual four-package packaging/build/install cold/warm native acceptance"]
fn actual_packaged_ordinary_consumer_round_trip_reuses_only_registry_dependencies() {
    use memcordon_ci::{
        command::rustup_cargo,
        release::{
            artifacts,
            distribution::Distribution,
            packages::{self, PackageConsumer},
            source::{BuildSourceIdentity, PUBLIC_PACKAGES},
        },
    };
    use std::{fs, time::Duration};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let temporary = directory();
    let temporary = temporary.path().canonicalize().unwrap();
    let workspace = directory();
    let archives = workspace.path().join("packages");
    let distribution = Distribution::read(&root).unwrap().native().unwrap().clone();
    let source = BuildSourceIdentity::working(&root).unwrap();
    packages::prepare_build(
        &root,
        &source,
        &workspace.path().join("package-target"),
        &archives,
    )
    .unwrap();
    let (bundle, _) = packages::PackageBundle::load(&archives).unwrap();
    assert_eq!(bundle.files.len(), PUBLIC_PACKAGES.len());
    let stable = memcordon_ci::config::toolchains(&root).unwrap().stable;
    let slot = OrdinarySlot::open_at(&root, &temporary, &distribution.target).unwrap();
    let source_path = slot.source().to_owned();
    let home = slot.cargo_home();
    let install = slot.install();
    let target = slot.build().to_owned();
    assert!(
        !target.exists(),
        "acceptance requires a fresh dedicated build root"
    );
    fs::create_dir(&source_path).unwrap();
    let compile = |consumer: &PackageConsumer, release: bool| {
        let manifest = if release {
            consumer.cli_source.join("Cargo.toml")
        } else {
            consumer.manifest.clone()
        };
        let mut command = rustup_cargo(
            manifest.parent().unwrap(),
            &stable,
            ["build", "--locked", "--message-format=json"],
            Duration::from_secs(1800),
        )
        .isolated_cargo(&home)
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--config")
        .arg(&consumer.config)
        .arg("--target-dir")
        .arg(&target)
        .arg("--target")
        .arg(&distribution.target);
        if release {
            command = command.arg("--release");
            for feature in &distribution.features {
                command = command.arg("--features").arg(feature);
            }
            for binary in &distribution.binaries {
                command = command.arg("--bin").arg(binary);
            }
        }
        let output = command.output_quiet().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut freshness = Vec::new();
        for message in cargo_metadata::Message::parse_stream(output.stdout.as_slice()) {
            if let cargo_metadata::Message::CompilerArtifact(artifact) = message.unwrap() {
                freshness.push((artifact.package_id.repr, artifact.fresh));
            }
        }
        assert!(
            !freshness.is_empty(),
            "Cargo emitted no real compiler artifacts"
        );
        freshness
    };
    let installed = |consumer: &PackageConsumer| {
        assert!(!install.exists(), "installation must start fresh");
        consumer.install_cli(&root, &target, &distribution).unwrap();
        for binary in &distribution.binaries {
            let installed = memcordon_ci::release::installed_consumer::binary_path(
                &install.join("bin"),
                binary,
                &distribution.target,
            );
            let built = memcordon_ci::release::installed_consumer::binary_path(
                &target.join(&distribution.target).join("release"),
                binary,
                &distribution.target,
            );
            let bytes = artifacts::read_file(&installed).unwrap();
            assert!(!bytes.is_empty());
            assert_eq!(
                artifacts::checksum(&bytes),
                artifacts::checksum(&artifacts::read_file(&built).unwrap())
            );
            println!(
                "ordinary installed {binary}: {} bytes sha256={}",
                bytes.len(),
                artifacts::checksum(&bytes)
            );
        }
    };
    let cold =
        PackageConsumer::prepare_cached_ordinary(&root, &archives, &distribution, slot).unwrap();
    let cold_dev = compile(&cold, false);
    let cold_release = compile(&cold, true);
    assert!(
        cold_dev
            .iter()
            .chain(&cold_release)
            .all(|(_, fresh)| !fresh)
    );
    cold.build(&root, &target).unwrap();
    installed(&cold);
    cold.ordinary_build_layout_for_transport().unwrap();
    drop(cold);
    let mut archive = tar::Builder::new(Vec::new());
    archive.append_dir_all("build", &target).unwrap();
    let archive = archive.into_inner().unwrap();
    // Destroy only this test's owned paths. No source/home/install enters transport.
    for path in [&source_path, &home, &install, &target] {
        fs::remove_dir_all(path).unwrap();
    }
    let slot = OrdinarySlot::open_at(&root, &temporary, &distribution.target).unwrap();
    fs::create_dir(&source_path).unwrap();
    let warm =
        PackageConsumer::prepare_cached_ordinary(&root, &archives, &distribution, slot).unwrap();
    tar::Archive::new(archive.as_slice())
        .unpack(target.parent().unwrap())
        .unwrap();
    warm.sanitize_ordinary_build(&root).unwrap();
    for (release, freshness) in [(false, compile(&warm, false)), (true, compile(&warm, true))] {
        let local: Vec<_> = freshness
            .iter()
            .filter(|(id, _)| id.starts_with("path+"))
            .collect();
        let external: Vec<_> = freshness
            .iter()
            .filter(|(id, _)| id.starts_with("registry+"))
            .collect();
        println!(
            "ordinary warm release={release}: {} local units, {} registry units, {} registry units fresh",
            local.len(),
            external.len(),
            external.iter().filter(|artifact| artifact.1).count()
        );
        assert!(!external.is_empty(), "real registry dependency required");
        assert!(
            external.iter().any(|artifact| artifact.1),
            "no registry artifact was reused"
        );
        assert!(!local.is_empty());
        assert!(
            local.iter().all(|artifact| !artifact.1),
            "a selected local package was retained"
        );
    }
    warm.build(&root, &target).unwrap();
    installed(&warm);
    drop(warm);
    fs::remove_dir_all(&target).unwrap();
    let (after, _) = packages::PackageBundle::load(&archives).unwrap();
    assert_eq!(
        serde_json::to_value(after).unwrap(),
        serde_json::to_value(bundle).unwrap(),
        "packaged archive inputs changed"
    );
}
