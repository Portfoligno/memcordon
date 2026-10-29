//! Bounded, validated archive fixtures. Header images are never executed.
use memcordon_ci::release::{
    artifacts::{self, FileRecord},
    bundle::{CandidateBundle, CandidateManifest, NotesSelection, PreparedBundle, PublicManifest},
    compatibility::{CompatibilityV2 as Compatibility, NativePackage},
    distribution::Distribution,
    finalize::finalize_preparation,
    installed_consumer,
    rehearsal_input::RehearsalInput,
    source::{BuildSourceIdentity, SelectedSource},
    target,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

fn scratch() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        tempfile::tempdir_in("/tmp").unwrap()
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().unwrap()
    }
}

fn header(target: &str) -> Vec<u8> {
    let arm = target.starts_with("aarch64-");
    let mut bytes = vec![0; 128];
    if target.contains("linux") {
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(if arm { &[183, 0] } else { &[62, 0] });
    } else if target.contains("apple") {
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(if arm { &[12, 0, 0, 1] } else { &[7, 0, 0, 1] });
    } else {
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(if arm { &[0x64, 0xaa] } else { &[0x64, 0x86] });
    }
    bytes
}

fn append(
    files: &mut Vec<FileRecord>,
    payloads: &mut BTreeMap<String, Vec<u8>>,
    name: String,
    kind: &str,
    target: Option<String>,
    package: Option<String>,
    bytes: Vec<u8>,
) {
    files.push(FileRecord {
        name: name.clone(),
        kind: kind.into(),
        target,
        package,
        byte_len: bytes.len() as u64,
        sha256: artifacts::checksum(&bytes),
    });
    assert!(payloads.insert(name, bytes).is_none());
}

fn fixture(root: &Path, candidate: bool) -> (PathBuf, PathBuf, PathBuf) {
    fixture_profile(root, candidate, true)
}

fn fixture_profile(root: &Path, candidate: bool, readiness: bool) -> (PathBuf, PathBuf, PathBuf) {
    let source = SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: "fixture/repository".into(),
        tag_ref: "refs/tags/1.2.3".into(),
        commit: hex::encode([1; 20]),
        version: "1.2.3".parse().unwrap(),
    };
    let build = if candidate {
        BuildSourceIdentity::Working {
            version: source.version.clone(),
            commit: source.commit.clone(),
        }
    } else {
        source.clone().into()
    };
    let input = root.join("input");
    fs::create_dir(&input).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::create_dir(root.join("ci")).unwrap();
    fs::copy(
        workspace.join("ci/distribution.toml"),
        root.join("ci/distribution.toml"),
    )
    .unwrap();
    fs::write(
        root.join("CHANGELOG.md"),
        if candidate {
            "# Changelog\n"
        } else {
            "# Changelog\n\n## 1.2.3\nOriginal exact release notes\n"
        },
    )
    .unwrap();
    let distribution = Distribution::read(root).unwrap();
    let distribution = if readiness {
        distribution.consumer_readiness().unwrap()
    } else {
        distribution
    };
    let mut files = Vec::new();
    let mut payloads = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    for selection in &distribution.targets {
        let native = scratch();
        let mut members = BTreeMap::new();
        let mut executables = BTreeSet::new();
        for binary in &selection.binaries {
            let name = target::binary_name(binary, &selection.target);
            let bytes = header(&selection.target);
            fs::write(native.path().join(&name), &bytes).unwrap();
            members.insert(name.clone(), bytes);
            executables.insert(name);
        }
        for unit in &selection.units {
            members.insert(
                unit.clone(),
                b"[Unit]\nDescription=Finalizer fixture\n".to_vec(),
            );
        }
        let manifest =
            installed_consumer::measured_current_manifest(&build, selection, native.path())
                .unwrap();
        members.insert(
            "runtime-manifest.json".into(),
            serde_json::to_vec(&manifest).unwrap(),
        );
        manifests.insert(selection.target.clone(), manifest);
        let package = NativePackage::measured(&build, selection, &members).unwrap();
        members.insert("package.json".into(), serde_json::to_vec(&package).unwrap());
        append(
            &mut files,
            &mut payloads,
            selection.target.clone(),
            "archive",
            Some(selection.target.clone()),
            None,
            target::encode_archive(&selection.target, &members, &executables).unwrap(),
        );
    }
    for package in [
        "memcordon-core",
        "memcordon-platform",
        "memcordon-windows-launch-core",
        "memcordon",
    ] {
        let mut dependencies = BTreeMap::new();
        if package != "memcordon-core" {
            dependencies.insert("memcordon-core", serde_json::json!({"version":"=1.2.3"}));
        }
        if package == "memcordon" {
            dependencies.insert(
                "memcordon-platform",
                serde_json::json!({"version":"=1.2.3"}),
            );
            dependencies.insert(
                "memcordon-windows-launch-core",
                serde_json::json!({"version":"=1.2.3"}),
            );
        }
        let manifest = toml::to_string(&serde_json::json!({"package":{"name":package,"version":"1.2.3","license":"MIT"},"dependencies":dependencies})).unwrap();
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut member = tar::Header::new_gnu();
        member.set_size(manifest.len() as u64);
        member.set_mode(0o644);
        member.set_cksum();
        archive
            .append_data(
                &mut member,
                Path::new(&format!("{package}-1.2.3")).join("Cargo.toml"),
                Cursor::new(manifest.as_bytes()),
            )
            .unwrap();
        append(
            &mut files,
            &mut payloads,
            package.into(),
            "crate",
            None,
            Some(package.into()),
            archive.into_inner().unwrap().finish().unwrap(),
        );
    }
    append(
        &mut files,
        &mut payloads,
        "compatibility.json".into(),
        "compatibility",
        None,
        None,
        serde_json::to_vec(&Compatibility::selected(&build, &distribution, &manifests).unwrap())
            .unwrap(),
    );
    let manifest = if candidate {
        serde_json::to_vec(&CandidateManifest {
            format: "memcordon.candidate-manifest".into(),
            revision: 1,
            version: source.version.clone(),
            commit: source.commit.clone(),
            files: files.clone(),
        })
        .unwrap()
    } else {
        serde_json::to_vec(&PublicManifest {
            schema: 1,
            version: source.version.clone(),
            tag: source.version.to_string(),
            commit: source.commit.clone(),
            files: files.clone(),
        })
        .unwrap()
    };
    append(
        &mut files,
        &mut payloads,
        "manifest.json".into(),
        "manifest",
        None,
        None,
        manifest,
    );
    let mut ordered: Vec<_> = files.iter().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    let mut checksums = Vec::new();
    for file in ordered {
        writeln!(&mut checksums, "{}  {}", file.sha256, file.name).unwrap();
    }
    append(
        &mut files,
        &mut payloads,
        "SHA256SUMS".into(),
        "checksums",
        None,
        None,
        checksums,
    );
    for (name, bytes) in payloads {
        fs::write(input.join(name), bytes).unwrap();
    }
    if candidate {
        fs::write(
            input.join("candidate.json"),
            serde_json::to_vec(&CandidateBundle {
                format: "memcordon.prepared-candidate".into(),
                revision: 1,
                source: build.clone(),
                distribution,
                files,
                notes_selection: NotesSelection::Unavailable,
                notes: None,
            })
            .unwrap(),
        )
        .unwrap();
    } else {
        fs::write(
            input.join("prepared.json"),
            serde_json::to_vec(&PreparedBundle {
                format: "memcordon.prepared-release".into(),
                revision: 1,
                source,
                distribution,
                files,
                notes: "Original exact release notes\n".into(),
            })
            .unwrap(),
        )
        .unwrap();
    }
    RehearsalInput::load(&input).unwrap();
    let selection = root.join("build-source.json");
    fs::write(&selection, serde_json::to_vec(&build).unwrap()).unwrap();
    let publisher = root.join("publisher.tar.gz");
    fs::write(
        &publisher,
        target::encode_archive(
            "x86_64-unknown-linux-gnu",
            &BTreeMap::from([("memcordon-ci".into(), header("x86_64-unknown-linux-gnu"))]),
            &BTreeSet::from(["memcordon-ci".into()]),
        )
        .unwrap(),
    )
    .unwrap();
    (selection, input, publisher)
}

#[test]
fn candidate_and_tagged_finalization_preserve_every_original_byte() {
    for candidate in [false, true] {
        let temporary = scratch();
        let root = temporary.path().canonicalize().unwrap();
        let (selection, input, publisher) = fixture(&root, candidate);
        let output = root.join("final");
        finalize_preparation(&root, &selection, &input, &publisher, &output).unwrap();
        let copied = output.join(if candidate { "candidate" } else { "prepared" });
        for entry in fs::read_dir(&input).unwrap() {
            let entry = entry.unwrap();
            assert_eq!(
                fs::read(entry.path()).unwrap(),
                fs::read(copied.join(entry.file_name())).unwrap()
            );
        }
        assert_eq!(
            fs::read(publisher).unwrap(),
            fs::read(output.join("tool/memcordon-publication-tool.tar.gz")).unwrap()
        );
        assert!(
            !output
                .join(if candidate { "prepared" } else { "candidate" })
                .exists()
        );
    }
}

#[test]
fn malformed_inputs_and_changed_selection_cannot_create_final_artifacts() {
    for mutation in ["source", "ambiguous", "extra", "payload", "publisher"] {
        let temporary = scratch();
        let root = temporary.path().canonicalize().unwrap();
        let (selection, input, publisher) = fixture(&root, true);
        let output = root.join("final");
        match mutation {
            "source" => {
                let changed = BuildSourceIdentity::Working {
                    version: "1.2.3".parse().unwrap(),
                    commit: hex::encode([2; 20]),
                };
                fs::write(&selection, serde_json::to_vec(&changed).unwrap()).unwrap();
            }
            "ambiguous" => fs::write(input.join("prepared.json"), b"{}\n").unwrap(),
            "extra" => fs::write(input.join("unexpected"), b"not in inventory\n").unwrap(),
            "payload" => fs::write(input.join("manifest.json"), b"wrong bytes\n").unwrap(),
            "publisher" => fs::write(&publisher, b"wrong publisher\n").unwrap(),
            _ => unreachable!(),
        }
        assert!(
            finalize_preparation(&root, &selection, &input, &publisher, &output).is_err(),
            "{mutation}"
        );
        assert!(!output.exists(), "{mutation} created a final tree");
    }
}

#[test]
fn existing_destination_is_refused_without_overwriting() {
    let temporary = scratch();
    let root = temporary.path().canonicalize().unwrap();
    let output = root.join("final");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("sentinel"), b"retained\n").unwrap();
    let absent = root.join("absent");
    assert!(finalize_preparation(&root, &absent, &absent, &absent, &output).is_err());
    assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"retained\n");
}

#[test]
fn valid_envelopes_cannot_substitute_notes_or_downgrade_effective_features() {
    for candidate in [true, false] {
        let temporary = scratch();
        let root = temporary.path().canonicalize().unwrap();
        let (selection, input, publisher) = fixture(&root, candidate);
        let envelope = input.join(if candidate {
            "candidate.json"
        } else {
            "prepared.json"
        });
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(&envelope).unwrap()).unwrap();
        metadata["notes"] = "different valid nonempty notes\n".into();
        if candidate {
            metadata["notes_selection"] = "exact-version".into();
        }
        fs::write(&envelope, serde_json::to_vec(&metadata).unwrap()).unwrap();
        RehearsalInput::load(&input).expect(
            "notes substitution is structurally valid and must be caught against selected source",
        );
        assert!(
            finalize_preparation(&root, &selection, &input, &publisher, &root.join("final"))
                .is_err()
        );
        assert!(!root.join("final").exists());
    }
    let temporary = scratch();
    let root = temporary.path().canonicalize().unwrap();
    let (selection, input, publisher) = fixture_profile(&root, true, false);
    RehearsalInput::load(&input)
        .expect("ordinary CLI distribution is a valid bundle but not this readiness preparation");
    assert!(
        finalize_preparation(&root, &selection, &input, &publisher, &root.join("final")).is_err()
    );
    assert!(!root.join("final").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_payload_and_destination_parent_are_refused() {
    let temporary = scratch();
    let root = temporary.path().canonicalize().unwrap();
    let (selection, input, publisher) = fixture(&root, true);
    let outside = root.join("outside");
    fs::create_dir(&outside).unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&outside, &alias).unwrap();
    assert!(
        finalize_preparation(&root, &selection, &input, &publisher, &alias.join("final")).is_err()
    );
    assert!(fs::read_dir(&outside).unwrap().next().is_none());
    let payload = input.join("manifest.json");
    let saved = root.join("manifest-original.json");
    fs::rename(&payload, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &payload).unwrap();
    let output = root.join("final");
    assert!(finalize_preparation(&root, &selection, &input, &publisher, &output).is_err());
    assert!(!output.exists());
}
