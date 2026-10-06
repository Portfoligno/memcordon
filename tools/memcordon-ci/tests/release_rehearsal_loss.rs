//! Real publisher and HTTP response-loss controls with small, validated archive fixtures.
//! Structural executable headers are never executed or described as compiled native artifacts.
use memcordon_ci::{
    rehearsal_support::{coordinator, protocol::*, server},
    release::{
        artifacts::{self, FileRecord},
        bundle::{LoadedBundle, PreparedBundle, PublicManifest},
        compatibility::{Compatibility, NativePackage},
        distribution::Distribution,
        installed_consumer,
        publish::{Credentials, Publisher, RemoteState},
        rehearsal::LoopbackTransport,
        source::{BuildSourceIdentity, SelectedSource},
        target,
    },
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Write},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
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

fn executable_header(target: &str) -> Vec<u8> {
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

fn bundle(directory: &Path) -> LoadedBundle {
    let source = SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: "fixture/repository".into(),
        tag_ref: "refs/tags/1.2.3".into(),
        commit: hex::encode([1; 20]),
        version: "1.2.3".parse().unwrap(),
    };
    let build = BuildSourceIdentity::Tagged {
        source: source.clone(),
    };
    let distribution =
        Distribution::read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let mut files = Vec::new();
    let mut payloads = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    for selection in &distribution.targets {
        let native = scratch();
        let mut members = BTreeMap::new();
        let mut executables = BTreeSet::new();
        for binary in &selection.binaries {
            let name = target::binary_name(binary, &selection.target);
            let bytes = executable_header(&selection.target);
            fs::write(native.path().join(&name), &bytes).unwrap();
            members.insert(name.clone(), bytes);
            executables.insert(name);
        }
        for unit in &selection.units {
            members.insert(
                unit.clone(),
                b"[Unit]\nDescription=Small publication fixture\n".to_vec(),
            );
        }
        let manifest =
            installed_consumer::measured_manifest(&build, selection, native.path()).unwrap();
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
    // A finite normal/build graph, independently decoded by the HTTP fixture.
    for package in [
        "memcordon-core",
        "memcordon-platform",
        "memcordon-windows-launch-core",
        "memcordon",
    ] {
        let mut dependencies = BTreeMap::new();
        if package != "memcordon-core" {
            dependencies.insert("memcordon-core", json!({"version":"=1.2.3"}));
        }
        if package == "memcordon" {
            dependencies.insert("memcordon-platform", json!({"version":"=1.2.3"}));
            dependencies.insert("memcordon-windows-launch-core", json!({"version":"=1.2.3"}));
        }
        let manifest=toml::to_string(&json!({"package":{"name":package,"version":"1.2.3","license":"MIT"},"dependencies":dependencies})).unwrap();
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
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
    let public = PublicManifest {
        schema: 1,
        version: source.version.clone(),
        tag: source.version.to_string(),
        commit: source.commit.clone(),
        files: files.clone(),
    };
    append(
        &mut files,
        &mut payloads,
        "manifest.json".into(),
        "manifest",
        None,
        None,
        serde_json::to_vec(&public).unwrap(),
    );
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
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
    let metadata = PreparedBundle {
        format: "memcordon.prepared-release".into(),
        revision: 1,
        source,
        distribution,
        files,
        notes: "Small actual HTTP response-loss fixture".into(),
    };
    for (name, bytes) in payloads {
        fs::write(directory.join(name), bytes).unwrap();
    }
    fs::write(
        directory.join("prepared.json"),
        serde_json::to_vec(&metadata).unwrap(),
    )
    .unwrap();
    PreparedBundle::load(directory).unwrap()
}

struct RetiringChild(Child);
impl std::ops::Deref for RetiringChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for RetiringChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for RetiringChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        let kill = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Err(error) => {
                    eprintln!("secondary fixture retirement error: {error}; kill: {kill:?}");
                    return;
                }
                Ok(None) if Instant::now() >= deadline => {
                    eprintln!("secondary fixture retirement remained unobserved; kill: {kill:?}");
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }
}
struct Fixture {
    child: RetiringChild,
    transport: LoopbackTransport,
}
impl Fixture {
    fn start(state: &Path, bundle: &LoadedBundle, ordinal: usize) -> Self {
        let deadline = Instant::now() + Duration::from_secs(15);
        let setup = Setup {
            revision: REVISION,
            case_id: "asset-loss".into(),
            selection: FixtureSelection {
                version: bundle.metadata.source.version.to_string(),
                commit: bundle.metadata.source.commit.clone(),
                repository: bundle.metadata.source.repository.clone(),
                notes: bundle.metadata.notes.clone(),
                prerelease: false,
                files: bundle
                    .metadata
                    .files
                    .iter()
                    .map(|file| ExpectedFile {
                        name: file.name.clone(),
                        size: file.byte_len,
                        sha256: file.sha256.clone(),
                        package: file.package.clone(),
                    })
                    .collect(),
            },
            fault: Fault::Loss {
                boundary: Boundary::Asset(u32::try_from(ordinal).unwrap()),
            },
            budget: BudgetPreset::Normal20min,
            work_unix_ms: memcordon_ci::release::rehearsal::unix_ms().unwrap() + 15_000,
        };
        fs::write(
            state.join("setup.json"),
            serde_json::to_vec(&setup).unwrap(),
        )
        .unwrap();
        let ready = state.join("ready.json");
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-release-rehearsal"));
        command
            .args(["serve", "--case", "asset-loss", "--state"])
            .arg(state)
            .arg("--ready")
            .arg(&ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        coordinator::sanitize_child(&mut command);
        // Own the child before readiness parsing or assertions can fail.
        let mut child = RetiringChild(command.spawn().unwrap());
        let transport = loop {
            if let Ok(bytes) = fs::read(&ready) {
                if let Ok(record) = serde_json::from_slice(&bytes) {
                    break LoopbackTransport::new(record).unwrap();
                }
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "fixture exited before readiness"
            );
            assert!(Instant::now() < deadline, "fixture readiness expired");
            std::thread::sleep(Duration::from_millis(5));
        };
        Self { child, transport }
    }
    fn stop(&mut self) {
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"stop\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            assert!(Instant::now() < deadline, "fixture settlement expired");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn every_managed_asset_lost_reply_is_resolved_by_real_http_without_duplicate_effects() {
    let prepared = scratch();
    let bundle = bundle(prepared.path());
    assert!(bundle.metadata.files.len() > 2);
    assert!(
        bundle.payloads.iter().map(Vec::len).sum::<usize>() < 1024 * 1024,
        "focused fixtures remain small"
    );
    let selection = FixtureSelection {
        version: bundle.metadata.source.version.to_string(),
        commit: bundle.metadata.source.commit.clone(),
        repository: bundle.metadata.source.repository.clone(),
        notes: bundle.metadata.notes.clone(),
        prerelease: false,
        files: bundle
            .metadata
            .files
            .iter()
            .map(|file| ExpectedFile {
                name: file.name.clone(),
                size: file.byte_len,
                sha256: file.sha256.clone(),
                package: file.package.clone(),
            })
            .collect(),
    };
    for ordinal in 0..bundle.metadata.files.len() {
        let state = scratch();
        let mut fixture = Fixture::start(state.path(), &bundle, ordinal);
        let deadline = fixture.transport.deadline().unwrap();
        let credentials =
            Credentials::for_transport(GITHUB_TOKEN.into(), Some(REGISTRY_TOKEN.into())).unwrap();
        let summary = Publisher::new(&fixture.transport, &credentials, &bundle, deadline)
            .publish()
            .unwrap();
        assert!(summary.complete, "asset position {ordinal}: {summary:?}");
        assert!(
            summary
                .objects
                .iter()
                .all(|object| object.observation == RemoteState::Matching)
        );
        let observed = server::read_snapshot(state.path()).unwrap();
        assert_eq!(
            observed.fault_boundary,
            Some(Boundary::Asset(u32::try_from(ordinal).unwrap()))
        );
        assert_eq!(observed.assets.len(), bundle.metadata.files.len());
        for (position, (record, bytes)) in bundle
            .metadata
            .files
            .iter()
            .zip(&bundle.payloads)
            .enumerate()
        {
            assert_eq!(
                observed
                    .effects
                    .iter()
                    .filter(|effect| effect.boundary
                        == Boundary::Asset(u32::try_from(position).unwrap()))
                    .count(),
                1
            );
            let asset = observed
                .assets
                .iter()
                .find(|asset| asset.name == record.name)
                .unwrap();
            assert_eq!(fs::read(state.path().join(&asset.path)).unwrap(), *bytes);
        }
        coordinator::assert_complete(
            &selection,
            &observed,
            &fixture.transport,
            &summary,
            deadline,
        )
        .unwrap();
        let before = server::read_snapshot(state.path()).unwrap();
        let retried = Publisher::new(&fixture.transport, &credentials, &bundle, deadline)
            .publish()
            .unwrap();
        assert!(retried.complete);
        let after = server::read_snapshot(state.path()).unwrap();
        assert_eq!(
            serde_json::to_value(&before.assets).unwrap(),
            serde_json::to_value(&after.assets).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&before.effects).unwrap(),
            serde_json::to_value(&after.effects).unwrap()
        );
        assert!(
            after
                .requests
                .iter()
                .skip(before.requests.len())
                .all(|request| !matches!(
                    request.method.as_str(),
                    "POST" | "PUT" | "PATCH" | "DELETE"
                ))
        );
        fixture.stop();
    }
}
