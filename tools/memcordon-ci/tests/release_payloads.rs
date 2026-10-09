use memcordon_ci::release::{
    artifacts,
    http::{self, ReadBudget, Response, Transport},
    packages::{self, PackageBundle},
    recovery,
    source::SelectedSource,
    target,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

fn source() -> SelectedSource {
    SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: "example/repository".into(),
        tag_ref: "refs/tags/1.2.3".into(),
        commit: hex::encode([1_u8; 20]),
        version: "1.2.3".parse().unwrap(),
    }
}
fn crate_bytes(name: &str, dependency: &str) -> Vec<u8> {
    let manifest =
        format!("[package]\nname={name:?}\nversion=\"1.2.3\"\nlicense=\"MIT\"\n{dependency}\n");
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(
            &mut header,
            format!("{name}-1.2.3/Cargo.toml"),
            Cursor::new(manifest.as_bytes()),
        )
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}
#[test]
fn normalized_dependencies_are_ordered_independently_of_bundle_rows() {
    let names = [
        "memcordon",
        "memcordon-platform",
        "memcordon-windows-launch-core",
        "memcordon-core",
    ];
    let dependencies = [
        "[dependencies.renamed]\npackage=\"memcordon-platform\"\nversion=\"=1.2.3\"",
        "[target.'cfg(windows)'.build-dependencies]\nmemcordon-windows-launch-core=\"=1.2.3\"",
        "[dependencies]\nmemcordon-core=\"=1.2.3\"",
        "",
    ];
    let payloads: Vec<_> = names
        .iter()
        .zip(dependencies)
        .map(|(name, deps)| crate_bytes(name, deps))
        .collect();
    let files = names
        .iter()
        .zip(&payloads)
        .map(|(name, bytes)| artifacts::FileRecord {
            name: format!("{name}-1.2.3.crate"),
            kind: "crate".into(),
            target: None,
            package: Some((*name).into()),
            byte_len: bytes.len() as u64,
            sha256: artifacts::checksum(bytes),
        })
        .collect();
    let bundle = PackageBundle {
        format: "memcordon.packages".into(),
        revision: 1,
        source: source().into(),
        files,
    };
    assert_eq!(
        packages::archive_order(&bundle, &payloads).unwrap(),
        [
            "memcordon-core",
            "memcordon-windows-launch-core",
            "memcordon-platform",
            "memcordon"
        ]
    );
    let mut cycle = payloads.clone();
    cycle[3] = crate_bytes("memcordon-core", "[dependencies]\nmemcordon=\"=1.2.3\"");
    assert!(packages::archive_order(&bundle, &cycle).is_err());
    let mut hidden = payloads.clone();
    hidden[3] = crate_bytes(
        "memcordon-core",
        "[dependencies]\nmemcordon-testkit=\"1.2.3\"",
    );
    assert!(packages::archive_order(&bundle, &hidden).is_err());
}
#[test]
fn independent_dependency_siblings_require_archive_order_in_persisted_bundle() {
    let names = [
        "memcordon-core",
        "memcordon-windows-launch-core",
        "memcordon-platform",
        "memcordon",
    ];
    let payloads: Vec<_> = names
        .iter()
        .map(|name| {
            let dependencies = match *name {
                "memcordon-core" => "",
                "memcordon" => "[dependencies.memcordon-platform]\nversion=\"=1.2.3\"\n[dependencies.memcordon-windows-launch-core]\nversion=\"=1.2.3\"",
                _ => "[dependencies.memcordon-core]\nversion=\"=1.2.3\"",
            };
            crate_bytes(name, dependencies)
        })
        .collect();
    let mut bundle = PackageBundle {
        format: "memcordon.packages".into(),
        revision: 1,
        source: source().into(),
        files: names
            .iter()
            .zip(&payloads)
            .map(|(name, bytes)| artifacts::FileRecord {
                name: format!("{name}-1.2.3.crate"),
                kind: "crate".into(),
                target: None,
                package: Some((*name).into()),
                byte_len: bytes.len() as u64,
                sha256: artifacts::checksum(bytes),
            })
            .collect(),
    };
    let order = packages::archive_order(&bundle, &payloads).unwrap();
    assert_eq!(
        order,
        [
            "memcordon-core",
            "memcordon-platform",
            "memcordon-windows-launch-core",
            "memcordon"
        ]
    );
    let directory = tempfile::tempdir().unwrap();
    for (record, bytes) in bundle.files.iter().zip(&payloads) {
        std::fs::write(directory.path().join(&record.name), bytes).unwrap();
    }
    let persist = |bundle: &PackageBundle| {
        std::fs::write(
            directory.path().join("packages.json"),
            serde_json::to_vec(bundle).unwrap(),
        )
        .unwrap();
    };
    persist(&bundle);
    assert_eq!(
        PackageBundle::load(directory.path())
            .unwrap_err()
            .to_string(),
        "package bundle is not in actual archive dependency order"
    );
    bundle.files.swap(1, 2);
    persist(&bundle);
    let (loaded, _) = PackageBundle::load(directory.path()).unwrap();
    assert_eq!(
        loaded
            .files
            .iter()
            .map(|file| file.package.as_ref().unwrap())
            .collect::<Vec<_>>(),
        order.iter().collect::<Vec<_>>()
    );
}

#[test]
fn target_archives_reject_traversal_truncation_and_wrong_architecture() {
    for name in [
        "../escape",
        "./alias",
        "a//b",
        "a:b",
        "CON",
        "aux.txt",
        "trailing.",
        "a\\b",
    ] {
        assert!(artifacts::safe_relative(Path::new(name)).is_err(), "{name}");
    }
    let mut elf = vec![0_u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[18] = 62;
    assert!(target::validate_executable(&elf, "x86_64-unknown-linux-gnu").is_ok());
    assert!(target::validate_executable(&elf, "aarch64-unknown-linux-gnu").is_err());
    let members = BTreeMap::from([("memcordon".into(), elf)]);
    let names = BTreeSet::from(["memcordon".into()]);
    let archive = target::encode_archive("x86_64-unknown-linux-gnu", &members, &names).unwrap();
    assert_eq!(
        target::decode_archive(&archive, "x86_64-unknown-linux-gnu").unwrap(),
        members
    );
    let mut trailing = archive.clone();
    trailing.extend_from_slice(b"garbage");
    assert!(target::decode_archive(&trailing, "x86_64-unknown-linux-gnu").is_err());
    let truncated = &archive[..archive.len() / 2];
    assert!(target::decode_archive(truncated, "x86_64-unknown-linux-gnu").is_err());
}
type TransportCall = (String, Vec<(String, String)>, Instant);

struct RedirectFixture {
    calls: Mutex<Vec<TransportCall>>,
}
impl Transport for RedirectFixture {
    fn request(
        &self,
        _: &str,
        url: &url::Url,
        headers: &[(String, String)],
        _: &[u8],
        deadline: Instant,
        _: u64,
    ) -> memcordon_ci::Result<Response> {
        self.calls
            .lock()
            .unwrap()
            .push((url.to_string(), headers.to_vec(), deadline));
        Ok(if url.host_str() == Some("api.github.com") {
            Response {
                status: 302,
                headers: BTreeMap::from([(
                    "location".into(),
                    "https://storage.example/file".into(),
                )]),
                body: Vec::new(),
            }
        } else {
            Response {
                status: 200,
                headers: BTreeMap::new(),
                body: b"actual bytes".to_vec(),
            }
        })
    }
}
#[test]
fn redirects_strip_credentials_and_keep_original_deadline() {
    let fixture = RedirectFixture {
        calls: Mutex::new(Vec::new()),
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let budget = ReadBudget::new(deadline);
    assert_eq!(
        http::download(
            &fixture,
            &budget,
            &url::Url::parse("https://api.github.com/file").unwrap(),
            &[("Authorization".into(), "Bearer secret".into())],
            1024
        )
        .unwrap(),
        b"actual bytes"
    );
    let calls = fixture.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1.len(), 1);
    assert!(calls[1].1.is_empty());
    assert!(calls.iter().all(|call| call.2 == deadline));
}
#[test]
fn recovery_inputs_reject_ambiguous_or_overflowing_ids_and_wrong_mode() {
    let good=br#"{"inputs":{"tag":"1.2.3","recovery-mode":"publication-only","original-run-id":"12","prepared-artifact-id":"13","tool-artifact-id":"14"}}"#;
    let input = recovery::parse_event(good).unwrap();
    assert_eq!(input.original.unwrap().run_id, 12);
    for replacement in ["0", "-1", "18446744073709551616", "12\n"] {
        let mut value: serde_json::Value = serde_json::from_slice(good).unwrap();
        value["inputs"]["original-run-id"] = replacement.into();
        assert!(recovery::parse_event(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut value: serde_json::Value = serde_json::from_slice(good).unwrap();
    value["inputs"]["recovery-mode"] = "reprepare".into();
    assert!(recovery::parse_event(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(recovery::parse_event(br#"{"inputs":{"tag":"1.2.3","tag":"1.2.4"}}"#).is_err());
}
