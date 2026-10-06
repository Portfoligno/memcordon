//! Typed transport fault injection; no requests leave this test process.
use memcordon_ci::{
    CiError, Result,
    release::{
        artifacts::{self, FileRecord},
        bundle::{LoadedBundle, PreparedBundle},
        distribution::Distribution,
        http::{self, ReadBudget, Response, Transport},
        publish::{Credentials, Publisher, RemoteState},
        recovery::{self, PreparedArtifactLocator},
        source::SelectedSource,
    },
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Write},
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use url::Url;

fn source() -> SelectedSource {
    SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: "example/repository".into(),
        tag_ref: "refs/tags/1.2.3".into(),
        commit: hex::encode([1; 20]),
        version: "1.2.3".parse().unwrap(),
    }
}
fn response(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        headers: BTreeMap::new(),
        body,
    }
}
fn json_response(value: Value) -> Response {
    response(200, serde_json::to_vec(&value).unwrap())
}

type TransportCall = (String, Vec<(String, String)>, Instant, u64);

struct Script {
    responses: Mutex<std::collections::VecDeque<Response>>,
    calls: Mutex<Vec<TransportCall>>,
}
impl Script {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(vec![]),
        }
    }
}
impl Transport for Script {
    fn request(
        &self,
        method: &str,
        url: &Url,
        headers: &[(String, String)],
        body: &[u8],
        deadline: Instant,
        maximum: u64,
    ) -> Result<Response> {
        assert_eq!(method, "GET");
        assert!(body.is_empty());
        self.calls
            .lock()
            .unwrap()
            .push((url.to_string(), headers.to_vec(), deadline, maximum));
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra HTTP request"))
    }
}

#[test]
fn redirects_and_throttle_preserve_one_deadline_and_strip_storage_credentials() {
    let mut redirect = response(302, vec![]);
    redirect
        .headers
        .insert("location".into(), "https://storage.example/archive".into());
    let mut throttle = response(403, vec![]);
    throttle
        .headers
        .insert("x-ratelimit-remaining".into(), "0".into());
    throttle.headers.insert("retry-after".into(), "0".into());
    let expected = b"archive bytes";
    let transport = Script::new(vec![redirect, throttle, response(200, expected.to_vec())]);
    let deadline = Instant::now() + Duration::from_secs(2);
    let bytes = http::download(
        &transport,
        &ReadBudget::new(deadline),
        &Url::parse("https://api.github.com/artifact").unwrap(),
        &[("Authorization".into(), "fixture secret".into())],
        expected.len() as u64,
    )
    .unwrap();
    assert_eq!(bytes, expected);
    let calls = transport.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].1.len(), 1);
    assert!(calls[1].1.is_empty() && calls[2].1.is_empty());
    assert!(
        calls
            .iter()
            .all(|call| call.2 == deadline && call.3 == expected.len() as u64)
    );
}

#[test]
fn expired_and_excessive_retry_budgets_never_issue_another_read() {
    let empty = Script::new(vec![]);
    assert!(
        ReadBudget::new(Instant::now())
            .read(&empty, &Url::parse("https://example.com").unwrap(), &[], 1)
            .is_err()
    );
    assert!(empty.calls.lock().unwrap().is_empty());
    let mut throttled = response(429, vec![]);
    throttled.headers.insert("retry-after".into(), "60".into());
    let transport = Script::new(vec![throttled]);
    assert!(
        ReadBudget::new(Instant::now() + Duration::from_secs(1))
            .read(
                &transport,
                &Url::parse("https://example.com").unwrap(),
                &[],
                1
            )
            .is_err()
    );
    assert_eq!(transport.calls.lock().unwrap().len(), 1);
    for status in [401, 403, 404, 500] {
        let transport = Script::new(vec![response(status, vec![])]);
        assert!(
            http::download(
                &transport,
                &ReadBudget::new(Instant::now() + Duration::from_secs(1)),
                &Url::parse("https://example.com").unwrap(),
                &[],
                1
            )
            .is_err()
        );
        assert_eq!(transport.calls.lock().unwrap().len(), 1);
    }
}

// Publication treats already prepared files as opaque bytes. These tests validate the complete
// selected metadata inventory; no fixture byte stream is labelled a native runtime execution.
fn bundle() -> LoadedBundle {
    let distribution =
        Distribution::read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let mut files = Vec::new();
    let mut payloads = Vec::new();
    let mut append = |name: String, kind: &str, target: Option<String>, package: Option<String>| {
        let bytes = serde_json::to_vec(&json!({"fixture_object":name})).unwrap();
        files.push(FileRecord {
            name,
            kind: kind.into(),
            target,
            package,
            byte_len: bytes.len() as u64,
            sha256: artifacts::checksum(&bytes),
        });
        payloads.push(bytes);
    };
    for target in &distribution.targets {
        append(
            target.target.clone(),
            "archive",
            Some(target.target.clone()),
            None,
        );
    }
    for package in &distribution.packages {
        append(package.clone(), "crate", None, Some(package.clone()));
    }
    append("compatibility.json".into(), "compatibility", None, None);
    append("manifest.json".into(), "manifest", None, None);
    append("SHA256SUMS".into(), "checksums", None, None);
    let metadata = PreparedBundle {
        format: "memcordon.prepared-release".into(),
        revision: 1,
        source: source(),
        distribution,
        files,
        notes: "Release transport fixture".into(),
    };
    metadata.validate().unwrap();
    LoadedBundle { metadata, payloads }
}

struct PublicationRemote<'a> {
    bundle: &'a LoadedBundle,
    public: Mutex<bool>,
    mutations: Mutex<usize>,
    anonymous_reads: Mutex<usize>,
    content_status: u16,
    corrupt_content: bool,
}
impl Transport for PublicationRemote<'_> {
    fn request(
        &self,
        method: &str,
        url: &Url,
        headers: &[(String, String)],
        body: &[u8],
        deadline: Instant,
        maximum: u64,
    ) -> Result<Response> {
        assert!(Instant::now() < deadline);
        assert!(maximum > 0);
        let path = url.path();
        if method == "PATCH" {
            assert_eq!(path, "/repos/example/repository/releases/7");
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap(),
                json!({"draft":false})
            );
            *self.public.lock().unwrap() = true;
            *self.mutations.lock().unwrap() += 1;
            return Err(CiError::Message(
                "reply lost after server committed mutation".into(),
            ));
        }
        assert_eq!(method, "GET");
        assert!(body.is_empty());
        if url.host_str() == Some("index.crates.io") {
            assert!(
                !headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            );
            let package = path.rsplit('/').next().unwrap();
            let record = self
                .bundle
                .metadata
                .files
                .iter()
                .find(|row| row.package.as_deref() == Some(package))
                .unwrap();
            return Ok(json_response(
                json!({"name":package,"vers":"1.2.3","cksum":record.sha256,"yanked":false}),
            ));
        }
        if url.host_str() == Some("static.crates.io") {
            assert!(
                !headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            );
            let package = path.split('/').nth(2).unwrap();
            let index = self
                .bundle
                .metadata
                .files
                .iter()
                .position(|row| row.package.as_deref() == Some(package))
                .unwrap();
            assert_eq!(maximum, self.bundle.metadata.files[index].byte_len);
            return Ok(response(200, self.bundle.payloads[index].clone()));
        }
        match path {
            "/repos/example/repository"=>Ok(json_response(json!({"full_name":"example/repository","private":false}))),
            "/repos/example/repository/git/ref/tags/1.2.3"=>Ok(json_response(json!({"object":{"type":"commit","sha":self.bundle.metadata.source.commit}}))),
            "/repos/example/repository/releases"=>Ok(json_response(json!([{"id":7,"tag_name":"1.2.3","body":self.bundle.metadata.notes,"prerelease":false,"draft":!*self.public.lock().unwrap()}]))),
            "/repos/example/repository/releases/7/assets"=>Ok(json_response(Value::Array(self.bundle.metadata.files.iter().enumerate().map(|(index,row)| json!({"id":100+index,"name":row.name,"size":row.byte_len,"state":"uploaded","digest":format!("sha256:{}",row.sha256)})).collect()))),
            _=>{
                let index=path.strip_prefix("/repos/example/repository/releases/assets/").expect("unexpected publication URL").parse::<usize>().unwrap()-100;
                assert!(!headers.iter().any(|(name,_)| name.eq_ignore_ascii_case("authorization")));
                assert_eq!(maximum,self.bundle.metadata.files[index].byte_len);
                *self.anonymous_reads.lock().unwrap()+=1;
                let mut bytes=self.bundle.payloads[index].clone();
                if self.corrupt_content { bytes[0]^=1; }
                Ok(response(self.content_status,bytes))
            }
        }
    }
}

struct CreationRemote<'a> {
    existing: PublicationRemote<'a>,
    created: Mutex<bool>,
    uploaded: Mutex<BTreeSet<String>>,
    creations: Mutex<usize>,
    deadline: Instant,
    receipt_change: Option<(&'static str, Value)>,
    readback_change: Option<(&'static str, Value)>,
    readback_status: u16,
    lost_creation_reply: bool,
    conflicting_listing: bool,
}

impl CreationRemote<'_> {
    fn release(&self) -> Value {
        json!({"id":7,"name":"1.2.3","tag_name":"1.2.3",
            "body":self.existing.bundle.metadata.notes,"prerelease":false,
            "draft":!*self.existing.public.lock().unwrap()})
    }
}

impl Transport for CreationRemote<'_> {
    fn request(
        &self,
        method: &str,
        url: &Url,
        headers: &[(String, String)],
        body: &[u8],
        deadline: Instant,
        maximum: u64,
    ) -> Result<Response> {
        assert_eq!(
            deadline, self.deadline,
            "every request retains the shared deadline"
        );
        let path = url.path();
        if path == "/repos/example/repository/releases" {
            assert!(
                headers.iter().any(|(name, value)| name == "Authorization"
                    && value == "Bearer private fixture token")
            );
            if method == "GET" {
                let rows = if self.conflicting_listing && *self.created.lock().unwrap() {
                    let mut other = self.release();
                    other["id"] = json!(8);
                    vec![other]
                } else {
                    Vec::new()
                };
                return Ok(json_response(json!(rows)));
            }
            assert_eq!(method, "POST");
            let value: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(
                value["target_commitish"],
                self.existing.bundle.metadata.source.commit
            );
            assert_eq!(value["draft"], true);
            assert!(
                !*self.created.lock().unwrap(),
                "never repeat an accepted creation"
            );
            *self.created.lock().unwrap() = true;
            *self.creations.lock().unwrap() += 1;
            if self.lost_creation_reply {
                return Err(CiError::Message("creation reply lost".into()));
            }
            let mut value = self.release();
            if let Some((key, changed)) = &self.receipt_change {
                value[*key] = changed.clone();
            }
            return Ok(response(201, serde_json::to_vec(&value).unwrap()));
        }
        if method == "GET"
            && path
                .strip_prefix("/repos/example/repository/releases/")
                .is_some_and(|tail| tail.parse::<u64>().is_ok() && tail != "7")
        {
            return Ok(response(404, Vec::new()));
        }
        if path == "/repos/example/repository/releases/7" && method == "GET" {
            assert!(headers.iter().any(|(name, _)| name == "Authorization"));
            assert_eq!(url.host_str(), Some("api.github.com"));
            assert!(*self.created.lock().unwrap());
            let mut value = self.release();
            if let Some((key, changed)) = &self.readback_change {
                value[*key] = changed.clone();
            }
            return Ok(response(
                self.readback_status,
                serde_json::to_vec(&value).unwrap(),
            ));
        }
        if path == "/repos/example/repository/releases/7/assets" {
            let uploaded = self.uploaded.lock().unwrap();
            if method == "GET" {
                let rows: Vec<_> = self.existing.bundle.metadata.files.iter().enumerate()
                    .filter(|(_, row)| uploaded.contains(&row.name))
                    .map(|(index,row)| json!({"id":100+index,"name":row.name,"size":row.byte_len,"state":"uploaded","digest":format!("sha256:{}",row.sha256)})).collect();
                return Ok(json_response(json!(rows)));
            }
            drop(uploaded);
            assert_eq!(method, "POST");
            assert_eq!(url.host_str(), Some("uploads.github.com"));
            let name = url
                .query_pairs()
                .find(|(key, _)| key == "name")
                .unwrap()
                .1
                .into_owned();
            let index = self
                .existing
                .bundle
                .metadata
                .files
                .iter()
                .position(|row| row.name == name)
                .unwrap();
            assert_eq!(body, self.existing.bundle.payloads[index]);
            assert!(self.uploaded.lock().unwrap().insert(name));
            return Ok(json_response(json!({})));
        }
        self.existing
            .request(method, url, headers, body, deadline, maximum)
    }
}

fn creation_remote(bundle: &LoadedBundle, deadline: Instant) -> CreationRemote<'_> {
    CreationRemote {
        existing: PublicationRemote {
            bundle,
            public: Mutex::new(false),
            mutations: Mutex::new(0),
            anonymous_reads: Mutex::new(0),
            content_status: 200,
            corrupt_content: false,
        },
        created: Mutex::new(false),
        uploaded: Mutex::new(BTreeSet::new()),
        creations: Mutex::new(0),
        deadline,
        receipt_change: None,
        readback_change: None,
        readback_status: 200,
        lost_creation_reply: false,
        conflicting_listing: false,
    }
}

#[test]
fn accepted_creation_uses_validated_direct_readback_when_collection_stays_absent() {
    let bundle = bundle();
    let deadline = Instant::now() + Duration::from_secs(5);
    let remote = creation_remote(&bundle, deadline);
    let credentials = Credentials::for_transport("private fixture token".into(), None).unwrap();
    let summary = Publisher::new(&remote, &credentials, &bundle, deadline)
        .publish()
        .unwrap();
    assert!(summary.complete);
    assert_eq!(*remote.creations.lock().unwrap(), 1);
    assert_eq!(
        remote.uploaded.lock().unwrap().len(),
        bundle.metadata.files.len()
    );
    assert_eq!(
        *remote.existing.anonymous_reads.lock().unwrap(),
        bundle.metadata.files.len()
    );
    assert_eq!(
        summary.writes[0].endpoint,
        "/repos/example/repository/releases"
    );
    assert_eq!(summary.writes[0].release_id, Some(7));
}

#[test]
fn accepted_creation_rejects_conflicting_or_uncertain_identity_before_asset_writes() {
    let bundle = bundle();
    let credentials = Credentials::for_transport("private fixture token".into(), None).unwrap();
    for direct in [false, true] {
        for (key, value) in [
            ("id", json!(0)),
            ("id", json!(8)),
            ("tag_name", json!("other")),
            ("name", json!("other")),
            ("body", json!("changed")),
            ("prerelease", json!(true)),
            ("draft", Value::Null),
        ] {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut remote = creation_remote(&bundle, deadline);
            if direct {
                remote.readback_change = Some((key, value));
            } else {
                remote.receipt_change = Some((key, value));
            }
            assert!(
                Publisher::new(&remote, &credentials, &bundle, deadline)
                    .publish()
                    .is_err()
            );
            assert_eq!(*remote.creations.lock().unwrap(), 1);
            assert!(remote.uploaded.lock().unwrap().is_empty());
        }
    }
    for status in [404, 403, 500] {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut remote = creation_remote(&bundle, deadline);
        remote.readback_status = status;
        assert!(
            Publisher::new(&remote, &credentials, &bundle, deadline)
                .publish()
                .is_err()
        );
        assert!(remote.uploaded.lock().unwrap().is_empty());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut remote = creation_remote(&bundle, deadline);
    remote.conflicting_listing = true;
    assert!(
        Publisher::new(&remote, &credentials, &bundle, deadline)
            .publish()
            .is_err()
    );
    assert!(remote.uploaded.lock().unwrap().is_empty());
}

#[test]
fn lost_creation_reply_with_absent_collection_never_repeats_the_post() {
    let bundle = bundle();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut remote = creation_remote(&bundle, deadline);
    remote.lost_creation_reply = true;
    let credentials = Credentials::for_transport("private fixture token".into(), None).unwrap();
    let summary = Publisher::new(&remote, &credentials, &bundle, deadline)
        .publish()
        .unwrap();
    assert!(!summary.complete);
    assert_eq!(*remote.creations.lock().unwrap(), 1);
    assert!(remote.uploaded.lock().unwrap().is_empty());
    assert!(summary.writes[0].transport_failed);
}

#[test]
fn direct_release_readback_still_requires_anonymous_matching_asset_bytes() {
    let bundle = bundle();
    let credentials = Credentials::for_transport("private fixture token".into(), None).unwrap();
    for (status, corrupt) in [(403, false), (200, true)] {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut remote = creation_remote(&bundle, deadline);
        remote.existing.content_status = status;
        remote.existing.corrupt_content = corrupt;
        let summary = Publisher::new(&remote, &credentials, &bundle, deadline)
            .publish()
            .unwrap();
        assert!(!summary.complete);
        assert!(summary.objects.iter().any(|object| {
            object.destination == "github"
                && if corrupt {
                    matches!(object.observation, RemoteState::Conflicting { .. })
                } else {
                    matches!(object.observation, RemoteState::Unknown { .. })
                }
        }));
        assert_eq!(*remote.creations.lock().unwrap(), 1);
    }
}

#[test]
fn lost_mutation_reply_is_resolved_by_actual_readback_and_anonymous_content() {
    let bundle = bundle();
    let remote = PublicationRemote {
        bundle: &bundle,
        public: Mutex::new(false),
        mutations: Mutex::new(0),
        anonymous_reads: Mutex::new(0),
        content_status: 200,
        corrupt_content: false,
    };
    let credentials = Credentials::for_transport("private fixture token".into(), None).unwrap();
    let summary = Publisher::new(
        &remote,
        &credentials,
        &bundle,
        Instant::now() + Duration::from_secs(5),
    )
    .publish()
    .unwrap();
    assert!(summary.complete);
    assert_eq!(summary.public, Some(true));
    assert_eq!(*remote.mutations.lock().unwrap(), 1);
    assert_eq!(
        *remote.anonymous_reads.lock().unwrap(),
        bundle.metadata.files.len()
    );
    assert!(
        summary
            .objects
            .iter()
            .all(|object| object.observation == RemoteState::Matching)
    );
}

#[test]
fn inaccessible_public_bytes_are_unknown_and_changed_bytes_are_conflicting() {
    let bundle = bundle();
    let credentials = Credentials::for_transport("private fixture token".into(), None).unwrap();
    for (status, corrupt) in [(404, false), (500, false), (200, true)] {
        let remote = PublicationRemote {
            bundle: &bundle,
            public: Mutex::new(false),
            mutations: Mutex::new(0),
            anonymous_reads: Mutex::new(0),
            content_status: status,
            corrupt_content: corrupt,
        };
        let summary = Publisher::new(
            &remote,
            &credentials,
            &bundle,
            Instant::now() + Duration::from_secs(5),
        )
        .publish()
        .unwrap();
        assert!(!summary.complete);
        assert!(
            summary
                .objects
                .iter()
                .filter(|object| object.destination == "github")
                .all(|object| if corrupt {
                    matches!(object.observation, RemoteState::Conflicting { .. })
                } else {
                    matches!(object.observation, RemoteState::Unknown { .. })
                })
        );
        assert_eq!(*remote.mutations.lock().unwrap(), 1);
    }
}

fn zip_bytes(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    archive
        .start_file(name, zip::write::SimpleFileOptions::default())
        .unwrap();
    archive.write_all(bytes).unwrap();
    archive.finish().unwrap().into_inner()
}

// Structural archive fixtures exercise recovery decoding, not native execution.
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

fn prepared_zip() -> Vec<u8> {
    bundle_zip(false)
}

fn bundle_zip(candidate: bool) -> Vec<u8> {
    let selected = source();
    let build = if candidate {
        memcordon_ci::release::source::BuildSourceIdentity::Working {
            commit: selected.commit.clone(),
            version: selected.version.clone(),
        }
    } else {
        selected.into()
    };
    bundle_zip_with_identity(build)
}

fn bundle_zip_with_identity(build: memcordon_ci::release::source::BuildSourceIdentity) -> Vec<u8> {
    use memcordon_ci::release::{
        bundle::{CandidateBundle, CandidateManifest, NotesSelection, PublicManifest},
        compatibility::{Compatibility, NativePackage},
        installed_consumer,
        source::BuildSourceIdentity,
        target,
    };
    let candidate = matches!(build, BuildSourceIdentity::Working { .. });
    let mut selected = source();
    selected.commit = build.commit().into();
    selected.version = build.version().clone();
    let distribution =
        Distribution::read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let mut files = Vec::new();
    let mut payloads = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    let mut append = |name: String,
                      kind: &str,
                      target: Option<String>,
                      package: Option<String>,
                      bytes: Vec<u8>| {
        files.push(FileRecord {
            name: name.clone(),
            kind: kind.into(),
            target,
            package,
            byte_len: bytes.len() as u64,
            sha256: artifacts::checksum(&bytes),
        });
        assert!(payloads.insert(name, bytes).is_none());
    };
    for selection in &distribution.targets {
        let directory = tempfile::tempdir().unwrap();
        let mut members = BTreeMap::new();
        let mut executables = BTreeSet::new();
        for binary in &selection.binaries {
            let name = target::binary_name(binary, &selection.target);
            let bytes = executable_header(&selection.target);
            std::fs::write(directory.path().join(&name), &bytes).unwrap();
            members.insert(name.clone(), bytes);
            executables.insert(name);
        }
        for name in &selection.units {
            members.insert(
                name.clone(),
                b"[Unit]\nDescription=Recovery fixture\n".to_vec(),
            );
        }
        let manifest =
            installed_consumer::measured_manifest(&build, selection, directory.path()).unwrap();
        members.insert(
            "runtime-manifest.json".into(),
            serde_json::to_vec(&manifest).unwrap(),
        );
        assert!(
            manifests
                .insert(selection.target.clone(), manifest)
                .is_none()
        );
        let package = NativePackage::measured(&build, selection, &members).unwrap();
        members.insert("package.json".into(), serde_json::to_vec(&package).unwrap());
        append(
            selection.target.clone(),
            "archive",
            Some(selection.target.clone()),
            None,
            target::encode_archive(&selection.target, &members, &executables).unwrap(),
        );
    }
    // Independent order for this fixture's actual dependency graph.
    for package in [
        "memcordon-core",
        "memcordon-platform",
        "memcordon-windows-launch-core",
        "memcordon",
    ] {
        let mut dependencies = BTreeMap::new();
        if package != "memcordon-core" {
            dependencies.insert("memcordon-core", json!({"version": "=1.2.3"}));
        }
        if package == "memcordon" {
            dependencies.insert("memcordon-platform", json!({"version": "=1.2.3"}));
            dependencies.insert(
                "memcordon-windows-launch-core",
                json!({"version": "=1.2.3"}),
            );
        }
        let manifest = toml::to_string(&json!({"package":{"name":package,"version":"1.2.3","license":"MIT"},"dependencies":dependencies})).unwrap();
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        let member = Path::new(&format!("{package}-1.2.3")).join("Cargo.toml");
        archive
            .append_data(&mut header, member, Cursor::new(manifest.as_bytes()))
            .unwrap();
        append(
            package.to_owned(),
            "crate",
            None,
            Some(package.to_owned()),
            archive.into_inner().unwrap().finish().unwrap(),
        );
    }
    let compatibility = Compatibility::selected(&build, &distribution, &manifests).unwrap();
    append(
        "compatibility.json".into(),
        "compatibility",
        None,
        None,
        serde_json::to_vec(&compatibility).unwrap(),
    );
    let bytes = if candidate {
        serde_json::to_vec(&CandidateManifest {
            format: "memcordon.candidate-manifest".into(),
            revision: 1,
            version: selected.version.clone(),
            commit: selected.commit.clone(),
            files: files.clone(),
        })
        .unwrap()
    } else {
        let public = PublicManifest {
            schema: 1,
            version: selected.version.clone(),
            tag: selected.version.to_string(),
            commit: selected.commit.clone(),
            files: files.clone(),
        };
        serde_json::to_vec(&public).unwrap()
    };
    files.push(FileRecord {
        name: "manifest.json".into(),
        kind: "manifest".into(),
        target: None,
        package: None,
        byte_len: bytes.len() as u64,
        sha256: artifacts::checksum(&bytes),
    });
    payloads.insert("manifest.json".into(), bytes);
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let mut checksums = Vec::new();
    for file in ordered {
        writeln!(&mut checksums, "{}  {}", file.sha256, file.name).unwrap();
    }
    files.push(FileRecord {
        name: "SHA256SUMS".into(),
        kind: "checksums".into(),
        target: None,
        package: None,
        byte_len: checksums.len() as u64,
        sha256: artifacts::checksum(&checksums),
    });
    payloads.insert("SHA256SUMS".into(), checksums);
    let (metadata_name, metadata_bytes) = if candidate {
        let metadata = CandidateBundle {
            format: "memcordon.prepared-candidate".into(),
            revision: 1,
            source: build,
            distribution,
            files,
            notes_selection: NotesSelection::ExactVersion,
            notes: Some("Candidate archive fixture".into()),
        };
        ("candidate.json", serde_json::to_vec(&metadata).unwrap())
    } else {
        let metadata = PreparedBundle {
            format: "memcordon.prepared-release".into(),
            revision: 1,
            source: selected,
            distribution,
            files,
            notes: "Recovery archive fixture".into(),
        };
        ("prepared.json", serde_json::to_vec(&metadata).unwrap())
    };
    payloads.insert(metadata_name.into(), metadata_bytes);
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in payloads {
        archive
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(&bytes).unwrap();
    }
    archive.finish().unwrap().into_inner()
}

fn publication_tool_zip() -> Vec<u8> {
    let members = BTreeMap::from([(
        "memcordon-ci".into(),
        executable_header("x86_64-unknown-linux-gnu"),
    )]);
    let tar = memcordon_ci::release::target::encode_archive(
        "x86_64-unknown-linux-gnu",
        &members,
        &BTreeSet::from(["memcordon-ci".into()]),
    )
    .unwrap();
    zip_bytes("memcordon-publication-tool.tar.gz", &tar)
}

#[test]
fn candidate_payloads_validate_and_reject_publication_before_transport() {
    use memcordon_ci::release::{bundle::CandidateBundle, source::BuildSourceIdentity};
    let directory = tempfile::tempdir().unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(bundle_zip(true))).unwrap();
    archive.extract(directory.path()).unwrap();
    let (candidate, payloads) = CandidateBundle::load(directory.path()).unwrap();
    assert_eq!(candidate.files.len(), payloads.len());
    assert_eq!(candidate.distribution.targets.len(), 6);
    assert_eq!(candidate.distribution.packages.len(), 4);
    assert!(matches!(
        candidate.source,
        BuildSourceIdentity::Working { .. }
    ));
    assert!(!directory.path().join("prepared.json").exists());
    assert!(PreparedBundle::load(directory.path()).is_err());
    assert!(memcordon_ci::release::publish::run(directory.path(), true).is_err());

    // Relabeling the candidate metadata never turns it into a tagged envelope.
    std::fs::copy(
        directory.path().join("candidate.json"),
        directory.path().join("prepared.json"),
    )
    .unwrap();
    let transport = Script::new(vec![]);
    let attempt = || -> Result<()> {
        let loaded = PreparedBundle::load(directory.path())?;
        let credentials = Credentials::for_transport("fixture".into(), Some("fixture".into()))?;
        Publisher::new(
            &transport,
            &credentials,
            &loaded,
            Instant::now() + Duration::from_secs(1),
        )
        .publish()?;
        Ok(())
    };
    assert!(attempt().is_err());
    assert!(transport.calls.lock().unwrap().is_empty());
    assert!(CandidateBundle::load(directory.path()).is_err());

    let wrong_source = tempfile::tempdir().unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(bundle_zip(true))).unwrap();
    archive.extract(wrong_source.path()).unwrap();
    let mut changed = candidate.clone();
    changed.source = source().into();
    std::fs::write(
        wrong_source.path().join("candidate.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(CandidateBundle::load(wrong_source.path()).is_err());
    changed.source = BuildSourceIdentity::Working {
        commit: hex::encode([2; 20]),
        version: "1.2.3".parse().unwrap(),
    };
    std::fs::write(
        wrong_source.path().join("candidate.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(CandidateBundle::load(wrong_source.path()).is_err());
}

#[test]
fn shared_assembler_validates_real_working_source_payloads_and_target_coverage() {
    use memcordon_ci::release::{
        bundle::{self, CandidateBundle, NotesSelection},
        git::Git,
        packages::PackageBundle,
        source::{self, BuildSourceIdentity},
        target::{self, TargetBundle},
    };
    #[cfg(unix)]
    let workspace = tempfile::Builder::new()
        .prefix("memcordon-assembly-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let workspace = tempfile::Builder::new()
        .prefix("memcordon-assembly-")
        .tempdir()
        .unwrap();
    let root = workspace.path();
    std::fs::create_dir(root.join("ci")).unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for config in ["toolchains.toml", "distribution.toml"] {
        std::fs::copy(
            repository.join("ci").join(config),
            root.join("ci").join(config),
        )
        .unwrap();
    }
    let names = [
        "memcordon-core",
        "memcordon-platform",
        "memcordon-windows-launch-core",
        "memcordon",
    ];
    std::fs::write(
        root.join("Cargo.toml"),
        format!("[workspace]\nresolver=\"3\"\nmembers={names:?}\n"),
    )
    .unwrap();
    for name in names {
        std::fs::create_dir_all(root.join(name).join("src")).unwrap();
        std::fs::write(root.join(name).join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        let dependency = if name == "memcordon-core" {
            ""
        } else {
            "[dependencies]\nmemcordon-core={path=\"../memcordon-core\",version=\"=1.2.3\"}\n"
        };
        std::fs::write(
            root.join(name).join("Cargo.toml"),
            format!("[package]\nname={name:?}\nversion=\"1.2.3\"\nedition=\"2024\"\n{dependency}"),
        )
        .unwrap();
    }
    std::fs::write(
        root.join("CHANGELOG.md"),
        "## [1.2.3]\nActual fixture notes\n",
    )
    .unwrap();
    let git = Git::new(root).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text(["config", "user.name", "Assembly fixture"])
        .unwrap();
    git.text(["config", "user.email", "fixture@example.invalid"])
        .unwrap();
    git.text(["add", "."]).unwrap();
    git.text(["commit", "--no-gpg-sign", "-m", "Fixture source"])
        .unwrap();
    let selected = BuildSourceIdentity::working(root).unwrap();
    let staging = tempfile::tempdir().unwrap();
    let inventory = staging.path().join("inventory");
    std::fs::create_dir(&inventory).unwrap();
    let mut zip =
        zip::ZipArchive::new(Cursor::new(bundle_zip_with_identity(selected.clone()))).unwrap();
    zip.extract(&inventory).unwrap();
    let (candidate, _) = CandidateBundle::load(&inventory).unwrap();
    let package_dir = staging.path().join("packages");
    std::fs::create_dir(&package_dir).unwrap();
    let packages = PackageBundle {
        format: "memcordon.packages".into(),
        revision: 1,
        source: selected.clone(),
        files: candidate
            .files
            .iter()
            .filter(|file| file.kind == "crate")
            .cloned()
            .collect(),
    };
    for file in &packages.files {
        std::fs::copy(inventory.join(&file.name), package_dir.join(&file.name)).unwrap();
    }
    source::write_json(&package_dir.join("packages.json"), &packages).unwrap();
    let mut targets = Vec::new();
    for (index, selection) in candidate.distribution.targets.iter().enumerate() {
        let directory = staging.path().join(index.to_string());
        std::fs::create_dir(&directory).unwrap();
        let archive = candidate
            .files
            .iter()
            .find(|file| file.target.as_deref() == Some(selection.target.as_str()))
            .unwrap()
            .clone();
        let bytes = std::fs::read(inventory.join(&archive.name)).unwrap();
        let members = target::decode_archive(&bytes, &selection.target).unwrap();
        let records = members
            .iter()
            .map(|(name, bytes)| FileRecord {
                name: name.clone(),
                kind: "runtime-data".into(),
                target: Some(selection.target.clone()),
                package: None,
                byte_len: bytes.len() as u64,
                sha256: artifacts::checksum(bytes),
            })
            .collect();
        let fixture_bytes = executable_header(&selection.target);
        let fixture = FileRecord {
            name: target::binary_name("memcordon-test-fixture", &selection.target),
            kind: "fixture".into(),
            target: Some(selection.target.clone()),
            package: None,
            byte_len: fixture_bytes.len() as u64,
            sha256: artifacts::checksum(&fixture_bytes),
        };
        std::fs::write(directory.join(&archive.name), bytes).unwrap();
        std::fs::write(directory.join(&fixture.name), fixture_bytes).unwrap();
        let target = TargetBundle {
            format: "memcordon.target".into(),
            revision: 1,
            source: selected.clone(),
            distribution: selection.clone(),
            archive,
            members: records,
            fixture,
        };
        source::write_json(&directory.join("target.json"), &target).unwrap();
        targets.push(directory);
    }
    let destination = staging.path().join("candidate-output");
    bundle::assemble_build(root, &selected, &package_dir, &targets, &destination).unwrap();
    let (loaded, _) = CandidateBundle::load(&destination).unwrap();
    assert_eq!(loaded.notes_selection, NotesSelection::ExactVersion);
    assert_eq!(loaded.source, selected);
    assert!(!destination.join("prepared.json").exists());
    let missing = &targets[..targets.len() - 1];
    assert!(
        bundle::assemble_build(
            root,
            &selected,
            &package_dir,
            missing,
            &staging.path().join("missing-output")
        )
        .is_err()
    );
    let mut duplicate = targets.clone();
    duplicate.push(targets[0].clone());
    assert!(
        bundle::assemble_build(
            root,
            &selected,
            &package_dir,
            &duplicate,
            &staging.path().join("duplicate-output")
        )
        .is_err()
    );
    let mut wrong = packages.clone();
    wrong.source = BuildSourceIdentity::Working {
        version: "1.2.3".parse().unwrap(),
        commit: hex::encode([2; 20]),
    };
    source::write_json(&package_dir.join("packages.json"), &wrong).unwrap();
    assert!(
        bundle::assemble_build(
            root,
            &selected,
            &package_dir,
            &targets,
            &staging.path().join("wrong-source-output")
        )
        .is_err()
    );
}

struct RecoveryRemote {
    source: SelectedSource,
    artifact_name: String,
    tool_name: String,
    assembly_conclusion: String,
    archive: Vec<u8>,
}
impl Transport for RecoveryRemote {
    fn request(
        &self,
        method: &str,
        url: &Url,
        _headers: &[(String, String)],
        _body: &[u8],
        _deadline: Instant,
        _maximum: u64,
    ) -> Result<Response> {
        assert_eq!(method, "GET");
        let prefix = "/repos/example/repository/actions/";
        match url.path().strip_prefix(prefix).expect("wrong repository") {
            "runs/9" => Ok(json_response(
                json!({"id":9,"run_attempt":2,"event":"push","head_sha":self.source.commit,"head_branch":"1.2.3","path":".github/workflows/release.yml","repository":{"full_name":self.source.repository}}),
            )),
            "runs/9/attempts/1/jobs" => Ok(json_response(
                json!({"jobs":[{"id":1,"run_id":9,"name":"select","status":"completed","conclusion":"success","head_sha":self.source.commit,"started_at":"2026-10-01T01:00:00Z","completed_at":"2026-10-01T01:05:00Z"},{"id":2,"run_id":9,"name":"assemble","status":"completed","conclusion":self.assembly_conclusion,"head_sha":self.source.commit,"started_at":"2026-10-01T01:10:00Z","completed_at":"2026-10-01T01:15:00Z"}]}),
            )),
            "runs/9/attempts/2/jobs" => Ok(json_response(
                json!({"jobs":[{"id":3,"run_id":9,"name":"assemble","status":"completed","conclusion":"failure","head_sha":self.source.commit,"started_at":"2026-10-01T02:10:00Z","completed_at":"2026-10-01T02:15:00Z"}]}),
            )),
            "artifacts/10" | "artifacts/11" => {
                let id = url
                    .path()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
                let name = if id == 10 {
                    self.artifact_name.as_str()
                } else {
                    self.tool_name.as_str()
                };
                let bytes = if id == 10 {
                    self.archive.clone()
                } else {
                    publication_tool_zip()
                };
                Ok(json_response(
                    json!({"id":id,"expired":false,"size_in_bytes":bytes.len(),"name":name,"created_at":"2026-10-01T01:14:00Z","digest":format!("sha256:{}",artifacts::checksum(&bytes)),"workflow_run":{"id":9,"head_sha":self.source.commit}}),
                ))
            }
            "artifacts/10/zip" => Ok(response(200, self.archive.clone())),
            "artifacts/11/zip" => Ok(response(200, publication_tool_zip())),
            _ => panic!("unexpected recovery path"),
        }
    }
}

#[test]
fn recovery_requires_exact_original_artifact_names_and_complete_archive_inventory() {
    let locator = PreparedArtifactLocator {
        run_id: 9,
        prepared_artifact_id: 10,
        tool_artifact_id: 11,
    };
    let run = |remote: &RecoveryRemote| {
        recovery::validate_original(
            remote,
            &ReadBudget::new(Instant::now() + Duration::from_secs(2)),
            &[],
            &remote.source,
            &locator,
        )
    };
    let mut remote = RecoveryRemote {
        source: source(),
        artifact_name: "prepared-9-1".into(),
        tool_name: "publication-tool-9-1".into(),
        assembly_conclusion: "success".into(),
        archive: prepared_zip(),
    };
    run(&remote).unwrap();
    for name in [
        "prepared-09-1",
        "prepared-10-1",
        "prepared-9-2",
        "prepared-9-0",
        "prepared-9-01",
        "prepared-9-9",
        "prepared",
        "publication-tool-9",
    ] {
        remote.artifact_name = name.into();
        assert!(run(&remote).is_err());
    }
    remote.artifact_name = "prepared-9-1".into();
    remote.tool_name = "publication-tool-9-2".into();
    assert!(run(&remote).is_err(), "different final attempts must fail");
    remote.tool_name = "publication-tool-9-1".into();
    remote.assembly_conclusion = "failure".into();
    assert!(
        run(&remote).is_err(),
        "partial upload from failed final producer must fail"
    );
    remote.assembly_conclusion = "success".into();
    for name in ["prepared.json.old", "../prepared.json", "Prepared.JSON"] {
        remote.archive = zip_bytes(name, b"{}");
        assert!(run(&remote).is_err());
    }
}
