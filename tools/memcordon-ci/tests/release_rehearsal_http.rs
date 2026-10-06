//! Small actual process/HTTP controls; assembled bundle matrix belongs to Release CI.
use memcordon_ci::{
    rehearsal_support::{protocol::*, server, wire},
    release::{
        http::{ReadBudget, Transport},
        rehearsal::LoopbackTransport,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn scratch() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        tempfile::Builder::new()
            .prefix("memcordon-rehearsal-http-")
            .tempdir_in("/tmp")
            .unwrap()
    }
    #[cfg(not(unix))]
    {
        tempfile::Builder::new()
            .prefix("memcordon-rehearsal-http-")
            .tempdir()
            .unwrap()
    }
}
fn archive() -> Vec<u8> {
    let manifest=b"[package]\nname='fixture-package'\nversion='1.2.3'\nedition='2021'\nlicense='MIT'\n[features]\ndefault=[]\n[target.'cfg(unix)'.build-dependencies.renamed]\npackage='real-name'\nversion='1'\noptional=false\n";
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(
        &mut header,
        "fixture-package-1.2.3/Cargo.toml",
        Cursor::new(manifest),
    )
    .unwrap();
    tar.into_inner().unwrap().finish().unwrap()
}
fn metadata() -> Value {
    json!({"name":"fixture-package","vers":"1.2.3","deps":[{"name":"real-name","version_req":"1","features":[],"optional":false,"default_features":true,"target":"cfg(unix)","kind":"build","registry":null,"explicit_name_in_toml":"renamed"}],"features":{"default":[]},"badges":{},"authors":[],"keywords":[],"categories":[],"description":null,"documentation":null,"homepage":null,"license":"MIT","license_file":null,"repository":null,"links":null,"rust_version":null,"readme":null,"readme_file":null})
}
fn wire_body(metadata: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(u32::try_from(metadata.len()).unwrap().to_le_bytes());
    body.extend(metadata);
    body.extend(u32::try_from(archive.len()).unwrap().to_le_bytes());
    body.extend(archive);
    body
}

#[test]
fn cargo_received_archive_oracle_checks_renames_targets_and_exact_framing() {
    let root = scratch();
    let archive = archive();
    let body = wire_body(&serde_json::to_vec(&metadata()).unwrap(), &archive);
    let received = root.path().join("received");
    fs::write(&received, &body).unwrap();
    let decoded = wire::decode_upload(
        &received,
        &root.path().join("archive"),
        archive.len() as u64,
    )
    .unwrap();
    assert_eq!(decoded.sha256, hex::encode(Sha256::digest(&archive)));
    assert_eq!(decoded.index["deps"][0]["name"], "renamed");
    assert_eq!(decoded.index["deps"][0]["package"], "real-name");
    assert_eq!(decoded.index["deps"][0]["kind"], "build");
    let in_place = root.path().join("in-place");
    fs::write(&in_place, &body).unwrap();
    wire::decode_upload(&in_place, &in_place, archive.len() as u64).unwrap();
    assert_eq!(fs::read(&in_place).unwrap(), archive);
    let mut changed = metadata();
    changed["deps"][0]["target"] = json!(null);
    fs::write(
        &received,
        wire_body(&serde_json::to_vec(&changed).unwrap(), &archive),
    )
    .unwrap();
    assert!(
        wire::decode_upload(
            &received,
            &root.path().join("changed"),
            archive.len() as u64
        )
        .is_err()
    );
    let mut overlong = body;
    overlong.push(0);
    fs::write(&received, overlong).unwrap();
    assert!(
        wire::decode_upload(
            &received,
            &root.path().join("overlong"),
            archive.len() as u64
        )
        .is_err()
    );
    fs::write(
        &received,
        wire_body(
            b"{\"name\":\"fixture-package\",\"name\":\"other\"}",
            &archive,
        ),
    )
    .unwrap();
    assert!(
        wire::decode_upload(
            &received,
            &root.path().join("duplicate"),
            archive.len() as u64
        )
        .is_err()
    );
}

struct Fixture {
    child: RetiringChild,
    record: FixtureRecord,
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
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
impl Fixture {
    fn start(state: &Path, bytes: &[u8], fault: Fault) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let setup = Setup {
            revision: REVISION,
            case_id: "focused".into(),
            selection: FixtureSelection {
                version: "1.2.3".into(),
                commit: "1111111111111111111111111111111111111111".into(),
                repository: "fixture/repository".into(),
                notes: "actual notes".into(),
                prerelease: false,
                files: vec![ExpectedFile {
                    name: "asset.bin".into(),
                    size: bytes.len() as u64,
                    sha256: hex::encode(Sha256::digest(bytes)),
                    package: None,
                }],
            },
            fault,
            budget: BudgetPreset::Normal20min,
            work_unix_ms: now + 30_000,
        };
        fs::write(
            state.join("setup.json"),
            serde_json::to_vec(&setup).unwrap(),
        )
        .unwrap();
        let ready = state.join("ready.json");
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-release-rehearsal"));
        command
            .args(["serve", "--case", "focused", "--state"])
            .arg(state)
            .arg("--ready")
            .arg(&ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in [
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "CARGO_REGISTRY_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_CACHE_URL",
        ] {
            command.env_remove(name);
        }
        let mut child = RetiringChild(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        let record = loop {
            if let Ok(bytes) = fs::read(&ready) {
                if let Ok(record) = serde_json::from_slice(&bytes) {
                    break record;
                }
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "fixture exited before ready"
            );
            assert!(Instant::now() < deadline, "fixture readiness elapsed");
            std::thread::sleep(Duration::from_millis(10));
        };
        Self { child, record }
    }
    fn transport(&self) -> LoopbackTransport {
        LoopbackTransport::new(self.record.clone()).unwrap()
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
                break;
            }
            if Instant::now() >= deadline {
                self.child.kill().unwrap();
                self.child.wait().unwrap();
                panic!("fixture did not settle");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn github_headers() -> Vec<(String, String)> {
    vec![("Authorization".into(), format!("Bearer {GITHUB_TOKEN}"))]
}
fn request(
    transport: &LoopbackTransport,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> memcordon_ci::release::http::Response {
    transport
        .request(
            method,
            &url::Url::parse(url).unwrap(),
            headers,
            body,
            Instant::now() + Duration::from_secs(5),
            1024 * 1024,
        )
        .unwrap()
}

#[test]
fn actual_http_fixture_commits_received_bytes_and_rejects_duplicate_effect() {
    let root = scratch();
    let bytes = b"distinct actual received asset bytes";
    let mut fixture = Fixture::start(root.path(), bytes, Fault::None);
    let transport = fixture.transport();
    let draft=serde_json::to_vec(&json!({"tag_name":"1.2.3","target_commitish":"1111111111111111111111111111111111111111","body":"actual notes","draft":true,"prerelease":false})).unwrap();
    assert_eq!(
        request(
            &transport,
            "POST",
            "https://api.github.com/repos/fixture/repository/releases",
            &github_headers(),
            &draft
        )
        .status,
        201
    );
    let url =
        "https://uploads.github.com/repos/fixture/repository/releases/1/assets?name=asset.bin";
    assert_eq!(
        request(&transport, "POST", url, &github_headers(), bytes).status,
        201
    );
    assert_eq!(
        request(&transport, "POST", url, &github_headers(), bytes).status,
        422
    );
    let snapshot = server::read_snapshot(root.path()).unwrap();
    assert_eq!(snapshot.effects.len(), 2);
    assert_eq!(snapshot.assets.len(), 1);
    assert_eq!(
        fs::read(root.path().join(&snapshot.assets[0].path)).unwrap(),
        bytes
    );
    let download_url =
        url::Url::parse("https://api.github.com/repos/fixture/repository/releases/assets/1")
            .unwrap();
    assert!(
        transport
            .request(
                "GET",
                &download_url,
                &[],
                &[],
                Instant::now() + Duration::from_secs(5),
                bytes.len() as u64 - 1
            )
            .is_err(),
        "an extra received byte must exceed the selected bound"
    );
    let exposed = memcordon_ci::release::http::download(
        &transport,
        &ReadBudget::new(Instant::now() + Duration::from_secs(5)),
        &download_url,
        &[],
        bytes.len() as u64,
    )
    .unwrap();
    assert_eq!(exposed, bytes);
    assert_eq!(
        request(
            &transport,
            "PUT",
            "https://crates.io/api/v1/crates/new",
            &github_headers(),
            b""
        )
        .status,
        403
    );
    assert_eq!(
        request(
            &transport,
            "POST",
            url,
            &github_headers(),
            &vec![0; bytes.len() + 1]
        )
        .status,
        413
    );
    assert_eq!(
        server::read_snapshot(root.path())
            .unwrap()
            .credential_errors,
        1
    );
    assert_eq!(server::read_snapshot(root.path()).unwrap().effects.len(), 2);
    fixture.stop();
    assert_eq!(
        server::read_snapshot(root.path()).unwrap().body_downloads,
        2
    );
}
