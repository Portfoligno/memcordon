use memcordon_ci::{
    rehearsal_support::protocol::*,
    release::rehearsal::{LoopbackTransport, unix_ms},
};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

struct RetiringChild(std::process::Child);
impl std::ops::Deref for RetiringChild {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for RetiringChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for RetiringChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.0.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[test]
fn numeric_endpoint_and_closed_logical_origins_are_required() {
    let mut record = FixtureRecord {
        revision: REVISION,
        address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
        session: "control".into(),
        budget: BudgetPreset::Short5s,
        expires_unix_ms: unix_ms().unwrap() + 5000,
    };
    assert!(LoopbackTransport::new(record.clone()).is_ok());
    record.address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 80);
    assert!(LoopbackTransport::new(record.clone()).is_err());
    record.address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    assert!(LoopbackTransport::new(record.clone()).is_err());
    record.address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80);
    record.revision += 1;
    assert!(LoopbackTransport::new(record).is_err());
    for logical in [
        "https://example.invalid/",
        "http://api.github.com/",
        "https://api.github.com:444/",
        "https://user@api.github.com/",
    ] {
        assert!(
            memcordon_ci::release::rehearsal::service(&url::Url::parse(logical).unwrap()).is_err()
        );
    }
}

#[test]
fn hostile_standard_proxies_do_not_receive_fixture_requests() {
    #[cfg(unix)]
    let root = tempfile::tempdir_in("/tmp").unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    let setup = Setup {
        revision: REVISION,
        case_id: "proxy-control".into(),
        selection: FixtureSelection {
            version: "1.2.3".into(),
            commit: "1111111111111111111111111111111111111111".into(),
            repository: "fixture/repository".into(),
            notes: "notes".into(),
            prerelease: false,
            files: vec![ExpectedFile {
                name: "fixture.txt".into(),
                size: 1,
                sha256: memcordon_ci::release::artifacts::checksum(b"x"),
                package: None,
            }],
        },
        fault: Fault::None,
        budget: BudgetPreset::Short5s,
        work_unix_ms: unix_ms().unwrap() + 5000,
    };
    fs::write(
        root.path().join("setup.json"),
        serde_json::to_vec(&setup).unwrap(),
    )
    .unwrap();
    let ready = root.path().join("ready.json");
    let mut server = Command::new(env!("CARGO_BIN_EXE_memcordon-release-rehearsal"));
    server
        .args(["serve", "--case", "proxy-control", "--state"])
        .arg(root.path())
        .arg("--ready")
        .arg(&ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    memcordon_ci::rehearsal_support::coordinator::sanitize_child(&mut server);
    let mut child = RetiringChild(server.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(4);
    while fs::read(&ready)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<FixtureRecord>(&bytes).ok())
        .is_none()
    {
        assert!(child.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let trap = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    trap.set_nonblocking(true).unwrap();
    let mut proxy = url::Url::parse("http://127.0.0.1").unwrap();
    proxy
        .set_port(Some(trap.local_addr().unwrap().port()))
        .unwrap();
    let mut probe = Command::new(env!("CARGO_BIN_EXE_memcordon-release-rehearsal"));
    probe.args(["transport-control", "--fixture"]).arg(&ready);
    probe
        .env("HTTP_PROXY", proxy.as_str())
        .env("HTTPS_PROXY", proxy.as_str())
        .env("ALL_PROXY", proxy.as_str())
        .env("http_proxy", proxy.as_str())
        .env("https_proxy", proxy.as_str())
        .env("all_proxy", proxy.as_str())
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    memcordon_ci::rehearsal_support::coordinator::sanitize_child(&mut probe);
    let output = memcordon_testkit::run_with_deadline(&mut probe, Duration::from_secs(4)).unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    child.kill().unwrap();
    child.wait().unwrap();
}
