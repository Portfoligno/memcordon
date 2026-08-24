#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use memcordon_platform::test_support::ProcessIdentity;
use memcordon_testkit::run_with_deadline;

const DESCENDANT_IDENTITY: &str = "descendant.pid";
const HELPER_TEST: &str = "outer_boundary_helper_leaves_descendant";

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should follow the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "memcordon-testkit-outer-boundary-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("temporary directory should exist");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn outer_boundary_returns_only_after_a_leaked_descendant_is_absent() {
    let temporary = TemporaryDirectory::new();
    let executable = std::env::current_exe().expect("test executable path should exist");
    let mut command = Command::new(executable);
    command
        .args([
            HELPER_TEST,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(temporary.path());

    let output = run_with_deadline(&mut command, Duration::from_secs(5))
        .expect("outer boundary should retire the helper descendant");
    assert!(
        output.status.success(),
        "helper failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let identity = read_identity(&temporary.path().join(DESCENDANT_IDENTITY));
    assert!(
        !identity
            .still_exists()
            .expect("descendant identity should remain queryable"),
        "outer boundary returned while the descendant still existed"
    );
}

#[test]
#[ignore = "subprocess helper for outer boundary coverage"]
#[expect(
    clippy::zombie_processes,
    reason = "the outer boundary under test must inherit and reap this descendant"
)]
fn outer_boundary_helper_leaves_descendant() {
    let child = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("descendant should start");
    ProcessIdentity::for_pid(child.id())
        .expect("descendant identity should be readable")
        .publish_to(Path::new(DESCENDANT_IDENTITY))
        .expect("descendant identity should publish");
}

fn read_identity(path: &Path) -> ProcessIdentity {
    let value = std::fs::read_to_string(path).expect("descendant identity should read");
    let mut fields = value.split_ascii_whitespace();
    let pid = fields
        .next()
        .expect("descendant identity should contain a pid")
        .parse()
        .expect("descendant pid should parse");
    let birth = fields
        .next()
        .expect("descendant identity should contain a birth identity")
        .parse()
        .expect("descendant birth identity should parse");
    assert!(fields.next().is_none(), "descendant identity was malformed");
    ProcessIdentity { pid, birth }
}
