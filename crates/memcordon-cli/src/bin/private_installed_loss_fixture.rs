//! Explicit test-fixture operation. Protected records identify a running test;
//! they grant no production permission and are never modified by this observer.
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memcordon_core::workload_contract::WorkloadContractV2;
use memcordon_platform::test_support::ProcessIdentity;
use serde_json::Value;
use sha2::{Digest, Sha256};

const ROOT: &str = "/var/lib/memcordon/sealed";
const IMAGE: &str = "/usr/libexec/memcordon-installed-private-fixture";
const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";

fn bounded(path: &Path, protected: bool) -> Result<(File, Vec<u8>), String> {
    bounded_limit(path, protected, 1024 * 1024)
}

fn bounded_limit(path: &Path, protected: bool, limit: u64) -> Result<(File, Vec<u8>), String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() > limit
        || protected && (before.uid() != 0 || before.mode() & 0o777 != 0o600)
    {
        return Err("loss fixture input metadata differs".into());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if u64::try_from(bytes.len()).map_err(|_| "input size")? > limit
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err("loss fixture input changed".into());
    }
    Ok((file, bytes))
}

fn json(bytes: &[u8]) -> Result<Value, String> {
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}

fn number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("loss fixture missing {key}"))
}

fn journal(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let (body, checksum) = text
        .rsplit_once("digest=")
        .ok_or("journal checksum absent")?;
    let actual = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if checksum.strip_suffix('\n') != Some(actual.as_str()) {
        return Err("journal checksum differs".into());
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
    {
        return Err("loss fixture journal namespace differs".into());
    }
    let attempt = lines
        .next()
        .and_then(|line| line.strip_prefix("cgroup="))
        .ok_or("journal attempt absent")?;
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or("journal payload absent")?;
    if lines.next().is_some() {
        return Err("journal has extra lines".into());
    }
    let value = json(payload.as_bytes())?;
    if value.get("attempt_id").and_then(Value::as_str) != Some(attempt)
        || value.get("phase").and_then(Value::as_str) != Some("execution-observed")
        || value.get("release_knowledge").and_then(Value::as_str) != Some("exec-observed")
    {
        return Err("journal is not a live execution observation".into());
    }
    Ok(value)
}

struct HeldProcess {
    pidfd: OwnedFd,
    identity: ProcessIdentity,
}
impl HeldProcess {
    fn open(pid: u32, birth: u64) -> Result<Self, String> {
        let identity = ProcessIdentity {
            pid,
            birth: u128::from(birth),
        };
        if !identity.still_exists().map_err(|e| e.to_string())? {
            return Err("observed process is absent".into());
        }
        // SAFETY: pidfd_open receives a native PID checked before and after acquisition.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: successful pidfd_open returns a uniquely owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).map_err(|_| "pidfd range")?) };
        let held = Self { pidfd, identity };
        held.revalidate()?;
        Ok(held)
    }
    fn revalidate(&self) -> Result<(), String> {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized native descriptor slot.
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0
            || !self.identity.still_exists().map_err(|e| e.to_string())?
        {
            return Err("held process lifetime changed".into());
        }
        Ok(())
    }
    fn kill(&self) -> Result<(), String> {
        self.revalidate()?;
        // SAFETY: signal targets only this retained, independently verified pidfd.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

fn process_path(pid: u32, leaf: &str) -> PathBuf {
    Path::new("/proc").join(pid.to_string()).join(leaf)
}

pub fn run(
    request: &Path,
    ready: &Path,
    mode: &str,
    expected_image_sha256: &str,
    observed: &Path,
    assessed: &Path,
) -> Result<Value, String> {
    // SAFETY: geteuid is a query-only native call.
    if unsafe { libc::geteuid() } != 0 || !matches!(mode, "init" | "worker") {
        return Err("explicit root native loss fixture requires init or worker".into());
    }
    let (_, request_bytes) = bounded(request, false)?;
    let contract: WorkloadContractV2 =
        serde_json::from_value(json(&request_bytes)?).map_err(|e| e.to_string())?;
    contract.validate()?;
    let (_, ready_bytes) = bounded(ready, false)?;
    let mut fields = std::str::from_utf8(&ready_bytes)
        .map_err(|e| e.to_string())?
        .split_whitespace();
    let namespace_pid = fields
        .next()
        .ok_or("ready PID absent")?
        .parse::<u32>()
        .map_err(|e| e.to_string())?;
    let birth = fields
        .next()
        .ok_or("ready birth absent")?
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    if fields.next().is_some() || namespace_pid == 0 || birth == 0 {
        return Err("ready identity differs".into());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ROOT)
        .map_err(|e| e.to_string())?;
    let root_metadata = directory.metadata().map_err(|e| e.to_string())?;
    if root_metadata.uid() != 0 || root_metadata.mode() & 0o777 != 0o700 {
        return Err("protected journal root differs".into());
    }
    let until = Instant::now() + Duration::from_secs(5);
    let (journal_file, journal_bytes, record, target) = loop {
        let mut selected = Vec::new();
        for entry in fs::read_dir(ROOT).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            if name.as_encoded_bytes().len() != std::mem::size_of::<[u8; 16]>() * 2
                || !name.as_encoded_bytes().iter().all(u8::is_ascii_hexdigit)
            {
                continue;
            }
            let (file, bytes) = bounded(&entry.path(), true)?;
            let Ok(record) = journal(&bytes) else {
                continue;
            };
            let Some(metadata) = record.get("admission_metadata") else {
                continue;
            };
            let metadata: memcordon_core::workload_admission_v2::RuntimePrivateAdmissionSnapshot =
                serde_json::from_value(metadata.clone()).map_err(|e| e.to_string())?;
            metadata.validate()?;
            if metadata.request != contract {
                continue;
            }
            let Some(target) = record.get("target").filter(|value| !value.is_null()) else {
                continue;
            };
            if number(target, "start_time")? != birth {
                continue;
            }
            let pid = u32::try_from(number(target, "pid")?).map_err(|_| "target PID range")?;
            let held = HeldProcess::open(pid, birth)?;
            let status =
                fs::read_to_string(process_path(pid, "status")).map_err(|e| e.to_string())?;
            let observed_namespace_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .and_then(|line| line.split_whitespace().last())
                .and_then(|value| value.parse::<u32>().ok());
            if observed_namespace_pid != Some(namespace_pid) {
                continue;
            }
            let actual_image = fs::metadata(process_path(pid, "exe")).map_err(|e| e.to_string())?;
            let image = fs::metadata(IMAGE).map_err(|e| e.to_string())?;
            if actual_image.dev() != image.dev()
                || actual_image.ino() != image.ino()
                || image.uid() != 0
                || image.mode() & 0o022 != 0
            {
                return Err("held target image differs from installed trusted fixture".into());
            }
            let (_, image_bytes) = bounded_limit(Path::new(IMAGE), false, 128 * 1024 * 1024)?;
            let image_sha = Sha256::digest(&image_bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            if image_sha != expected_image_sha256 {
                return Err("selected installed fixture bytes differ".into());
            }
            let network = fs::metadata(process_path(pid, "ns/net")).map_err(|e| e.to_string())?;
            if number(&record, "network_namespace_inode")? != network.ino() {
                return Err("target namespace differs from journal".into());
            }
            selected.push((file, bytes, record, held));
        }
        if selected.len() > 1 {
            return Err("native installed loss association is ambiguous".into());
        }
        if let Some(selected) = selected.pop() {
            break selected;
        }
        if Instant::now() >= until {
            return Err("live installed loss association not found".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let attempt = record
        .get("attempt_id")
        .and_then(Value::as_str)
        .ok_or("attempt absent")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| e.to_string())?;
    if record.get("boot_identity").and_then(Value::as_str) != Some(boot.trim()) {
        return Err("journal belongs to another native boot".into());
    }
    let mut reservations = Vec::new();
    for entry in fs::read_dir(ROOT).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .ends_with(b".reservation")
        {
            continue;
        }
        let (file, bytes) = bounded(&entry.path(), true)?;
        let reservation = json(&bytes)?;
        if reservation.get("format").and_then(Value::as_str)
            != Some("memcordon.account-reservation")
            || number(&reservation, "revision")? != 1
        {
            return Err("reservation namespace differs".into());
        }
        if reservation.get("boot_identity").and_then(Value::as_str) != Some(boot.trim()) {
            return Err("reservation belongs to another native boot".into());
        }
        let encoded: [u8; 16] = serde_json::from_value(
            reservation
                .get("attempt")
                .cloned()
                .ok_or("reservation attempt absent")?,
        )
        .map_err(|e| e.to_string())?;
        let encoded = encoded
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if encoded == attempt {
            reservations.push((entry.path(), file, bytes, reservation));
        }
    }
    if reservations.len() != 1 {
        return Err("exact live account reservation is absent or ambiguous".into());
    }
    let (reservation_path, _reservation_file, reservation_bytes, reservation) =
        reservations.pop().expect("exact one");
    let identity = if mode == "init" {
        let init = record.get("namespace_init").ok_or("init absent")?;
        (number(init, "pid")?, number(init, "start_time")?)
    } else {
        (
            number(&reservation, "owner_pid")?,
            number(&reservation, "owner_birth")?,
        )
    };
    let selected = HeldProcess::open(
        u32::try_from(identity.0).map_err(|_| "selected PID range")?,
        identity.1,
    )?;
    let mut remaining = Vec::new();
    for key in ["namespace_init", "guardian"] {
        let value = record.get(key).ok_or("native companion identity absent")?;
        remaining.push(HeldProcess::open(
            u32::try_from(number(value, "pid")?).map_err(|_| "companion PID range")?,
            number(value, "start_time")?,
        )?);
    }
    let selected_image =
        fs::metadata(process_path(selected.identity.pid, "exe")).map_err(|e| e.to_string())?;
    let agent = fs::metadata(AGENT).map_err(|e| e.to_string())?;
    if selected_image.dev() != agent.dev() || selected_image.ino() != agent.ino() {
        return Err("selected native owner image differs".into());
    }
    target.revalidate()?;
    let current_root = fs::symlink_metadata(ROOT).map_err(|e| e.to_string())?;
    if current_root.dev() != root_metadata.dev()
        || current_root.ino() != root_metadata.ino()
        || journal_file.metadata().map_err(|e| e.to_string())?.len()
            != u64::try_from(journal_bytes.len()).map_err(|_| "journal size")?
    {
        return Err("protected native association changed".into());
    }
    let (fresh_journal, fresh_journal_bytes) = bounded(&Path::new(ROOT).join(attempt), true)?;
    let old_journal = journal_file.metadata().map_err(|e| e.to_string())?;
    let new_journal = fresh_journal.metadata().map_err(|e| e.to_string())?;
    if old_journal.dev() != new_journal.dev()
        || old_journal.ino() != new_journal.ino()
        || fresh_journal_bytes != journal_bytes
        || bounded(&reservation_path, true)?.1 != reservation_bytes
    {
        return Err("native journal or reservation changed before signal".into());
    }
    selected.kill()?;
    let mut result = serde_json::json!({"format":"memcordon.installed-native-owner-loss", "revision":1,
        "mode":mode, "attempt":attempt, "target_pid":target.identity.pid, "target_birth":target.identity.birth,
        "owner_pid":selected.identity.pid, "owner_birth":selected.identity.birth,
        "journal_sha256":Sha256::digest(&journal_bytes).iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
        "reservation_sha256":Sha256::digest(&reservation_bytes).iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
        "signal_sent":true, "retirement_observed":false,
        "runtime_quarantine_retained":false, "administrative_fixture_cleanup":false});
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        let exited = std::iter::once(&target)
            .chain(std::iter::once(&selected))
            .chain(remaining.iter())
            .map(|held| {
                held.identity
                    .still_exists()
                    .map(|exists| !exists)
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if exited.iter().all(|value| *value)
            && !Path::new("/sys/fs/cgroup/memcordon-sealed")
                .join(attempt)
                .try_exists()
                .map_err(|e| e.to_string())?
        {
            break;
        }
        if Instant::now() >= until {
            return Err("native owner-loss fixture did not observe complete process absence and cgroup removal".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    result["retirement_observed"] = Value::Bool(true);
    if mode == "worker" {
        if bounded(&Path::new(ROOT).join(attempt), true)?.1 != journal_bytes
            || bounded(&reservation_path, true)?.1 != reservation_bytes
        {
            return Err(
                "lost worker did not retain its exact uncertain journal and reservation".into(),
            );
        }
        result["runtime_quarantine_retained"] = Value::Bool(true);
    }
    let bytes = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(observed)
        .map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut output, &bytes)
        .and_then(|()| output.sync_all())
        .map_err(|e| e.to_string())?;
    while !assessed.try_exists().map_err(|e| e.to_string())? {
        if Instant::now() >= until {
            return Err("owner-loss assessment acknowledgement deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if mode == "worker" {
        // Explicit disposal of this test's records occurs only after independent
        // frontend failure/capacity assessment and actual process absence. It is
        // not runtime recovery, retirement evidence or permission reconstruction.
        if bounded(&Path::new(ROOT).join(attempt), true)?.1 != journal_bytes
            || bounded(&reservation_path, true)?.1 != reservation_bytes
        {
            return Err("quarantined test records changed before fixture disposal".into());
        }
        fs::remove_file(Path::new(ROOT).join(attempt)).map_err(|e| e.to_string())?;
        fs::remove_file(reservation_path).map_err(|e| e.to_string())?;
        directory.sync_all().map_err(|e| e.to_string())?;
        result["administrative_fixture_cleanup"] = Value::Bool(true);
    }
    Ok(result)
}
