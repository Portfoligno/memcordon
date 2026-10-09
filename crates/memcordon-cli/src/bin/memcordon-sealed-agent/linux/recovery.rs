use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use super::{CGROUP_ROOT, STATE_ROOT};

pub(crate) const MAX_RECORD_BYTES: u64 = 16 * 1024
    + memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64
    + memcordon_core::workload_limits::CONTRACT_BYTES as u64
    + super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64;

pub fn recover() -> Result<Vec<String>, String> {
    recover_roots(Path::new(STATE_ROOT), Path::new(CGROUP_ROOT))
}

/// Administrative retry of persisted native obligations, without recreating
/// execution observations or treating an ambiguous owner as retired.
pub fn recover_administrative() -> Result<(), String> {
    // SAFETY: geteuid has no pointer preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("native recovery requires authenticated root administration".into());
    }
    let _package_owner = super::service::acquire_package_lease()?;
    let unresolved = recover()?;
    let receipt = serde_json::json!({
        "format": "memcordon.native-recovery", "revision": 1,
        "outstanding": unresolved,
    });
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|error| error.to_string())?
    );
    if unresolved.is_empty() {
        Ok(())
    } else {
        Err("native recovery retains ambiguous ownership obligations".into())
    }
}

#[cfg(feature = "test-support")]
pub fn recover_test_roots(state_root: &Path, cgroup_root: &Path) -> Result<Vec<String>, String> {
    recover_roots(state_root, cgroup_root)
}

fn recover_roots(state_root: &Path, cgroup_root: &Path) -> Result<Vec<String>, String> {
    let mut ambiguous = Vec::new();
    let mut authenticated = BTreeSet::new();
    match fs::symlink_metadata(state_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            recover_records(state_root, cgroup_root, &mut authenticated, &mut ambiguous)?;
        }
        Ok(_) => {
            return Err("MCSEALED-RECOVERY: state root is not a no-follow directory".to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("MCSEALED-RECOVERY: {error}")),
    }
    inspect_cgroup_root(cgroup_root, &authenticated, &mut ambiguous)?;
    ambiguous.sort();
    ambiguous.dedup();
    Ok(ambiguous)
}

fn recover_records(
    state_root: &Path,
    cgroup_root: &Path,
    authenticated: &mut BTreeSet<OsString>,
    ambiguous: &mut Vec<String>,
) -> Result<(), String> {
    let reservations = fs::read_dir(state_root)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    for entry in &reservations {
        let name = entry.file_name();
        let Some(identity) = name
            .to_str()
            .filter(|value| super::cgroup::valid_attempt_identity(value))
        else {
            continue;
        };
        let bytes = match read_record_no_follow(&entry.path()) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let record = match super::private_attempt::PrivateAttemptRecordV4::parse(bytes.as_bytes()) {
            Ok(record)
                if record.attempt_id.as_str() == identity
                    && record.mixed_admission_metadata.is_some() =>
            {
                record
            }
            _ => continue,
        };
        if let Err(error) = recover_mixed_record(state_root, cgroup_root, &record, &entry.path()) {
            authenticated.insert(name.clone());
            ambiguous.push(format!("{identity}: {error}"));
        }
    }
    let reservations = fs::read_dir(state_root)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    for entry in reservations {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("account-") && name.ends_with(".reservation"))
            && !recover_account_reservation(state_root, cgroup_root, &entry)?
        {
            ambiguous.push(name.to_string_lossy().into_owned());
        }
    }
    // Refresh after retiring a known pre-allocation journal, avoiding stale
    // directory entries and preserving every unreclaimed uncertain owner.
    let entries = fs::read_dir(state_root)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let mut blocked_by_temporary = BTreeSet::new();
    for entry in &entries {
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        let Some(identity) = name_text
            .strip_suffix(".new")
            .filter(|name| super::cgroup::valid_attempt_identity(name))
        else {
            continue;
        };
        if interrupted_transition_is_recoverable(state_root, cgroup_root, identity, entry)? {
            fs::remove_file(entry.path()).map_err(|error| {
                format!("MCSEALED-RECOVERY: interrupted transition rollback failed: {error}")
            })?;
            File::open(state_root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?;
        } else {
            ambiguous.push(name_text.to_owned());
            blocked_by_temporary.insert(identity.to_owned());
        }
    }

    for entry in entries {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("account-") && name.ends_with(".reservation"))
        {
            continue;
        }
        if name.to_str().is_some_and(|name| {
            name.strip_suffix(".new")
                .is_some_and(super::cgroup::valid_attempt_identity)
        }) {
            continue;
        }
        let Some(identity) = name
            .to_str()
            .filter(|name| super::cgroup::valid_attempt_identity(name))
        else {
            ambiguous.push(name.to_string_lossy().into_owned());
            continue;
        };
        if blocked_by_temporary.contains(identity) {
            ambiguous.push(identity.to_owned());
            continue;
        }
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if !file_type.is_file() {
            ambiguous.push(identity.to_owned());
            continue;
        }
        let record = read_record_no_follow(&entry.path())?;
        if !integrity_valid(&record)
            || record.lines().find_map(|line| line.strip_prefix("cgroup=")) != Some(identity)
        {
            ambiguous.push(identity.to_owned());
            continue;
        }
        if record.starts_with("format=memcordon.private-native-journal\nrevision=1\n") {
            if super::private_attempt::PrivateAttemptRecordV4::parse(record.as_bytes())
                .is_ok_and(|record| record.attempt_id.as_str() == identity)
            {
                // A V4 attempt may have released the target and owns more than
                // a cgroup. Until its terminal ledger can be reconstructed,
                // preserve every protected resource for explicit recovery.
                authenticated.insert(name.clone());
            }
            ambiguous.push(identity.to_owned());
            continue;
        }
        authenticated.insert(name.clone());
        if record
            .lines()
            .find_map(|line| line.strip_prefix("frontend-pid="))
            .and_then(|value| value.parse::<libc::pid_t>().ok())
            .is_some_and(process_is_live)
        {
            ambiguous.push(identity.to_owned());
            continue;
        }
        let cgroup_path = cgroup_root.join(&name);
        match fs::symlink_metadata(&cgroup_path) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                super::cgroup::AttemptCgroup::authenticated(cgroup_path)
                    .kill_and_retire(Instant::now() + Duration::from_secs(10))?;
            }
            Ok(_) => {
                return Err(format!(
                    "MCSEALED-RECOVERY: authenticated boundary {identity} is not a directory"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("MCSEALED-RECOVERY: {error}")),
        }
        fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn recover_mixed_record(
    state_root: &Path,
    cgroup_root: &Path,
    record: &super::private_attempt::PrivateAttemptRecordV4,
    journal: &Path,
) -> Result<(), String> {
    let metadata = record
        .mixed_admission_metadata
        .as_ref()
        .ok_or("mixed recovery metadata absent")?;
    let lease = crate::policy_registry::native::Lease::acquire()?;
    let registry = lease.retained_registry_v3(&metadata.registry_digest)?;
    let layout = registry
        .root_layouts
        .as_slice()
        .iter()
        .find(|layout| layout.reference().ok().as_ref() == Some(&metadata.request.root_layout))
        .ok_or("retained recovery root layout absent")?;
    let account = registry
        .execution_identities
        .as_slice()
        .iter()
        .find(|identity| {
            identity.reference().ok().as_ref() == Some(&metadata.request.execution_identity)
        })
        .ok_or("retained recovery exclusive identity absent")?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_root)
        .map_err(|error| error.to_string())?;
    let parent = directory.metadata().map_err(|error| error.to_string())?;
    if parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("mixed recovery state ancestry differs".into());
    }
    let reference_path = state_root.join(format!("{}.mixed-admission", record.attempt_id.as_str()));
    let reference = held_recovery_file(&reference_path)?;
    if let Some(file) = &reference {
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if memcordon_core::workload_admission_v3::RuntimeMixedAdmissionSnapshot::parse(&bytes)?
            != *metadata
        {
            return Err("mixed recovery reference differs from journal".into());
        }
    }
    let journal_file = held_recovery_file(journal)?.ok_or("mixed recovery journal disappeared")?;
    let mut journal_bytes = Vec::new();
    (&journal_file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut journal_bytes)
        .map_err(|error| error.to_string())?;
    if super::private_attempt::PrivateAttemptRecordV4::parse(&journal_bytes)? != *record {
        return Err("mixed recovery held journal differs from parsed owner".into());
    }
    super::mixed_recovery::settle_native(record, cgroup_root, layout.output_files.as_slice())?;
    super::mixed_admission::require_account_quiescent(account.uid.get(), None)?;
    // Reservation deletion remains under the same retained native settlement;
    // an unrelated or malformed reservation is never consumed by filename.
    for entry in fs::read_dir(state_root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("account-") && name.ends_with(".reservation"))
        {
            continue;
        }
        let file =
            held_recovery_file(&entry.path())?.ok_or("mixed recovery reservation disappeared")?;
        let mut bytes = Vec::new();
        (&file)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        let expected_keys = std::collections::BTreeSet::from([
            "format",
            "revision",
            "user_namespace_device",
            "user_namespace_inode",
            "uid",
            "attempt",
            "owner_pid",
            "owner_birth",
            "boot_identity",
        ]);
        if value
            .as_object()
            .ok_or("reservation is not an object")?
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != expected_keys
        {
            return Err("mixed recovery reservation fields differ".into());
        }
        let attempt: Vec<u8> = serde_json::from_value(
            value
                .get("attempt")
                .cloned()
                .ok_or("reservation attempt absent")?,
        )
        .map_err(|error| error.to_string())?;
        let expected = record.attempt_id.as_str();
        let encoded = attempt
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect::<String>();
        if encoded != expected {
            continue;
        }
        let namespace_device = value
            .get("user_namespace_device")
            .and_then(serde_json::Value::as_u64)
            .filter(|value| *value != 0)
            .ok_or("reservation namespace device absent")?;
        let namespace_inode = value
            .get("user_namespace_inode")
            .and_then(serde_json::Value::as_u64)
            .filter(|value| *value != 0)
            .ok_or("reservation namespace inode absent")?;
        if entry.file_name()
            != OsString::from(format!(
                "account-{namespace_device}-{namespace_inode}-{}.reservation",
                account.uid.get()
            ))
        {
            return Err("mixed recovery reservation filename differs".into());
        }
        let worker = record
            .mixed_worker
            .as_ref()
            .ok_or("mixed recovery reservation has no recorded creator")?;
        if value.get("owner_pid").and_then(serde_json::Value::as_u64) != Some(u64::from(worker.pid))
            || value.get("owner_birth").and_then(serde_json::Value::as_u64)
                != Some(worker.start_time)
        {
            return Err("mixed recovery reservation creator differs".into());
        }
        if value.get("format").and_then(serde_json::Value::as_str)
            != Some("memcordon.account-reservation")
            || value.get("revision").and_then(serde_json::Value::as_u64) != Some(1)
            || value.get("uid").and_then(serde_json::Value::as_u64)
                != Some(u64::from(account.uid.get()))
            || value
                .get("boot_identity")
                .and_then(serde_json::Value::as_str)
                != Some(record.boot_identity.as_str())
        {
            return Err("mixed recovery reservation binding differs".into());
        }
        unlink_recovery_file(&entry.path(), &file, &directory)?;
    }
    if let Some(reference) = reference {
        unlink_recovery_file(&reference_path, &reference, &directory)?;
    }
    unlink_recovery_file(journal, &journal_file, &directory)
}

fn held_recovery_file(path: &Path) -> Result<Option<File>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_RECORD_BYTES
    {
        return Err("mixed recovery record custody differs".into());
    }
    Ok(Some(file))
}
fn unlink_recovery_file(path: &Path, file: &File, directory: &File) -> Result<(), String> {
    let held = file.metadata().map_err(|error| error.to_string())?;
    let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !named.is_file()
        || (
            named.dev(),
            named.ino(),
            named.len(),
            named.mtime(),
            named.mtime_nsec(),
        ) != (
            held.dev(),
            held.ino(),
            held.len(),
            held.mtime(),
            held.mtime_nsec(),
        )
    {
        return Err("mixed recovery named record changed".into());
    }
    fs::remove_file(path).map_err(|error| error.to_string())?;
    if file.metadata().map_err(|error| error.to_string())?.nlink() != 0 {
        return Err("mixed recovery removed inode remains linked".into());
    }
    directory.sync_all().map_err(|error| error.to_string())
}

/// Reclaim a fully written reservation only after creator loss and boundary absence.
/// Its journal must be absent or validate as allocation-only state with no native
/// resources. Malformed or torn records remain quarantined and grant no permission.
fn recover_account_reservation(
    state_root: &Path,
    cgroup_root: &Path,
    entry: &fs::DirEntry,
) -> Result<bool, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reservation {
        format: String,
        revision: u32,
        user_namespace_device: u64,
        user_namespace_inode: u64,
        uid: u32,
        attempt: [u8; 16],
        owner_pid: libc::pid_t,
        owner_birth: u64,
        boot_identity: String,
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_root)
        .map_err(|error| error.to_string())?;
    let directory_metadata = directory.metadata().map_err(|error| error.to_string())?;
    if directory_metadata.uid() != 0 || directory_metadata.mode() & 0o022 != 0 {
        return Ok(false);
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(entry.path())
    {
        Ok(file) => file,
        Err(_) => return Ok(false),
    };
    let held = file.metadata().map_err(|error| error.to_string())?;
    if !held.is_file()
        || held.uid() != 0
        || held.nlink() != 1
        || held.mode() & 0o7777 != 0o600
        || held.len() > 4096
    {
        return Ok(false);
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 4096
        || memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes).is_err()
    {
        return Ok(false);
    }
    let reservation: Reservation = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if reservation.format != "memcordon.account-reservation"
        || reservation.revision != 1
        || reservation.user_namespace_device == 0
        || reservation.user_namespace_inode == 0
        || reservation.uid == 0
        || !canonical_boot_identity(&reservation.boot_identity)
        || reservation.owner_pid <= 0
        || reservation.owner_birth == 0
        || reservation.attempt == [0; 16]
        || entry.file_name()
            != OsString::from(format!(
                "account-{}-{}-{}.reservation",
                reservation.user_namespace_device,
                reservation.user_namespace_inode,
                reservation.uid
            ))
    {
        return Ok(false);
    }
    let boot =
        fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| error.to_string())?;
    if reservation.boot_identity == boot.trim() {
        match super::envelope::process_start_time(reservation.owner_pid) {
            Ok(birth) if birth == reservation.owner_birth => return Ok(false),
            Ok(birth) if birth > reservation.owner_birth => (),
            Ok(_) => return Ok(false),
            Err(_)
                if !Path::new("/proc")
                    .join(reservation.owner_pid.to_string())
                    .exists() => {}
            Err(_) => return Ok(false),
        }
    }
    let identity: String = reservation
        .attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for path in [
        state_root.join(format!("{identity}.new")),
        cgroup_root.join(&identity),
    ] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Ok(false),
        }
    }
    let journal = state_root.join(&identity);
    match fs::symlink_metadata(&journal) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Ok(metadata)
            if metadata.is_file()
                && metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o7777 == 0o600 =>
        {
            let bytes = read_record_no_follow(&journal)?;
            let record =
                match super::private_attempt::PrivateAttemptRecordV4::parse(bytes.as_bytes()) {
                    Ok(record) => record,
                    Err(_) => return Ok(false),
                };
            if record.attempt_id.as_str() != identity
                || record.mixed_admission_metadata.is_some()
                || record.boot_identity.as_str() != reservation.boot_identity
                || record.phase != super::private_attempt::PrivateAttemptPhase::Allocated
                || record.target.is_some()
                || record.namespace_init.is_some()
                || record.guardian.is_some()
                || record.network_namespace_inode.is_some()
                || record.gated_facts.is_some()
            {
                return Ok(false);
            }
            let current = fs::symlink_metadata(&journal).map_err(|error| error.to_string())?;
            if (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            ) != (
                current.dev(),
                current.ino(),
                current.len(),
                current.mtime(),
                current.mtime_nsec(),
            ) {
                return Ok(false);
            }
            fs::remove_file(&journal).map_err(|error| error.to_string())?;
            directory.sync_all().map_err(|error| error.to_string())?;
        }
        _ => return Ok(false),
    }
    let current = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
    if (
        current.dev(),
        current.ino(),
        current.len(),
        current.mtime(),
        current.mtime_nsec(),
    ) != (
        held.dev(),
        held.ino(),
        held.len(),
        held.mtime(),
        held.mtime_nsec(),
    ) {
        return Ok(false);
    }
    fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
    directory.sync_all().map_err(|error| error.to_string())?;
    Ok(true)
}

fn canonical_boot_identity(value: &str) -> bool {
    let shape = "00000000-0000-0000-0000-000000000000";
    value.len() == shape.len()
        && value.bytes().zip(shape.bytes()).all(|(actual, expected)| {
            if expected == b'-' {
                actual == b'-'
            } else {
                actual.is_ascii_digit() || (b'a'..=b'f').contains(&actual)
            }
        })
        && value
            .bytes()
            .any(|byte| (b'1'..=b'9').contains(&byte) || (b'a'..=b'f').contains(&byte))
}

fn interrupted_transition_is_recoverable(
    state_root: &Path,
    cgroup_root: &Path,
    identity: &str,
    temporary: &fs::DirEntry,
) -> Result<bool, String> {
    let canonical_path = state_root.join(identity);
    let canonical_metadata = match fs::symlink_metadata(&canonical_path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) | Err(_) => return Ok(false),
    };
    let temporary_metadata = fs::symlink_metadata(temporary.path())
        .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?;
    if !temporary
        .file_type()
        .map_err(|error| error.to_string())?
        .is_file()
        || temporary_metadata.uid() != canonical_metadata.uid()
        || temporary_metadata.permissions().mode() & 0o777 != 0o600
        || temporary_metadata.nlink() != 1
        || temporary_metadata.len() > MAX_RECORD_BYTES
    {
        return Ok(false);
    }

    let canonical = match read_record_no_follow(&canonical_path) {
        Ok(record) => record,
        Err(_) => return Ok(false),
    };
    if !integrity_valid(&canonical)
        || canonical
            .lines()
            .find_map(|line| line.strip_prefix("cgroup="))
            != Some(identity)
    {
        return Ok(false);
    }
    if canonical.starts_with("version=4\n")
        || canonical.starts_with("format=memcordon.private-native-journal\n")
    {
        return Ok(false);
    }
    if canonical
        .lines()
        .find_map(|line| line.strip_prefix("frontend-pid="))
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .is_some_and(process_is_live)
    {
        return Ok(false);
    }

    let interrupted = match read_record_no_follow(&temporary.path()) {
        Ok(record) => record,
        Err(_) => return Ok(false),
    };
    if interrupted.starts_with("version=4\n")
        || interrupted.starts_with("format=memcordon.private-native-journal\n")
    {
        return Ok(false);
    }
    if interrupted
        .lines()
        .find_map(|line| line.strip_prefix("cgroup="))
        .is_some_and(|bound| bound != identity)
    {
        return Ok(false);
    }

    let cgroup_path = cgroup_root.join(identity);
    match fs::symlink_metadata(&cgroup_path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            super::cgroup::AttemptCgroup::authenticated(cgroup_path)
                .kill_and_retire(Instant::now() + Duration::from_secs(10))?;
        }
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("MCSEALED-RECOVERY: {error}")),
    }
    Ok(true)
}

fn process_is_live(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal zero does not mutate the target process; `pid` is a validated positive
    // scalar, and errno is inspected only when libc reports failure.
    let status = unsafe { libc::kill(pid, 0) };
    status == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn inspect_cgroup_root(
    cgroup_root: &Path,
    authenticated: &BTreeSet<OsString>,
    ambiguous: &mut Vec<String>,
) -> Result<(), String> {
    match fs::symlink_metadata(cgroup_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err("MCSEALED-RECOVERY: cgroup root is not a no-follow directory".to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("MCSEALED-RECOVERY: {error}")),
    }
    for entry in fs::read_dir(cgroup_root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        match super::cgroup::classify_attempt_root_entry(&entry)
            .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?
        {
            super::cgroup::AttemptRootEntry::KernelControl => continue,
            super::cgroup::AttemptRootEntry::Attempt { name, .. } => {
                if !authenticated.contains(&name) {
                    ambiguous.push(name.to_string_lossy().into_owned());
                }
            }
            super::cgroup::AttemptRootEntry::InvalidDirectory(name) => {
                return Err(format!(
                    "MCSEALED-RECOVERY: invalid attempt directory {}",
                    name.to_string_lossy()
                ));
            }
            super::cgroup::AttemptRootEntry::Unsafe(name) => {
                return Err(format!(
                    "MCSEALED-RECOVERY: unsafe cgroup entry {}",
                    name.to_string_lossy()
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn read_record_no_follow(path: &Path) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?
        .file_type()
        .is_file()
    {
        return Err("MCSEALED-RECOVERY: attempt record is not a regular file".to_owned());
    }
    let mut record = String::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_string(&mut record)
        .map_err(|error| format!("MCSEALED-RECOVERY: {error}"))?;
    if record.len() as u64 > MAX_RECORD_BYTES {
        return Err("MCSEALED-RECOVERY: attempt record exceeds size limit".to_owned());
    }
    Ok(record)
}

pub(crate) fn integrity_valid(record: &str) -> bool {
    if record.starts_with("format=memcordon.private-native-journal\nrevision=1\n") {
        super::private_attempt::PrivateAttemptRecordV4::parse(record.as_bytes()).is_ok()
    } else {
        super::attempt::parse_durable_policy(record).is_ok()
    }
}
