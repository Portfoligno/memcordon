//! Fixed package-owned credentials, independent of workload approval.
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::{Duration, Instant};

pub const NAME: &str = "memcordon-workload";
const PARENT: &str = "/var/lib/memcordon";
const RECORD: &str = "/var/lib/memcordon/workload-account.json";
const PENDING: &str = "/var/lib/memcordon/workload-account.pending";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRecord {
    format: String,
    revision: u32,
    uid: u32,
    gid: u32,
    allocation_marker: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountIntent {
    format: String,
    revision: u32,
    allocation_marker: String,
}
fn allocation_marker() -> Result<Option<String>, String> {
    let name = CString::new(NAME).expect("fixed account name");
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut storage = vec![0 as libc::c_char; 64 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: bounded writable passwd storage and stable NUL-terminated name.
    let code = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            entry.as_mut_ptr(),
            storage.as_mut_ptr(),
            storage.len(),
            &mut result,
        )
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code).to_string());
    }
    if result.is_null() {
        return Ok(None);
    }
    // SAFETY: successful native lookup initialized entry and its storage pointers.
    let entry = unsafe { entry.assume_init() };
    let marker = unsafe { CStr::from_ptr(entry.pw_gecos) }
        .to_str()
        .map_err(|e| e.to_string())?;
    Ok(Some(marker.into()))
}
fn valid_marker(marker: &str) -> bool {
    marker
        .strip_prefix("memcordon-package-")
        .is_some_and(|nonce| {
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
fn read_intent() -> Result<Option<AccountIntent>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PENDING)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 4096
    {
        return Err("package allocation intent custody differs".into());
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
    let intent: AccountIntent = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if intent.format != "memcordon.package-workload-account-intent"
        || intent.revision != 1
        || !valid_marker(&intent.allocation_marker)
    {
        return Err("invalid package account allocation intent".into());
    }
    Ok(Some(intent))
}
pub struct VerifiedPackageAccount {
    uid: u32,
    gid: u32,
}
impl VerifiedPackageAccount {
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
}

fn protected_parent() -> Result<File, String> {
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PARENT)
        .map_err(|e| e.to_string())?;
    let metadata = parent.metadata().map_err(|e| e.to_string())?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("package account parent custody differs".into());
    }
    Ok(parent)
}

pub(crate) fn has_current_installation_state() -> Result<bool, String> {
    match std::fs::symlink_metadata(PARENT) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if lookup()?.is_some() || group()?.is_some() {
                return Err("unmanaged workload credentials occupy the fixed native role".into());
            }
            return Ok(false);
        }
        Err(error) => return Err(error.to_string()),
        Ok(_) => {}
    }
    let _parent = protected_parent()?;
    if read_record()?.is_some() {
        verify()?;
        return Ok(true);
    }
    if let Some(intent) = read_intent()? {
        if lookup()?.is_some()
            && allocation_marker()?.as_deref() != Some(intent.allocation_marker.as_str())
        {
            return Err("current account intent differs from actual native user marker".into());
        }
        return Ok(true);
    }
    if lookup()?.is_some() || group()?.is_some() {
        return Err("unmanaged workload credentials have no current package record".into());
    }
    Ok(false)
}

struct EmptyCreatedParent(Option<File>);
impl Drop for EmptyCreatedParent {
    fn drop(&mut self) {
        if let Some(held) = &self.0 {
            if let (Ok(identity), Ok(metadata)) =
                (held.metadata(), std::fs::symlink_metadata(PARENT))
            {
                if metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && (metadata.dev(), metadata.ino()) == (identity.dev(), identity.ino())
                {
                    // rmdir never removes entries; a retained current intent is preserved.
                    let _ = std::fs::remove_dir(PARENT);
                }
            }
        }
    }
}
fn lookup() -> Result<Option<(u32, u32)>, String> {
    let name = CString::new(NAME).expect("fixed account name");
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut storage = vec![0 as libc::c_char; 64 * 1024];
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            entry.as_mut_ptr(),
            storage.as_mut_ptr(),
            storage.len(),
            &mut result,
        )
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code).to_string());
    }
    if result.is_null() {
        return Ok(None);
    }
    let entry = unsafe { entry.assume_init() };
    let shell = unsafe { CStr::from_ptr(entry.pw_shell) }.to_bytes();
    let home = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
    if entry.pw_uid == 0
        || entry.pw_gid == 0
        || !matches!(shell, b"/usr/sbin/nologin" | b"/sbin/nologin")
        || home != b"/nonexistent"
    {
        return Err("fixed account credential/home/shell conflict".into());
    }
    let ids = (entry.pw_uid, entry.pw_gid);
    let mut count = 0_i32;
    unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            entry.pw_gid,
            std::ptr::null_mut(),
            &mut count,
        )
    };
    if count != 1 {
        return Err("fixed workload account has supplementary memberships".into());
    }
    let mut primary_group = 0;
    if unsafe { libc::getgrouplist(name.as_ptr(), entry.pw_gid, &mut primary_group, &mut count) }
        < 0
        || count != 1
        || primary_group != entry.pw_gid
    {
        return Err("fixed workload group changed".into());
    }
    let mut shadow = std::mem::MaybeUninit::<libc::spwd>::uninit();
    let mut shadow_result = std::ptr::null_mut();
    let code = unsafe {
        libc::getspnam_r(
            name.as_ptr(),
            shadow.as_mut_ptr(),
            storage.as_mut_ptr(),
            storage.len(),
            &mut shadow_result,
        )
    };
    if code != 0 || shadow_result.is_null() {
        return Err("cannot verify fixed account password lock".into());
    }
    let shadow = unsafe { shadow.assume_init() };
    if !matches!(
        unsafe { CStr::from_ptr(shadow.sp_pwdp) }.to_bytes().first(),
        Some(b'!' | b'*')
    ) {
        return Err("fixed account password is not locked".into());
    }
    if group()? != Some(ids.1) {
        return Err("fixed account primary group ownership differs".into());
    }
    verify_no_aliases(ids)?;
    Ok(Some(ids))
}
fn verify_no_aliases((uid, gid): (u32, u32)) -> Result<(), String> {
    struct Cursor(bool);
    impl Drop for Cursor {
        fn drop(&mut self) {
            // SAFETY: closes this worker's native account-database enumeration cursor.
            unsafe {
                if self.0 {
                    libc::endpwent()
                } else {
                    libc::endgrent()
                }
            }
        }
    }
    // Each provider worker verifies credentials before creating threads. A
    // finite scan rejects aliases instead of relying on the first UID match.
    unsafe { libc::setpwent() };
    let passwd_cursor = Cursor(true);
    let mut storage = vec![0 as libc::c_char; 64 * 1024];
    let mut finished = false;
    for _ in 0..65536 {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: bounded writable native record and backing character buffer.
        let code = unsafe {
            libc::getpwent_r(
                entry.as_mut_ptr(),
                storage.as_mut_ptr(),
                storage.len(),
                &mut result,
            )
        };
        if code == libc::ENOENT || (code == 0 && result.is_null()) {
            finished = true;
            break;
        }
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code).to_string());
        }
        let entry = unsafe { entry.assume_init() };
        if (entry.pw_uid == uid || entry.pw_gid == gid)
            && unsafe { CStr::from_ptr(entry.pw_name) }.to_bytes() != NAME.as_bytes()
        {
            return Err("package workload UID/GID has another native account alias".into());
        }
    }
    drop(passwd_cursor);
    if !finished {
        return Err("native account enumeration exceeds finite bound".into());
    }
    unsafe { libc::setgrent() };
    let group_cursor = Cursor(false);
    finished = false;
    for _ in 0..65536 {
        let mut entry = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: bounded writable native record and backing character buffer.
        let code = unsafe {
            libc::getgrent_r(
                entry.as_mut_ptr(),
                storage.as_mut_ptr(),
                storage.len(),
                &mut result,
            )
        };
        if code == libc::ENOENT || (code == 0 && result.is_null()) {
            finished = true;
            break;
        }
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code).to_string());
        }
        let entry = unsafe { entry.assume_init() };
        if entry.gr_gid == gid
            && unsafe { CStr::from_ptr(entry.gr_name) }.to_bytes() != NAME.as_bytes()
        {
            return Err("package workload GID has another native group alias".into());
        }
    }
    drop(group_cursor);
    if !finished {
        return Err("native group enumeration exceeds finite bound".into());
    }
    Ok(())
}
fn group() -> Result<Option<u32>, String> {
    let name = CString::new(NAME).expect("fixed account name");
    let mut entry = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut storage = vec![0 as libc::c_char; 64 * 1024];
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            entry.as_mut_ptr(),
            storage.as_mut_ptr(),
            storage.len(),
            &mut result,
        )
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code).to_string());
    }
    if result.is_null() {
        return Ok(None);
    }
    let entry = unsafe { entry.assume_init() };
    if entry.gr_gid == 0 || (!entry.gr_mem.is_null() && !unsafe { *entry.gr_mem }.is_null()) {
        return Err("fixed workload group has unexpected members".into());
    }
    Ok(Some(entry.gr_gid))
}
fn read_record() -> Result<Option<AccountRecord>, String> {
    let _parent = protected_parent()?;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(RECORD)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("package account record custody differs".into());
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 4096 {
        return Err("package account record exceeds bound".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
    let record: AccountRecord = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if record.format != "memcordon.package-workload-account"
        || record.revision != 1
        || record.uid == 0
        || record.gid == 0
    {
        return Err("invalid package account record".into());
    }
    Ok(Some(record))
}
pub fn verify() -> Result<VerifiedPackageAccount, String> {
    let record = read_record()?.ok_or("package-owned workload account absent")?;
    if lookup()? != Some((record.uid, record.gid))
        || !valid_marker(&record.allocation_marker)
        || allocation_marker()?.as_deref() != Some(record.allocation_marker.as_str())
    {
        return Err("package-owned workload credential changed".into());
    }
    Ok(VerifiedPackageAccount {
        uid: record.uid,
        gid: record.gid,
    })
}
fn settle_allocator(mut child: std::process::Child, primary: &str) -> String {
    let termination = child.kill();
    // This allowance only observes termination of the original child;
    // it cannot authorize another account operation after the cutoff.
    let cleanup_cutoff = Instant::now() + Duration::from_secs(5);
    let wait = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Err(error) => break Err(error.to_string()),
            Ok(None) if Instant::now() >= cleanup_cutoff => {
                break Err("original allocator remains unreaped after bounded cleanup".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    format!("{primary}; termination={termination:?}; wait={wait:?}")
}
fn allocator(program: &str, arguments: &[&str], deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline {
        return Err("package account deadline expired".into());
    }
    let mut child = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| e.to_string())?;
    loop {
        let observed = match child.try_wait() {
            Ok(observed) => observed,
            Err(error) => return Err(settle_allocator(child, &error.to_string())),
        };
        if let Some(status) = observed {
            if Instant::now() >= deadline {
                return Err(format!(
                    "account deadline exceeded; original child reaped: {status}"
                ));
            }
            return if status.success() {
                Ok(())
            } else {
                Err(format!("native account allocator failed: {status}"))
            };
        }
        if Instant::now() >= deadline {
            return Err(settle_allocator(child, "account deadline exceeded"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
/// The existing exclusive package transaction must own installation and drain.
pub fn install(
    deadline: Instant,
    current_parent_allowed: bool,
) -> Result<VerifiedPackageAccount, String> {
    let mut created_parent = EmptyCreatedParent(None);
    match std::fs::symlink_metadata(PARENT) {
        Ok(_) if !current_parent_allowed => {
            return Err("unmanaged occupied workload account root".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if lookup()?.is_some() || group()?.is_some() {
                return Err("unmanaged workload credentials already exist".into());
            }
            std::fs::create_dir(PARENT).map_err(|error| error.to_string())?;
            let held = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(PARENT)
                .map_err(|error| error.to_string())?;
            use std::os::unix::fs::PermissionsExt;
            held.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
            let metadata = held.metadata().map_err(|error| error.to_string())?;
            if metadata.uid() != 0 {
                return Err("new workload account root ownership differs".into());
            }
            created_parent.0 = Some(held);
            File::open("/var/lib")
                .and_then(|parent| parent.sync_all())
                .map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    let parent = protected_parent()?;
    if read_record()?.is_some() {
        let verified = verify()?;
        if let Some(intent) = read_intent()? {
            if allocation_marker()?.as_deref() != Some(intent.allocation_marker.as_str()) {
                return Err("retained account allocation marker differs".into());
            }
            std::fs::remove_file(PENDING).map_err(|e| e.to_string())?;
            parent.sync_all().map_err(|e| e.to_string())?;
        }
        return Ok(verified);
    }
    let intent = match read_intent()? {
        Some(intent) => intent,
        None => {
            if lookup()?.is_some() || group()?.is_some() {
                return Err("unmanaged workload credential installation conflict".into());
            }
            let mut nonce = [0_u8; 16];
            // SAFETY: getrandom writes only the bounded nonce buffer.
            if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) } != 16 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let allocation_marker = format!(
                "memcordon-package-{}",
                nonce
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let intent = AccountIntent {
                format: "memcordon.package-workload-account-intent".into(),
                revision: 1,
                allocation_marker,
            };
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(PENDING)
                .map_err(|e| format!("unresolved package account allocation: {e}"))?;
            file.write_all(&serde_json::to_vec(&intent).map_err(|e| e.to_string())?)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            parent.sync_all().map_err(|e| e.to_string())?;
            intent
        }
    };
    if lookup()?.is_some() {
        if allocation_marker()?.as_deref() != Some(intent.allocation_marker.as_str()) {
            return Err("interrupted allocation found replacement workload account".into());
        }
    } else {
        if group()?.is_some() {
            return Err(
                "interrupted allocation retains unmatched native group; refusing adoption".into(),
            );
        }
        allocator(
            "/usr/sbin/useradd",
            &[
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--password",
                "!",
                "--comment",
                &intent.allocation_marker,
                NAME,
            ],
            deadline,
        )?;
    }
    let (uid, gid) = lookup()?.ok_or("created workload account absent")?;
    if allocation_marker()?.as_deref() != Some(intent.allocation_marker.as_str()) {
        return Err("native allocation marker readback differs".into());
    }
    let record = AccountRecord {
        format: "memcordon.package-workload-account".into(),
        revision: 1,
        uid,
        gid,
        allocation_marker: intent.allocation_marker,
    };
    let mut bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    super::atomic_publication::publish(
        &parent,
        std::ffi::OsStr::new("workload-account.json"),
        &bytes,
        0o600,
        4096,
    )
    .map_err(|e| e.to_string())?;
    std::fs::remove_file(PENDING).map_err(|e| e.to_string())?;
    parent.sync_all().map_err(|e| e.to_string())?;
    verify()
}
/// Only after exact workload/service drain; never called by per-attempt retirement.
pub fn uninstall(deadline: Instant) -> Result<(), String> {
    if matches!(std::fs::symlink_metadata(PARENT),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
    {
        if lookup()?.is_some() || group()?.is_some() {
            return Err("uninstall refuses unrecorded native workload credentials".into());
        }
        return Ok(());
    }
    let parent = protected_parent()?;
    if read_record()?.is_none() && read_intent()?.is_some() {
        if lookup()?.is_some() {
            // Reconcile only the exact native allocation marker before deletion.
            install(deadline, true)?;
        } else if group()?.is_none() {
            std::fs::remove_file(PENDING).map_err(|e| e.to_string())?;
            parent.sync_all().map_err(|e| e.to_string())?;
        } else {
            return Err("uninstall retains unmatched interrupted native group allocation".into());
        }
    }
    let Some(record) = read_record()? else {
        if lookup()?.is_some() || group()?.is_some() {
            return Err("uninstall refuses unrecorded native workload credentials".into());
        }
        return retire_empty_parent(&parent);
    };
    match lookup()? {
        Some(ids) if ids == (record.uid, record.gid) => {
            verify()?;
            allocator("/usr/sbin/userdel", &[NAME], deadline)?;
        }
        Some(_) => return Err("uninstall refuses replacement workload credentials".into()),
        None => {}
    }
    if lookup()?.is_some() {
        return Err("fixed account remains after deletion".into());
    }
    if let Some(gid) = group()? {
        if gid != record.gid {
            return Err("uninstall refuses replacement workload group".into());
        }
        allocator("/usr/sbin/groupdel", &[NAME], deadline)?;
        if group()?.is_some() {
            return Err("package-owned workload group remains".into());
        }
    }
    std::fs::remove_file(RECORD).map_err(|e| e.to_string())?;
    parent.sync_all().map_err(|e| e.to_string())?;
    retire_empty_parent(&parent)
}

fn retire_empty_parent(parent: &File) -> Result<(), String> {
    let pinned = parent.metadata().map_err(|error| error.to_string())?;
    let named = std::fs::symlink_metadata(PARENT).map_err(|error| error.to_string())?;
    if (pinned.dev(), pinned.ino()) != (named.dev(), named.ino()) {
        return Err("workload account parent replaced before final retirement".into());
    }
    match std::fs::remove_dir(PARENT) {
        Ok(()) => File::open("/var/lib")
            .and_then(|parent| parent.sync_all())
            .map_err(|error| error.to_string()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}
