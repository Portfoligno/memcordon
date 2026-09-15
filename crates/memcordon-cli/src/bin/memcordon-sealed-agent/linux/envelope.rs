use memcordon_core::sealed_provider::envelope::parse_namespace_identity;
pub use memcordon_core::sealed_provider::envelope::parse_proc_status;
use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::request::{CallerExecutionEnvelopeV2, FileIdentity, NamespaceIdentity};

pub struct CapturedCallerEnvelopeV2 {
    pub envelope: CallerExecutionEnvelopeV2,
    pub mount_namespace: OwnedFd,
    pub root: OwnedFd,
}

pub fn capture(
    pid: libc::pid_t,
    authenticated_uid: libc::uid_t,
    authenticated_gid: libc::gid_t,
    authenticated_groups: &[libc::gid_t],
    current_directory: BorrowedFd<'_>,
) -> Result<CapturedCallerEnvelopeV2, String> {
    if pid <= 0 {
        return Err("MCSEALED-CALLER-ENVELOPE-CAPTURE: invalid caller pid".to_owned());
    }
    let process = Path::new("/proc").join(pid.to_string());
    let observed_start_time = process_start_time_at(&process)?;
    let status = std::fs::read_to_string(process.join("status"))
        .map_err(|error| format!("MCSEALED-CALLER-ENVELOPE-CAPTURE: {error}"))?;
    let status = parse_proc_status(&status)
        .map_err(|error| format!("MCSEALED-CALLER-ENVELOPE-CAPTURE: {error}"))?;
    let expected_uids = [authenticated_uid; 4];
    let expected_gids = [authenticated_gid; 4];
    let mut expected_groups = authenticated_groups.to_vec();
    let mut actual_groups = status.supplementary_groups.clone();
    expected_groups.sort_unstable();
    actual_groups.sort_unstable();
    if status.uids != expected_uids
        || status.gids != expected_gids
        || actual_groups != expected_groups
    {
        return Err(
            "MCSEALED-CALLER-ENVELOPE-CAPTURE: authenticated credentials changed during capture"
                .to_owned(),
        );
    }
    if status.capability_inheritable_set != 0
        || status.capability_permitted_set != 0
        || status.capability_effective_set != 0
        || status.capability_ambient_set != 0
    {
        return Err(
            "MCSEALED-CREDENTIAL-TRANSITION-POLICY: callers with active capability sets are unsupported"
                .to_owned(),
        );
    }

    let namespace_root = process.join("ns");
    let mount_namespace_identity = namespace_identity(&namespace_root, "mnt")?;
    let pid_namespace_identity = namespace_identity(&namespace_root, "pid")?;
    let user_namespace_identity = namespace_identity(&namespace_root, "user")?;
    let network_namespace_identity = namespace_identity(&namespace_root, "net")?;
    let ipc_namespace_identity = namespace_identity(&namespace_root, "ipc")?;
    let uts_namespace_identity = namespace_identity(&namespace_root, "uts")?;
    let time_namespace_identity = namespace_identity(&namespace_root, "time")?;
    for (kind, caller) in [
        ("user", user_namespace_identity),
        ("net", network_namespace_identity),
        ("ipc", ipc_namespace_identity),
        ("uts", uts_namespace_identity),
        ("time", time_namespace_identity),
    ] {
        let provider = namespace_identity(Path::new("/proc/self/ns"), kind)?;
        if caller != provider {
            return Err(format!(
                "MCSEALED-CALLER-ENVELOPE-CAPTURE: unsupported caller {kind} namespace"
            ));
        }
    }

    let mount_namespace = open_descriptor(namespace_root.join("mnt"), libc::O_RDONLY)?;
    let root = open_descriptor(process.join("root"), libc::O_RDONLY | libc::O_DIRECTORY)?;
    let current_metadata = descriptor_metadata(current_directory.as_raw_fd())?;
    let live_current_metadata = std::fs::metadata(process.join("cwd"))
        .map_err(|error| format!("MCSEALED-CALLER-ENVELOPE-CAPTURE: {error}"))?;
    let root_metadata = descriptor_metadata(root.as_raw_fd())?;
    if current_metadata.dev() != live_current_metadata.dev()
        || current_metadata.ino() != live_current_metadata.ino()
    {
        return Err(
            "MCSEALED-CALLER-ENVELOPE-CAPTURE: transferred current directory does not match caller"
                .to_owned(),
        );
    }
    if process_start_time_at(&process)? != observed_start_time {
        return Err(
            "MCSEALED-CALLER-ENVELOPE-CAPTURE: caller identity changed during capture".to_owned(),
        );
    }
    Ok(CapturedCallerEnvelopeV2 {
        envelope: CallerExecutionEnvelopeV2 {
            pid,
            process_start_time: observed_start_time,
            uid: authenticated_uid,
            gid: authenticated_gid,
            supplementary_groups: authenticated_groups.to_vec(),
            no_new_privs: status.no_new_privs,
            capability_bounding_set: status.capability_bounding_set,
            mount_namespace_identity,
            pid_namespace_identity,
            user_namespace_identity,
            network_namespace_identity,
            ipc_namespace_identity,
            uts_namespace_identity,
            time_namespace_identity,
            current_directory_identity: FileIdentity {
                device: current_metadata.dev(),
                inode: current_metadata.ino(),
            },
            root_identity: FileIdentity {
                device: root_metadata.dev(),
                inode: root_metadata.ino(),
            },
        },
        mount_namespace,
        root,
    })
}

pub fn descriptor_matches(fd: BorrowedFd<'_>, expected: FileIdentity) -> Result<bool, String> {
    let metadata = descriptor_metadata(fd.as_raw_fd())?;
    Ok(metadata.dev() == expected.device && metadata.ino() == expected.inode)
}

pub fn namespace_descriptor_matches(
    fd: BorrowedFd<'_>,
    expected: NamespaceIdentity,
) -> Result<bool, String> {
    let metadata = descriptor_metadata(fd.as_raw_fd())?;
    Ok(metadata.dev() == expected.device && metadata.ino() == expected.inode)
}

pub fn verify_live(caller: &CallerExecutionEnvelopeV2) -> Result<(), String> {
    let process = Path::new("/proc").join(caller.pid.to_string());
    if process_start_time_at(&process)? != caller.process_start_time {
        return Err("MCSEALED-CALLER-ENVELOPE-CAPTURE: caller process identity changed".to_owned());
    }
    let status = std::fs::read_to_string(process.join("status"))
        .map_err(|error| format!("MCSEALED-CALLER-ENVELOPE-CAPTURE: {error}"))?;
    let status = parse_proc_status(&status)
        .map_err(|error| format!("MCSEALED-CALLER-ENVELOPE-CAPTURE: {error}"))?;
    let mut expected_groups = caller.supplementary_groups.clone();
    let mut actual_groups = status.supplementary_groups.clone();
    expected_groups.sort_unstable();
    actual_groups.sort_unstable();
    if status.uids != [caller.uid; 4]
        || status.gids != [caller.gid; 4]
        || actual_groups != expected_groups
        || status.no_new_privs != caller.no_new_privs
        || status.capability_bounding_set != caller.capability_bounding_set
        || status.capability_inheritable_set != 0
        || status.capability_permitted_set != 0
        || status.capability_effective_set != 0
        || status.capability_ambient_set != 0
    {
        return Err("MCSEALED-CALLER-ENVELOPE-CAPTURE: caller envelope changed".to_owned());
    }
    for (kind, expected) in [
        ("mnt", caller.mount_namespace_identity),
        ("pid", caller.pid_namespace_identity),
        ("user", caller.user_namespace_identity),
        ("net", caller.network_namespace_identity),
        ("ipc", caller.ipc_namespace_identity),
        ("uts", caller.uts_namespace_identity),
        ("time", caller.time_namespace_identity),
    ] {
        if namespace_identity(&process.join("ns"), kind)? != expected {
            return Err(format!(
                "MCSEALED-CALLER-ENVELOPE-CAPTURE: caller {kind} namespace changed"
            ));
        }
    }
    for (name, expected) in [
        ("cwd", caller.current_directory_identity),
        ("root", caller.root_identity),
    ] {
        let metadata = std::fs::metadata(process.join(name))
            .map_err(|error| format!("MCSEALED-CALLER-ENVELOPE-CAPTURE: {error}"))?;
        if metadata.dev() != expected.device || metadata.ino() != expected.inode {
            return Err(format!(
                "MCSEALED-CALLER-ENVELOPE-CAPTURE: caller {name} identity changed"
            ));
        }
    }
    Ok(())
}

fn namespace_identity(root: &Path, kind: &str) -> Result<NamespaceIdentity, String> {
    let path = root.join(kind);
    let link = std::fs::read_link(&path)
        .map_err(|error| format!("namespace identity unavailable: {error}"))?;
    parse_namespace_identity(&link.to_string_lossy(), kind)?;
    let metadata = std::fs::metadata(&path)
        .map_err(|error| format!("namespace metadata unavailable: {error}"))?;
    Ok(NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn open_descriptor(path: PathBuf, flags: i32) -> Result<OwnedFd, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("MCSEALED-CALLER-ENVELOPE-CAPTURE: {error}"))?;
    Ok(file.into())
}

fn descriptor_metadata(fd: i32) -> Result<std::fs::Metadata, String> {
    let duplicate = unsafe {
        // SAFETY: fcntl duplicates a live descriptor and returns an independently owned handle.
        libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0)
    };
    if duplicate == -1 {
        return Err(format!(
            "descriptor identity unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe {
        // SAFETY: successful F_DUPFD_CLOEXEC returned a fresh descriptor owned by this File.
        File::from_raw_fd(duplicate)
    };
    file.metadata()
        .map_err(|error| format!("descriptor identity unavailable: {error}"))
}

pub fn process_start_time(pid: libc::pid_t) -> Result<u64, String> {
    if pid <= 0 {
        return Err("MCSEALED-CALLER-ENVELOPE-CAPTURE: invalid process id".to_owned());
    }
    process_start_time_at(&Path::new("/proc").join(pid.to_string()))
}

fn process_start_time_at(process: &Path) -> Result<u64, String> {
    let stat = std::fs::read_to_string(process.join("stat"))
        .map_err(|error| format!("MCSEALED-CALLER-ENVELOPE-CAPTURE: {error}"))?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| "MCSEALED-CALLER-ENVELOPE-CAPTURE: malformed process stat".to_owned())?;
    fields
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| "MCSEALED-CALLER-ENVELOPE-CAPTURE: process start time missing".to_owned())?
        .parse()
        .map_err(|_| "MCSEALED-CALLER-ENVELOPE-CAPTURE: process start time invalid".to_owned())
}
