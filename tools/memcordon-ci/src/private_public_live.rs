//! Supervisor-owned live measurements. These raw samples do not assert any
//! selector outcome and are never collected from the verifier's local /proc.

use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeldPublicTaskSampleV1 {
    pub tid: u32,
    pub start_time_ticks: u64,
    pub tgid: u32,
    pub namespace_inodes: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeldPublicTargetSamplesV1 {
    pub schema_version: u8,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub begin_monotonic_ns: u64,
    pub end_monotonic_ns: u64,
    pub executable_sha256: DiagnosticSha256,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub tasks: Vec<HeldPublicTaskSampleV1>,
    /// Exact bytes, not convenient summaries. Paths are relative to the
    /// caller's physical interval sample directory and enter the origin I.
    pub leaves: BTreeMap<String, Vec<u8>>,
}

/// Explicit late-phase source collection: network fixtures hold their actual
/// endpoints while this read-only observer enters only the target netns.
#[cfg(target_os = "linux")]
pub(crate) fn sample_held_network_source(sample: &mut HeldPublicTargetSamplesV1) -> Result<()> {
    let raw = memcordon_platform::test_support::private_sample_network_namespace(
        sample.pid,
        sample.start_time_ticks,
    )?;
    if sample
        .leaves
        .insert("network-source-v1.bin".into(), serde_json::to_vec(&raw)?)
        .is_some()
    {
        return Err(CiError::Message(
            "held network source already exists".into(),
        ));
    }
    sample.end_monotonic_ns = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sample_held_network_source(_sample: &mut HeldPublicTargetSamplesV1) -> Result<()> {
    Err(CiError::Message(
        "held network source requires native Linux".into(),
    ))
}

/// Observer-owned namespace handles are kept across actual retirement. They
/// never transfer to the target and must close before the capture detaches.
pub struct HeldPublicNamespaceCustodyV1 {
    handles: Vec<(String, u64, std::fs::File)>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicNamespaceCloseV1 {
    pub namespace: String,
    pub inode: u64,
    pub observer_pid: u32,
    pub fd: i32,
    pub before_close_monotonic_ns: u64,
    pub after_close_monotonic_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedAncestorSourceV1 {
    pub uid: u32,
    pub mode: u32,
    pub kind: String,
    pub dev: u64,
    pub inode: u64,
}
#[cfg(target_os = "linux")]
pub fn hold_sampled_public_namespaces(
    samples: &HeldPublicTargetSamplesV1,
) -> Result<HeldPublicNamespaceCustodyV1> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut handles = Vec::new();
    for task in &samples.tasks {
        if crate::private_process_clock::read_live_start_ticks(task.tid)? != task.start_time_ticks {
            return Err(CiError::Message(
                "sampled namespace task identity changed before hold".into(),
            ));
        }
        for (name, inode) in &task.namespace_inodes {
            let path = std::path::Path::new("/proc")
                .join(task.tid.to_string())
                .join("ns")
                .join(name);
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC)
                .open(path)?;
            if file.metadata()?.ino() != *inode {
                return Err(CiError::Message(
                    "held sampled namespace inode differs".into(),
                ));
            }
            handles.push((name.clone(), *inode, file));
        }
    }
    if handles.is_empty() {
        return Err(CiError::Message(
            "sampled namespace custody is empty".into(),
        ));
    }
    Ok(HeldPublicNamespaceCustodyV1 { handles })
}
#[cfg(not(target_os = "linux"))]
pub fn hold_sampled_public_namespaces(
    _samples: &HeldPublicTargetSamplesV1,
) -> Result<HeldPublicNamespaceCustodyV1> {
    Err(CiError::Message(
        "namespace custody requires native Linux".into(),
    ))
}
impl HeldPublicNamespaceCustodyV1 {
    #[cfg(target_os = "linux")]
    pub fn close(self) -> Result<Vec<PublicNamespaceCloseV1>> {
        use std::os::fd::AsRawFd;
        let mut records = Vec::new();
        for (name, inode, file) in self.handles {
            let fd = file.as_raw_fd();
            let before = memcordon_platform::test_support::private_observer_monotonic_ns()?;
            drop(file);
            let after = memcordon_platform::test_support::private_observer_monotonic_ns()?;
            records.push(PublicNamespaceCloseV1 {
                namespace: name,
                inode,
                observer_pid: std::process::id(),
                fd,
                before_close_monotonic_ns: before,
                after_close_monotonic_ns: after,
            });
        }
        Ok(records)
    }
    #[cfg(not(target_os = "linux"))]
    pub fn close(self) -> Result<Vec<PublicNamespaceCloseV1>> {
        Err(CiError::Message(
            "namespace custody close requires native Linux".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn sample_held_target_raw(
    pid: u32,
    start_ticks: u64,
    expected_image: &DiagnosticSha256,
) -> Result<HeldPublicTargetSamplesV1> {
    use memcordon_core::workload_codec::hash_bytes;
    use std::os::unix::fs::MetadataExt;
    const MAX_SAMPLE: usize = 1024 * 1024;
    if pid == 0
        || start_ticks == 0
        || expected_image.bytes() == &[0; 32]
        || !rustix::process::geteuid().is_root()
    {
        return Err(CiError::Message(
            "live public sampling requires a held nonroot target and protected supervisor".into(),
        ));
    }
    let root = std::path::Path::new("/proc").join(pid.to_string());
    let read = |path: &std::path::Path| -> Result<Vec<u8>> {
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take((MAX_SAMPLE + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_SAMPLE {
            return Err(CiError::Message(
                "live public proc sample exceeds reviewed bound".into(),
            ));
        }
        Ok(bytes)
    };
    let identity = |bytes: &[u8], expected_pid| -> Result<u64> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("proc stat is not text".into()))?;
        Ok(crate::private_supervisor::parse_linux_child_stat(text, expected_pid)?.start_time_ticks)
    };
    let begin = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    let reader_pid = std::process::id();
    let reader_root = std::path::Path::new("/proc").join(reader_pid.to_string());
    let reader_stat_before = read(&reader_root.join("stat"))?;
    let reader_start = identity(&reader_stat_before, reader_pid)?;
    let reader_namespaces = || -> Result<BTreeMap<String, u64>> {
        let mut namespaces = BTreeMap::new();
        for name in ["pid", "net", "mnt"] {
            let path = reader_root.join("ns").join(name);
            let held = std::fs::File::open(&path)?;
            let inode = held.metadata()?.ino();
            let link = std::fs::read_link(&path)?;
            let text = link
                .to_str()
                .ok_or_else(|| CiError::Message("reader namespace link is not text".into()))?;
            let (_, suffix) = text
                .split_once(":[")
                .ok_or_else(|| CiError::Message("reader namespace link differs".into()))?;
            let named_inode: u64 = suffix
                .strip_suffix(']')
                .ok_or_else(|| CiError::Message("reader namespace suffix differs".into()))?
                .parse()
                .map_err(|_| CiError::Message("reader namespace inode differs".into()))?;
            if inode == 0 || inode != named_inode {
                return Err(CiError::Message(
                    "held reader namespace identity differs".into(),
                ));
            }
            namespaces.insert(name.into(), inode);
        }
        Ok(namespaces)
    };
    let reader_namespaces_before = reader_namespaces()?;
    let first_stat = read(&root.join("stat"))?;
    if identity(&first_stat, pid)? != start_ticks {
        return Err(CiError::Message(
            "live target start identity changed before sample".into(),
        ));
    }
    let mut leaves = BTreeMap::new();
    leaves.insert("reader-stat-before.raw".into(), reader_stat_before);
    leaves.insert(
        "reader-namespaces-before.json".into(),
        serde_json::to_vec(&reader_namespaces_before)?,
    );
    leaves.insert("stat-before.raw".into(), first_stat);
    let status = read(&root.join("status"))?;
    leaves.insert("status.raw".into(), status);
    let cmdline = read(&root.join("cmdline"))?;
    leaves.insert("cmdline.raw".into(), cmdline);
    let image = std::fs::File::open(root.join("exe"))?;
    let image_meta = image.metadata()?;
    // Keep every actual ancestor object open for the entire sample. Root
    // ownership and no group/other write are checked on held objects before
    // and after the image read, not on an untrusted path-only summary.
    use std::os::unix::fs::OpenOptionsExt;
    let installed_path = std::fs::read_link(root.join("exe"))?;
    if !installed_path.is_absolute()
        || installed_path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(CiError::Message(
            "held executable path is not canonical absolute".into(),
        ));
    }
    let named_image = std::fs::symlink_metadata(&installed_path)?;
    if !named_image.is_file()
        || named_image.dev() != image_meta.dev()
        || named_image.ino() != image_meta.ino()
    {
        return Err(CiError::Message(
            "held executable path/object differs".into(),
        ));
    }
    let mut ancestor_paths = installed_path
        .parent()
        .ok_or_else(|| CiError::Message("held executable parent absent".into()))?
        .ancestors()
        .collect::<Vec<_>>();
    ancestor_paths.reverse();
    let mut ancestor_handles = Vec::new();
    let ancestor_metadata = |file: &std::fs::File| -> Result<ProtectedAncestorSourceV1> {
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "held executable ancestor is not protected".into(),
            ));
        }
        Ok(ProtectedAncestorSourceV1 {
            uid: metadata.uid(),
            mode: metadata.mode(),
            kind: "directory".into(),
            dev: metadata.dev(),
            inode: metadata.ino(),
        })
    };
    let mut ancestor_before = Vec::new();
    for path in ancestor_paths {
        let named = std::fs::symlink_metadata(path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = ancestor_metadata(&file)?;
        if !named.is_dir() || named.dev() != metadata.dev || named.ino() != metadata.inode {
            return Err(CiError::Message("held ancestor path/object changed".into()));
        }
        ancestor_before.push(metadata);
        ancestor_handles.push(file);
    }
    leaves.insert(
        "ancestors-before.json".into(),
        serde_json::to_vec(&ancestor_before)?,
    );
    use std::io::Read;
    let mut image_bytes = Vec::new();
    (&image)
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut image_bytes)?;
    if image_bytes.len() > 64 * 1024 * 1024 || image_bytes.len() as u64 != image_meta.len() {
        return Err(CiError::Message(
            "held target image exceeds reviewed ELF bound or changed".into(),
        ));
    }
    let image_after = image.metadata()?;
    if image_after.dev() != image_meta.dev()
        || image_after.ino() != image_meta.ino()
        || image_after.len() != image_meta.len()
        || image_after.mtime() != image_meta.mtime()
        || image_after.mtime_nsec() != image_meta.mtime_nsec()
        || image_after.ctime() != image_meta.ctime()
        || image_after.ctime_nsec() != image_meta.ctime_nsec()
    {
        return Err(CiError::Message(
            "held target executable metadata changed during read".into(),
        ));
    }
    if image_meta.uid() != 0
        || !image_meta.is_file()
        || image_meta.nlink() != 1
        || image_meta.mode() & 0o022 != 0
        || hash_bytes(&image_bytes) != *expected_image
    {
        return Err(CiError::Message(
            "held public target executable differs from installed pinned image".into(),
        ));
    }
    leaves.insert("image-metadata.json".into(),serde_json::to_vec(&serde_json::json!({
        "device":image_meta.dev(),"inode":image_meta.ino(),"uid":image_meta.uid(),"gid":image_meta.gid(),
        "mode":image_meta.mode(),"nlink":image_meta.nlink(),"size":image_meta.len(),"sha256":expected_image,
    }))?);
    leaves.insert("image.raw".into(), image_bytes);
    let ticks = memcordon_platform::test_support::private_observer_clock_ticks_per_second()?;
    leaves.insert(
        "clock-ticks.json".into(),
        serde_json::to_vec(&serde_json::json!({"clock_ticks_per_second":ticks}))?,
    );
    for name in [
        "cgroup",
        "mountinfo",
        "limits",
        "net/dev",
        "net/tcp",
        "net/tcp6",
        "net/route",
        "net/ipv6_route",
        "net/unix",
        "net/if_inet6",
    ] {
        leaves.insert(name.replace('/', "-") + ".raw", read(&root.join(name))?);
    }
    let mut task_ids = std::fs::read_dir(root.join("task"))?
        .map(|entry| {
            entry?
                .file_name()
                .to_str()
                .ok_or_else(|| CiError::Message("task id is not text".into()))?
                .parse::<u32>()
                .map_err(|_| CiError::Message("task id differs".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    task_ids.sort_unstable();
    let mut tasks = Vec::new();
    for tid in task_ids {
        let task_root = root.join("task").join(tid.to_string());
        let stat = read(&task_root.join("stat"))?;
        let start_time_ticks = identity(&stat, tid)?;
        let status = read(&task_root.join("status"))?;
        let task_status = std::str::from_utf8(&status)
            .map_err(|_| CiError::Message("task status not text".into()))?;
        let tgid = task_status
            .lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .ok_or_else(|| CiError::Message("task Tgid absent".into()))?
            .trim()
            .parse::<u32>()
            .map_err(|_| CiError::Message("task Tgid differs".into()))?;
        if tgid != pid {
            return Err(CiError::Message("task membership differs".into()));
        }
        let mut namespaces = BTreeMap::new();
        for name in [
            "net",
            "pid",
            "pid_for_children",
            "mnt",
            "user",
            "time",
            "time_for_children",
            "cgroup",
        ] {
            let link = std::fs::read_link(task_root.join("ns").join(name))?;
            let text = link
                .to_str()
                .ok_or_else(|| CiError::Message("namespace link not text".into()))?;
            let (_, inode) = text
                .split_once(":[")
                .ok_or_else(|| CiError::Message("namespace link shape differs".into()))?;
            let inode = inode
                .strip_suffix(']')
                .ok_or_else(|| CiError::Message("namespace link suffix differs".into()))?
                .parse::<u64>()
                .map_err(|_| CiError::Message("namespace inode differs".into()))?;
            if inode == 0 {
                return Err(CiError::Message("namespace inode zero".into()));
            }
            namespaces.insert(name.into(), inode);
        }
        let prefix = std::path::Path::new("tasks").join(tid.to_string());
        let key = |name: &str| prefix.join(name).to_string_lossy().into_owned();
        leaves.insert(key("stat.raw"), stat);
        leaves.insert(key("status.raw"), status);
        leaves.insert(key("namespaces.json"), serde_json::to_vec(&namespaces)?);
        let mut fds = std::fs::read_dir(task_root.join("fd"))?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        fds.sort();
        for fd in fds {
            let number = fd
                .to_str()
                .ok_or_else(|| CiError::Message("descriptor number not text".into()))?
                .parse::<u32>()
                .map_err(|_| CiError::Message("descriptor number differs".into()))?;
            let path = task_root.join("fd").join(&fd);
            let link = std::fs::read_link(&path)?;
            let meta = std::fs::metadata(&path)?;
            let info = read(&task_root.join("fdinfo").join(&fd))?;
            let fd_prefix = prefix.join("fds").join(number.to_string());
            leaves.insert(
                fd_prefix.join("fdinfo.raw").to_string_lossy().into_owned(),
                info,
            );
            leaves.insert(fd_prefix.join("identity.json").to_string_lossy().into_owned(),serde_json::to_vec(&serde_json::json!({
                "fd":number,"link":link,"device":meta.dev(),"inode":meta.ino(),"mode":meta.mode()
            }))?);
            if tid == pid && number == 3 && meta.mode() & 0o170000 == 0o140000 {
                let (inode, socket_type, domain) =
                    memcordon_platform::test_support::private_observe_process_socket(
                        pid,
                        start_ticks,
                        3,
                    )?;
                if inode != meta.ino() {
                    return Err(CiError::Message(
                        "held target fd3 socket object changed".into(),
                    ));
                }
                leaves.insert(fd_prefix.join("socket-type.json").to_string_lossy().into_owned(),
                    serde_json::to_vec(&serde_json::json!({"inode":inode,"socket_type":socket_type,"domain":domain}))?);
            }
        }
        let after = read(&task_root.join("stat"))?;
        if identity(&after, tid)? != start_time_ticks {
            return Err(CiError::Message(
                "held task identity changed during sample".into(),
            ));
        }
        leaves.insert(key("stat-after.raw"), after);
        tasks.push(HeldPublicTaskSampleV1 {
            tid,
            start_time_ticks,
            tgid,
            namespace_inodes: namespaces,
        });
    }
    let after = read(&root.join("stat"))?;
    if identity(&after, pid)? != start_ticks {
        return Err(CiError::Message(
            "held target identity changed during sample".into(),
        ));
    }
    leaves.insert("stat-after.raw".into(), after);
    let ancestor_after = ancestor_handles
        .iter()
        .map(ancestor_metadata)
        .collect::<Result<Vec<_>>>()?;
    if ancestor_before != ancestor_after {
        return Err(CiError::Message(
            "held executable ancestor metadata changed".into(),
        ));
    }
    leaves.insert(
        "ancestors-after.json".into(),
        serde_json::to_vec(&ancestor_after)?,
    );
    let reader_namespaces_after = reader_namespaces()?;
    let reader_stat_after = read(&reader_root.join("stat"))?;
    if identity(&reader_stat_after, reader_pid)? != reader_start
        || reader_namespaces_after != reader_namespaces_before
    {
        return Err(CiError::Message(
            "sampler reader identity or namespaces changed".into(),
        ));
    }
    leaves.insert("reader-stat-after.raw".into(), reader_stat_after);
    leaves.insert(
        "reader-namespaces-after.json".into(),
        serde_json::to_vec(&reader_namespaces_after)?,
    );
    let end = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    if end < begin {
        return Err(CiError::Message(
            "supervisor monotonic clock moved backward".into(),
        ));
    }
    Ok(HeldPublicTargetSamplesV1 {
        schema_version: 1,
        pid,
        start_time_ticks: start_ticks,
        begin_monotonic_ns: begin,
        end_monotonic_ns: end,
        executable_sha256: expected_image.clone(),
        executable_device: image_meta.dev(),
        executable_inode: image_meta.ino(),
        tasks,
        leaves,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn sample_held_target_raw(
    _pid: u32,
    _start_ticks: u64,
    _expected_image: &DiagnosticSha256,
) -> Result<HeldPublicTargetSamplesV1> {
    Err(CiError::Message(
        "live public target measurements require native Linux".into(),
    ))
}

pub fn sample_held_public_target(
    pid: u32,
    start_ticks: u64,
    uid: u32,
    gid: u32,
    expected_image: &DiagnosticSha256,
    expected_argv: &[String],
) -> Result<HeldPublicTargetSamplesV1> {
    if uid == 0 || gid == 0 || expected_argv.is_empty() {
        return Err(CiError::Message(
            "prepared target credentials/argv differ".into(),
        ));
    }
    let samples = sample_held_target_raw(pid, start_ticks, expected_image)?;
    let status = std::str::from_utf8(&samples.leaves["status.raw"])
        .map_err(|_| CiError::Message("target status is not text".into()))?;
    let values = |name: &str| -> Result<Vec<u32>> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| CiError::Message("target credential/status field absent".into()))?
            .split_whitespace()
            .map(|word| {
                word.parse()
                    .map_err(|_| CiError::Message("target credential/status number differs".into()))
            })
            .collect()
    };
    let mut argv = samples.leaves["cmdline.raw"]
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    if argv.last() == Some(&&[][..]) {
        argv.pop();
    }
    if values("Uid:")? != vec![uid; 4]
        || values("Gid:")? != vec![gid; 4]
        || !values("Groups:")?.is_empty()
        || argv
            != expected_argv
                .iter()
                .map(|arg| arg.as_bytes())
                .collect::<Vec<_>>()
    {
        return Err(CiError::Message(
            "live target credentials/argv differ from prepared generation".into(),
        ));
    }
    Ok(samples)
}
/// Actual owned-child wait result, not a fabricated kernel descendant event.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicFrontendSupervisorWaitV1 {
    pub schema_version: u8,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub raw_wait_status: i32,
    pub signal: i32,
    pub stdout_sha256: memcordon_core::DiagnosticSha256,
    pub stderr_sha256: memcordon_core::DiagnosticSha256,
    pub wait_observed_monotonic_ns: u64,
}
