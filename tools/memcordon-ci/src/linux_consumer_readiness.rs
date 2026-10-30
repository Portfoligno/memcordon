//! Actual Linux pidfd, process-birth, namespace and protected-byte observations.
#![cfg(target_os = "linux")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
};

#[cfg(test)]
#[path = "../tests/support/linux_intervention_capability.rs"]
mod intervention_native_tests;

/// Native observation owner. Only acquisition before fixture release can
/// establish a hold; parsing a terminal report never constructs this value.
pub struct HeldLinuxProcess {
    pub process_id: u32,
    pub birth: u64,
    pidfd: std::os::fd::OwnedFd,
    observed_parent: Option<(u32, u64)>,
    pub namespace_pid: Option<u32>,
    observed_images: Vec<(File, std::fs::Metadata)>,
}

#[derive(Debug, Serialize)]
pub struct InterventionHoldFailure {
    pub stage: &'static str,
    pub pid: u32,
    pub expected_birth: u64,
    pub observed_birth: Option<u64>,
    pub retirement_observed: Option<bool>,
    pub native_error: Option<i32>,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxNativeNamespace {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxHeldSnapshot {
    pub process_id: u32,
    pub birth: u64,
    pub namespace_pids: Vec<u32>,
    pub user: LinuxNativeNamespace,
    pub mount: LinuxNativeNamespace,
    pub pid: LinuxNativeNamespace,
    pub network: LinuxNativeNamespace,
    pub ipc: LinuxNativeNamespace,
}

pub(crate) fn process_birth(pid: u32) -> Result<u64, String> {
    let bytes = std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat"))
        .map_err(|e| e.to_string())?;
    bytes
        .rsplit_once(')')
        .ok_or("native process stat malformed")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("native birth missing")?
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())
}

impl HeldLinuxProcess {
    /// Duplicate the original pidfd, never reacquire authority from a numeric PID.
    pub fn duplicate_for_intervention(
        &self,
        cutoff: std::time::Instant,
    ) -> Result<Self, InterventionHoldFailure> {
        let mut failure = InterventionHoldFailure {
            stage: "original-cutoff",
            pid: self.process_id,
            expected_birth: self.birth,
            observed_birth: None,
            retirement_observed: None,
            native_error: None,
            detail: String::new(),
        };
        let acquired = (|| -> Result<Self, String> {
            if std::time::Instant::now() >= cutoff {
                return Err("original intervention cutoff expired".into());
            }
            failure.stage = "original-pidfd-liveness";
            let exited = self.exited()?;
            failure.retirement_observed = Some(exited);
            if exited {
                return Err("original selected actor already retired".into());
            }
            failure.stage = "original-process-birth";
            let observed = process_birth(self.process_id)?;
            failure.observed_birth = Some(observed);
            if observed != self.birth {
                return Err("original selected actor birth differs".into());
            }
            failure.stage = "duplicate-original-pidfd";
            let pidfd = self.pidfd.try_clone().map_err(|error| {
                failure.native_error = error.raw_os_error();
                error.to_string()
            })?;
            let value = Self {
                process_id: self.process_id,
                birth: self.birth,
                pidfd,
                observed_parent: self.observed_parent,
                namespace_pid: self.namespace_pid,
                observed_images: Vec::new(),
            };
            failure.stage = "duplicated-pidfd-readback";
            let exited = value.exited()?;
            failure.retirement_observed = Some(exited);
            if exited {
                return Err("original selected actor retired during pidfd duplication".into());
            }
            failure.observed_birth = None;
            let observed = process_birth(value.process_id)?;
            failure.observed_birth = Some(observed);
            if observed != value.birth {
                return Err(
                    "original selected actor birth changed during pidfd duplication".into(),
                );
            }
            if std::time::Instant::now() >= cutoff {
                return Err("original intervention cutoff expired after pidfd duplication".into());
            }
            Ok(value)
        })();
        acquired.map_err(|detail| {
            failure.detail = detail;
            failure
        })
    }
    /// The outer result describes ownership/liveness checks; the inner result
    /// preserves the actual PIDFD syscall outcome and native errno.
    pub fn signal_interrupt(&self) -> Result<Result<(), i32>, String> {
        self.signal_held(rustix::process::Signal::INT)
    }
    pub fn signal_stop(&self) -> Result<Result<(), i32>, String> {
        self.signal_held(rustix::process::Signal::STOP)
    }
    pub fn native_credentials(&self) -> Result<serde_json::Value, String> {
        use std::io::Read;
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("original process absent before credential observation".into());
        }
        let file = std::fs::File::open(format!("/proc/{}/status", self.process_id))
            .map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > 65536 {
            return Err("native credential observation exceeds bound".into());
        }
        let status = std::str::from_utf8(&bytes).map_err(|error| error.to_string())?;
        let field = |prefix: &str| -> Result<&str, String> {
            let values = status
                .lines()
                .filter_map(|line| line.strip_prefix(prefix))
                .collect::<Vec<_>>();
            if values.len() != 1 {
                return Err("native credential field missing or duplicated".into());
            }
            Ok(values[0].trim())
        };
        let numbers = |prefix: &str| -> Result<Vec<u32>, String> {
            field(prefix)?
                .split_whitespace()
                .map(|value| value.parse::<u32>().map_err(|error| error.to_string()))
                .collect()
        };
        let uid = numbers("Uid:")?;
        let gid = numbers("Gid:")?;
        let groups = numbers("Groups:")?;
        if uid.len() != 4 || gid.len() != 4 {
            return Err("native credential UID/GID columns differ".into());
        }
        let cap = |prefix: &str| {
            u64::from_str_radix(field(prefix)?, 16).map_err(|error| error.to_string())
        };
        let result = serde_json::json!({"uid":uid,"gid":gid,"groups":groups,"cap_effective":cap("CapEff:")?,"cap_permitted":cap("CapPrm:")?,"cap_ambient":cap("CapAmb:")?,"no_new_privileges":field("NoNewPrivs:")?.parse::<u32>().map_err(|error|error.to_string())?});
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("original process changed during credential observation".into());
        }
        Ok(result)
    }
    pub fn signal_continue(&self) -> Result<Result<(), i32>, String> {
        self.signal_held(rustix::process::Signal::CONT)
    }
    pub fn observe_stopped_until(&self, cutoff: std::time::Instant) -> Result<(), String> {
        loop {
            if self.exited()? || process_birth(self.process_id)? != self.birth {
                return Err(
                    "original native process exited or changed before stopped observation".into(),
                );
            }
            let status = std::fs::read_to_string(format!("/proc/{}/status", self.process_id))
                .map_err(|error| error.to_string())?;
            let state = status
                .lines()
                .find_map(|line| line.strip_prefix("State:\t"))
                .ok_or("native process state absent")?;
            if matches!(state.as_bytes().first(), Some(b'T' | b't')) {
                if self.exited()? || process_birth(self.process_id)? != self.birth {
                    return Err("original stopped process changed during native observation".into());
                }
                return Ok(());
            }
            if std::time::Instant::now() >= cutoff {
                return Err("original stopped-process observation cutoff exhausted".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    pub fn signal_kill(&self) -> Result<Result<(), i32>, String> {
        self.signal_held(rustix::process::Signal::KILL)
    }
    fn signal_held(&self, signal: rustix::process::Signal) -> Result<Result<(), i32>, String> {
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("held process is no longer live at native signal boundary".into());
        }
        Ok(rustix::process::pidfd_send_signal(&self.pidfd, signal)
            .map_err(|error| error.raw_os_error()))
    }
    /// Reads the native kernel TCP table and actual root descriptor ownership
    /// while the same PIDFD and birth remain live on both sides of observation.
    pub fn observe_loopback_listeners(
        &self,
        endpoints: [std::net::SocketAddrV4; 2],
    ) -> Result<serde_json::Value, String> {
        use std::collections::BTreeSet;
        let before = self.live_snapshot()?;
        if endpoints[0] == endpoints[1]
            || endpoints
                .iter()
                .any(|endpoint| !endpoint.ip().is_loopback() || endpoint.port() == 0)
        {
            return Err(
                "native endpoint observation requires two distinct owned loopback listeners".into(),
            );
        }
        let base = Path::new("/proc").join(self.process_id.to_string());
        let observe = || -> Result<[u64; 2], String> {
            let mut descriptors = BTreeSet::new();
            let mut count = 0usize;
            for entry in std::fs::read_dir(base.join("fd")).map_err(|error| error.to_string())? {
                count += 1;
                if count > 4096 {
                    return Err("native endpoint root descriptor table exceeds bound".into());
                }
                let path = entry.map_err(|error| error.to_string())?.path();
                let link = std::fs::read_link(path).map_err(|error| error.to_string())?;
                if let Some(text) = link
                    .to_str()
                    .and_then(|text| text.strip_prefix("socket:["))
                    .and_then(|text| text.strip_suffix(']'))
                {
                    descriptors.insert(text.parse::<u64>().map_err(|error| error.to_string())?);
                }
            }
            let mut bytes = Vec::new();
            File::open(base.join("net/tcp"))
                .map_err(|error| error.to_string())?
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err("native TCP table exceeds bound".into());
            }
            let table = std::str::from_utf8(&bytes).map_err(|_| "native TCP table is not ASCII")?;
            let mut observed = [0u64; 2];
            for line in table.lines().skip(1) {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() < 10 {
                    return Err("native TCP row is malformed".into());
                }
                if fields[3] != "0A" {
                    continue;
                }
                for (ordinal, endpoint) in endpoints.iter().enumerate() {
                    let local = format!(
                        "{:08X}:{:04X}",
                        u32::from_le_bytes(endpoint.ip().octets()),
                        endpoint.port()
                    );
                    if fields[1] != local {
                        continue;
                    }
                    let inode = fields[9]
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?;
                    if inode == 0 || !descriptors.contains(&inode) || observed[ordinal] != 0 {
                        return Err(
                            "native listener is absent from exact held root or duplicated".into(),
                        );
                    }
                    observed[ordinal] = inode;
                }
            }
            if observed.contains(&0) || observed[0] == observed[1] {
                return Err("two native retained listener identities absent or aliased".into());
            }
            Ok(observed)
        };
        let first = observe()?;
        let second = observe()?;
        let after = self.live_snapshot()?;
        if first != second
            || before.network.device != after.network.device
            || before.network.inode != after.network.inode
        {
            return Err("native listener or held root namespace changed during observation".into());
        }
        Ok(
            serde_json::json!({"format":"memcordon.linux-native-endpoint-mismatch","revision":1,
            "process_id":self.process_id,"birth":self.birth,"network":before.network,
            "listeners":endpoints.iter().zip(first).map(|(endpoint,inode)|serde_json::json!({"endpoint":endpoint.to_string(),"socket_inode":inode})).collect::<Vec<_>>(),
            "root_held_live_before_and_after":true,"kernel_listen_and_root_descriptor_observed_twice":true}),
        )
    }
    /// Reads the native parent while this exact child and expected parent are
    /// both held live. Namespace-local transcript ancestry never substitutes
    /// for this host identity join.
    pub fn verify_parent(&mut self, parent: &Self) -> Result<(), String> {
        if self.exited()?
            || parent.exited()?
            || process_birth(self.process_id)? != self.birth
            || process_birth(parent.process_id)? != parent.birth
        {
            return Err("native ancestry owner no longer held live".into());
        }
        let stat = std::fs::read_to_string(
            Path::new("/proc")
                .join(self.process_id.to_string())
                .join("stat"),
        )
        .map_err(|e| e.to_string())?;
        let fields = stat
            .rsplit_once(')')
            .ok_or("native child stat malformed")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        let parent_pid = fields
            .get(1)
            .ok_or("native parent PID absent")?
            .parse::<u32>()
            .map_err(|e| e.to_string())?;
        if parent_pid != parent.process_id
            || parent.birth > self.birth
            || self.exited()?
            || parent.exited()?
            || process_birth(self.process_id)? != self.birth
            || process_birth(parent.process_id)? != parent.birth
        {
            return Err("native held parent/creation-time association differs".into());
        }
        self.observed_parent = Some((parent.process_id, parent.birth));
        Ok(())
    }

    pub fn retirement_identity(
        &self,
    ) -> Result<crate::release::linux_recovery_owners::HeldProcessIdentity, String> {
        Ok(crate::release::linux_recovery_owners::HeldProcessIdentity {
            pid: self.process_id,
            birth: self.birth,
            parent_pid: self.observed_parent.map(|parent| parent.0),
            parent_birth: self.observed_parent.map(|parent| parent.1),
            retirement_observed: self.exited()?,
        })
    }
    pub fn acquire(process_id: u32, expected_birth: u64) -> Result<Self, String> {
        if process_id == 0 || process_birth(process_id)? != expected_birth {
            return Err("live native process birth differs".into());
        }
        let pid =
            rustix::process::Pid::from_raw(i32::try_from(process_id).map_err(|e| e.to_string())?)
                .ok_or("native PID absent")?;
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
            .map_err(|e| e.to_string())?;
        let value = Self {
            process_id,
            birth: expected_birth,
            pidfd,
            observed_parent: None,
            namespace_pid: None,
            observed_images: Vec::new(),
        };
        if value.exited()? || process_birth(process_id)? != expected_birth {
            return Err("native process changed/exited during hold acquisition".into());
        }
        Ok(value)
    }

    pub fn exited(&self) -> Result<bool, String> {
        use rustix::event::{PollFd, PollFlags};
        let mut descriptors = [PollFd::new(&self.pidfd, PollFlags::IN)];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let status =
            rustix::event::poll(&mut descriptors, Some(&timeout)).map_err(|e| e.to_string())?;
        let events = descriptors[0].revents();
        if events.intersects(PollFlags::NVAL | PollFlags::ERR) {
            return Err("native process descriptor poll failed".into());
        }
        Ok(status != 0 && events.intersects(PollFlags::IN | PollFlags::HUP))
    }

    pub fn hold_executable_image(
        &mut self,
        deadline: std::time::Instant,
    ) -> Result<serde_json::Value, String> {
        use std::os::unix::fs::MetadataExt;
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("held process exited before native executable acquisition".into());
        }
        // This is the kernel procfs executable link of an already PIDFD-held
        // process, not a fixture-supplied pathname or imported descriptor.
        let mut image = File::open(format!("/proc/{}/exe", self.process_id))
            .map_err(|error| error.to_string())?;
        let before = image.metadata().map_err(|error| error.to_string())?;
        if !before.is_file() || before.len() > 512 * 1024 * 1024 {
            return Err("native held executable type/length exceeds bound".into());
        }
        let mut hash = Sha256::new();
        let mut length = 0u64;
        let mut chunk = [0; 65536];
        loop {
            if std::time::Instant::now() >= deadline {
                return Err("native held executable observation deadline exhausted".into());
            }
            let count = image.read(&mut chunk).map_err(|error| error.to_string())?;
            if count == 0 {
                break;
            }
            length += count as u64;
            if length > before.len() {
                return Err("native held executable changed size while measured".into());
            }
            hash.update(&chunk[..count]);
        }
        let after = image.metadata().map_err(|error| error.to_string())?;
        let named = File::open(format!("/proc/{}/exe", self.process_id))
            .map_err(|error| error.to_string())?
            .metadata()
            .map_err(|error| error.to_string())?;
        if self.exited()?
            || process_birth(self.process_id)? != self.birth
            || length != before.len()
            || (
                before.dev(),
                before.ino(),
                before.len(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.dev(),
                after.ino(),
                after.len(),
                after.ctime(),
                after.ctime_nsec(),
            )
            || (named.dev(), named.ino()) != (after.dev(), after.ino())
        {
            return Err("held executable/birth changed through native readback".into());
        }
        let receipt = serde_json::json!({"device":before.dev(),"inode":before.ino(),"length":length,"sha256":hex::encode(hash.finalize())});
        self.observed_images.push((image, after));
        Ok(receipt)
    }

    /// Recheck current executable association without rehashing an unchanged pin.
    pub fn verify_intervention_image(
        &self,
        cutoff: std::time::Instant,
    ) -> Result<serde_json::Value, String> {
        use std::os::unix::fs::MetadataExt;
        if std::time::Instant::now() >= cutoff || self.exited()? {
            return Err(
                "original selected actor/cutoff is no longer live before image readback".into(),
            );
        }
        if process_birth(self.process_id)? != self.birth {
            return Err("original selected actor birth differs before image readback".into());
        }
        let (image, original) = self
            .observed_images
            .last()
            .ok_or("selected actor has no originally measured executable pin")?;
        let held = image
            .metadata()
            .map_err(|error| format!("held executable metadata: {error}"))?;
        let current = File::open(format!("/proc/{}/exe", self.process_id))
            .map_err(|error| format!("current selected actor executable open: {error}"))?;
        let named = current
            .metadata()
            .map_err(|error| format!("current selected actor executable metadata: {error}"))?;
        let stamp = |m: &std::fs::Metadata| (m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec());
        if stamp(&held) != stamp(original) || stamp(&named) != stamp(original) {
            return Err(format!(
                "selected actor executable changed after original measurement; original={:?} held={:?} current={:?}",
                stamp(original),
                stamp(&held),
                stamp(&named)
            ));
        }
        if self.exited()?
            || process_birth(self.process_id)? != self.birth
            || std::time::Instant::now() >= cutoff
        {
            return Err(
                "original selected actor/cutoff changed through current executable readback".into(),
            );
        }
        Ok(
            serde_json::json!({"current_image_verified":true,"pid":self.process_id,"birth":self.birth,
            "device":held.dev(),"inode":held.ino(),"length":held.len(),"original_held_metadata_unchanged":true,
            "rehash":"not repeated; unchanged original measured executable remains held"}),
        )
    }

    pub fn live_snapshot(&self) -> Result<LinuxHeldSnapshot, String> {
        use std::os::unix::fs::MetadataExt;
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("snapshot process is no longer held live".into());
        }
        let root = Path::new("/proc").join(self.process_id.to_string());
        let namespace = |name: &str| -> Result<LinuxNativeNamespace, String> {
            let metadata =
                std::fs::metadata(root.join("ns").join(name)).map_err(|e| e.to_string())?;
            if metadata.ino() == 0 {
                return Err("native namespace inode absent".into());
            }
            Ok(LinuxNativeNamespace {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        };
        let status = std::fs::read_to_string(root.join("status")).map_err(|e| e.to_string())?;
        let namespace_pids = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .ok_or("native namespace PID tuple absent")?
            .split_whitespace()
            .map(|value| value.parse::<u32>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        if namespace_pids.first() != Some(&self.process_id) || namespace_pids.contains(&0) {
            return Err("native namespace PID tuple differs".into());
        }
        let snapshot = LinuxHeldSnapshot {
            process_id: self.process_id,
            birth: self.birth,
            namespace_pids,
            user: namespace("user")?,
            mount: namespace("mnt")?,
            pid: namespace("pid")?,
            network: namespace("net")?,
            ipc: namespace("ipc")?,
        };
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("native process changed while namespaces were observed".into());
        }
        Ok(snapshot)
    }

    /// Resolves a fixture-local identity only inside this already held native
    /// PID namespace. A PID string or transcript alone cannot select a host
    /// process from another attempt.
    pub fn hold_namespace_member(
        &self,
        local_pid: u32,
        expected_birth: u64,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;
        let root = self.live_snapshot()?;
        let mut selected = None;
        for entry in std::fs::read_dir("/proc").map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let namespace = match std::fs::metadata(entry.path().join("ns/pid")) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if (namespace.dev(), namespace.ino()) != (root.pid.device, root.pid.inode) {
                continue;
            }
            let status = match std::fs::read_to_string(entry.path().join("status")) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let observed_local = status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .and_then(|values| values.split_whitespace().last())
                .and_then(|value| value.parse::<u32>().ok());
            if observed_local != Some(local_pid) {
                continue;
            }
            let mut held = Self::acquire(pid, expected_birth)?;
            let snapshot = held.live_snapshot()?;
            if (snapshot.pid.device, snapshot.pid.inode) != (root.pid.device, root.pid.inode)
                || snapshot.namespace_pids.last() != Some(&local_pid)
            {
                return Err("native member changed PID namespace during hold".into());
            }
            held.namespace_pid = Some(local_pid);
            if selected.replace(held).is_some() {
                return Err("fixture identity maps to multiple native host processes".into());
            }
        }
        if self.exited()? {
            return Err("held root exited before cohort observation completed".into());
        }
        selected.ok_or("fixture-local process is not live in the held attempt PID namespace".into())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxTranscriptRow {
    pub format: String,
    pub revision: u32,
    pub sequence: u64,
    pub challenge: String,
    pub root_pid: u32,
    pub root_birth: u64,
    pub operation: String,
    pub observation: serde_json::Value,
}

pub(crate) fn measured(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("Linux artifact custody requires an absolute normalized path".into());
    }
    let mut ancestors = Vec::new();
    let mut current_path = std::path::PathBuf::from("/");
    for component in path.parent().ok_or("artifact parent absent")?.components() {
        if let std::path::Component::Normal(name) = component {
            current_path.push(name);
        } else if !matches!(component, std::path::Component::RootDir) {
            return Err("artifact ancestor invalid".into());
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(&current_path)
            .map_err(|error| {
                format!("open measured artifact ancestor {current_path:?} for {path:?}: {error}")
            })?;
        let metadata = held.metadata().map_err(|error| error.to_string())?;
        ancestors.push((current_path.clone(), held, metadata.dev(), metadata.ino()));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open measured artifact {path:?}: {error}"))?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.nlink() != 1 || before.len() > maximum {
        return Err("Linux driver artifact is not bounded exclusive regular custody".into());
    }
    let mut bytes = Vec::new();
    file.try_clone()
        .map_err(|e| e.to_string())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("reopen measured artifact {path:?}: {error}"))?;
    let current = named.metadata().map_err(|e| e.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || (before.dev(), before.ino()) != (current.dev(), current.ino())
    {
        return Err("Linux driver artifact changed during collection".into());
    }
    let mut readback = Vec::new();
    named
        .take(maximum + 1)
        .read_to_end(&mut readback)
        .map_err(|e| e.to_string())?;
    if readback != bytes {
        return Err("Linux driver named readback differs".into());
    }
    for (path, held, device, inode) in ancestors {
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(&path)
            .map_err(|error| format!("reopen measured artifact ancestor {path:?}: {error}"))?;
        let original = held.metadata().map_err(|error| error.to_string())?;
        let named = named.metadata().map_err(|error| error.to_string())?;
        if (original.dev(), original.ino()) != (device, inode)
            || (named.dev(), named.ino()) != (device, inode)
        {
            return Err("Linux driver named ancestor changed during artifact readback".into());
        }
    }
    Ok(bytes)
}
