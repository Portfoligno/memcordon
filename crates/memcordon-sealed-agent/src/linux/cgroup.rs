use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::CGROUP_ROOT;

const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const PRIVATE_ROOT_CONTROLS: &[&str] = &[
    "cgroup.controllers",
    "cgroup.events",
    "cgroup.kill",
    "cgroup.procs",
    "cgroup.subtree_control",
];
const ATTEMPT_CONTROLS: &[&str] = &[
    "cgroup.events",
    "cgroup.kill",
    "cgroup.procs",
    "memory.events",
    "memory.max",
    "memory.swap.max",
];

pub fn prepare_private_root() -> Result<(), String> {
    let root = Path::new(CGROUP_ROOT);
    fs::create_dir_all(root)
        .map_err(|error| format!("MCSEALED-CGROUP-PRIVATE-SUBTREE: {error}"))?;
    verify_cgroup2_filesystem(root)?;
    prepare_private_root_at(root)
}

#[cfg(feature = "test-support")]
pub fn prepare_private_root_for_test(root: &Path) -> Result<(), String> {
    prepare_private_root_at(root)
}

#[cfg(feature = "test-support")]
pub fn verify_attempt_controls_for_test(root: &Path) -> Result<(), String> {
    require_controls(root, ATTEMPT_CONTROLS, "attempt")
}

fn prepare_private_root_at(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("MCSEALED-CGROUP-PRIVATE-SUBTREE: {error}"))?;
    if !metadata.file_type().is_dir() {
        return Err("MCSEALED-CGROUP-PRIVATE-SUBTREE: root is not a directory".to_owned());
    }
    require_controls(root, PRIVATE_ROOT_CONTROLS, "private root")?;
    let controllers = read_control_tokens(&root.join("cgroup.controllers"))?;
    if !controllers.iter().any(|controller| controller == "memory") {
        return Err(
            "MCSEALED-CGROUP-CONTROLLER: memory is unavailable in cgroup.controllers".to_owned(),
        );
    }
    let subtree = read_control_tokens(&root.join("cgroup.subtree_control"))?;
    if !subtree.iter().any(|controller| controller == "memory") {
        write_control(&root.join("cgroup.subtree_control"), b"+memory")?;
    }
    let readback = read_control_tokens(&root.join("cgroup.subtree_control"))?;
    if !readback.iter().any(|controller| controller == "memory") {
        return Err(
            "MCSEALED-CGROUP-CONTROLLER: memory subtree enablement readback failed".to_owned(),
        );
    }
    Ok(())
}

fn verify_cgroup2_filesystem(path: &Path) -> Result<(), String> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "MCSEALED-CGROUP-PRIVATE-SUBTREE: path contains NUL".to_owned())?;
    // SAFETY: `path` is a live NUL-terminated buffer and `value` is writable for the entire
    // syscall; statfs initializes it on success and does not retain either pointer.
    let mut value = unsafe { std::mem::zeroed::<libc::statfs>() };
    // SAFETY: both pointers refer to live buffers of the exact libc-declared types; the return
    // value is checked before any field is read.
    if unsafe { libc::statfs(path.as_ptr(), &raw mut value) } == -1 {
        return Err(format!(
            "MCSEALED-CGROUP-PRIVATE-SUBTREE: statfs failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if value.f_type as u64 != CGROUP2_SUPER_MAGIC {
        return Err("MCSEALED-CGROUP-PRIVATE-SUBTREE: filesystem is not cgroup2".to_owned());
    }
    Ok(())
}

#[derive(Clone)]
pub struct AttemptCgroup {
    path: PathBuf,
}

pub(crate) struct AttemptRetirementObservation {
    pub cgroup_kill_invoked: bool,
    pub populated_zero_observed: bool,
    pub containment_removed: bool,
}

impl AttemptCgroup {
    pub fn create(
        identity: &str,
        memory_max: Option<u64>,
        swap_limit: crate::request::SwapLimit,
    ) -> Result<Self, String> {
        if identity.len() != 32
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid attempt identity".to_owned());
        }
        let path = Path::new(CGROUP_ROOT).join(identity);
        fs::create_dir(&path).map_err(|error| format!("MCSEALED-CGROUP-CREATE: {error}"))?;
        let configured = (|| {
            require_controls(&path, ATTEMPT_CONTROLS, "attempt")?;
            if let Some(bytes) = memory_max {
                write_control(&path.join("memory.max"), bytes.to_string().as_bytes())?;
                let readback = fs::read_to_string(path.join("memory.max"))
                    .map_err(|error| error.to_string())?;
                if readback.trim() != bytes.to_string() {
                    return Err("MCSEALED-CGROUP-CONFIGURE: readback mismatch".to_owned());
                }
            }
            match swap_limit {
                crate::request::SwapLimit::Bytes(bytes) => {
                    write_control(&path.join("memory.swap.max"), bytes.to_string().as_bytes())?;
                }
                crate::request::SwapLimit::Unlimited => {
                    write_control(&path.join("memory.swap.max"), b"max")?;
                }
                crate::request::SwapLimit::Host => {}
            }
            Ok(())
        })();
        if let Err(error) = configured {
            if let Err(remove_error) = fs::remove_dir(&path) {
                return Err(format!(
                    "{error}; MCSEALED-BOUNDARY-NOT-RETIRED: {remove_error}"
                ));
            }
            return Err(error);
        }
        Ok(Self { path })
    }

    pub fn authenticated(path: PathBuf) -> Self {
        Self { path }
    }
    pub fn open(&self) -> Result<File, String> {
        File::open(&self.path).map_err(|error| error.to_string())
    }

    pub fn member_pids(&self) -> Result<Vec<libc::pid_t>, String> {
        fs::read_to_string(self.path.join("cgroup.procs"))
            .map_err(|error| error.to_string())?
            .lines()
            .map(|line| {
                line.parse()
                    .map_err(|_| "invalid cgroup member pid".to_owned())
            })
            .collect()
    }

    pub fn memory_oom_killed(&self) -> Result<bool, String> {
        let path = self.path.join("memory.events");
        if !path.exists() {
            return Ok(false);
        }
        let events = fs::read_to_string(path).map_err(|error| error.to_string())?;
        Ok(events
            .lines()
            .find_map(|line| line.strip_prefix("oom_kill "))
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|count| count > 0))
    }

    pub fn wait_until_empty(
        &self,
        deadline: Instant,
        poll_interval: Duration,
    ) -> Result<bool, String> {
        let poll_interval = poll_interval.max(Duration::from_millis(1));
        loop {
            if !populated(&self.path)? {
                return Ok(true);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            std::thread::sleep(poll_interval.min(deadline.saturating_duration_since(now)));
        }
    }

    pub fn kill_and_retire(self, deadline: Instant) -> Result<(), String> {
        write_control(&self.path.join("cgroup.kill"), b"1")?;
        while Instant::now() < deadline {
            if !populated(&self.path)? {
                fs::remove_dir(&self.path)
                    .map_err(|error| format!("MCSEALED-BOUNDARY-NOT-RETIRED: {error}"))?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err("MCSEALED-CGROUP-NOT-EMPTY: cleanup deadline expired".to_owned())
    }

    pub(crate) fn kill_and_retire_after_provider_loss(
        self,
        deadline: Instant,
    ) -> Result<AttemptRetirementObservation, String> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                self.kill_and_retire(deadline)?;
                Ok(AttemptRetirementObservation {
                    cgroup_kill_invoked: true,
                    populated_zero_observed: true,
                    containment_removed: true,
                })
            }
            Ok(_) => Err(
                "MCSEALED-BOUNDARY-NOT-RETIRED: authenticated attempt path is not a directory"
                    .to_owned(),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(AttemptRetirementObservation {
                    cgroup_kill_invoked: false,
                    populated_zero_observed: false,
                    containment_removed: true,
                })
            }
            Err(error) => Err(format!("MCSEALED-BOUNDARY-NOT-RETIRED: {error}")),
        }
    }
}

fn populated(path: &Path) -> Result<bool, String> {
    let mut value = String::new();
    File::open(path.join("cgroup.events"))
        .and_then(|mut file| file.read_to_string(&mut value))
        .map_err(|error| error.to_string())?;
    value
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .map(|value| value == "1")
        .ok_or_else(|| "cgroup.events omitted populated state".to_owned())
}

fn write_control(path: &Path, value: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("MCSEALED-CGROUP-CONFIGURE: {error}"))?;
    file.write_all(value).map_err(|error| error.to_string())
}

fn read_control_tokens(path: &Path) -> Result<Vec<String>, String> {
    let mut value = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|mut file| file.read_to_string(&mut value))
        .map_err(|error| format!("MCSEALED-CGROUP-CONTROLLER: {error}"))?;
    Ok(value.split_ascii_whitespace().map(str::to_owned).collect())
}

fn require_controls(root: &Path, controls: &[&str], scope: &str) -> Result<(), String> {
    for control in controls {
        let path = root.join(control);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("MCSEALED-CGROUP-READBACK: {scope} omitted {control}: {error}")
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "MCSEALED-CGROUP-READBACK: {scope} control {control} is not a regular interface"
            ));
        }
    }
    Ok(())
}
