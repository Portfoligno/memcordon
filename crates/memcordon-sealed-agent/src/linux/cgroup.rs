use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::CGROUP_ROOT;

#[derive(Clone)]
pub struct AttemptCgroup {
    path: PathBuf,
}

impl AttemptCgroup {
    pub fn create(
        identity: &str,
        memory_max: Option<u64>,
        swap_limit: crate::request::SwapLimit,
    ) -> Result<Self, String> {
        if identity.is_empty() || !identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid attempt identity".to_owned());
        }
        let path = Path::new(CGROUP_ROOT).join(identity);
        fs::create_dir(&path).map_err(|error| format!("MCSEALED-CGROUP-CREATE: {error}"))?;
        let configured = (|| {
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
