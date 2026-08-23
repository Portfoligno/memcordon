use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use super::STATE_ROOT;
use sha2::{Digest, Sha256};

pub struct AttemptRecord {
    identity: String,
    path: PathBuf,
}

impl AttemptRecord {
    pub fn create(identity: String, frontend_pid: libc::pid_t) -> Result<Self, String> {
        if identity.len() != 32 || !identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("attempt identity must be 128-bit lowercase hexadecimal".to_owned());
        }
        secure_state_root()?;
        let path = PathBuf::from(STATE_ROOT).join(&identity);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| error.to_string())?;
        write_record(
            &mut file,
            &format!(
                "version=1\ncgroup={identity}\nfrontend-pid={frontend_pid}\nstate=allocated\n"
            ),
        )?;
        file.sync_all().map_err(|error| error.to_string())?;
        sync_state_root()?;
        Ok(Self { identity, path })
    }

    pub fn transition(&self, state: &str) -> Result<(), String> {
        let temporary = self.path.with_extension("new");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        write_record(
            &mut file,
            &format!("version=1\ncgroup={}\nstate={state}\n", self.identity),
        )?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temporary, &self.path).map_err(|error| error.to_string())?;
        sync_state_root()
    }

    pub fn retire(self) -> Result<(), String> {
        fs::remove_file(&self.path).map_err(|error| error.to_string())?;
        sync_state_root()
    }
}

pub fn secure_state_root() -> Result<(), String> {
    fs::create_dir_all(STATE_ROOT).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(STATE_ROOT).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != 0 {
        return Err("MCSEALED-RECOVERY: state root identity is unsafe".to_owned());
    }
    fs::set_permissions(STATE_ROOT, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    sync_state_root()
}

fn sync_state_root() -> Result<(), String> {
    File::open(STATE_ROOT)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn write_record(file: &mut File, body: &str) -> Result<(), String> {
    let digest: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    write!(file, "{body}digest={digest}\n").map_err(|error| error.to_string())
}
