use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::STATE_ROOT;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct AttemptRecord {
    policy_binding: Option<String>,
    private_invocation: Option<(u32, memcordon_core::DiagnosticSha256)>,
    policy_checkpoint: Option<String>,
    identity: String,
    path: PathBuf,
    state_root: PathBuf,
    caller_envelope_digest: Option<String>,
}

struct TransitionTemporary {
    path: PathBuf,
    state_root: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    committed: bool,
}

impl TransitionTemporary {
    fn create(path: PathBuf, state_root: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        Ok(Self {
            path,
            state_root: state_root.to_owned(),
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            committed: false,
        })
    }

    fn commit(&mut self, canonical: &Path, state_root: &Path) -> Result<(), String> {
        fs::rename(&self.path, canonical).map_err(|error| error.to_string())?;
        self.committed = true;
        sync_directory(state_root)
    }
}

impl Drop for TransitionTemporary {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let caller_still_owns_path = fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_file()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        });
        if caller_still_owns_path && fs::remove_file(&self.path).is_ok() {
            let _ = sync_directory(&self.state_root);
        }
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionFault {
    BeforeRename,
    AfterRename,
}

impl AttemptRecord {
    pub fn create(identity: String, frontend_pid: libc::pid_t) -> Result<Self, String> {
        secure_state_root()?;
        Self::create_in(Path::new(STATE_ROOT), identity, frontend_pid, None)
    }

    pub fn create_v2(
        identity: String,
        frontend_pid: libc::pid_t,
        caller_envelope_digest: String,
    ) -> Result<Self, String> {
        secure_state_root()?;
        Self::create_in(
            Path::new(STATE_ROOT),
            identity,
            frontend_pid,
            Some(caller_envelope_digest),
        )
    }

    pub fn adopt_v2(
        identity: String,
        frontend_pid: libc::pid_t,
        caller_envelope_digest: String,
    ) -> Result<Self, String> {
        secure_state_root()?;
        validate_identity(&identity, Some(&caller_envelope_digest))?;
        let state_root = Path::new(STATE_ROOT);
        let path = state_root.join(&identity);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err("attempt record identity or permissions are unsafe".to_owned());
        }
        let mut observed = String::new();
        let limit = 16 * 1024;
        if metadata.len() > limit {
            return Err("allocated attempt record exceeds bound".into());
        }
        file.take(limit + 1)
            .read_to_string(&mut observed)
            .map_err(|error| error.to_string())?;
        if observed.len() as u64 > limit {
            return Err("allocated attempt record exceeds bound".into());
        }
        let body = format!(
            "version=2\ncgroup={identity}\nfrontend-pid={frontend_pid}\ncaller-envelope-digest={caller_envelope_digest}\nstate=allocated\n"
        );
        if observed != record_text(&body) {
            return Err("attempt record does not match authenticated broker identity".to_owned());
        }
        Ok(Self {
            policy_binding: None,
            private_invocation: None,
            policy_checkpoint: None,
            identity,
            path,
            state_root: state_root.to_owned(),
            caller_envelope_digest: Some(caller_envelope_digest),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn create_for_test(
        state_root: &Path,
        identity: String,
        frontend_pid: libc::pid_t,
    ) -> Result<Self, String> {
        fs::create_dir_all(state_root).map_err(|error| error.to_string())?;
        fs::set_permissions(state_root, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        sync_directory(state_root)?;
        Self::create_in(state_root, identity, frontend_pid, None)
    }

    fn create_in(
        state_root: &Path,
        identity: String,
        frontend_pid: libc::pid_t,
        caller_envelope_digest: Option<String>,
    ) -> Result<Self, String> {
        validate_identity(&identity, caller_envelope_digest.as_deref())?;
        let path = state_root.join(&identity);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| error.to_string())?;
        let version = if caller_envelope_digest.is_some() {
            2
        } else {
            1
        };
        let envelope = caller_envelope_digest
            .as_deref()
            .map(|digest| format!("caller-envelope-digest={digest}\n"))
            .unwrap_or_default();
        let persist = write_record(
            &mut file,
            &format!(
                "version={version}\ncgroup={identity}\nfrontend-pid={frontend_pid}\n{envelope}state=allocated\n"
            ),
        )
        .and_then(|()| file.sync_all().map_err(|error| error.to_string()))
        .and_then(|()| sync_directory(state_root));
        if let Err(error) = persist {
            drop(file);
            let cleanup = fs::remove_file(&path)
                .and_then(|()| File::open(state_root)?.sync_all())
                .map_err(|cleanup_error| cleanup_error.to_string());
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => {
                    format!("{error}; MCSEALED-RECORD-CLEANUP: {cleanup_error}")
                }
            });
        }
        Ok(Self {
            policy_binding: None,
            private_invocation: None,
            policy_checkpoint: None,
            identity,
            path,
            state_root: state_root.to_owned(),
            caller_envelope_digest,
        })
    }

    pub fn transition(&self, state: &str) -> Result<(), String> {
        self.transition_inner(state, None)
    }

    pub fn bind_policy_checkpoint(
        &mut self,
        binding: &memcordon_core::workload_evidence::AttemptBindingV1,
        checkpoint: &memcordon_core::workload_evidence::VerifiedCheckpointV1,
    ) -> Result<(), String> {
        let snapshot: crate::admission::FrozenAdmission = serde_json::from_str(
            self.policy_binding
                .as_deref()
                .ok_or("policy checkpoint lacks frozen admission")?,
        )
        .map_err(|error| error.to_string())?;
        if !binding.matches_snapshot(&snapshot)
            || binding.attempt_id.as_str() != self.identity
            || !checkpoint.matches_binding(binding)
        {
            return Err("policy checkpoint differs from exact durable admission".into());
        }
        let bytes =
            serde_json::to_string(&(binding, checkpoint)).map_err(|error| error.to_string())?;
        if bytes.len() > memcordon_core::workload_limits::CONTRACT_BYTES {
            return Err("policy checkpoint exceeds durable limit".into());
        }
        if self
            .policy_checkpoint
            .as_ref()
            .is_some_and(|previous| previous != &bytes)
        {
            return Err("policy checkpoint cannot change".into());
        }
        self.policy_checkpoint = Some(bytes);
        self.transition("policy-verified-before-authorization")
    }

    pub fn bind_policy(
        mut self,
        admission: &crate::admission::FrozenAdmission,
        authenticated_uid: u32,
        native_invocation_digest: memcordon_core::DiagnosticSha256,
    ) -> Result<Self, String> {
        admission.validate()?;
        if admission.caller
            != (memcordon_core::workload_registry::CallerSelector::Linux {
                uid: authenticated_uid,
            })
            || admission.private_invocation_digest != native_invocation_digest
            || self.policy_binding.is_some()
        {
            return Err(
                "frozen admission differs from authenticated caller or exact native invocation"
                    .into(),
            );
        }
        let bytes = serde_json::to_string(admission).map_err(|error| error.to_string())?;
        if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("policy binding exceeds durable limit".into());
        }
        self.policy_binding = Some(bytes);
        self.private_invocation = Some((authenticated_uid, native_invocation_digest));
        self.transition("policy-planned")?;
        Ok(self)
    }

    #[cfg(feature = "test-support")]
    pub fn transition_for_test(&self, state: &str, fault: TransitionFault) -> Result<(), String> {
        self.transition_inner(state, Some(fault))
    }

    fn transition_inner(
        &self,
        state: &str,
        #[cfg(feature = "test-support")] fault: Option<TransitionFault>,
        #[cfg(not(feature = "test-support"))] _fault: Option<()>,
    ) -> Result<(), String> {
        let mut temporary =
            TransitionTemporary::create(self.path.with_extension("new"), &self.state_root)?;
        let version = if self.policy_binding.is_some() {
            3
        } else if self.caller_envelope_digest.is_some() {
            2
        } else {
            1
        };
        let envelope = self
            .caller_envelope_digest
            .as_deref()
            .map(|digest| format!("caller-envelope-digest={digest}\n"))
            .unwrap_or_default();
        let policy = self
            .policy_binding
            .as_deref()
            .map(|binding| format!("policy-binding={binding}\n"))
            .unwrap_or_default();
        let checkpoint = self
            .policy_checkpoint
            .as_deref()
            .map(|value| format!("policy-checkpoint={value}\n"))
            .unwrap_or_default();
        let private_invocation = self
            .private_invocation
            .as_ref()
            .map(|(uid, digest)| {
                let digest: String = digest.clone().into();
                format!("authenticated-uid={uid}\nprivate-invocation-digest={digest}\n")
            })
            .unwrap_or_default();
        write_record(
            &mut temporary.file,
            &format!(
                "version={version}\ncgroup={}\n{envelope}{private_invocation}{policy}{checkpoint}state={state}\n",
                self.identity
            ),
        )?;
        temporary
            .file
            .sync_all()
            .map_err(|error| error.to_string())?;
        #[cfg(feature = "test-support")]
        if fault == Some(TransitionFault::BeforeRename) {
            return Err("MCSEALED-RECORD-FAULT: before rename".to_owned());
        }
        temporary.commit(&self.path, &self.state_root)?;
        #[cfg(feature = "test-support")]
        if fault == Some(TransitionFault::AfterRename) {
            return Err("MCSEALED-RECORD-FAULT: after rename".to_owned());
        }
        Ok(())
    }

    pub fn retire(self) -> Result<(), String> {
        fs::remove_file(&self.path).map_err(|error| error.to_string())?;
        sync_directory(&self.state_root)
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
    sync_directory(Path::new(STATE_ROOT))
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn write_record(file: &mut File, body: &str) -> Result<(), String> {
    file.write_all(record_text(body).as_bytes())
        .map_err(|error| error.to_string())
}

pub(crate) fn parse_durable_policy(
    record: &str,
) -> Result<Option<crate::admission::FrozenAdmission>, String> {
    if !record.ends_with('\n') {
        return Err("durable record lacks newline".into());
    }
    let (body, digest) = record
        .rsplit_once("digest=")
        .ok_or("durable record digest absent")?;
    let expected: String = memcordon_core::workload_codec::hash_bytes(body.as_bytes()).into();
    if digest.strip_suffix('\n') != Some(expected.as_str()) {
        return Err("durable record digest differs".into());
    }
    let mut fields = std::collections::BTreeMap::new();
    for line in body.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or("malformed durable record field")?;
        if fields.insert(key, value).is_some() {
            return Err("duplicate durable record field".into());
        }
    }
    let version = fields.remove("version").ok_or("durable version absent")?;
    let identity = fields
        .remove("cgroup")
        .ok_or("durable attempt identity absent")?;
    validate_identity(identity, None)?;
    let state = fields.remove("state").ok_or("durable state absent")?;
    if state.is_empty() {
        return Err("durable state empty".into());
    }
    match fields.remove("frontend-pid") {
        Some(pid)
            if state == "allocated" && pid.parse::<libc::pid_t>().is_ok_and(|pid| pid > 0) => {}
        None if state != "allocated" => {}
        _ => return Err("durable frontend identity differs from allocated state".into()),
    }
    if matches!(version, "2" | "3") {
        let digest = fields
            .remove("caller-envelope-digest")
            .ok_or("durable caller envelope absent")?;
        let _: memcordon_core::DiagnosticSha256 = memcordon_core::DiagnosticSha256::try_from(
            memcordon_core::BoundedText::new(digest).map_err(str::to_owned)?,
        )
        .map_err(str::to_owned)?;
    }
    let admission = match version {
        "1" | "2" => None,
        "3" => {
            let bytes = fields
                .remove("policy-binding")
                .ok_or("durable policy admission absent")?
                .as_bytes();
            if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
                return Err("durable policy admission exceeds bound".into());
            }
            memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
            let snapshot: crate::admission::FrozenAdmission =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            snapshot.validate()?;
            let uid = fields
                .remove("authenticated-uid")
                .ok_or("durable authenticated UID absent")?
                .parse::<u32>()
                .map_err(|_| "invalid durable authenticated UID")?;
            let invocation = fields
                .remove("private-invocation-digest")
                .ok_or("durable native invocation absent")?;
            let invocation = memcordon_core::DiagnosticSha256::try_from(
                memcordon_core::BoundedText::new(invocation).map_err(str::to_owned)?,
            )
            .map_err(str::to_owned)?;
            if snapshot.caller != (memcordon_core::workload_registry::CallerSelector::Linux { uid })
                || snapshot.private_invocation_digest != invocation
            {
                return Err("durable caller or native invocation binding differs".into());
            }
            if let Some(bytes) = fields.remove("policy-checkpoint") {
                if bytes.len() > memcordon_core::workload_limits::CONTRACT_BYTES {
                    return Err("durable checkpoint exceeds bound".into());
                }
                memcordon_core::workload_contract::reject_duplicate_json_keys(bytes.as_bytes())?;
                let (binding, checkpoint): (
                    memcordon_core::workload_evidence::AttemptBindingV1,
                    memcordon_core::workload_evidence::VerifiedCheckpointV1,
                ) = serde_json::from_str(bytes).map_err(|error| error.to_string())?;
                if binding.attempt_id.as_str() != identity
                    || !binding.matches_snapshot(&snapshot)
                    || !checkpoint.matches_binding(&binding)
                {
                    return Err("durable policy checkpoint binding differs".into());
                }
            } else if matches!(state, "authorized" | "policy-verified-before-authorization") {
                return Err("durable authorization checkpoint absent".into());
            }
            Some(snapshot)
        }
        _ => return Err("unsupported durable record version".into()),
    };
    if !fields.is_empty() {
        return Err("unknown durable record fields".into());
    }
    Ok(admission)
}

fn record_text(body: &str) -> String {
    let digest: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{body}digest={digest}\n")
}

fn validate_identity(identity: &str, caller_envelope_digest: Option<&str>) -> Result<(), String> {
    if identity.len() != 32
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("attempt identity must be 128-bit lowercase hexadecimal".to_owned());
    }
    if caller_envelope_digest.is_some_and(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err("caller envelope digest must be SHA-256 lowercase hexadecimal".to_owned());
    }
    Ok(())
}
