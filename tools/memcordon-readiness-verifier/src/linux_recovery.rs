//! Independent native crash-controller association. Account recovery is a
//! separate obligation; these receipts alone do not establish its completion.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxNativeRecoveryCaseEvidence {
    pub format: String,
    pub revision: u32,
    pub key: crate::CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub component_recipe_id: String,
    pub executable: String,
    pub executable_sha256: String,
    pub source_artifact: String,
    pub source_artifact_sha256: String,
    pub invocation: String,
    pub native_preinput: String,
    pub native_retirement: String,
    pub stdout: String,
    pub stderr: String,
    pub recovery: LinuxRecoveryComponentEvidence,
}

impl LinuxNativeRecoveryCaseEvidence {
    pub fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.executable.as_str(),
            self.source_artifact.as_str(),
            self.invocation.as_str(),
            self.native_preinput.as_str(),
            self.native_retirement.as_str(),
            self.stdout.as_str(),
            self.stderr.as_str(),
        ];
        paths.extend(self.recovery.artifact_paths());
        paths
    }
}

/// Raw transport for recovery recipes. A deliberately killed native harness
/// has no successful Rust-test count or synthesized native exit code.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LinuxRecoveryComponentEvidence {
    AccountRetirementCrash {
        input: String,
        boundary: String,
        ownership: String,
        controller_intent: String,
        crash_exit: String,
        recovery_invocation: String,
        recovery_capture: String,
        recovery_process: String,
        package_owner: String,
        recovered_ownership: String,
        fixture_acquisition: crate::ComponentFixtureAcquisition,
    },
    LostTerminalResponse {
        input: String,
        boundary: String,
        ownership: String,
        delivery_receipt: String,
        completed_carrier: String,
        terminal_request: String,
        helper_retirements: String,
        recovery_invocation: String,
        recovery_capture: String,
        recovery_process: String,
        package_owner: String,
        recovered_ownership: String,
        fixture_acquisition: crate::ComponentFixtureAcquisition,
    },
}

impl LinuxRecoveryComponentEvidence {
    pub fn artifact_paths(&self) -> Vec<&str> {
        let (mut paths, fixture) = match self {
            Self::AccountRetirementCrash {
                input,
                boundary,
                ownership,
                controller_intent,
                crash_exit,
                recovery_invocation,
                recovery_capture,
                recovery_process,
                package_owner,
                recovered_ownership,
                fixture_acquisition,
            } => (
                vec![
                    input.as_str(),
                    boundary.as_str(),
                    ownership.as_str(),
                    controller_intent.as_str(),
                    crash_exit.as_str(),
                    recovery_invocation.as_str(),
                    recovery_capture.as_str(),
                    recovery_process.as_str(),
                    package_owner.as_str(),
                    recovered_ownership.as_str(),
                ],
                fixture_acquisition,
            ),
            Self::LostTerminalResponse {
                input,
                boundary,
                ownership,
                delivery_receipt,
                completed_carrier,
                terminal_request,
                helper_retirements,
                recovery_invocation,
                recovery_capture,
                recovery_process,
                package_owner,
                recovered_ownership,
                fixture_acquisition,
            } => (
                vec![
                    input.as_str(),
                    boundary.as_str(),
                    ownership.as_str(),
                    delivery_receipt.as_str(),
                    completed_carrier.as_str(),
                    terminal_request.as_str(),
                    helper_retirements.as_str(),
                    recovery_invocation.as_str(),
                    recovery_capture.as_str(),
                    recovery_process.as_str(),
                    package_owner.as_str(),
                    recovered_ownership.as_str(),
                ],
                fixture_acquisition,
            ),
        };
        paths.extend([
            fixture.checkpoint.as_str(),
            fixture.account_intent.as_str(),
            fixture.account_readback.as_str(),
            fixture.group_readback.as_str(),
        ]);
        paths
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryOwnedLeaf {
    pub path: String,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub links: u64,
    pub uid: u32,
    pub mode: u32,
    pub parent_device: u64,
    pub parent_inode: u64,
    pub parent_uid: u32,
    pub parent_mode: u32,
}

macro_rules! recovery_owned_shape {
    ($name:ident { $($extra:ident: $kind:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub path: String, pub device: u64, pub inode: u64,
            pub length: u64, pub links: u64, pub uid: u32, pub mode: u32,
            pub parent_device: u64, pub parent_inode: u64,
            pub parent_uid: u32, pub parent_mode: u32,
            $(pub $extra: $kind),*
        }
        impl $name {
            fn leaf(&self) -> LinuxRecoveryOwnedLeaf {
                LinuxRecoveryOwnedLeaf {
                    path: self.path.clone(), device: self.device, inode: self.inode,
                    length: self.length, links: self.links, uid: self.uid, mode: self.mode,
                    parent_device: self.parent_device, parent_inode: self.parent_inode,
                    parent_uid: self.parent_uid, parent_mode: self.parent_mode,
                }
            }
        }
    };
}
recovery_owned_shape!(LinuxRecoveryJournalOwnership {
    parent_path: String
});
recovery_owned_shape!(LinuxRecoveryReservationOwnership { bytes: Vec<u8>, sha256: String });

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryAccountOwnership {
    pub attempt_id: String,
    pub account_uid: u32,
    pub reference_path: String,
    pub reference: crate::LinuxReleaseReference,
    pub reservation: LinuxRecoveryReservationOwnership,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryOwnership {
    pub journal: LinuxRecoveryJournalOwnership,
    pub journal_sha256: String,
    pub account: LinuxRecoveryAccountOwnership,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryReservationRecord {
    pub format: String,
    pub revision: u32,
    pub user_namespace_device: u64,
    pub user_namespace_inode: u64,
    pub uid: u32,
    pub attempt: [u8; 16],
    pub owner_pid: u32,
    pub owner_birth: u64,
    pub boot_identity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryCapture {
    pub format: String,
    pub revision: u32,
    pub invocation_sha256: String,
    pub native_wait_status: i32,
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryProgram {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub links: u64,
    pub uid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryInvocation {
    pub format: String,
    pub revision: u32,
    pub identity: serde_json::Value,
    pub run_id: String,
    pub recipe_id: String,
    pub native_target: String,
    pub program: Vec<u8>,
    pub arguments: Vec<Vec<u8>>,
    pub working_directory: Vec<u8>,
    pub executable_sha256: String,
    pub environment: Vec<serde_json::Value>,
    pub package_owner_sha256: String,
    pub selected_program: LinuxRecoveryProgram,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
    pub boundary_sha256: String,
    pub ownership_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryImage {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryCreation {
    pub process_id: u32,
    pub birth: u64,
    pub image: Option<LinuxRecoveryImage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryProcessRetirement {
    pub process_id: u32,
    pub birth: u64,
    pub pidfd_retirement_observed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryCommandProcess {
    pub format: String,
    pub revision: u32,
    pub invocation_sha256: String,
    pub creation: LinuxRecoveryCreation,
    pub native_wait_status: i32,
    pub retirement: LinuxRecoveryProcessRetirement,
}

pub fn validate_linux_recovery_command_process(
    invocation: &LinuxRecoveryInvocation,
    process: &LinuxRecoveryCommandProcess,
    capture: &LinuxRecoveryCapture,
    invocation_bytes: &[u8],
    owner_bytes: &[u8],
    selected_source: &serde_json::Value,
    identity: &serde_json::Value,
    recipe_id: &str,
    target: &str,
    admin_root: &str,
    boundary_bytes: &[u8],
    ownership_bytes: &[u8],
    work_unix: u64,
    cleanup_unix: u64,
) -> Result<(), String> {
    if owner_bytes.is_empty()
        || owner_bytes.len() > 16 * 1024 * 1024
        || invocation_bytes.is_empty()
        || invocation_bytes.len() > 4 * 1024 * 1024
        || boundary_bytes.is_empty()
        || boundary_bytes.len() > 4 * 1024 * 1024
        || ownership_bytes.is_empty()
        || ownership_bytes.len() > 4 * 1024 * 1024
    {
        return Err("recovery command original owner/input bounds differ".into());
    }
    let owner: serde_json::Value = crate::wire::decode(owner_bytes)?;
    let actual: LinuxRecoveryInvocation =
        serde_json::from_slice(invocation_bytes).map_err(|error| error.to_string())?;
    let digest = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let fields = [
        "format",
        "revision",
        "source",
        "distribution",
        "cleanup_agent",
        "cleanup_agent_sha256",
        "cleanup_agent_device",
        "cleanup_agent_inode",
        "original_installation_absent",
        "legacy",
    ];
    let program = owner["cleanup_agent"]
        .as_str()
        .ok_or("original selected cleanup agent path absent")?;
    let native = &invocation.selected_program;
    if owner.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || owner["format"] != "memcordon.consumer-readiness.native-package-owner"
        || owner["revision"] != 1
        || owner["source"] != *selected_source
        || owner["distribution"]["target"] != target
        || owner["original_installation_absent"] != true
        || serde_json::to_value(invocation).map_err(|error| error.to_string())?
            != serde_json::to_value(actual).map_err(|error| error.to_string())?
        || invocation.format != "memcordon.native-component-recovery-invocation"
        || invocation.revision != 1
        || invocation.identity != *identity
        || identity["run_id"].as_str() != Some(invocation.run_id.as_str())
        || invocation.recipe_id != recipe_id
        || invocation.native_target != target
        || invocation.program != program.as_bytes()
        || program != format!("{admin_root}/native-package-cleanup-agent")
        || !admin_root.starts_with("/var/lib/memcordon-native-readiness/")
        || !admin_root.ends_with("/component-package-admin")
        || !program.starts_with('/')
        || program.as_bytes().contains(&0)
        || invocation.arguments
            != [
                b"package".to_vec(),
                b"policy".to_vec(),
                b"recover".to_vec(),
                b"--json".to_vec(),
            ]
        || invocation.working_directory.first() != Some(&b'/')
        || invocation.working_directory.contains(&0)
        || !invocation.environment.is_empty()
        || Some(invocation.executable_sha256.as_str()) != owner["cleanup_agent_sha256"].as_str()
        || invocation.executable_sha256.len() != 64
        || !invocation
            .executable_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || invocation.package_owner_sha256 != digest(owner_bytes)
        || invocation.boundary_sha256 != digest(boundary_bytes)
        || invocation.ownership_sha256 != digest(ownership_bytes)
        || work_unix == 0
        || cleanup_unix <= work_unix
        || invocation.work_deadline_unix_millis != work_unix
        || invocation.cleanup_deadline_unix_millis != cleanup_unix
        || native.device == 0
        || native.inode == 0
        || native.length == 0
        || native.links != 1
        || native.uid != 0
        || native.mode & 0o170000 != 0o100000
        || native.mode & 0o7777 != 0o555
        || owner["cleanup_agent_device"] != native.device
        || owner["cleanup_agent_inode"] != native.inode
        || process.format != "memcordon.native-component-recovery-process"
        || process.revision != 1
        || process.invocation_sha256 != digest(invocation_bytes)
        || process.invocation_sha256 != capture.invocation_sha256
        || process.native_wait_status != capture.native_wait_status
        || process.native_wait_status != 0
        || process.creation.process_id == 0
        || process.creation.process_id > i32::MAX as u32
        || process.creation.birth == 0
        || process.retirement.process_id != process.creation.process_id
        || process.retirement.birth != process.creation.birth
        || !process.retirement.pidfd_retirement_observed
        || process
            .creation
            .image
            .as_ref()
            .is_some_and(|image| image.device != native.device || image.inode != native.inode)
    {
        return Err(
            "recovery native command/process adopts a different selected owner or creation".into(),
        );
    }
    validate_linux_recovery_capture(capture, invocation_bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryAbsentLeaf {
    pub role: String,
    pub original: serde_json::Value,
    pub path: String,
    pub basename: String,
    pub parent_path: String,
    pub parent_device: u64,
    pub parent_inode: u64,
    pub parent_uid: u32,
    pub parent_mode: u32,
    pub native_errno: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryTask {
    pub pid: u32,
    pub tid: u32,
    pub birth: u64,
    pub uids: [u32; 4],
    pub gids: [u32; 4],
    pub groups: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveredOwnership {
    pub format: String,
    pub revision: u32,
    pub identity: serde_json::Value,
    pub run_id: String,
    pub recipe_id: String,
    pub native_target: String,
    pub boundary_sha256: String,
    pub ownership_sha256: String,
    pub checkpoint_sha256: String,
    pub attempt_id: String,
    pub account_uid: u32,
    pub account_gid: u32,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
    pub absent_owned_leaves: Vec<LinuxRecoveryAbsentLeaf>,
    pub tasks: Vec<LinuxRecoveryTask>,
}

pub fn validate_linux_recovered_ownership(
    recovered: &LinuxRecoveredOwnership,
    ownership: &LinuxRecoveryOwnership,
    boundary_bytes: &[u8],
    ownership_bytes: &[u8],
    checkpoint_bytes: &[u8],
    identity: &serde_json::Value,
    recipe_id: &str,
    target: &str,
    account: (u32, u32),
    work_unix: u64,
    cleanup_unix: u64,
) -> Result<(), String> {
    let digest = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    if recovered.format != "memcordon.native-component-recovered-ownership"
        || recovered.revision != 1
        || identity["run_id"].as_str() != Some(recovered.run_id.as_str())
        || recovered.identity != *identity
        || recovered.recipe_id != recipe_id
        || recovered.native_target != target
        || !target.ends_with("linux-gnu")
        || boundary_bytes.is_empty()
        || boundary_bytes.len() > 4 * 1024 * 1024
        || ownership_bytes.is_empty()
        || ownership_bytes.len() > 4 * 1024 * 1024
        || checkpoint_bytes.is_empty()
        || checkpoint_bytes.len() > 16 * 1024 * 1024
        || recovered.boundary_sha256 != digest(boundary_bytes)
        || recovered.ownership_sha256 != digest(ownership_bytes)
        || recovered.checkpoint_sha256 != digest(checkpoint_bytes)
        || recovered.attempt_id != ownership.account.attempt_id
        || account.0 == 0
        || account.1 == 0
        || recovered.account_uid != account.0
        || recovered.account_gid != account.1
        || ownership.account.account_uid != account.0
        || work_unix == 0
        || cleanup_unix <= work_unix
        || recovered.work_deadline_unix_millis != work_unix
        || recovered.cleanup_deadline_unix_millis != cleanup_unix
        || recovered.absent_owned_leaves.len() != 3
        || recovered.tasks.is_empty()
        || recovered.tasks.len() > 1_048_576
    {
        return Err(
            "native recovered ownership crosses original source/attempt/account/cutoff".into(),
        );
    }
    let original: LinuxRecoveryOwnership =
        serde_json::from_slice(ownership_bytes).map_err(|error| error.to_string())?;
    if serde_json::to_value(&original).map_err(|error| error.to_string())?
        != serde_json::to_value(ownership).map_err(|error| error.to_string())?
    {
        return Err("native recovered ownership substitutes parsed original snapshot".into());
    }
    for (leaf, (role, path, original)) in recovered.absent_owned_leaves.iter().zip([
        (
            "journal",
            ownership.journal.path.as_str(),
            serde_json::to_value(&ownership.journal).map_err(|error| error.to_string())?,
        ),
        (
            "reference",
            ownership.account.reference_path.as_str(),
            serde_json::to_value(&ownership.account.reference)
                .map_err(|error| error.to_string())?,
        ),
        (
            "reservation",
            ownership.account.reservation.path.as_str(),
            serde_json::to_value(&ownership.account.reservation)
                .map_err(|error| error.to_string())?,
        ),
    ]) {
        let basename = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("original recovery basename absent")?;
        if leaf.role != role
            || leaf.path != path
            || leaf.original != original
            || leaf.basename != basename
            || leaf.parent_path != "/var/lib/memcordon/sealed"
            || leaf.parent_path != ownership.journal.parent_path
            || std::path::Path::new(path).parent() != Some(std::path::Path::new(&leaf.parent_path))
            || leaf.parent_device != ownership.journal.parent_device
            || leaf.parent_inode != ownership.journal.parent_inode
            || leaf.parent_uid != 0
            || leaf.parent_uid != ownership.journal.parent_uid
            || leaf.parent_mode != ownership.journal.parent_mode
            || leaf.parent_mode & 0o170000 != 0o040000
            || leaf.parent_mode & 0o022 != 0
            || leaf.native_errno != 2
        {
            return Err("native recovery adopts a different leaf or parent absence".into());
        }
    }
    let mut tasks = std::collections::BTreeSet::new();
    let mut credentials = 0usize;
    for task in &recovered.tasks {
        credentials = credentials
            .checked_add(8 + task.groups.len())
            .ok_or("recovered census size overflow")?;
        if task.pid == 0
            || task.pid > i32::MAX as u32
            || task.tid == 0
            || task.tid > i32::MAX as u32
            || task.birth == 0
            || !tasks.insert((task.pid, task.tid))
            || credentials > 262144
            || task.uids.contains(&account.0)
            || task.gids.contains(&account.1)
            || task.groups.contains(&account.1)
        {
            return Err(
                "native recovered account census retains exclusive credentials or reused task"
                    .into(),
            );
        }
    }
    Ok(())
}

/// Successful recovery command capture is necessary but does not replace the
/// independently observed removal of each original native owner.
pub fn validate_linux_recovery_capture(
    capture: &LinuxRecoveryCapture,
    invocation_bytes: &[u8],
) -> Result<(), String> {
    let digest = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    if invocation_bytes.is_empty()
        || invocation_bytes.len() > 4 * 1024 * 1024
        || capture.format != "memcordon.native-component-recovery-capture"
        || capture.revision != 1
        || capture.invocation_sha256 != digest(invocation_bytes)
        || capture.native_wait_status != 0
        || capture.status != Some(0)
        || capture.stdout.is_empty()
        || capture.stdout.len() > 4 * 1024 * 1024
        || capture.stderr.len() > 4 * 1024 * 1024
        || capture.stdout_sha256 != digest(&capture.stdout)
        || capture.stderr_sha256 != digest(&capture.stderr)
    {
        return Err("native recovery capture differs from original command/native wait".into());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Response {
        format: String,
        revision: u32,
        outstanding: Vec<serde_json::Value>,
    }
    let response: Response =
        serde_json::from_slice(&capture.stdout).map_err(|error| error.to_string())?;
    if response.format != "memcordon.native-recovery"
        || response.revision != 1
        || !response.outstanding.is_empty()
    {
        return Err("native recovery command retains original obligations".into());
    }
    Ok(())
}

pub fn validate_linux_recovery_reservation(
    record: &LinuxRecoveryReservationRecord,
    ownership: &LinuxRecoveryOwnership,
    worker: &LinuxRecoveryProcess,
    caller_user_namespace: (u64, u64),
    boot_identity: &str,
) -> Result<(), String> {
    if ownership.account.reservation.bytes.is_empty()
        || ownership.account.reservation.bytes.len() > 65536
    {
        return Err("recovery reservation raw bytes exceed original bound".into());
    }
    let captured: LinuxRecoveryReservationRecord =
        serde_json::from_slice(&ownership.account.reservation.bytes)
            .map_err(|error| error.to_string())?;
    let attempt = record
        .attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let expected_path = format!(
        "/var/lib/memcordon/sealed/account-{}-{}-{}.reservation",
        caller_user_namespace.0, caller_user_namespace.1, ownership.account.account_uid
    );
    if serde_json::to_value(record).map_err(|error| error.to_string())?
        != serde_json::to_value(&captured).map_err(|error| error.to_string())?
        || record.format != "memcordon.account-reservation"
        || record.revision != 1
        || caller_user_namespace.0 == 0
        || caller_user_namespace.1 == 0
        || (record.user_namespace_device, record.user_namespace_inode) != caller_user_namespace
        || record.uid == 0
        || record.uid != ownership.account.account_uid
        || attempt != ownership.account.attempt_id
        || worker.pid == 0
        || worker.pid > i32::MAX as u32
        || worker.birth == 0
        || record.owner_pid != worker.pid
        || record.owner_birth != worker.birth
        || boot_identity.len() != 36
        || !boot_identity.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        || record.boot_identity != boot_identity
        || ownership.account.reservation.path != expected_path
    {
        return Err("recovery reservation differs from original caller/worker/account".into());
    }
    Ok(())
}

/// Joins the original pending owners to boundary bytes. Subsequent recovery
/// must independently prove removal of these exact names and native owners.
pub fn validate_linux_recovery_ownership(
    ownership: &LinuxRecoveryOwnership,
    native: &LinuxPreAccountNative,
    journal_bytes: &[u8],
    reference_bytes: &[u8],
    expected_reference_path: &str,
    expected_reservation_path: &str,
) -> Result<(), String> {
    let parent = "/var/lib/memcordon/sealed";
    let account = &ownership.account;
    let journal = &ownership.journal;
    let reservation = &account.reservation;
    let journal_leaf = journal.leaf();
    let reservation_leaf = reservation.leaf();
    let digest = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let valid_leaf = |leaf: &LinuxRecoveryOwnedLeaf, length: usize| {
        leaf.device != 0
            && leaf.inode != 0
            && leaf.length == length as u64
            && leaf.links == 1
            && leaf.uid == 0
            && leaf.mode & 0o170000 == 0o100000
            && leaf.mode & 0o7777 == 0o600
            && leaf.parent_device != 0
            && leaf.parent_inode != 0
            && leaf.parent_uid == 0
            && leaf.parent_mode & 0o170000 == 0o040000
            && leaf.parent_mode & 0o022 == 0
    };
    if native.attempt_id.len() != 32
        || !native
            .attempt_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || account.attempt_id != native.attempt_id
        || account.account_uid == 0
        || account.account_uid != native.admission_reference.account_uid
        || serde_json::to_value(&account.reference).map_err(|error| error.to_string())?
            != serde_json::to_value(&native.admission_reference)
                .map_err(|error| error.to_string())?
        || account.reference.length != reference_bytes.len() as u64
        || account.reference.device == 0
        || account.reference.inode == 0
        || account.reference.links != 1
        || account.reference.uid != 0
        || account.reference.mode & 0o170000 != 0o100000
        || account.reference.mode & 0o7777 != 0o600
        || account.reference.named_absent
        || account.reference.retired
        || reference_bytes.is_empty()
        || reference_bytes.len() > 65536
        || account.reference_path != expected_reference_path
        || expected_reference_path != format!("{parent}/{}.mixed-admission", native.attempt_id)
        || reservation_leaf.path != expected_reservation_path
        || std::path::Path::new(expected_reference_path).parent()
            != Some(std::path::Path::new(parent))
        || std::path::Path::new(expected_reservation_path).parent()
            != Some(std::path::Path::new(parent))
        || journal.parent_path != parent
        || journal_leaf.path != format!("{parent}/{}", native.attempt_id)
        || journal_bytes.is_empty()
        || journal_bytes.len() > 4 * 1024 * 1024
        || reservation.bytes.is_empty()
        || reservation.bytes.len() > 65536
        || !valid_leaf(&journal_leaf, journal_bytes.len())
        || !valid_leaf(&reservation_leaf, reservation.bytes.len())
        || journal_leaf.parent_device != reservation_leaf.parent_device
        || journal_leaf.parent_inode != reservation_leaf.parent_inode
        || journal_leaf.parent_mode != reservation_leaf.parent_mode
        || journal_leaf.inode == reservation_leaf.inode
        || (journal_leaf.device, journal_leaf.inode)
            == (account.reference.device, account.reference.inode)
        || (reservation_leaf.device, reservation_leaf.inode)
            == (account.reference.device, account.reference.inode)
        || ownership.journal_sha256 != digest(journal_bytes)
        || reservation.sha256 != digest(&reservation.bytes)
    {
        return Err("recovery original journal/account ownership differs from boundary".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryCgroup {
    pub schema_version: u8,
    pub cgroup_path: String,
    pub cgroup_inode: u64,
    pub last_members: Vec<i32>,
    pub empty_monotonic_ns: u64,
    pub removed_monotonic_ns: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPreAccountNative {
    pub attempt_id: String,
    pub native_wait_status: Option<i32>,
    pub cgroup_retirement: LinuxRecoveryCgroup,
    pub root_layout: serde_json::Value,
    pub execution_identity: serde_json::Value,
    pub export_path: String,
    pub export_receipt_sha256: String,
    pub admission_reference: crate::LinuxReleaseReference,
}

pub fn validate_linux_pre_account_native(
    native: &LinuxPreAccountNative,
    account_uid: u32,
    reference_bytes: &[u8],
    export_bytes: &[u8],
) -> Result<(), String> {
    if native.attempt_id.len() != 32
        || !native
            .attempt_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || native.native_wait_status != Some(0)
        || account_uid == 0
    {
        return Err(
            "pre-account native execution/attempt differs from successful native target".into(),
        );
    }
    let cgroup = &native.cgroup_retirement;
    if cgroup.schema_version != 1
        || cgroup.cgroup_path != format!("/sys/fs/cgroup/memcordon-sealed/{}", native.attempt_id)
        || cgroup.cgroup_inode == 0
        || !cgroup.last_members.is_empty()
        || cgroup.empty_monotonic_ns == 0
        || cgroup.removed_monotonic_ns < cgroup.empty_monotonic_ns
    {
        return Err("pre-account cgroup empty/removal observation differs".into());
    }
    let reference = &native.admission_reference;
    if reference.device == 0
        || reference.inode == 0
        || reference.length != reference_bytes.len() as u64
        || reference_bytes.is_empty()
        || reference.links != 1
        || reference.uid != 0
        || reference.mode & 0o170000 != 0o100000
        || reference.mode & 0o777 != 0o600
        || reference.named_absent
        || reference.retired
        || reference.account_uid != account_uid
    {
        return Err(
            "pre-account boundary does not retain original account admission reference".into(),
        );
    }
    if export_bytes.is_empty()
        || export_bytes.len() > 16 * 1024 * 1024
        || native.export_receipt_sha256
            != Sha256::digest(export_bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
    {
        return Err("pre-account export receipt measurement differs".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryProcess {
    pub pid: u32,
    pub birth: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRecoveryWorker {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxLostTerminalReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub native_target: String,
    pub test_name: String,
    pub worker: LinuxRecoveryWorker,
    pub challenge_sha256: String,
    pub carrier: String,
    pub request: String,
    pub delivery_error: String,
    pub native_errno: i32,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

/// This validates the actual failed write association, not completed execution
/// or recovery. The original carrier and recovery obligations remain mandatory.
pub fn validate_linux_lost_terminal_delivery(
    receipt: &LinuxLostTerminalReceipt,
    run_id: &str,
    recipe_id: &str,
    target: &str,
    worker: &LinuxRecoveryProcess,
    challenge: &[u8],
    prefix: &str,
    work: u64,
    cleanup: u64,
) -> Result<(), String> {
    let challenge_sha256 = Sha256::digest(challenge)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if worker.pid == 0
        || worker.pid > i32::MAX as u32
        || worker.birth == 0
        || challenge.len() != 32
        || work == 0
        || cleanup <= work
        || prefix.is_empty()
        || prefix.starts_with('/')
        || prefix
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.contains('\\'))
        || receipt.format != "memcordon.linux-lost-terminal-component"
        || receipt.revision != 1
        || receipt.run_id != run_id
        || receipt.recipe_id != recipe_id
        || receipt.native_target != target
        || receipt.test_name
            != "native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt"
        || receipt.worker.pid != worker.pid
        || receipt.worker.start_time != worker.birth
        || receipt.challenge_sha256 != challenge_sha256
        || receipt.carrier != format!("{prefix}/completed-terminal-carrier.json")
        || receipt.request != format!("{prefix}/terminal-request.json")
        || receipt.work_deadline_unix_millis != work
        || receipt.cleanup_deadline_unix_millis != cleanup
        || receipt.delivery_error != "Io(BrokenPipe)"
        || receipt.native_errno != 32
    {
        return Err(
            "native lost-terminal delivery differs from original held worker/closed Linux peer"
                .into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxCrashIntent {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub native_target: String,
    pub worker_pid: u32,
    pub worker_birth: u64,
    pub worker_image_sha256: String,
    pub boundary_sha256: String,
    pub requested_signal: String,
    pub held_before_boundary: bool,
    pub caller: LinuxRecoveryProcess,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxCrashExit {
    pub format: String,
    pub revision: u32,
    pub worker_pid: u32,
    pub worker_birth: u64,
    pub worker_image_sha256: String,
    pub raw_wait_status: i32,
    pub native_signal: Option<i32>,
    pub native_exit_code: Option<i32>,
    pub worker_pidfd_retirement_observed: bool,
    pub caller_pidfd_retirements: Vec<LinuxRecoveryProcess>,
}

pub fn validate_linux_crash_controller(
    intent: &LinuxCrashIntent,
    exit: &LinuxCrashExit,
    boundary_bytes: &[u8],
    run_id: &str,
    recipe_id: &str,
    target: &str,
    image_sha256: &str,
    worker: &LinuxRecoveryProcess,
    caller: &LinuxRecoveryProcess,
) -> Result<(), String> {
    let native_identity = |identity: &LinuxRecoveryProcess| {
        identity.pid > 0 && identity.pid <= i32::MAX as u32 && identity.birth > 0
    };
    if !native_identity(worker) || !native_identity(caller) || worker.pid == caller.pid {
        return Err("native crash worker/caller identities are invalid".into());
    }
    if image_sha256.len() != 64
        || !image_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || boundary_bytes.is_empty()
        || boundary_bytes.len() > 4 * 1024 * 1024
    {
        return Err("native crash image/boundary measurement is invalid".into());
    }
    let digest = Sha256::digest(boundary_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if intent.format != "memcordon.linux-native-crash-intent"
        || intent.revision != 1
        || intent.run_id != run_id
        || intent.recipe_id != recipe_id
        || intent.native_target != target
        || intent.worker_pid != worker.pid
        || intent.worker_birth != worker.birth
        || intent.worker_image_sha256 != image_sha256
        || intent.boundary_sha256 != digest
        || intent.requested_signal != "SIGKILL"
        || !intent.held_before_boundary
        || &intent.caller != caller
    {
        return Err("native crash intent differs from held original worker/boundary".into());
    }
    if exit.format != "memcordon.linux-native-crash-exit"
        || exit.revision != 1
        || exit.worker_pid != worker.pid
        || exit.worker_birth != worker.birth
        || exit.worker_image_sha256 != image_sha256
        || exit.raw_wait_status != 9
        || exit.native_signal != Some(9)
        || exit.native_exit_code.is_some()
        || !exit.worker_pidfd_retirement_observed
        || exit.caller_pidfd_retirements.as_slice() != [caller.clone()]
    {
        return Err(
            "native crash wait/PIDFD retirement differs from requested native SIGKILL".into(),
        );
    }
    Ok(())
}
