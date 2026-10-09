//! Original native-job component collection. Public installed cells stay separate.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use memcordon_readiness_verifier::{Artifact, ComponentBuild, ProducerManifest, ProductKey};
use serde::Deserialize;

use super::{artifacts, native_component_harness, source};
use crate::consumer_readiness_ledger::{CellEvidence, SourceIdentity};
use crate::{CiError, Result};

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub identity: PathBuf,
    #[arg(
        long,
        required_unless_present = "github_context",
        conflicts_with = "github_context"
    )]
    pub run_attempt: Option<u64>,
    #[arg(long)]
    pub github_context: bool,
    #[arg(long)]
    pub destination: PathBuf,
    #[arg(long)]
    pub cleanup: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    role: String,
    package: String,
    test: String,
    features: Option<String>,
    executable: PathBuf,
    sha256: String,
    compiler_output: PathBuf,
    compiler_errors: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquiredRoles {
    format: String,
    revision: u32,
    source: source::BuildSourceIdentity,
    native_target: String,
    roles: Vec<Role>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquiredHost {
    format: String,
    revision: u32,
    source: source::BuildSourceIdentity,
    target: String,
    host: memcordon_readiness_verifier::HostObservation,
    compiler: PathBuf,
    compiler_artifact: String,
    compiler_length: u64,
    compiler_sha256: String,
    compiler_path_stdout: String,
    compiler_path_stderr: String,
    compiler_identity_stdout: String,
    compiler_identity_stderr: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionOrigin {
    format: String,
    revision: u32,
    source: source::BuildSourceIdentity,
    target: String,
    job: String,
    run_id: String,
    run_attempt: u64,
    harnesses_sha256: String,
    host_sha256: String,
    deadline_sha256: String,
    actor_sha256: Option<String>,
    fixture_sha256: Option<String>,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquiredActor {
    format: String,
    revision: u32,
    source: source::BuildSourceIdentity,
    native_target: String,
    features: Vec<String>,
    runtime_manifest: memcordon_core::runtime_manifest::RuntimeManifest,
}

#[cfg(windows)]
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsOriginalOwner {
    format: String,
    revision: u32,
    identity: SourceIdentity,
    job: String,
    run_attempt: u64,
    config: crate::windows_installed_cases::InstalledWindowsPayload,
    removal: crate::windows_readiness_adapter::WindowsRemovalPlan,
    original_work_unix_millis: u64,
    original_cleanup_unix_millis: u64,
}

#[cfg(windows)]
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsInstallIntent {
    format: String,
    revision: u32,
    owner_sha256: String,
    job: String,
    run_attempt: u64,
}

#[cfg(windows)]
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsSettlement {
    format: String,
    revision: u32,
    owner_sha256: String,
    job: String,
    run_attempt: u64,
    cleanup_directory: PathBuf,
    receipts: WindowsCleanupReceipts,
}

#[cfg(windows)]
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsCleanupReceipts {
    recovery: crate::windows_installed_cases::SelectedArtifact,
    uninstall: crate::windows_installed_cases::SelectedArtifact,
    removal: crate::windows_installed_cases::SelectedArtifact,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsPackageIntent {
    operation: String,
    agent: crate::windows_installed_cases::SelectedArtifact,
    original_job: String,
    original_attempt: u64,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsPackageCapture {
    operation: String,
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsRecoveryInvocation {
    format: String,
    revision: u32,
    cli: crate::windows_installed_cases::SelectedArtifact,
    provider: memcordon_core::PublicProviderBindingV1,
    cwd: PathBuf,
    argv_utf16: Vec<Vec<u16>>,
    environment_cleared: bool,
    command_budget_millis: u64,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsRemovalReceipt {
    format: String,
    revision: u32,
    provider_generation: String,
    absent_services: Vec<String>,
    absent_paths: Vec<PathBuf>,
    fixture_processes_absent: bool,
    installed_image_processes_absent: bool,
    native_component_census: String,
    service_observations: Vec<WindowsServiceAbsence>,
    path_observations: Vec<WindowsPathAbsence>,
}
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsServiceAbsence {
    service_name: String,
    api: String,
    native_domain: String,
    native_code: u32,
}
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsPathAbsence {
    path: PathBuf,
    native_domain: String,
    native_code: i32,
}
struct Selection {
    identity: SourceIdentity,
    target: String,
    job: String,
    run_attempt: u64,
    roles: AcquiredRoles,
    deadline: native_component_harness::OriginalNativeDeadline,
    work: Instant,
    cleanup: Instant,
    records: Vec<OwnedRecord>,
    host: AcquiredHost,
    #[cfg_attr(
        not(windows),
        allow(
            dead_code,
            reason = "The acquired fixture hash is consumed by the Windows native selection path"
        )
    )]
    fixture_sha256: Option<String>,
}

impl Selection {
    fn scope_recipe(&self) -> String {
        format!(
            "original-native-components-v1:{}:{}",
            self.job, self.run_attempt
        )
    }
}

struct OwnedRecord {
    path: PathBuf,
    bytes: Vec<u8>,
    #[cfg(unix)]
    file: File,
    #[cfg(unix)]
    ancestry: DirectoryCustody,
    #[cfg(windows)]
    custody: crate::windows_readiness_adapter::HeldWindowsArtifact,
}
impl OwnedRecord {
    fn read(path: &Path) -> Result<Self> {
        let path = std::path::absolute(path)?;
        #[cfg(windows)]
        {
            let custody =
                crate::windows_readiness_adapter::hold_artifact(&path, None, 16 * 1024 * 1024)?;
            return Ok(Self {
                path,
                bytes: custody.bytes.clone(),
                custody,
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let ancestry = DirectoryCustody::acquire(
                path.parent()
                    .ok_or_else(|| CiError::Message("owned record parent absent".into()))?,
            )?;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let native = file.metadata()?;
            if !native.is_file()
                || native.nlink() != 1
                || native.len() > 16 * 1024 * 1024
                || native.mode() & 0o022 != 0
            {
                return Err(CiError::Message(
                    "owned component record native custody differs".into(),
                ));
            }
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut file)
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            let record = Self {
                path,
                bytes,
                file,
                ancestry,
            };
            record.verify()?;
            Ok(record)
        }
    }
    fn parse<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        memcordon_core::canonical_json::reject_duplicate_json_keys(&self.bytes)
            .map_err(CiError::Message)?;
        Ok(serde_json::from_slice(&self.bytes)?)
    }
    fn verify(&self) -> Result<()> {
        #[cfg(windows)]
        {
            crate::windows_readiness_adapter::verify_named_artifact(&self.custody, &self.path)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            self.ancestry.verify()?;
            let held = self.file.metadata()?;
            let mut named = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&self.path)?;
            let current = named.metadata()?;
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut named)
                .take(self.bytes.len() as u64 + 1)
                .read_to_end(&mut bytes)?;
            if held.nlink() != 1
                || current.nlink() != 1
                || (held.dev(), held.ino()) != (current.dev(), current.ino())
                || held.len() != self.bytes.len() as u64
                || bytes != self.bytes
            {
                return Err(CiError::Message(
                    "owned component record named identity/bytes changed".into(),
                ));
            }
        }
        Ok(())
    }
}

fn select(root: &Path, args: &Args) -> Result<Selection> {
    let identity_record = OwnedRecord::read(&args.identity)?;
    let identity: SourceIdentity = identity_record.parse()?;
    let target = super::distribution::native_target()?;
    let roles_record =
        OwnedRecord::read(&root.join(".release/native-components/measured-harnesses.json"))?;
    let roles: AcquiredRoles = roles_record.parse()?;
    let deadline_record = OwnedRecord::read(&root.join(".release/native-operation-deadline.json"))?;
    let deadline: native_component_harness::OriginalNativeDeadline = deadline_record.parse()?;
    let host_record = OwnedRecord::read(&root.join(".release/native-components/native-host.json"))?;
    let host: AcquiredHost = host_record.parse()?;
    let target_job = match target {
        "x86_64-unknown-linux-gnu" => "native-linux-x64",
        "aarch64-unknown-linux-gnu" => "native-linux-arm64",
        "x86_64-pc-windows-msvc" => "native-windows-x64",
        "aarch64-pc-windows-msvc" => "native-windows-arm64",
        _ => {
            return Err(CiError::Message(
                "unsupported native component target".into(),
            ));
        }
    };
    let attempt = if args.github_context {
        if std::env::var("GITHUB_JOB").ok().as_deref() != Some(target_job)
            || std::env::var("GITHUB_RUN_ID").ok().as_deref() != Some(identity.run_id.as_str())
        {
            return Err(CiError::Message(
                "actual original native job/run differs".into(),
            ));
        }
        std::env::var("GITHUB_RUN_ATTEMPT")
            .map_err(|error| CiError::Message(error.to_string()))?
            .parse::<u64>()
            .map_err(|error| CiError::Message(error.to_string()))?
    } else {
        args.run_attempt
            .ok_or_else(|| CiError::Message("original native run attempt absent".into()))?
    };
    if attempt == 0
        || roles.format != "memcordon.consumer-readiness.native-harnesses"
        || roles.revision != 1
        || roles.native_target != target
        || roles.source.commit() != identity.source_commit
        || roles.source.version().to_string() != identity.version
        || deadline.format != "memcordon.consumer-readiness.original-native-deadline"
        || deadline.revision != 1
        || deadline.native_target != target
        || serde_json::to_vec(&deadline.source)? != serde_json::to_vec(&roles.source)?
        || deadline
            .work_deadline_unix_millis
            .checked_sub(deadline.started_unix_millis)
            != Some(140 * 60 * 1000)
        || deadline
            .cleanup_deadline_unix_millis
            .checked_sub(deadline.work_deadline_unix_millis)
            != Some(15 * 60 * 1000)
    {
        return Err(CiError::Message(
            "original measured roles/source/deadline association differs".into(),
        ));
    }
    let features = if target.contains("windows") {
        "windows-sealed-runtime,test-support"
    } else {
        "private-tcp,test-support"
    };
    if roles.roles.len() != 2
        || roles
            .roles
            .iter()
            .filter(|role| {
                role.role == "operational"
                    && role.package == "memcordon"
                    && role.test == "sealed_agent"
                    && role.features.as_deref() == Some(features)
            })
            .count()
            != 1
        || roles
            .roles
            .iter()
            .filter(|role| {
                role.role == "parser"
                    && role.package == "memcordon-readiness-verifier"
                    && role.test == "contract"
                    && role.features.is_none()
            })
            .count()
            != 1
    {
        return Err(CiError::Message(
            "original native executable roles differ".into(),
        ));
    }
    roles.source.recheck(root)?;
    let origin_record =
        OwnedRecord::read(&root.join(".release/native-components/acquisition-origin.json"))?;
    let origin: AcquisitionOrigin = origin_record.parse()?;
    let actor_record = if target.ends_with("-pc-windows-msvc") {
        Some(OwnedRecord::read(&root.join(
            ".release/native-components/actor/internal-actor-build.json",
        ))?)
    } else {
        None
    };
    if origin.format != "memcordon.consumer-readiness.native-acquisition-origin"
        || origin.revision != 1
        || origin.target != target
        || origin.job != target_job
        || origin.run_id != identity.run_id
        || origin.run_id.parse::<u64>().ok().is_none_or(|run| run == 0)
        || origin.run_attempt != attempt
        || serde_json::to_vec(&origin.source)? != serde_json::to_vec(&roles.source)?
        || origin.harnesses_sha256 != artifacts::checksum(&roles_record.bytes)
        || origin.host_sha256 != artifacts::checksum(&host_record.bytes)
        || origin.deadline_sha256 != artifacts::checksum(&deadline_record.bytes)
        || origin.actor_sha256
            != actor_record
                .as_ref()
                .map(|record| artifacts::checksum(&record.bytes))
        || origin.fixture_sha256.is_some() != target.ends_with("-pc-windows-msvc")
        || origin.fixture_sha256.as_ref().is_some_and(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(CiError::Message(
            "original acquisition job/attempt or byte binding differs".into(),
        ));
    }
    if host.format != "memcordon.consumer-readiness.original-native-host"
        || host.revision != 1
        || host.target != target
        || serde_json::to_vec(&host.source)? != serde_json::to_vec(&roles.source)?
        || host.host.native_target != target
        || host.host.executable_target != target
        || host.host.emulated
        || host.host.kernel.is_empty()
        || !host.compiler.is_absolute()
        || host.compiler_artifact != "native-compiler.bin"
        || host.compiler_path_stdout != "compiler-path.stdout"
        || host.compiler_path_stderr != "compiler-path.stderr"
        || host.compiler_identity_stdout != "compiler-identity.stdout"
        || host.compiler_identity_stderr != "compiler-identity.stderr"
        || host.compiler_length == 0
        || host.compiler_length > 512 * 1024 * 1024
        || host.compiler_sha256 != host.host.toolchain_sha256
        || !host
            .host
            .toolchain_identity
            .lines()
            .any(|line| line.strip_prefix("host: ") == Some(target))
    {
        return Err(CiError::Message(
            "original native host/compiler acquisition record differs".into(),
        ));
    }
    let lockfile = OwnedRecord::read(&root.join("Cargo.lock"))?;
    if artifacts::checksum(&lockfile.bytes) != host.host.lockfile_sha256 {
        return Err(CiError::Message(
            "original acquired native host lockfile differs".into(),
        ));
    }
    for role in &roles.roles {
        let owned = root.join(".release/native-components").join(&role.role);
        if !role.executable.is_absolute()
            || !role.executable.starts_with(&owned)
            || role.compiler_output != owned.join("cargo-output.jsonl")
            || role.compiler_errors != owned.join("cargo-stderr.bin")
        {
            return Err(CiError::Message(
                "native role paths differ from original measured acquisition".into(),
            ));
        }
    }
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CiError::Message(error.to_string()))?
            .as_millis(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    if now < deadline.started_unix_millis
        || now >= deadline.cleanup_deadline_unix_millis
        || (!args.cleanup && now >= deadline.work_deadline_unix_millis)
    {
        return Err(CiError::Message(
            "original native component cutoff exhausted or clock regressed".into(),
        ));
    }
    let instant = Instant::now();
    let work = instant
        .checked_add(Duration::from_millis(
            deadline.work_deadline_unix_millis.saturating_sub(now),
        ))
        .ok_or_else(|| CiError::Message("native work cutoff overflow".into()))?;
    let cleanup = instant
        .checked_add(Duration::from_millis(
            deadline.cleanup_deadline_unix_millis - now,
        ))
        .ok_or_else(|| CiError::Message("native cleanup cutoff overflow".into()))?;
    let mut records = vec![
        identity_record,
        roles_record,
        deadline_record,
        host_record,
        origin_record,
        lockfile,
    ];
    records.extend(actor_record);
    Ok(Selection {
        identity,
        target: target.to_owned(),
        job: target_job.into(),
        run_attempt: attempt,
        roles,
        deadline,
        work,
        cleanup,
        records,
        host,
        fixture_sha256: origin.fixture_sha256,
    })
}

fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(windows)]
    {
        let _held = crate::windows_readiness_adapter::publish_receipt(path, bytes)?;
        return Ok(());
    }
    #[cfg(unix)]
    {
        persist_unix(path, bytes, 0o444)
    }
}

#[cfg(unix)]
fn persist_unix(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    {
        use std::os::unix::fs::MetadataExt;
        let ancestry = DirectoryCustody::acquire(
            path.parent()
                .ok_or_else(|| CiError::Message("native artifact parent absent".into()))?,
        )?;
        ancestry.verify()?;
        let parent = ancestry
            .handles
            .last()
            .ok_or_else(|| CiError::Message("native artifact held parent absent".into()))?;
        let name = path
            .file_name()
            .ok_or_else(|| CiError::Message("native artifact leaf absent".into()))?;
        let mut file = File::from(
            rustix::fs::openat(
                parent,
                name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(mode),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        file.write_all(bytes)?;
        file.sync_all()?;
        let held = file.metadata()?;
        let mut named = File::from(
            rustix::fs::openat(
                parent,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let native = named.metadata()?;
        let mut readback = Vec::new();
        std::io::Read::by_ref(&mut named)
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut readback)?;
        if held.nlink() != 1
            || native.nlink() != 1
            || (held.dev(), held.ino()) != (native.dev(), native.ino())
            || readback != bytes
        {
            return Err(CiError::Message(
                "original component artifact readback differs".into(),
            ));
        }
        parent.sync_all()?;
        ancestry.verify()?;
        Ok(())
    }
}

fn retain_file(
    source: &Path,
    bundle: &Path,
    relative: &Path,
    expected: Option<&str>,
    limit: u64,
) -> Result<Artifact> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(CiError::Message(
            "original component artifact path escapes bundle".into(),
        ));
    }
    #[cfg(windows)]
    let held = crate::windows_readiness_adapter::hold_artifact(source, expected, limit)?;
    #[cfg(windows)]
    let bytes = held.bytes.clone();
    #[cfg(unix)]
    let (bytes, source_custody, source_ancestry, source_identity) = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let ancestry = DirectoryCustody::acquire(
            source
                .parent()
                .ok_or_else(|| CiError::Message("native source parent absent".into()))?,
        )?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source)?;
        let before = file.metadata()?;
        if !before.is_file() || before.nlink() != 1 || before.len() > limit {
            return Err(CiError::Message(
                "original component source type/size differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)?;
        let named = std::fs::symlink_metadata(source)?;
        let after = file.metadata()?;
        if !named.is_file()
            || (named.dev(), named.ino()) != (before.dev(), before.ino())
            || after.len() != before.len()
            || after.mtime() != before.mtime()
            || after.mtime_nsec() != before.mtime_nsec()
            || bytes.len() as u64 != before.len()
        {
            return Err(CiError::Message(
                "original component source changed during read".into(),
            ));
        }
        (bytes, file, ancestry, before)
    };
    let sha = artifacts::checksum(&bytes);
    if expected.is_some_and(|expected| expected != sha) {
        return Err(CiError::Message(
            "original measured component source hash differs".into(),
        ));
    }
    let destination = bundle.join(relative);
    #[cfg(unix)]
    let bundle_custody = DirectoryCustody::acquire(bundle)?;
    #[cfg(unix)]
    let created_custody = DirectoryCustody::create_confined(
        bundle,
        relative.parent().expect("confined artifact parent"),
    )?;
    #[cfg(windows)]
    std::fs::create_dir_all(destination.parent().expect("confined artifact parent"))?;
    #[cfg(unix)]
    let destination_custody =
        DirectoryCustody::acquire(destination.parent().expect("confined artifact parent"))?;
    #[cfg(windows)]
    let _custody =
        crate::windows_readiness_adapter::copy_owned_artifact(source, &destination, &sha)?;
    #[cfg(unix)]
    persist(&destination, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        source_ancestry.verify()?;
        bundle_custody.verify()?;
        destination_custody.verify()?;
        created_custody.verify()?;
        let named = std::fs::symlink_metadata(source)?;
        let after = source_custody.metadata()?;
        if !named.is_file()
            || (named.dev(), named.ino()) != (source_identity.dev(), source_identity.ino())
            || after.len() != source_identity.len()
            || after.mtime() != source_identity.mtime()
            || after.mtime_nsec() != source_identity.mtime_nsec()
        {
            return Err(CiError::Message(
                "native source custody changed before projection completed".into(),
            ));
        }
    }
    Ok(Artifact {
        path: relative
            .to_str()
            .ok_or_else(|| CiError::Message("component artifact name is not UTF-8".into()))?
            .replace('\\', "/"),
        length: bytes.len() as u64,
        sha256: sha,
    })
}

fn seal(root: &Path, args: &Args, selection: &Selection, cell: &CellEvidence) -> Result<()> {
    for record in &selection.records {
        record.verify()?;
    }
    if cell.product.is_some()
        || cell.component_build.is_none()
        || cell.records.is_empty()
        || !cell.cache_quiescent
        || !cell.cleanup_failures.is_empty()
        || cell.records.iter().any(|record| {
            record.run_id != selection.identity.run_id
                || record.key.target != selection.target
                || record.key.channel.is_some()
        })
    {
        return Err(CiError::Message(
            "original component producer cannot seal empty, mixed or unresolved ownership".into(),
        ));
    }
    persist(
        &args.destination.join("cell.json"),
        &serde_json::to_vec_pretty(cell)?,
    )?;
    let manifest = ProducerManifest {
        format: "memcordon.consumer-readiness.producer".into(),
        revision: 1,
        job: selection.job.clone(),
        run_id: selection.identity.run_id.clone(),
        run_attempt: selection.run_attempt,
        source_commit: selection.identity.source_commit.clone(),
        source_tree_sha256: selection.identity.source_tree_sha256.clone(),
        version: selection.identity.version.clone(),
        manifest_sha256: artifacts::checksum(&artifacts::read_file(
            &root.join("ci/consumer-readiness-v1.toml"),
        )?),
        artifacts: cell.artifacts.clone(),
        products: Vec::new(),
        component_builds: cell.component_build.clone().into_iter().collect(),
        records: cell.records.clone(),
    };
    persist(
        &args.destination.join("producer-manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )
}

fn source_archive(
    root: &Path,
    selection: &Selection,
    destination: &Path,
    relative: &Path,
) -> Result<Artifact> {
    let output = crate::command::CommandSpec::new("git", root, Duration::from_secs(60))
        .args([
            "archive",
            "--format=tar",
            selection.identity.source_commit.as_str(),
        ])
        .bounded_until(selection.work)
        .output_limit(super::source::MAX_SOURCE_ARCHIVE_BYTES)
        .output_quiet()?;
    if !output.status.success()
        || output.stdout.len() > super::source::MAX_SOURCE_ARCHIVE_BYTES
        || artifacts::checksum(&output.stdout) != selection.identity.source_tree_sha256
    {
        return Err(CiError::Message(
            "original selected source tar differs from measured producer source".into(),
        ));
    }
    let path = destination.join(relative);
    #[cfg(unix)]
    let _parents = DirectoryCustody::create_confined(
        destination,
        relative.parent().expect("source archive parent"),
    )?;
    #[cfg(windows)]
    std::fs::create_dir_all(path.parent().expect("source archive parent"))?;
    persist(&path, &output.stdout)?;
    Ok(Artifact {
        path: relative
            .to_str()
            .ok_or_else(|| CiError::Message("source archive path encoding differs".into()))?
            .replace('\\', "/"),
        length: output.stdout.len() as u64,
        sha256: artifacts::checksum(&output.stdout),
    })
}

#[cfg(target_os = "linux")]
pub fn run(root: &Path, args: &Args) -> Result<()> {
    use super::linux_native_component::NativeAdminScope;
    crate::workflow_output::write(&[("cache-quiescent", "false".into())])?;
    let root = std::path::absolute(root)?;
    let selection = select(&root, args)?;
    if !rustix::process::geteuid().is_root() {
        let mut native_path = std::ffi::OsString::from("PATH=");
        native_path.push(
            std::env::var_os("PATH")
                .ok_or_else(|| CiError::Message("native toolchain PATH absent".into()))?,
        );
        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
            .ok_or_else(|| CiError::Message("native Rust toolchain home absent".into()))?;
        let mut rustup_environment = std::ffi::OsString::from("RUSTUP_HOME=");
        rustup_environment.push(rustup_home);
        let mut command = crate::command::CommandSpec::new(
            "sudo",
            &root,
            selection.cleanup.saturating_duration_since(Instant::now()),
        )
        .args(["-n", "--"])
        .arg("/usr/bin/env")
        .arg(native_path)
        .arg(rustup_environment)
        .arg(std::env::current_exe()?)
        .arg("consumer-readiness-native-components")
        .arg("--identity")
        .arg(std::path::absolute(&args.identity)?)
        .arg("--run-attempt")
        .arg(selection.run_attempt.to_string())
        .arg("--destination")
        .arg(std::path::absolute(&args.destination)?)
        .bounded_until(selection.cleanup);
        if args.cleanup {
            command = command.arg("--cleanup");
        }
        return command.run().map(|_| ());
    }
    let destination = std::path::absolute(&args.destination)?;
    if args.cleanup {
        return cleanup_linux(&root, &destination, &selection);
    }
    let destination_custody = DirectoryCustody::create_fresh(&destination)?;
    let prefix = Path::new(&selection.target)
        .join("candidate-native")
        .join("components");
    let prefix_text = prefix
        .to_str()
        .ok_or_else(|| CiError::Message("native artifact prefix encoding differs".into()))?;
    let recipe_id = "original-native-components-v1";
    let scope_recipe = selection.scope_recipe();
    let mut scope = NativeAdminScope::allocate_owned_scope(
        &root,
        &selection.identity,
        &selection.target,
        &scope_recipe,
        prefix_text,
        selection.deadline.work_deadline_unix_millis,
        selection.deadline.cleanup_deadline_unix_millis,
    )?;
    let mut cell = empty_cell(&root, &selection)?;
    let result = (|| -> Result<()> {
        let (build, source, artifacts) = prepare_build(&root, &destination, &prefix, &selection)?;
        cell.component_build = Some(build.clone());
        cell.artifacts = artifacts;
        let operational = acquire_linux_role(&selection, "operational")?;
        let parser = acquire_linux_role(&selection, "parser")?;
        let operational = scope.prepare("operational", &operational)?;
        let parser = scope.prepare("parser", &parser)?;
        let preparation = scope.prepare_operational_fixture(
            &root,
            &selection.identity,
            &selection.target,
            &destination,
            selection.work,
            selection.cleanup,
            selection.deadline.work_deadline_unix_millis,
            selection.deadline.cleanup_deadline_unix_millis,
        );
        if let Err(error) = &preparation {
            cell.cleanup_failures
                .push(format!("original native fixture preparation: {error}"));
        }
        if preparation.is_ok()
            && let Err(error) = scope.execute(
                &parser,
                &operational,
                &selection.identity.run_id,
                recipe_id,
                &selection.target,
                prefix_text,
                selection.work,
                selection.cleanup,
                selection.deadline.work_deadline_unix_millis,
                selection.deadline.cleanup_deadline_unix_millis,
            )
        {
            cell.cleanup_failures
                .push(format!("original native execution: {error}"));
        }
        // Settlement precedes evidence decoding, but deletion never precedes copying.
        if let Err(error) = scope.settle(selection.cleanup) {
            cell.cleanup_failures.push(error.to_string());
        }
        cell.cleanup_failures
            .extend(scope.failures().iter().cloned());
        // Borrow the actual protected acquisition records before deleting the
        // administrative scope. The loan retains their native file/ancestor
        // custody throughout unchanged publication into the producer bundle.
        let fixture_acquisition = match scope.component_fixture_acquisition(selection.cleanup) {
            Ok(loan) => {
                let transfer =
                    (|| -> Result<memcordon_readiness_verifier::ComponentFixtureAcquisition> {
                        let relative = prefix.join("native-fixture");
                        let parents = DirectoryCustody::create_confined(&destination, &relative)?;
                        let mut paths = std::collections::BTreeMap::new();
                        for (name, bytes) in loan.entries() {
                            if Instant::now() >= selection.cleanup {
                                return Err(CiError::Message(
                                    "original fixture transfer cutoff exhausted".into(),
                                ));
                            }
                            let path = relative.join(name);
                            persist(&destination.join(&path), bytes)?;
                            parents.verify()?;
                            let path = path
                                .to_str()
                                .ok_or_else(|| {
                                    CiError::Message("fixture transport path not UTF8".into())
                                })?
                                .to_owned();
                            cell.artifacts.push(Artifact {
                                path: path.clone(),
                                length: bytes.len() as u64,
                                sha256: artifacts::checksum(bytes),
                            });
                            paths.insert(name.as_str(), path);
                        }
                        let mut take = |name| {
                            paths.remove(name).ok_or_else(|| {
                                CiError::Message(format!("actual fixture acquisition omits {name}"))
                            })
                        };
                        Ok(memcordon_readiness_verifier::ComponentFixtureAcquisition {
                            checkpoint: take("owned-resources-acquired.json")?,
                            account_intent: take("exclusive-account-intent.json")?,
                            account_readback: take("exclusive-account-getent.bin")?,
                            group_readback: take("exclusive-group-getent.bin")?,
                        })
                    })();
                let leaves = loan.verify(selection.cleanup);
                if let Err(error) = &leaves {
                    cell.cleanup_failures
                        .push(format!("native fixture acquired leaf custody: {error}"));
                }
                let named = scope.verify_named();
                if let Err(error) = &named {
                    cell.cleanup_failures
                        .push(format!("native fixture source named custody: {error}"));
                }
                let transfer = transfer.and_then(|acquired| leaves.and(named).map(|()| acquired));
                // The acquisition loan remains held through the final named
                // source check. A transfer failure cannot bypass settlement.
                match transfer {
                    Ok(acquired) => Some(acquired),
                    Err(error) => {
                        cell.cleanup_failures
                            .push(format!("native fixture acquisition transfer: {error}"));
                        if let Err(cleanup) = scope.settle(selection.cleanup) {
                            cell.cleanup_failures
                                .push(format!("native fixture transfer settlement: {cleanup}"));
                        }
                        None
                    }
                }
            }
            Err(error) => {
                cell.cleanup_failures
                    .push(format!("native fixture acquisition transfer: {error}"));
                None
            }
        };
        // The fast-exit recovery process is associated with this unchanged
        // originally selected package owner, not a reconstructed metadata view.
        match scope.component_package_owner(selection.cleanup) {
            Ok(loan) => {
                let transfer = (|| -> Result<()> {
                    let relative = prefix.join("native-fixture");
                    let parents = DirectoryCustody::create_confined(&destination, &relative)?;
                    if loan.entries().len() != 1
                        || loan.entries()[0].0 != "native-package-owner.json"
                    {
                        return Err(CiError::Message(
                            "native package owner loan has a different record set".into(),
                        ));
                    }
                    for (name, bytes) in loan.entries() {
                        if Instant::now() >= selection.cleanup {
                            return Err(CiError::Message(
                                "original package owner transfer cutoff exhausted".into(),
                            ));
                        }
                        let path = relative.join(name);
                        persist(&destination.join(&path), bytes)?;
                        parents.verify()?;
                        cell.artifacts.push(Artifact {
                            path: path
                                .to_str()
                                .ok_or_else(|| {
                                    CiError::Message("package owner transport path not UTF8".into())
                                })?
                                .to_owned(),
                            length: bytes.len() as u64,
                            sha256: artifacts::checksum(bytes),
                        });
                    }
                    Ok(())
                })();
                let leaves = loan.verify(selection.cleanup);
                let named = scope.verify_named();
                for (label, result) in [("leaf", &leaves), ("scope", &named)] {
                    if let Err(error) = result {
                        cell.cleanup_failures
                            .push(format!("native package owner {label} custody: {error}"));
                    }
                }
                if let Err(error) = transfer.and(leaves).and(named) {
                    cell.cleanup_failures
                        .push(format!("native package owner transfer: {error}"));
                    if let Err(cleanup) = scope.settle(selection.cleanup) {
                        cell.cleanup_failures.push(format!(
                            "native package owner transfer settlement: {cleanup}"
                        ));
                    }
                }
            }
            Err(error) => cell
                .cleanup_failures
                .push(format!("native package owner acquisition: {error}")),
        }
        for name in [
            "index-parser",
            "operational-parser",
            "filter",
            "versions",
            "journal",
            "release",
        ] {
            let output = scope.outputs().join("recipes").join(name);
            let nested = prefix.join(name);
            match crate::linux_consumer_readiness::normalize_native_harness_with_fixture(
                &selection.identity,
                &build,
                &source,
                &output,
                nested.to_str().ok_or_else(|| {
                    CiError::Message("native recipe prefix encoding differs".into())
                })?,
                &destination,
                if name == "release" {
                    fixture_acquisition.clone()
                } else {
                    None
                },
            ) {
                Ok((records, artifacts)) => merge_rows(&mut cell, records, artifacts)?,
                Err(error) => cell.cleanup_failures.push(format!(
                    "{name}: retained native products unavailable: {error}"
                )),
            }
        }
        for name in ["account-retirement", "lost-terminal"] {
            let projection = (|| -> Result<()> {
                let acquired = fixture_acquisition.clone().ok_or_else(|| {
                    CiError::Message(
                        "native recovery original fixture acquisition unavailable".into(),
                    )
                })?;
                let relative = prefix.join(name);
                let (records, products) =
                    crate::linux_consumer_readiness::normalize_native_recovery_harness(
                        &selection.identity,
                        &build,
                        &source,
                        &scope.outputs().join("recipes").join(name),
                        relative.to_str().ok_or_else(|| {
                            CiError::Message("native recovery prefix is not UTF8".into())
                        })?,
                        &destination,
                        acquired,
                    )
                    .map_err(CiError::Message)?;
                let parents = DirectoryCustody::create_confined(&destination, &relative)?;
                let mut retained = Vec::new();
                for (artifact, bytes) in products {
                    if Instant::now() >= selection.cleanup {
                        return Err(CiError::Message(
                            "original recovery transport cutoff exhausted".into(),
                        ));
                    }
                    let path = Path::new(&artifact.path);
                    if !path.starts_with(&relative)
                        || path.parent() != Some(relative.as_path())
                        || artifact.length != bytes.len() as u64
                        || artifact.sha256 != artifacts::checksum(&bytes)
                    {
                        return Err(CiError::Message(
                            "native recovery projection substitutes its confined bytes/path".into(),
                        ));
                    }
                    persist(&destination.join(path), &bytes)?;
                    parents.verify()?;
                    retained.push(artifact);
                }
                scope.verify_named()?;
                merge_rows(&mut cell, records, retained)
            })();
            let named = scope.verify_named();
            if let Err(error) = &named {
                cell.cleanup_failures
                    .push(format!("{name}: native recovery source custody: {error}"));
            }
            if let Err(error) = projection.and(named) {
                cell.cleanup_failures.push(format!(
                    "{name}: retained native recovery unavailable: {error}"
                ));
                if let Err(cleanup) = scope.settle(selection.cleanup) {
                    cell.cleanup_failures.push(format!(
                        "{name}: independent recovery transfer settlement: {cleanup}"
                    ));
                }
            }
        }
        // Persist partial evidence before any cleanup. Missing capture products are
        // an operation failure, never permission to publish fabricated test rows.
        persist(
            &destination.join("component-observations.json"),
            &serde_json::to_vec_pretty(&cell)?,
        )?;
        if !cell.cleanup_failures.is_empty() {
            return Err(CiError::Message(cell.cleanup_failures.join("; ")));
        }
        let retirement = scope.retire(selection.cleanup)?;
        publish_linux_retirement(&root, &destination, &serde_json::to_vec(&retirement)?)?;
        cell.cache_quiescent = true;
        seal(
            &root,
            &Args {
                destination: destination.clone(),
                ..args.clone()
            },
            &selection,
            &cell,
        )
    })();
    if let Err(error) = result {
        // All attempts are settled independently even after decode/copy failures.
        if let Err(cleanup) = scope.settle(selection.cleanup) {
            cell.cleanup_failures.push(cleanup.to_string());
        }
        cell.cache_quiescent = false;
        cell.cleanup_failures.push(error.to_string());
        // This failed observation is collected by the ordinary runner after
        // privileged settlement; private native owner records stay private.
        source::write_diagnostic_json(&destination.join("component-failure.json"), &cell)?;
        return Err(error);
    }
    destination_custody.verify()?;
    Ok(())
}

#[cfg(windows)]
fn prepare_windows_support(
    root: &Path,
    destination: &Path,
    selection: &Selection,
) -> Result<(
    WindowsOriginalOwner,
    Vec<crate::windows_readiness_adapter::HeldWindowsArtifact>,
)> {
    use crate::windows_installed_cases::{InstalledWindowsPayload, SelectedArtifact};
    let actor_root = root.join(".release/native-components/actor");
    let actor_record = selection
        .records
        .iter()
        .find(|record| record.path == actor_root.join("internal-actor-build.json"))
        .ok_or_else(|| {
            CiError::Message("original acquisition omits held actor descriptor".into())
        })?;
    let actor: AcquiredActor = actor_record.parse()?;
    if actor.format != "memcordon.consumer-readiness.internal-actor-build"
        || actor.revision != 1
        || actor.native_target != selection.target
        || actor.features != ["test-support", "windows-sealed-runtime"]
        || serde_json::to_vec(&actor.source)? != serde_json::to_vec(&selection.roles.source)?
        || actor.runtime_manifest.source_commit != selection.identity.source_commit
        || actor.runtime_manifest.version != selection.identity.version
        || actor.runtime_manifest.target != selection.target
        || actor.runtime_manifest.components.len() != 4
    {
        return Err(CiError::Message(
            "original support actor descriptor source/target/feature closure differs".into(),
        ));
    }
    let lifetime = destination.join("windows-support-lifetime");
    std::fs::create_dir(&lifetime)?;
    let selected = lifetime.join("selected-support");
    std::fs::create_dir(&selected)?;
    let mut custody = Vec::new();
    let mut measured = Vec::new();
    for component in &actor.runtime_manifest.components {
        let relative = artifacts::safe_relative(Path::new(&component.path))?;
        if relative.components().count() != 1 {
            return Err(CiError::Message(
                "support component filename is not one confined native name".into(),
            ));
        }
        let actual = actor_root.join(&relative);
        let held = crate::windows_readiness_adapter::hold_artifact(
            &actual,
            Some(&component.sha256),
            512 * 1024 * 1024,
        )?;
        if held.bytes.len() as u64 != component.size {
            return Err(CiError::Message(
                "support component measured length differs".into(),
            ));
        }
        super::target::validate_executable(&held.bytes, &selection.target)?;
        let copied = selected.join(&relative);
        custody.push(crate::windows_readiness_adapter::copy_owned_artifact(
            &actual,
            &copied,
            &component.sha256,
        )?);
        measured.push(SelectedArtifact {
            path: copied,
            sha256: component.sha256.clone(),
        });
    }
    let manifest = crate::windows_readiness_adapter::hold_artifact(
        &actor_root.join("runtime-manifest.json"),
        None,
        16 * 1024 * 1024,
    )?;
    let parsed = memcordon_core::runtime_manifest::RuntimeManifest::parse(&manifest.bytes)
        .map_err(CiError::Message)?;
    if serde_json::to_vec(&parsed)? != serde_json::to_vec(&actor.runtime_manifest)? {
        return Err(CiError::Message(
            "actual support runtime manifest differs from immutable acquisition descriptor".into(),
        ));
    }
    custody.push(crate::windows_readiness_adapter::copy_owned_artifact(
        &actor_root.join("runtime-manifest.json"),
        &selected.join("runtime-manifest.json"),
        &manifest.sha256,
    )?);
    let (bundle, _) = super::target::TargetBundle::load(&root.join(".release/target"))?;
    if bundle.source.commit() != selection.identity.source_commit
        || bundle.distribution.target != selection.target
        || selection.fixture_sha256.as_deref() != Some(bundle.fixture.sha256.as_str())
    {
        return Err(CiError::Message(
            "support fixture target/source differs from original native acquisition".into(),
        ));
    }
    let fixture_source = root
        .join(".release/target")
        .join(artifacts::safe_relative(Path::new(&bundle.fixture.name))?);
    let fixture_path = selected.join("memcordon-test-fixture.exe");
    custody.push(crate::windows_readiness_adapter::copy_owned_artifact(
        &fixture_source,
        &fixture_path,
        &bundle.fixture.sha256,
    )?);
    let fixture = SelectedArtifact {
        path: fixture_path,
        sha256: bundle.fixture.sha256.clone(),
    };
    let agent = measured
        .iter()
        .find(|item| {
            item.path
                .file_name()
                .is_some_and(|name| name == "memcordon-sealed-agent.exe")
        })
        .ok_or_else(|| {
            CiError::Message("support manifest omits its measured native agent".into())
        })?;
    let removal = super::windows_readiness_lease::inspect_removal_plan_for_agent(
        root,
        agent,
        &selection.identity,
        &lifetime,
        selection.work,
    )?;
    let config = InstalledWindowsPayload::from_materialized(
        crate::windows_causal_acceptance::InstalledChannel::NativeBundle,
        &actor.source,
        &bundle.distribution,
        measured,
        &selected,
        fixture,
        &removal.binary_root,
        lifetime.join("observations"),
    )?;
    std::fs::create_dir(&config.output_directory)?;
    let owner = WindowsOriginalOwner {
        format: "memcordon.consumer-readiness.windows-original-owner".into(),
        revision: 1,
        identity: selection.identity.clone(),
        job: selection.job.clone(),
        run_attempt: selection.run_attempt,
        config,
        removal,
        original_work_unix_millis: selection.deadline.work_deadline_unix_millis,
        original_cleanup_unix_millis: selection.deadline.cleanup_deadline_unix_millis,
    };
    // This checked no-overwrite publication precedes the first native package mutation.
    let owner_path = lifetime.join("owner.json");
    let owner_bytes = serde_json::to_vec(&owner)?;
    let _published_owner =
        crate::windows_readiness_adapter::publish_receipt(&owner_path, &owner_bytes)?;
    custody.push(crate::windows_readiness_adapter::hold_artifact(
        &owner_path,
        Some(&artifacts::checksum(&owner_bytes)),
        16 * 1024 * 1024,
    )?);
    Ok((owner, custody))
}

#[cfg(windows)]
pub fn run(root: &Path, args: &Args) -> Result<()> {
    crate::workflow_output::write(&[("cache-quiescent", "false".into())])?;
    let root = std::path::absolute(root)?;
    let selection = select(&root, args)?;
    let destination = std::path::absolute(&args.destination)?;
    if args.cleanup {
        return cleanup_windows(&root, &destination, &selection);
    }
    std::fs::create_dir(&destination)?;
    let prefix = Path::new(&selection.target)
        .join("candidate-native")
        .join("components");
    let mut cell = empty_cell(&root, &selection)?;
    let (mut build, source, retained) = prepare_build(&root, &destination, &prefix, &selection)?;
    cell.artifacts = retained;
    let (owner, _support_custody) = prepare_windows_support(&root, &destination, &selection)?;
    let actor = retain_file(
        &owner.config.cli.path,
        &destination,
        &prefix.join("actors/memcordon.exe"),
        Some(&owner.config.cli.sha256),
        512 * 1024 * 1024,
    )?;
    build.actor_executable = Some(actor.path.clone());
    cell.artifacts.push(actor);
    cell.component_build = Some(build);
    // An existing provider is never adopted as this original support owner.
    crate::windows_readiness_adapter::observe_removed(
        &owner.config,
        &owner.removal,
        &owner.config.output_directory.join("before-install"),
        selection.work,
    )?;
    let _install_intent = crate::windows_readiness_adapter::publish_receipt(
        &owner.config.output_directory.join("install-intent.json"),
        &serde_json::to_vec(&WindowsInstallIntent {
            format: "memcordon.windows-original-install-intent".into(),
            revision: 1,
            owner_sha256: artifacts::checksum(&serde_json::to_vec(&owner)?),
            job: selection.job.clone(),
            run_attempt: selection.run_attempt,
        })?,
    )?;
    let operation = (|| -> Result<()> {
        windows_package(&owner, "install", selection.work)?;
        windows_package(&owner, "verify", selection.work)?;
        crate::windows_consumer_readiness::provision_from_source_until(
            &root,
            &owner.config,
            selection.work,
        )?;
        execute_windows_harnesses(&destination, &prefix, &selection, &source, &mut cell)?;
        let input = crate::windows_readiness_components::ComponentInput {
            format: "memcordon.windows-readiness-component".into(),
            revision: 1,
            run_id: selection.identity.run_id.clone(),
            recipe_id: "original-native-components-v1".into(),
            source_commit: selection.identity.source_commit.clone(),
            native_target: selection.target.clone(),
            features: vec!["test-support".into(), "windows-sealed-runtime".into()],
            selected_components: owner.config.components.clone(),
            suite_input: owner
                .config
                .output_directory
                .join("windows-readiness-input.json"),
            artifact_prefix: prefix.join("actors"),
            original_work_deadline_unix_millis: selection.deadline.work_deadline_unix_millis,
            original_cleanup_deadline_unix_millis: selection.deadline.cleanup_deadline_unix_millis,
        };
        let mut actors = Vec::new();
        let execution = crate::windows_readiness_components::run_installed_until(
            &owner.config,
            &input,
            &mut actors,
            crate::windows_installed_cases::WindowsLeaseDeadlines {
                work: selection.work,
                cleanup: selection.cleanup,
                work_deadline_unix_millis: selection.deadline.work_deadline_unix_millis,
                cleanup_deadline_unix_millis: selection.deadline.cleanup_deadline_unix_millis,
            },
        );
        let context = crate::windows_readiness_adapter::WindowsComponentAdapterContext {
            identity: selection.identity.clone(),
            destination: destination.clone(),
            fixture_source: crate::windows_installed_cases::SelectedArtifact {
                path: destination.join(&source.path),
                sha256: source.sha256.clone(),
            },
        };
        let normalization = crate::windows_readiness_adapter::normalize_actors(
            &context,
            &owner.config,
            &input,
            &actors,
        );
        if let Ok(rows) = normalization.as_ref() {
            merge_rows(&mut cell, rows.records.clone(), rows.artifacts.clone())?;
        }
        if let Err(error) = execution {
            cell.cleanup_failures.push(error.to_string());
        }
        if let Err(error) = normalization {
            cell.cleanup_failures.push(error.to_string());
        }
        Ok(())
    })();
    if let Err(error) = operation {
        cell.cleanup_failures.push(error.to_string());
    }
    // Persist every available constituent before finalization can remove state.
    persist(
        &destination.join("component-observations.json"),
        &serde_json::to_vec(&cell)?,
    )?;
    let cleanup_directory = owner.config.output_directory.join("cleanup-0");
    std::fs::create_dir(&cleanup_directory)?;
    match settle_windows_support(&owner, &cleanup_directory, selection.cleanup) {
        Ok(receipts) => {
            let settled = WindowsSettlement {
                format: "memcordon.windows-original-settlement".into(),
                revision: 1,
                owner_sha256: artifacts::checksum(&serde_json::to_vec(&owner)?),
                job: selection.job.clone(),
                run_attempt: selection.run_attempt,
                cleanup_directory: cleanup_directory.clone(),
                receipts,
            };
            let _settlement_custody = validate_windows_settlement(&owner, &settled)?;
            persist(
                &destination.join("windows-support-settled.json"),
                &serde_json::to_vec(&settled)?,
            )?;
            for (role, receipt) in [
                ("recovery", &settled.receipts.recovery),
                ("uninstall", &settled.receipts.uninstall),
                ("removal", &settled.receipts.removal),
            ] {
                cell.artifacts.push(retain_file(
                    &receipt.path,
                    &destination,
                    &prefix.join("settlement").join(format!("{role}.json")),
                    Some(&receipt.sha256),
                    16 * 1024 * 1024,
                )?);
            }
            cell.cache_quiescent = true;
        }
        Err(error) => cell.cleanup_failures.push(error.to_string()),
    }
    if !cell.cleanup_failures.is_empty() {
        persist(
            &destination.join("component-failure.json"),
            &serde_json::to_vec(&cell)?,
        )?;
        return Err(CiError::Message(cell.cleanup_failures.join("; ")));
    }
    seal(
        &root,
        &Args {
            destination,
            ..args.clone()
        },
        &selection,
        &cell,
    )
}

#[cfg(windows)]
fn cleanup_windows(root: &Path, destination: &Path, selection: &Selection) -> Result<()> {
    let record = OwnedRecord::read(&destination.join("windows-support-lifetime/owner.json"))?;
    let owner: WindowsOriginalOwner = record.parse()?;
    if owner.format != "memcordon.consumer-readiness.windows-original-owner"
        || owner.revision != 1
        || serde_json::to_vec(&owner.identity)? != serde_json::to_vec(&selection.identity)?
        || owner.job != selection.job
        || owner.run_attempt != selection.run_attempt
        || owner.original_work_unix_millis != selection.deadline.work_deadline_unix_millis
        || owner.original_cleanup_unix_millis != selection.deadline.cleanup_deadline_unix_millis
        || owner.config.source_commit != selection.identity.source_commit
        || owner.config.target != selection.target
        || owner.config.version != selection.identity.version
        || owner.config.output_directory
            != destination.join("windows-support-lifetime/observations")
    {
        return Err(CiError::Message(
            "original Windows cleanup owner association differs".into(),
        ));
    }
    let actor_record = selection
        .records
        .iter()
        .find(|record| {
            record
                .path
                .file_name()
                .is_some_and(|name| name == "internal-actor-build.json")
        })
        .ok_or_else(|| {
            CiError::Message("original cleanup lacks acquisition-bound actor descriptor".into())
        })?;
    let actor: AcquiredActor = actor_record.parse()?;
    let selected_directory = destination.join("windows-support-lifetime/selected-support");
    let expected = actor
        .runtime_manifest
        .components
        .iter()
        .map(|component| {
            (
                selected_directory.join(&component.path),
                component.sha256.clone(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let observed = owner
        .config
        .components
        .iter()
        .map(|artifact| (artifact.path.clone(), artifact.sha256.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    if expected.len() != 4
        || observed != expected
        || owner.config.components.len() != 4
        || !expected.contains(&(
            owner.config.cli.path.clone(),
            owner.config.cli.sha256.clone(),
        ))
        || owner.config.cli.path != selected_directory.join("memcordon.exe")
        || !expected.contains(&(
            owner.config.agent.path.clone(),
            owner.config.agent.sha256.clone(),
        ))
        || owner.config.agent.path != selected_directory.join("memcordon-sealed-agent.exe")
        || owner.config.installed_agent.path
            != owner.removal.binary_root.join("memcordon-sealed-agent.exe")
        || owner.config.installed_agent.sha256 != owner.config.agent.sha256
        || owner.config.installed_manifest.path
            != owner.removal.binary_root.join("runtime-manifest.json")
        || owner.config.fixture.path != selected_directory.join("memcordon-test-fixture.exe")
        || selection.fixture_sha256.as_deref() != Some(owner.config.fixture.sha256.as_str())
    {
        return Err(CiError::Message(
            "original cleanup component paths/hashes differ from its immutable acquired roles"
                .into(),
        ));
    }
    let manifest = OwnedRecord::read(&selected_directory.join("runtime-manifest.json"))?;
    let parsed = memcordon_core::runtime_manifest::RuntimeManifest::parse(&manifest.bytes)
        .map_err(CiError::Message)?;
    if serde_json::to_vec(&parsed)? != serde_json::to_vec(&actor.runtime_manifest)?
        || artifacts::checksum(&manifest.bytes) != owner.config.installed_manifest.sha256
        || serde_json::to_vec(
            &parsed
                .public_binding(&manifest.bytes)
                .map_err(CiError::Message)?,
        )? != serde_json::to_vec(&owner.config.provider)?
    {
        return Err(CiError::Message(
            "original cleanup provider binding differs from measured selected manifest".into(),
        ));
    }
    let mut custody = Vec::new();
    for artifact in owner
        .config
        .components
        .iter()
        .chain(std::iter::once(&owner.config.fixture))
    {
        custody.push(crate::windows_readiness_adapter::hold_artifact(
            &artifact.path,
            Some(&artifact.sha256),
            512 * 1024 * 1024,
        )?);
    }
    let intent = OwnedRecord::read(&owner.config.output_directory.join("install-intent.json"))?;
    let intent: WindowsInstallIntent = intent.parse()?;
    if intent.format != "memcordon.windows-original-install-intent"
        || intent.revision != 1
        || intent.owner_sha256 != artifacts::checksum(&record.bytes)
        || intent.job != selection.job
        || intent.run_attempt != selection.run_attempt
    {
        return Err(CiError::Message(
            "support install intent is absent or not this original owner; no provider is adopted"
                .into(),
        ));
    }
    let directory = (1..128)
        .map(|ordinal| {
            owner
                .config
                .output_directory
                .join(format!("cleanup-{ordinal}"))
        })
        .find(|path| !path.exists())
        .ok_or_else(|| CiError::Message("Windows original cleanup retries exceed bound".into()))?;
    std::fs::create_dir(&directory)?;
    let inspected = super::windows_readiness_lease::inspect_removal_plan_for_agent(
        root,
        &owner.config.agent,
        &selection.identity,
        &directory,
        selection.cleanup,
    )?;
    if serde_json::to_vec(&inspected)? != serde_json::to_vec(&owner.removal)? {
        return Err(CiError::Message(
            "original support removal roots differ from actual selected native package layout"
                .into(),
        ));
    }
    if destination.join("windows-support-settled.json").exists() {
        let settled = OwnedRecord::read(&destination.join("windows-support-settled.json"))?;
        let settled: WindowsSettlement = settled.parse()?;
        if settled.format != "memcordon.windows-original-settlement"
            || settled.revision != 1
            || settled.owner_sha256 != artifacts::checksum(&record.bytes)
            || settled.job != selection.job
            || settled.run_attempt != selection.run_attempt
            || settled.cleanup_directory.parent() != Some(owner.config.output_directory.as_path())
        {
            return Err(CiError::Message(
                "original successful support settlement receipt binding differs".into(),
            ));
        }
        for receipt in [
            &settled.receipts.recovery,
            &settled.receipts.uninstall,
            &settled.receipts.removal,
        ] {
            if !receipt.path.starts_with(&owner.config.output_directory) {
                return Err(CiError::Message(
                    "original settlement receipt escapes its owned support output".into(),
                ));
            }
            custody.push(crate::windows_readiness_adapter::hold_artifact(
                &receipt.path,
                Some(&receipt.sha256),
                16 * 1024 * 1024,
            )?);
        }
        let _receipt_custody = validate_windows_settlement(&owner, &settled)?;
        crate::windows_readiness_adapter::observe_removed(
            &owner.config,
            &owner.removal,
            &directory.join("removal"),
            selection.cleanup,
        )?;
    } else {
        if let Some(settled) = recover_windows_settlement(&owner, selection.cleanup)? {
            let _receipts = validate_windows_settlement(&owner, &settled)?;
            crate::windows_readiness_adapter::observe_removed(
                &owner.config,
                &owner.removal,
                &directory.join("removal"),
                selection.cleanup,
            )?;
            persist(
                &destination.join("windows-support-settled.json"),
                &serde_json::to_vec(&settled)?,
            )?;
        } else {
            let receipts = settle_windows_support(&owner, &directory, selection.cleanup)?;
            let settled = WindowsSettlement {
                format: "memcordon.windows-original-settlement".into(),
                revision: 1,
                owner_sha256: artifacts::checksum(&record.bytes),
                job: owner.job.clone(),
                run_attempt: owner.run_attempt,
                cleanup_directory: directory.clone(),
                receipts,
            };
            let _receipts = validate_windows_settlement(&owner, &settled)?;
            persist(
                &destination.join("windows-support-settled.json"),
                &serde_json::to_vec(&settled)?,
            )?;
        }
    }
    record.verify()?;
    if Instant::now() >= selection.cleanup {
        return Err(CiError::Message(
            "original cleanup deadline exhausted before settlement custody completed".into(),
        ));
    }
    Ok(())
}

/// Continues publication only from actual successful native receipts. A missing
/// provider or path alone cannot establish an earlier recovery/uninstall.
#[cfg(windows)]
fn recover_windows_settlement(
    owner: &WindowsOriginalOwner,
    deadline: Instant,
) -> Result<Option<WindowsSettlement>> {
    for ordinal in 0..128 {
        if Instant::now() >= deadline {
            return Err(CiError::Message(
                "original cleanup deadline exhausted while locating native settlement receipts"
                    .into(),
            ));
        }
        let directory = owner
            .config
            .output_directory
            .join(format!("cleanup-{ordinal}"));
        let recovery = directory.join("recovery/cleanup.json");
        let removal = directory.join("removal/native-removal.json");
        if !recovery.try_exists()? || !removal.try_exists()? {
            continue;
        }
        let recovery_record = OwnedRecord::read(&recovery)?;
        let removal_record = OwnedRecord::read(&removal)?;
        for operation in 0..128 {
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "original cleanup deadline exhausted while binding native uninstall receipt"
                        .into(),
                ));
            }
            let uninstall = owner
                .config
                .output_directory
                .join(format!("package-uninstall-{operation}.json"));
            if !uninstall.try_exists()? {
                continue;
            }
            let uninstall_record = OwnedRecord::read(&uninstall)?;
            let capture: WindowsPackageCapture = uninstall_record.parse()?;
            if capture.status != Some(0) || capture.operation != "uninstall" {
                continue;
            }
            let settled = WindowsSettlement {
                format: "memcordon.windows-original-settlement".into(),
                revision: 1,
                owner_sha256: artifacts::checksum(&serde_json::to_vec(owner)?),
                job: owner.job.clone(),
                run_attempt: owner.run_attempt,
                cleanup_directory: directory.clone(),
                receipts: WindowsCleanupReceipts {
                    recovery: crate::windows_installed_cases::SelectedArtifact {
                        path: recovery.clone(),
                        sha256: artifacts::checksum(&recovery_record.bytes),
                    },
                    uninstall: crate::windows_installed_cases::SelectedArtifact {
                        path: uninstall,
                        sha256: artifacts::checksum(&uninstall_record.bytes),
                    },
                    removal: crate::windows_installed_cases::SelectedArtifact {
                        path: removal.clone(),
                        sha256: artifacts::checksum(&removal_record.bytes),
                    },
                },
            };
            let _receipts = validate_windows_settlement(owner, &settled)?;
            if Instant::now() >= deadline {
                return Err(CiError::Message("original cleanup deadline exhausted while validating native settlement receipts".into()));
            }
            return Ok(Some(settled));
        }
        return Err(CiError::Message("actual native removal exists without its successful original uninstall receipt; publication remains uncertain".into()));
    }
    Ok(None)
}

#[cfg(windows)]
fn validate_windows_settlement(
    owner: &WindowsOriginalOwner,
    settled: &WindowsSettlement,
) -> Result<Vec<OwnedRecord>> {
    if settled.format != "memcordon.windows-original-settlement"
        || settled.revision != 1
        || settled.owner_sha256 != artifacts::checksum(&serde_json::to_vec(owner)?)
        || settled.job != owner.job
        || settled.run_attempt != owner.run_attempt
    {
        return Err(CiError::Message(
            "native settlement original owner association differs".into(),
        ));
    }
    let cleanup_name = settled
        .cleanup_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CiError::Message("native cleanup directory name missing".into()))?;
    let cleanup_ordinal = cleanup_name
        .strip_prefix("cleanup-")
        .ok_or_else(|| CiError::Message("native cleanup directory stem differs".into()))?;
    let cleanup_number = cleanup_ordinal
        .parse::<u32>()
        .map_err(|error| CiError::Message(error.to_string()))?;
    if settled.cleanup_directory.parent() != Some(owner.config.output_directory.as_path())
        || cleanup_number >= 128
        || cleanup_number.to_string() != cleanup_ordinal
    {
        return Err(CiError::Message(
            "native cleanup directory is outside its original owned namespace".into(),
        ));
    }
    if settled.receipts.recovery.path != settled.cleanup_directory.join("recovery/cleanup.json")
        || settled.receipts.removal.path
            != settled
                .cleanup_directory
                .join("removal/native-removal.json")
        || settled.receipts.uninstall.path.parent() != Some(owner.config.output_directory.as_path())
    {
        return Err(CiError::Message(
            "original settlement receipt named destinations differ".into(),
        ));
    }
    let name = settled
        .receipts
        .uninstall
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CiError::Message("uninstall capture name missing".into()))?;
    let ordinal = name
        .strip_prefix("package-uninstall-")
        .and_then(|name| name.strip_suffix(".json"))
        .ok_or_else(|| {
            CiError::Message("uninstall capture is not an actual package receipt stem".into())
        })?;
    let number = ordinal
        .parse::<u32>()
        .map_err(|error| CiError::Message(error.to_string()))?;
    if number >= 128 || number.to_string() != ordinal {
        return Err(CiError::Message("uninstall capture ordinal differs".into()));
    }
    let mut records = Vec::new();
    for receipt in [
        &settled.receipts.recovery,
        &settled.receipts.uninstall,
        &settled.receipts.removal,
    ] {
        let record = OwnedRecord::read(&receipt.path)?;
        if artifacts::checksum(&record.bytes) != receipt.sha256 {
            return Err(CiError::Message(
                "original settlement byte hash differs".into(),
            ));
        }
        records.push(record);
    }
    let recovery: crate::windows_readiness_adapter::RecoveryCleanup = records[0].parse()?;
    if recovery.output_directory != settled.cleanup_directory.join("recovery")
        || recovery.deadline_exhausted
        || recovery.native_status != Some(0)
        || recovery.recovery.is_err()
        || recovery.native_quiescence.is_err()
        || recovery.artifacts.len() != 3
    {
        return Err(CiError::Message(
            "original successful recovery summary differs".into(),
        ));
    }
    let mut paths = std::collections::BTreeSet::new();
    for receipt in &recovery.artifacts {
        if receipt.path.parent() != Some(recovery.output_directory.as_path())
            || !paths.insert(receipt.path.clone())
        {
            return Err(CiError::Message(
                "raw recovery artifact destination duplicated or escaped".into(),
            ));
        }
        let record = OwnedRecord::read(&receipt.path)?;
        if artifacts::checksum(&record.bytes) != receipt.sha256 {
            return Err(CiError::Message(
                "raw recovery artifact bytes differ".into(),
            ));
        }
        records.push(record);
    }
    let invocation_path = recovery.output_directory.join("recovery-invocation.json");
    let stdout_path = recovery.output_directory.join("recovery.stdout.bin");
    let stderr_path = recovery.output_directory.join("recovery.stderr.bin");
    if paths
        != [invocation_path.clone(), stdout_path.clone(), stderr_path]
            .into_iter()
            .collect()
    {
        return Err(CiError::Message(
            "successful recovery raw artifact stems differ".into(),
        ));
    }
    let invocation: WindowsRecoveryInvocation = records
        .iter()
        .find(|record| record.path == invocation_path)
        .expect("checked invocation")
        .parse()?;
    let argv = invocation
        .argv_utf16
        .iter()
        .map(|argument| {
            String::from_utf16(argument).map_err(|error| CiError::Message(error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    if invocation.format != "memcordon.windows-native-recovery-invocation"
        || invocation.revision != 1
        || serde_json::to_vec(&invocation.cli)? != serde_json::to_vec(&owner.config.cli)?
        || serde_json::to_vec(&invocation.provider)? != serde_json::to_vec(&owner.config.provider)?
        || invocation.cwd != recovery.output_directory
        || !invocation.environment_cleared
        || !(100..=60000).contains(&invocation.command_budget_millis)
        || argv.len() != 3
        || argv[0] != "windows-recover"
        || argv[1] != "converge"
        || argv[2]
            != invocation
                .command_budget_millis
                .saturating_sub(100)
                .min(30000)
                .to_string()
    {
        return Err(CiError::Message(
            "actual recovery invocation differs from original selected CLI/provider".into(),
        ));
    }
    let inventory: memcordon_core::WindowsRecoveryInventoryV1 = records
        .iter()
        .find(|record| record.path == stdout_path)
        .expect("checked stdout")
        .parse()?;
    if !inventory.is_consistent()
        || inventory.provider_generation != owner.config.provider.generation.as_str()
        || inventory.executing != 0
        || inventory.incomplete_proof != 0
        || inventory.unacknowledged_outboxes != 0
        || inventory.ack_retirement_in_progress != 0
        || inventory.active_admissions != 0
        || inventory.quarantined != 0
    {
        return Err(CiError::Message(
            "actual original recovery inventory retains selected authority".into(),
        ));
    }
    let uninstall: WindowsPackageCapture = records[1].parse()?;
    if uninstall.operation != "uninstall"
        || uninstall.status != Some(0)
        || uninstall.stdout.len() > 16 * 1024 * 1024
        || uninstall.stderr.len() > 16 * 1024 * 1024
    {
        return Err(CiError::Message(
            "actual original uninstall capture differs".into(),
        ));
    }
    let intent = OwnedRecord::read(
        &settled
            .receipts
            .uninstall
            .path
            .with_extension("intent.json"),
    )?;
    let parsed: WindowsPackageIntent = intent.parse()?;
    if parsed.operation != "uninstall"
        || parsed.original_job != owner.job
        || parsed.original_attempt != owner.run_attempt
        || serde_json::to_vec(&parsed.agent)? != serde_json::to_vec(&owner.config.agent)?
    {
        return Err(CiError::Message(
            "actual uninstall intent does not belong to original measured owner".into(),
        ));
    }
    records.push(intent);
    let removal: WindowsRemovalReceipt = records[2].parse()?;
    let mut expected_paths = vec![
        owner.removal.binary_root.clone(),
        owner.removal.state_root.clone(),
        owner.removal.policy_root.clone(),
        owner.config.installed_agent.path.clone(),
        owner.config.installed_manifest.path.clone(),
    ];
    expected_paths.extend(
        owner
            .config
            .installed_components
            .iter()
            .map(|artifact| artifact.path.clone()),
    );
    expected_paths.sort();
    expected_paths.dedup();
    let mut services = crate::windows_owned_guardian::guardian_slot_names();
    services.extend(
        [
            memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,
            memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
            memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME,
        ]
        .map(str::to_owned),
    );
    if removal.format != "memcordon.windows-native-removal"
        || removal.revision != 1
        || removal.provider_generation != owner.config.provider.generation.as_str()
        || removal.absent_paths != expected_paths
        || removal.absent_services != services
        || !removal.fixture_processes_absent
        || !removal.installed_image_processes_absent
        || removal.native_component_census != "owned-package-image-names-no-live-candidate"
        || removal.service_observations.len() != services.len()
        || removal.path_observations.len() != expected_paths.len()
        || removal
            .service_observations
            .iter()
            .zip(&services)
            .any(|(observation, name)| {
                observation.service_name != *name
                    || observation.api != "OpenServiceW"
                    || observation.native_domain != "win32"
                    || observation.native_code != 1060
            })
        || removal
            .path_observations
            .iter()
            .zip(&expected_paths)
            .any(|(observation, path)| {
                observation.path != *path
                    || observation.native_domain != "win32"
                    || ![2, 3].contains(&observation.native_code)
            })
    {
        return Err(CiError::Message(
            "original native removal receipt layout/SCM/file observations differ".into(),
        ));
    }
    Ok(records)
}

#[cfg(windows)]
fn windows_package(
    owner: &WindowsOriginalOwner,
    operation: &str,
    deadline: Instant,
) -> Result<crate::windows_installed_cases::SelectedArtifact> {
    let budget = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(120));
    if budget.is_zero() {
        return Err(CiError::Message(
            "original support package cutoff exhausted".into(),
        ));
    }
    let capture = (0..128)
        .map(|ordinal| {
            owner
                .config
                .output_directory
                .join(format!("package-{operation}-{ordinal}.json"))
        })
        .find(|path| !path.exists())
        .ok_or_else(|| CiError::Message("support package receipt attempts exceed bound".into()))?;
    let intent = capture.with_extension("intent.json");
    let _intent = crate::windows_readiness_adapter::publish_receipt(
        &intent,
        &serde_json::to_vec(
            &serde_json::json!({"operation":operation,"agent":owner.config.agent,"original_job":owner.job,"original_attempt":owner.run_attempt}),
        )?,
    )?;
    let output = crate::command::CommandSpec::new(
        &owner.config.agent.path,
        &owner.config.output_directory,
        budget,
    )
    .args(["package", operation])
    .bounded_until(deadline)
    .output_quiet()?;
    let bytes = serde_json::to_vec(
        &serde_json::json!({"operation":operation,"status":output.status.code(),"stdout":output.stdout,"stderr":output.stderr}),
    )?;
    persist(&capture, &bytes)?;
    if !output.status.success() {
        return Err(CiError::Message(format!(
            "actual owned support package {operation} failed"
        )));
    }
    Ok(crate::windows_installed_cases::SelectedArtifact {
        path: capture,
        sha256: artifacts::checksum(&bytes),
    })
}

#[cfg(windows)]
fn settle_windows_support(
    owner: &WindowsOriginalOwner,
    directory: &Path,
    cleanup: Instant,
) -> Result<WindowsCleanupReceipts> {
    let mut errors = Vec::new();
    match crate::windows_readiness_adapter::recover_and_observe_quiescence(
        &owner.config,
        &directory.join("recovery"),
        cleanup,
    ) {
        Ok(observed) => {
            if let Err(error) = observed.recovery {
                errors.push(error);
            }
            if let Err(error) = observed.native_quiescence {
                errors.push(error);
            }
        }
        Err(error) => errors.push(error.to_string()),
    }
    // Retained authority forbids deleting provider state. A failed recovery is
    // preserved for the next original-deadline retry, rather than uninstalled.
    if !errors.is_empty() {
        return Err(CiError::Message(errors.join("; ")));
    }
    let uninstall = windows_package(owner, "uninstall", cleanup);
    if let Err(error) = &uninstall {
        errors.push(error.to_string());
    }
    let removal = crate::windows_readiness_adapter::observe_removed(
        &owner.config,
        &owner.removal,
        &directory.join("removal"),
        cleanup,
    );
    if let Err(error) = &removal {
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        let path = directory.join("recovery/cleanup.json");
        let held = crate::windows_readiness_adapter::hold_artifact(&path, None, 16 * 1024 * 1024)?;
        Ok(WindowsCleanupReceipts {
            recovery: crate::windows_installed_cases::SelectedArtifact {
                path,
                sha256: held.sha256,
            },
            uninstall: uninstall.expect("checked real uninstall capture"),
            removal: removal.expect("checked native removal").receipt,
        })
    } else {
        Err(CiError::Message(errors.join("; ")))
    }
}

#[cfg(unix)]
struct DirectoryCustody {
    paths: Vec<PathBuf>,
    handles: Vec<File>,
}
#[cfg(unix)]
impl DirectoryCustody {
    fn acquire(path: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        if !path.is_absolute() {
            return Err(CiError::Message(
                "native directory custody requires absolute path".into(),
            ));
        }
        let paths = path
            .ancestors()
            .map(Path::to_path_buf)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        let mut handles: Vec<File> = Vec::new();
        for path in &paths {
            let held = if let Some(parent) = handles.last() {
                File::from(
                    rustix::fs::openat(
                        parent,
                        path.file_name().ok_or_else(|| {
                            CiError::Message("native directory component absent".into())
                        })?,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|error| CiError::Message(error.to_string()))?,
                )
            } else {
                File::from(
                    rustix::fs::open(
                        "/",
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|error| CiError::Message(error.to_string()))?,
                )
            };
            let native = held.metadata()?;
            let named = std::fs::symlink_metadata(path)?;
            if !named.is_dir()
                || !native.is_dir()
                || (named.dev(), named.ino()) != (native.dev(), native.ino())
                || (native.mode() & 0o022 != 0
                    && !(native.uid() == 0 && native.mode() & libc::S_ISVTX != 0))
            {
                return Err(CiError::Message(
                    "native source/destination ancestry is writable or replaced".into(),
                ));
            }
            handles.push(held);
        }
        Ok(Self { paths, handles })
    }
    fn verify(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let mut fresh: Vec<File> = Vec::new();
        for (path, held) in self.paths.iter().zip(&self.handles) {
            let current = if let Some(parent) = fresh.last() {
                File::from(
                    rustix::fs::openat(
                        parent,
                        path.file_name().ok_or_else(|| {
                            CiError::Message("native named directory leaf absent".into())
                        })?,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|error| CiError::Message(error.to_string()))?,
                )
            } else {
                File::from(
                    rustix::fs::open(
                        "/",
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|error| CiError::Message(error.to_string()))?,
                )
            };
            let actual = current.metadata()?;
            let native = held.metadata()?;
            if !actual.is_dir()
                || !native.is_dir()
                || (actual.dev(), actual.ino(), actual.uid(), actual.mode())
                    != (native.dev(), native.ino(), native.uid(), native.mode())
                || (native.mode() & 0o022 != 0
                    && !(native.uid() == 0 && native.mode() & libc::S_ISVTX != 0))
            {
                return Err(CiError::Message(
                    "native retained directory pathname identity changed".into(),
                ));
            }
            fresh.push(current);
        }
        Ok(())
    }
    fn create_confined(root: &Path, relative: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let mut custody = Self::acquire(root)?;
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(CiError::Message(
                    "native relative artifact directory is not confined".into(),
                ));
            };
            custody.verify()?;
            let parent = custody.handles.last().expect("held native root");
            let flags = rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC;
            let fd = match rustix::fs::openat(parent, name, flags, rustix::fs::Mode::empty()) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) => {
                    match rustix::fs::mkdirat(parent, name, rustix::fs::Mode::from_raw_mode(0o755))
                    {
                        Ok(()) => {}
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(error) => return Err(CiError::Message(error.to_string())),
                    }
                    parent.sync_all()?;
                    rustix::fs::openat(parent, name, flags, rustix::fs::Mode::empty())
                        .map_err(|error| CiError::Message(error.to_string()))?
                }
                Err(error) => return Err(CiError::Message(error.to_string())),
            };
            let file = File::from(fd);
            let metadata = file.metadata()?;
            if !metadata.is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o022 != 0
            {
                return Err(CiError::Message(
                    "native artifact directory is not owned protected custody".into(),
                ));
            }
            let path = custody.paths.last().expect("native root path").join(name);
            custody.paths.push(path);
            custody.handles.push(file);
        }
        custody.verify()?;
        Ok(custody)
    }
    fn create_fresh(path: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let parent_path = path
            .parent()
            .ok_or_else(|| CiError::Message("fresh directory parent absent".into()))?;
        let name = path
            .file_name()
            .ok_or_else(|| CiError::Message("fresh directory name absent".into()))?;
        let mut parent = Self::acquire(parent_path)?;
        parent.verify()?;
        let parent_fd = parent.handles.last().expect("held fresh directory parent");
        rustix::fs::mkdirat(parent_fd, name, rustix::fs::Mode::from_raw_mode(0o755))
            .map_err(|error| CiError::Message(error.to_string()))?;
        let child = rustix::fs::openat(
            parent_fd,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let child = File::from(child);
        let metadata = child.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(CiError::Message(
                "fresh directory native owner/protection differs before chmod".into(),
            ));
        }
        rustix::fs::fchmod(&child, rustix::fs::Mode::from_raw_mode(0o755))
            .map_err(|error| CiError::Message(error.to_string()))?;
        parent_fd.sync_all()?;
        parent.verify()?;
        parent.paths.push(path.to_owned());
        parent.handles.push(child);
        parent.verify()?;
        Ok(parent)
    }
}

fn empty_cell(root: &Path, selection: &Selection) -> Result<CellEvidence> {
    let index = crate::consumer_readiness_ledger::initialize(
        &root.join("ci/consumer-readiness-v1.toml"),
        selection.identity.clone(),
    )
    .map_err(CiError::Message)?;
    Ok(CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 1,
        identity: selection.identity.clone(),
        key: ProductKey {
            target: selection.target.clone(),
            channel: "candidate-native".into(),
        },
        product: None,
        component_build: None,
        records: index
            .records
            .into_iter()
            .filter(|record| record.key.target == selection.target && record.key.channel.is_none())
            .collect(),
        artifacts: Vec::new(),
        cleanup_failures: Vec::new(),
        cache_quiescent: false,
    })
}

fn prepare_build(
    root: &Path,
    destination: &Path,
    prefix: &Path,
    selection: &Selection,
) -> Result<(ComponentBuild, Artifact, Vec<Artifact>)> {
    let mut retained = Vec::new();
    let host_root = root.join(".release/native-components");
    let compiler = retain_file(
        &host_root.join(&selection.host.compiler_artifact),
        destination,
        &prefix.join("roles/compiler/native-compiler.bin"),
        Some(&selection.host.compiler_sha256),
        512 * 1024 * 1024,
    )?;
    if compiler.length != selection.host.compiler_length {
        return Err(CiError::Message(
            "original copied native compiler length differs".into(),
        ));
    }
    super::target::validate_executable(
        &artifacts::read_file(&destination.join(&compiler.path))?,
        &selection.target,
    )?;
    retained.push(compiler);
    for name in [
        "native-host.json",
        "acquisition-origin.json",
        "measured-harnesses.json",
        selection.host.compiler_path_stdout.as_str(),
        selection.host.compiler_path_stderr.as_str(),
        selection.host.compiler_identity_stdout.as_str(),
        selection.host.compiler_identity_stderr.as_str(),
    ] {
        retained.push(retain_file(
            &host_root.join(name),
            destination,
            &prefix.join("roles/compiler").join(name),
            None,
            16 * 1024 * 1024,
        )?);
    }
    retained.push(retain_file(
        &root.join(".release/native-operation-deadline.json"),
        destination,
        &prefix.join("roles/compiler/native-operation-deadline.json"),
        None,
        16 * 1024 * 1024,
    )?);
    #[cfg(windows)]
    for name in [
        "internal-actor-build.json",
        "runtime-manifest.json",
        "cargo-output.jsonl",
        "cargo-stderr.bin",
        "cargo-status.json",
    ] {
        retained.push(retain_file(
            &host_root.join("actor").join(name),
            destination,
            &prefix.join("roles/actor").join(name),
            None,
            64 * 1024 * 1024,
        )?);
    }
    let path_record = OwnedRecord::read(&host_root.join(&selection.host.compiler_path_stdout))?;
    if std::str::from_utf8(&path_record.bytes).ok().map(str::trim)
        != selection.host.compiler.to_str()
    {
        return Err(CiError::Message(
            "actual compiler locator bytes differ from acquired path".into(),
        ));
    }
    let identity_record =
        OwnedRecord::read(&host_root.join(&selection.host.compiler_identity_stdout))?;
    if std::str::from_utf8(&identity_record.bytes)
        .ok()
        .map(str::trim)
        != Some(selection.host.host.toolchain_identity.as_str())
    {
        return Err(CiError::Message(
            "actual compiler verbose bytes differ from acquired host".into(),
        ));
    }
    let source = source_archive(root, selection, destination, &prefix.join("source.tar"))?;
    retained.push(source.clone());
    let mut operational = None;
    let mut parser = None;
    for role in &selection.roles.roles {
        let executable = prefix
            .join("roles")
            .join(&role.role)
            .join(super::target::binary_name("harness", &selection.target));
        let artifact = retain_file(
            &role.executable,
            destination,
            &executable,
            Some(&role.sha256),
            512 * 1024 * 1024,
        )?;
        let measured = artifacts::read_file(&destination.join(&executable))?;
        super::target::validate_executable(&measured, &selection.target)?;
        if role.role == "operational" {
            operational = Some(artifact.path.clone());
        } else {
            parser = Some(artifact.path.clone());
        }
        retained.push(artifact);
        for (name, path) in [
            ("cargo-output.jsonl", &role.compiler_output),
            ("cargo-stderr.bin", &role.compiler_errors),
        ] {
            retained.push(retain_file(
                path,
                destination,
                &prefix.join("roles").join(&role.role).join(name),
                None,
                64 * 1024 * 1024,
            )?);
        }
    }
    let recipe = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.consumer-readiness.original-native-recipe","revision":1,
        "recipe_id":"original-native-components-v1","source_commit":selection.identity.source_commit,
        "source_tree_sha256":selection.identity.source_tree_sha256,"native_target":selection.target,
        "measured_roles":serde_json::from_slice::<serde_json::Value>(&artifacts::read_file(&root.join(".release/native-components/measured-harnesses.json"))?)?}),
    )?;
    let relative = prefix.join("recipe.json");
    persist(&destination.join(&relative), &recipe)?;
    let recipe_hash = artifacts::checksum(&recipe);
    retained.push(Artifact {
        path: relative
            .to_str()
            .expect("confined recipe path")
            .replace('\\', "/"),
        length: recipe.len() as u64,
        sha256: recipe_hash.clone(),
    });
    Ok((
        ComponentBuild {
            target: selection.target.clone(),
            source_commit: selection.identity.source_commit.clone(),
            source_tree_sha256: selection.identity.source_tree_sha256.clone(),
            host: selection.host.host.clone(),
            recipe_id: "original-native-components-v1".into(),
            recipe_sha256: recipe_hash,
            executable: operational
                .ok_or_else(|| CiError::Message("operational native role absent".into()))?,
            instrumented: true,
            actor_executable: None,
            parser_executable: parser,
        },
        source,
        retained,
    ))
}

fn merge_rows(
    cell: &mut CellEvidence,
    records: Vec<memcordon_readiness_verifier::CaseRecord>,
    artifacts: Vec<Artifact>,
) -> Result<()> {
    for record in records {
        let target = cell
            .records
            .iter_mut()
            .find(|candidate| candidate.key == record.key)
            .ok_or_else(|| {
                CiError::Message("native normalizer emitted undeclared component key".into())
            })?;
        if target.state != memcordon_readiness_verifier::CaseState::NotRun {
            return Err(CiError::Message(
                "native component key executed twice".into(),
            ));
        }
        *target = record;
    }
    for artifact in artifacts {
        if let Some(previous) = cell
            .artifacts
            .iter()
            .find(|previous| previous.path == artifact.path)
        {
            if previous.length != artifact.length || previous.sha256 != artifact.sha256 {
                return Err(CiError::Message(
                    "native artifact association differs across recipes".into(),
                ));
            }
        } else {
            cell.artifacts.push(artifact);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn acquire_linux_role(
    selection: &Selection,
    name: &str,
) -> Result<native_component_harness::MeasuredHarness> {
    let role = selection
        .roles
        .roles
        .iter()
        .find(|role| role.role == name)
        .ok_or_else(|| CiError::Message("original measured role absent".into()))?;
    if artifacts::checksum(&artifacts::read_file(&role.executable)?) != role.sha256 {
        return Err(CiError::Message(
            "acquired native executable hash changed".into(),
        ));
    }
    Ok(native_component_harness::MeasuredHarness {
        executable: role.executable.clone(),
        sha256: role.sha256.clone(),
        compiler_output: role.compiler_output.clone(),
        compiler_errors: role.compiler_errors.clone(),
    })
}

/// Executes the two measured Windows harness roles without borrowing an
/// installed-product lifetime. Every partial assessment remains in the cell.
#[cfg(windows)]
fn execute_windows_harnesses(
    destination: &Path,
    prefix: &Path,
    selection: &Selection,
    source: &Artifact,
    cell: &mut CellEvidence,
) -> Result<()> {
    use crate::windows_installed_cases::SelectedArtifact;
    use crate::windows_readiness_adapter::WindowsComponentAdapterContext;
    let context = WindowsComponentAdapterContext {
        identity: selection.identity.clone(),
        destination: destination.to_owned(),
        fixture_source: SelectedArtifact {
            path: destination.join(&source.path),
            sha256: source.sha256.clone(),
        },
    };
    for name in ["operational", "parser"] {
        let role = selection
            .roles
            .roles
            .iter()
            .find(|role| role.role == name)
            .ok_or_else(|| {
                CiError::Message("original Windows measured harness role absent".into())
            })?;
        // Keep the measured image and every named ancestor throughout native
        // execution and projection, rather than merely trusting its pathname.
        let held = crate::windows_readiness_adapter::hold_artifact(
            &role.executable,
            Some(&role.sha256),
            512 * 1024 * 1024,
        )?;
        let input = crate::windows_readiness_native_tests::NativeTestInput {
            run_id: selection.identity.run_id.clone(),
            recipe_id: "original-native-components-v1".into(),
            native_target: selection.target.clone(),
            executable: SelectedArtifact {
                path: role.executable.clone(),
                sha256: role.sha256.clone(),
            },
            output_directory: destination.join(format!("native-{name}-observations")),
            artifact_prefix: prefix.join("tests").join(name),
            work_deadline: Some(selection.work),
        };
        let mut observations = Vec::new();
        let execution = if name == "parser" {
            crate::windows_readiness_native_tests::run_parser(&input, &mut observations)
        } else {
            crate::windows_readiness_native_tests::run(&input, &mut observations)
        };
        let normalization = crate::windows_readiness_adapter::normalize_native_tests(
            &context,
            &input,
            &observations,
        );
        if let Ok(rows) = normalization.as_ref() {
            merge_rows(cell, rows.records.clone(), rows.artifacts.clone())?;
        }
        crate::windows_readiness_adapter::verify_named_artifact(&held, &role.executable)?;
        if let Err(error) = execution {
            cell.cleanup_failures
                .push(format!("native {name} harness: {error}"));
        }
        if let Err(error) = normalization {
            cell.cleanup_failures
                .push(format!("native {name} projection: {error}"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_linux_retirement(root: &Path, destination: &Path, bytes: &[u8]) -> Result<()> {
    let path = root.join(".release/native-administrator-retirement.json");
    persist_unix(&path, bytes, 0o600)?;
    if crate::linux_consumer_readiness::measured(&path, 16 * 1024 * 1024)
        .map_err(CiError::Message)?
        != bytes
    {
        return Err(CiError::Message(
            "native administrator retirement original readback differs".into(),
        ));
    }
    persist(&destination.join("administrator-retirement.json"), bytes)
}

#[cfg(target_os = "linux")]
fn cleanup_linux(root: &Path, destination: &Path, selection: &Selection) -> Result<()> {
    use super::linux_native_component::NativeAdminScope;
    let prefix = Path::new(&selection.target)
        .join("candidate-native")
        .join("components");
    let prefix_text = prefix.to_str().expect("fixed native artifact prefix");
    let receipt = root.join(".release/native-administrator-retirement.json");
    let scope_recipe = selection.scope_recipe();
    if std::fs::symlink_metadata(&receipt).is_ok() {
        return NativeAdminScope::observe_retired_scope(
            root,
            &selection.identity,
            &selection.target,
            &scope_recipe,
            prefix_text,
            selection.deadline.work_deadline_unix_millis,
            selection.deadline.cleanup_deadline_unix_millis,
            &receipt,
        )
        .map(|_| ());
    }
    let mut scope = NativeAdminScope::recover_owned_scope(
        root,
        &selection.identity,
        &selection.target,
        &scope_recipe,
        prefix_text,
        selection.deadline.work_deadline_unix_millis,
        selection.deadline.cleanup_deadline_unix_millis,
        selection.cleanup,
    )?;
    let mut errors = Vec::new();
    let settled = match scope.settle(selection.cleanup) {
        Ok(()) => true,
        Err(error) => {
            errors.push(error.to_string());
            false
        }
    };
    errors.extend(scope.failures().iter().cloned());
    let recovery = (0..128)
        .map(|ordinal| destination.join(format!("recovery-raw-{ordinal}")))
        .find(|path| !path.exists())
        .ok_or_else(|| {
            CiError::Message("native component recovery artifact retries exceed bound".into())
        })?;
    let _recovery_custody = DirectoryCustody::create_fresh(&recovery)?;
    let mut copied = Vec::new();
    let mut pending = vec![(scope.outputs().to_path_buf(), PathBuf::new())];
    let mut visited = 0usize;
    while let Some((directory, relative)) = pending.pop() {
        if Instant::now() >= selection.cleanup {
            errors.push(
                "original native cleanup cutoff exhausted while copying retained evidence".into(),
            );
            break;
        }
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let relative = relative.join(entry.file_name());
            visited = visited
                .checked_add(1)
                .ok_or_else(|| CiError::Message("native recovery inventory overflow".into()))?;
            if visited > 8192 {
                return Err(CiError::Message(
                    "native recovery artifact inventory exceeds bound; scope retained".into(),
                ));
            }
            if metadata.is_dir() {
                pending.push((entry.path(), relative));
            } else if metadata.is_file() {
                copied.push(retain_file(
                    &entry.path(),
                    &recovery,
                    &relative,
                    None,
                    512 * 1024 * 1024,
                )?);
            } else {
                return Err(CiError::Message(
                    "native recovery source contains unresolved unsafe object; scope retained"
                        .into(),
                ));
            }
        }
    }
    persist(
        &recovery.join("recovery-observation.json"),
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.consumer-readiness.native-recovery-observation","revision":1,
        "identity":selection.identity,"native_target":selection.target,"recipe_id":"original-native-components-v1",
        "reconstructed_capture":false,"artifacts":copied,"errors":errors}))?,
    )?;
    // Missing native capture can be recorded but cannot be repaired into a passed test.
    // Preserve the privileged scope until all retained bytes have been copied.
    if !settled || !pending.is_empty() || Instant::now() >= selection.cleanup {
        return Err(CiError::Message(errors.join("; ")));
    }
    let retired = scope.retire(selection.cleanup)?;
    publish_linux_retirement(root, destination, &serde_json::to_vec(&retired)?)?;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CiError::Message(errors.join("; ")))
    }
}
