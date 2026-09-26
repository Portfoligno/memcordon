//! Reviewed final-public target mode embedded in the B-inventoried agent.
//! The target is launched by ordinary authenticated V2 PrivateLaunch under
//! the private filter. Its stdout is a bounded claim, never kernel authority;
//! the installed provider and independent BPF capture must join every child.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use memcordon_core::workload_evidence_v2::PrivateTcpCheckpointV2;
use memcordon_core::{BoundedText, DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::private_attempt::PrivateAttemptRecordV4;
use super::private_attempt::ProcessIdentityV4;

const ARM32_HELPER: &str = "/usr/libexec/memcordon-arm32-abi-helper";
const ARM_AUDIT_ARCH: u32 = 0x4000_0028;
const X86_AUDIT_ARCH: u32 = 0xc000_003e;
const I386_AUDIT_ARCH: u32 = 0x4000_0003;
const X32_BIT: u32 = 0x4000_0000;
const CHILD_LIMIT: Duration = Duration::from_secs(5);
const JOURNAL_ROOT: &str = "/var/lib/memcordon/sealed/private-public-abi-filtered";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilteredChildV1 {
    branch: String,
    pid: u32,
    start_time_ticks: u64,
    audit_arch: u32,
    syscall_number: u32,
    terminal_signal: i32,
    helper_device: Option<u64>,
    helper_inode: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilteredTargetReportV1 {
    schema_version: u8,
    evidence_scope: String,
    challenge: DiagnosticSha256,
    target_pid: u32,
    target_start_time_ticks: u64,
    target_uid: u32,
    target_gid: u32,
    no_new_privs: bool,
    seccomp_mode: u32,
    seccomp_filters: u32,
    native_getpid: u32,
    children: Vec<FilteredChildV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedFilteredAbiV1 {
    schema_version: u8,
    selector: String,
    evidence_scope: String,
    result_key: DiagnosticSha256,
    challenge: DiagnosticSha256,
    boot_id: String,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    attempt_id: String,
    target_pid: u32,
    target_start_time_ticks: u64,
    checkpoint_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    target_report_sha256: DiagnosticSha256,
    helper_device: Option<u64>,
    helper_inode: Option<u64>,
}

#[derive(Clone, Copy)]
enum Branch {
    X32,
    I386,
    Arm32,
}

impl Branch {
    fn name(self) -> &'static str {
        match self {
            Self::X32 => "x32",
            Self::I386 => "i386",
            Self::Arm32 => "arm32",
        }
    }

    fn audit_arch(self) -> u32 {
        match self {
            Self::X32 => X86_AUDIT_ARCH,
            Self::I386 => I386_AUDIT_ARCH,
            Self::Arm32 => ARM_AUDIT_ARCH,
        }
    }

    fn syscall_number(self) -> u32 {
        match self {
            Self::X32 => libc::SYS_getpid as u32 | X32_BIT,
            Self::I386 | Self::Arm32 => 20,
        }
    }
}

fn validate_branch_claims(
    report: &FilteredTargetReportV1,
    target: &ProcessIdentityV4,
    helper: Option<(u64, u64)>,
) -> Result<(), String> {
    let expected: &[Branch] = if cfg!(target_arch = "x86_64") {
        &[Branch::X32, Branch::I386]
    } else if cfg!(target_arch = "aarch64") {
        &[Branch::Arm32]
    } else {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: native ABI differs".into());
    };
    if report.target_pid != target.pid
        || report.target_start_time_ticks != target.start_time
        || report.target_uid == 0
        || report.target_gid == 0
        || !report.no_new_privs
        || report.seccomp_mode != 2
        || report.seccomp_filters < 2
        || report.native_getpid != target.pid
        || report.children.len() != expected.len()
    {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: target branch context differs".into());
    }
    let mut seen = std::collections::HashSet::new();
    for (branch, child) in expected.iter().zip(&report.children) {
        if child.branch != branch.name()
            || child.pid == 0
            || child.pid == target.pid
            || !seen.insert(child.pid)
            || child.start_time_ticks == 0
            || child.audit_arch != branch.audit_arch()
            || child.syscall_number != branch.syscall_number()
            || child.terminal_signal != libc::SIGSYS
            || child.helper_device != helper.map(|identity| identity.0)
            || child.helper_inode != helper.map(|identity| identity.1)
        {
            return Err("MCSEALED-PUBLIC-ABI-FILTERED: child branch differs".into());
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_branch_claims_for_test(
    bytes: &[u8],
    target_pid: u32,
    target_start_time_ticks: u64,
    helper: Option<(u64, u64)>,
) -> Result<(), String> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let report: FilteredTargetReportV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    validate_branch_claims(
        &report,
        &ProcessIdentityV4 {
            pid: target_pid,
            start_time: target_start_time_ticks,
        },
        helper,
    )
}

/// This mode is not a package/control verb: only an approved V2 entrypoint
/// may execute it. The copied image's exact SHA, path, argv and plan digest
/// must be pinned by registry, provider H1 and final-public intent.
pub(crate) fn run(challenge_hex: &str) -> Result<(), String> {
    let challenge =
        DiagnosticSha256::try_from(BoundedText::new(challenge_hex).map_err(str::to_owned)?)
            .map_err(str::to_owned)?;
    if challenge.bytes() == &[0; 32]
        || unsafe { libc::getuid() } == 0
        || unsafe { libc::getgid() } == 0
    {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: nonroot challenge differs".into());
    }
    let (no_new_privs, seccomp_mode, seccomp_filters) = read_filter_state()?;
    if !no_new_privs || seccomp_mode != 2 || seccomp_filters < 2 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: inherited private filter absent".into());
    }
    if fs::read_dir("/proc/self/task")
        .map_err(|error| error.to_string())?
        .count()
        != 1
    {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: target is multithreaded".into());
    }
    let self_pid = unsafe { libc::getpid() };
    // The installed private filter intentionally does not admit pidfd_open.
    // This target claim therefore reads /proc while its own task is live;
    // the provider owns the target pidfd and BPF must independently join it.
    let identity = ProcessIdentityV4 {
        pid: self_pid as u32,
        start_time: super::envelope::process_start_time(self_pid)?,
    };
    if identity.start_time == 0 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: target start time absent".into());
    }
    let native = unsafe { libc::syscall(libc::SYS_getpid) };
    if native != i64::from(identity.pid) {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: native getpid control differs".into());
    }
    let helper = if cfg!(target_arch = "aarch64") {
        Some(open_arm32_helper()?)
    } else {
        None
    };
    let branches: &[Branch] = if cfg!(target_arch = "x86_64") {
        &[Branch::X32, Branch::I386]
    } else if cfg!(target_arch = "aarch64") {
        &[Branch::Arm32]
    } else {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: unsupported native ABI".into());
    };
    let mut children = Vec::with_capacity(branches.len());
    for branch in branches {
        children.push(run_child(*branch, helper.as_ref())?);
    }
    let report = FilteredTargetReportV1 {
        schema_version: 1,
        evidence_scope: "filtered-public-target-claims-require-kernel-join".into(),
        challenge,
        target_pid: identity.pid,
        target_start_time_ticks: identity.start_time,
        target_uid: unsafe { libc::getuid() },
        target_gid: unsafe { libc::getgid() },
        no_new_privs,
        seccomp_mode,
        seccomp_filters,
        native_getpid: native as u32,
        children,
    };
    let bytes = serde_json::to_vec(&report).map_err(|error| error.to_string())?;
    if bytes.len() > 4096 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: target report exceeds bound".into());
    }
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Service-side custody after target/cgroup settlement but before durable V4
/// removal. The target report is a claim; BPF must independently authenticate
/// fork, compat syscall KILL, exact tasks and reap before P may use it.
pub(crate) fn persist_protected_report(
    record: &PrivateAttemptRecordV4,
    bytes: &[u8],
) -> Result<(), String> {
    let Some(binding) = super::private_public_provider::abi_filtered_binding_for_attempt(
        record.attempt_id.as_str(),
    )?
    else {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: provider reservation absent".into());
    };
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: protected report bound differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let report: FilteredTargetReportV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let challenge = DiagnosticSha256::try_from(
        BoundedText::new(binding.challenge.as_str()).map_err(str::to_owned)?,
    )
    .map_err(str::to_owned)?;
    let target = record.target.as_ref().ok_or("ABI target identity absent")?;
    let checkpoint = record.checkpoint.as_ref().ok_or("ABI checkpoint absent")?;
    if serde_json::to_vec(&report).map_err(|error| error.to_string())? != bytes
        || report.schema_version != 1
        || report.evidence_scope != "filtered-public-target-claims-require-kernel-join"
        || report.challenge != challenge
    {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: protected target claim differs".into());
    }
    let helper_metadata = if cfg!(target_arch = "aarch64") {
        Some(fs::symlink_metadata(ARM32_HELPER).map_err(|error| error.to_string())?)
    } else {
        None
    };
    validate_branch_claims(
        &report,
        target,
        helper_metadata
            .as_ref()
            .map(|entry| (entry.dev(), entry.ino())),
    )?;
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    if binding.installation_epoch != *lease.generation_digest()
        || binding.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
        || checkpoint.filter_digest != *lease.filter_digest()
    {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: H1/filter custody differs".into());
    }
    let boot =
        fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| error.to_string())?;
    super::attempt::secure_state_root()?;
    let root = Path::new(JOURNAL_ROOT);
    if !root.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root)
            .map_err(|error| error.to_string())?;
    }
    let root_meta = fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if !root_meta.is_dir() || root_meta.uid() != 0 || root_meta.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: protected root differs".into());
    }
    let path = root.join(String::from(binding.result_key.clone()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| error.to_string())?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| error.to_string())?;
    super::private_release_alt_abi_raw::write_immutable(
        &dir,
        "target-report.bin",
        "target-report.bin.new",
        bytes,
    )?;
    if record.checkpoint_digest.as_ref() != Some(&checkpoint.canonical_digest()?) {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: durable checkpoint digest differs".into());
    }
    let checkpoint_bytes = serde_json::to_vec(checkpoint).map_err(|error| error.to_string())?;
    if checkpoint_bytes.is_empty() || checkpoint_bytes.len() > 4096 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: checkpoint leaf bound differs".into());
    }
    super::private_release_alt_abi_raw::write_immutable(
        &dir,
        "checkpoint.json",
        "checkpoint.json.new",
        &checkpoint_bytes,
    )?;
    let protected = ProtectedFilteredAbiV1 {
        schema_version: 1,
        selector: "private_tcp::abi_alternate_entry_denied".into(),
        evidence_scope: "service-captured-filtered-target-stdout".into(),
        result_key: binding.result_key,
        challenge,
        boot_id: boot.trim().into(),
        installation_epoch: binding.installation_epoch,
        active_h1_receipt_sha256: binding.active_h1_receipt_sha256,
        attempt_id: record.attempt_id.as_str().into(),
        target_pid: target.pid,
        target_start_time_ticks: target.start_time,
        checkpoint_sha256: record
            .checkpoint_digest
            .clone()
            .ok_or("ABI checkpoint digest absent")?,
        filter_sha256: checkpoint.filter_digest.clone(),
        target_report_sha256: hash_bytes(bytes),
        helper_device: helper_metadata.as_ref().map(MetadataExt::dev),
        helper_inode: helper_metadata.as_ref().map(MetadataExt::ino),
    };
    let encoded = serde_json::to_vec(&protected).map_err(|error| error.to_string())?;
    super::private_release_alt_abi_raw::write_immutable(
        &dir,
        "filtered.json",
        "filtered.json.new",
        &encoded,
    )?;
    lease.revalidate_release_boundary()
}

/// Detached service journal readback, called from provider completion and the
/// fixed root command. It cannot itself authorize a launch or treat target
/// stdout as a kernel observation.
pub(crate) fn verify_protected_report(
    key: &DiagnosticSha256,
    challenge_hex: &str,
    attempt_id: &str,
    target: &ProcessIdentityV4,
) -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: detached root required".into());
    }
    super::attempt::secure_state_root()?;
    let root = Path::new(JOURNAL_ROOT);
    let root_meta = fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if !root_meta.is_dir() || root_meta.uid() != 0 || root_meta.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: detached journal root differs".into());
    }
    let path = root.join(String::from(key.clone()));
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| error.to_string())?;
    let meta = dir.metadata().map_err(|error| error.to_string())?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: detached journal case differs".into());
    }
    let report_bytes = super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "target-report.bin",
        "target-report.bin.new",
    )?;
    let wrapper_bytes = super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "filtered.json",
        "filtered.json.new",
    )?;
    let checkpoint_bytes = super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "checkpoint.json",
        "checkpoint.json.new",
    )?;
    if report_bytes.is_empty()
        || report_bytes.len() > 4096
        || wrapper_bytes.is_empty()
        || wrapper_bytes.len() > 4096
    {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: detached leaf bound differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&wrapper_bytes)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&checkpoint_bytes)?;
    let report: FilteredTargetReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let wrapper: ProtectedFilteredAbiV1 =
        serde_json::from_slice(&wrapper_bytes).map_err(|error| error.to_string())?;
    let checkpoint: PrivateTcpCheckpointV2 =
        serde_json::from_slice(&checkpoint_bytes).map_err(|error| error.to_string())?;
    let challenge =
        DiagnosticSha256::try_from(BoundedText::new(challenge_hex).map_err(str::to_owned)?)
            .map_err(str::to_owned)?;
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    let boot =
        fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| error.to_string())?;
    let helper = if cfg!(target_arch = "aarch64") {
        Some(fs::symlink_metadata(ARM32_HELPER).map_err(|error| error.to_string())?)
    } else {
        None
    };
    if serde_json::to_vec(&report).map_err(|error| error.to_string())? != report_bytes
        || serde_json::to_vec(&wrapper).map_err(|error| error.to_string())? != wrapper_bytes
        || wrapper.schema_version != 1
        || wrapper.selector != "private_tcp::abi_alternate_entry_denied"
        || wrapper.evidence_scope != "service-captured-filtered-target-stdout"
        || wrapper.result_key != *key
        || wrapper.challenge != challenge
        || wrapper.boot_id != boot.trim()
        || wrapper.installation_epoch != *lease.generation_digest()
        || wrapper.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
        || wrapper.attempt_id != attempt_id
        || wrapper.target_pid != target.pid
        || wrapper.target_start_time_ticks != target.start_time
        || wrapper.filter_sha256 != *lease.filter_digest()
        || wrapper.target_report_sha256 != hash_bytes(&report_bytes)
        || serde_json::to_vec(&checkpoint).map_err(|error| error.to_string())? != checkpoint_bytes
        || checkpoint.canonical_digest()? != wrapper.checkpoint_sha256
        || checkpoint.filter_digest != wrapper.filter_sha256
        || wrapper.helper_device != helper.as_ref().map(MetadataExt::dev)
        || wrapper.helper_inode != helper.as_ref().map(MetadataExt::ino)
        || report.schema_version != 1
        || report.evidence_scope != "filtered-public-target-claims-require-kernel-join"
        || report.challenge != challenge
    {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: detached journal binding differs".into());
    }
    validate_branch_claims(
        &report,
        target,
        helper.as_ref().map(|entry| (entry.dev(), entry.ino())),
    )?;
    lease.revalidate_release_boundary()?;
    String::from_utf8(wrapper_bytes).map_err(|error| error.to_string())
}

fn read_filter_state() -> Result<(bool, u32, u32), String> {
    let status = fs::read_to_string("/proc/self/status").map_err(|error| error.to_string())?;
    let field = |name: &str| -> Result<u32, String> {
        let mut matches = status.lines().filter_map(|line| line.strip_prefix(name));
        let value = matches.next().ok_or("filtered status field absent")?;
        if matches.next().is_some() {
            return Err("filtered status field repeated".into());
        }
        value
            .trim()
            .parse::<u32>()
            .map_err(|error| error.to_string())
    };
    Ok((
        field("NoNewPrivs:")? == 1,
        field("Seccomp:")?,
        field("Seccomp_filters:")?,
    ))
}

fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1_i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

fn read_one(fd: &OwnedFd) -> Result<u8, String> {
    let mut byte = [0_u8; 1];
    if unsafe { libc::read(fd.as_raw_fd(), byte.as_mut_ptr().cast(), 1) } != 1 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: child gate read differs".into());
    }
    Ok(byte[0])
}

fn write_one(fd: &OwnedFd, byte: u8) -> Result<(), String> {
    if unsafe { libc::write(fd.as_raw_fd(), (&byte as *const u8).cast(), 1) } != 1 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: child gate write differs".into());
    }
    Ok(())
}

fn run_child(branch: Branch, helper: Option<&(File, u64, u64)>) -> Result<FilteredChildV1, String> {
    let (ready_read, ready_write) = pipe()?;
    let (go_read, go_write) = pipe()?;
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if child == 0 {
        drop(ready_read);
        drop(go_write);
        let code = if write_one(&ready_write, b'R').is_ok() && read_one(&go_read) == Ok(b'G') {
            child_entry(branch, helper)
        } else {
            126
        };
        unsafe { libc::_exit(code) };
    }
    drop(ready_write);
    drop(go_read);
    if read_one(&ready_read)? != b'R' {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: child ready differs".into());
    }
    // The child is blocked on the GO pipe and cannot exit before this read.
    // The parent's unreaped child prevents PID reuse; independent BPF later
    // authenticates the claimed fork/start/exit/reap sequence.
    let observed = ProcessIdentityV4 {
        pid: child as u32,
        start_time: super::envelope::process_start_time(child)?,
    };
    if observed.pid != child as u32 || observed.start_time == 0 {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: child identity differs".into());
    }
    write_one(&go_write, b'G')?;
    let deadline = Instant::now() + CHILD_LIMIT;
    let status = loop {
        let mut status = 0_i32;
        let waited = unsafe { libc::waitpid(child, &raw mut status, libc::WNOHANG) };
        if waited == child {
            break status;
        }
        if waited < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(child, libc::SIGKILL) };
            let _ = unsafe { libc::waitpid(child, &raw mut status, 0) };
            return Err("MCSEALED-PUBLIC-ABI-FILTERED: compat entry returned or timed out".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGSYS {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: compat entry was not SIGSYS-killed".into());
    }
    Ok(FilteredChildV1 {
        branch: branch.name().into(),
        pid: observed.pid,
        start_time_ticks: observed.start_time,
        audit_arch: branch.audit_arch(),
        syscall_number: branch.syscall_number(),
        terminal_signal: libc::SIGSYS,
        helper_device: helper.map(|(_, device, _)| *device),
        helper_inode: helper.map(|(_, _, inode)| *inode),
    })
}

fn child_entry(branch: Branch, helper: Option<&(File, u64, u64)>) -> i32 {
    match branch {
        Branch::X32 => {
            unsafe { libc::syscall((libc::SYS_getpid as u32 | X32_BIT) as libc::c_long) };
        }
        Branch::I386 => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let mut eax = 20_i32;
                std::arch::asm!("int 0x80", inout("eax") eax, lateout("ecx") _, lateout("edx") _, options(nostack));
                let _ = eax;
            }
        }
        Branch::Arm32 => {
            if let Some((file, _, _)) = helper {
                let argv = [
                    b"memcordon-arm32-abi-helper\0"
                        .as_ptr()
                        .cast::<libc::c_char>(),
                    std::ptr::null(),
                ];
                let envp = [std::ptr::null::<libc::c_char>()];
                unsafe {
                    libc::syscall(
                        libc::SYS_execveat,
                        file.as_raw_fd(),
                        b"\0".as_ptr().cast::<libc::c_char>(),
                        argv.as_ptr(),
                        envp.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    );
                }
            }
        }
    }
    // A broken filter that allows the entry must not turn a later denied
    // write/exit into a false SIGSYS success. Parent times out and rejects.
    loop {
        std::hint::spin_loop();
    }
}

fn open_arm32_helper() -> Result<(File, u64, u64), String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ARM32_HELPER)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > 64 * 1024
    {
        return Err("MCSEALED-PUBLIC-ABI-FILTERED: ARM32 helper protection differs".into());
    }
    Ok((file, metadata.dev(), metadata.ino()))
}
