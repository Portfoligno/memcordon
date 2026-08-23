use std::fs;
use std::path::Path;

use super::CGROUP_ROOT;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize)]
pub struct QualificationReceipt {
    pub schema_version: u32,
    pub mechanism: String,
    pub provider_identity: String,
    pub receipt_digest: String,
    pub unified_cgroup_v2: bool,
    pub private_cgroup_subtree: bool,
    pub clone3: bool,
    pub clone3_into_cgroup: bool,
    pub pid_namespace: bool,
    pub mount_namespace: bool,
    pub cgroup_namespace: bool,
    pub pidfd: bool,
    pub close_range: bool,
    pub guardian_outside_boundary: bool,
    pub target_gated: bool,
    pub assignment_verified: bool,
    pub inherited_descriptors_verified: bool,
    pub frontend_loss_authority_verified: bool,
    pub cgroup_kill: bool,
    pub workload_empty: bool,
    pub helpers_reaped: bool,
    pub boundary_retired: bool,
    pub recovery_complete: bool,
}

impl QualificationReceipt {
    pub fn complete(&self) -> bool {
        self.schema_version == 1
            && self.unified_cgroup_v2
            && self.private_cgroup_subtree
            && self.clone3
            && self.clone3_into_cgroup
            && self.pid_namespace
            && self.mount_namespace
            && self.cgroup_namespace
            && self.pidfd
            && self.close_range
            && self.guardian_outside_boundary
            && self.target_gated
            && self.assignment_verified
            && self.inherited_descriptors_verified
            && self.frontend_loss_authority_verified
            && self.cgroup_kill
            && self.workload_empty
            && self.helpers_reaped
            && self.boundary_retired
            && self.recovery_complete
    }
    pub fn render(&self) -> String {
        serde_json::to_string(self).expect("qualification receipt is serializable")
    }
}

pub fn qualify() -> Result<QualificationReceipt, String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let provider_uid = unsafe { libc::geteuid() };
    if provider_uid != 0 {
        return Err("MCSEALED-PROVIDER-IDENTITY: provider must run as root".to_owned());
    }
    super::attempt::secure_state_root()?;
    fs::create_dir_all(CGROUP_ROOT)
        .map_err(|error| format!("MCSEALED-CGROUP-PRIVATE-SUBTREE: {error}"))?;
    let cgroup_v2 = ["cgroup.procs", "cgroup.events", "cgroup.kill"]
        .iter()
        .all(|name| Path::new("/sys/fs/cgroup").join(name).exists());
    let clone3 = syscall_present(libc::SYS_clone3);
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    let pidfd_available = if pidfd >= 0 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::close(pidfd as i32) };
        true
    } else {
        false
    };
    let close_range = syscall_present(libc::SYS_close_range);
    let recovery_complete = super::recovery::recover()?.is_empty();
    let sacrificial = sacrificial_attempt();
    let qualified = sacrificial.is_ok();
    let digest = sacrificial
        .as_ref()
        .map(|facts| {
            Sha256::digest(
                format!(
                    "memcordon-sealed-agent-v1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                    facts.child_status,
                    facts.target_pid,
                    facts.authorization_offset_millis,
                    facts.assignment_verified,
                    facts.namespaces_verified,
                    facts.credentials_verified,
                    facts.capabilities_empty,
                    facts.descriptors_verified,
                    facts.cgroup_view_denied,
                    facts.guardian_ready_before_authorization,
                    facts.frontend_loss_authority_verified,
                    facts.cgroup_kill_invoked,
                    facts.cgroup_empty,
                    facts.init_reaped,
                    facts.guardian_reaped,
                    facts.boundary_retired,
                    facts.memory_limit_exceeded,
                    facts.deadline_exceeded,
                )
                .as_bytes(),
            )
        })
        .ok();
    let receipt = QualificationReceipt {
        schema_version: 1,
        mechanism: "linux-pid-namespace-cgroup-v1".to_owned(),
        provider_identity: "memcordon-sealed-agent-v1".to_owned(),
        receipt_digest: digest
            .map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect())
            .unwrap_or_default(),
        unified_cgroup_v2: cgroup_v2,
        private_cgroup_subtree: Path::new(CGROUP_ROOT).exists(),
        clone3,
        clone3_into_cgroup: qualified,
        pid_namespace: qualified,
        mount_namespace: qualified,
        cgroup_namespace: qualified,
        pidfd: pidfd_available,
        close_range,
        guardian_outside_boundary: qualified,
        target_gated: qualified,
        assignment_verified: qualified,
        inherited_descriptors_verified: qualified,
        frontend_loss_authority_verified: qualified,
        cgroup_kill: qualified,
        workload_empty: sacrificial.as_ref().is_ok_and(|facts| facts.cgroup_empty),
        helpers_reaped: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.init_reaped && facts.guardian_reaped),
        boundary_retired: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.boundary_retired),
        recovery_complete,
    };
    if receipt.complete() {
        Ok(receipt)
    } else {
        Err(format!(
            "MCSEALED-PROVIDER-UNAVAILABLE: {}",
            receipt.render()
        ))
    }
}

fn sacrificial_attempt() -> Result<super::launch::TerminalFacts, String> {
    use crate::request::{
        DeadlineScope, DescriptorPurpose, LaunchPolicyV1, LaunchRequestV1, SwapLimit,
    };
    use std::os::fd::{FromRawFd, OwnedFd};
    let directory = std::fs::File::open("/").map_err(|error| error.to_string())?;
    let stdin = std::fs::File::open("/dev/null").map_err(|error| error.to_string())?;
    let stdout = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|error| error.to_string())?;
    let stderr = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|error| error.to_string())?;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut attempt = [0_u8; 16];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|error| error.to_string())?,
        &mut attempt,
    )
    .map_err(|error| error.to_string())?;
    let request = LaunchRequestV1 {
        program: b"/usr/bin/true".to_vec(),
        arguments: Vec::new(),
        environment: Vec::new(),
        policy: LaunchPolicyV1 {
            memory_limit_bytes: None,
            swap_limit: SwapLimit::Bytes(0),
            absolute_deadline_millis: Some(monotonic_millis().saturating_add(30_000)),
            deadline_scope: DeadlineScope::Attempt,
            lifetime: crate::request::Lifetime::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 0,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
        descriptors: vec![
            DescriptorPurpose::CurrentDirectory,
            DescriptorPurpose::Stdin,
            DescriptorPurpose::Stdout,
            DescriptorPurpose::Stderr,
            DescriptorPurpose::FrontendLiveness,
        ],
    };
    let groups = current_groups()?;
    super::launch::execute(
        request,
        vec![
            directory.into(),
            stdin.into(),
            stdout.into(),
            stderr.into(),
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { OwnedFd::from_raw_fd(pidfd) },
        ],
        attempt,
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::getpid() },
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::geteuid() },
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::getegid() },
        groups,
    )
}

fn monotonic_millis() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut value) };
    (value.tv_sec as u64)
        .saturating_mul(1_000)
        .saturating_add(value.tv_nsec as u64 / 1_000_000)
}

fn current_groups() -> Result<Vec<libc::gid_t>, String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut groups = vec![0; count as usize];
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(groups)
}

fn syscall_present(number: libc::c_long) -> bool {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let result = unsafe { libc::syscall(number, std::ptr::null::<libc::c_void>(), 0) };
    result >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
}
