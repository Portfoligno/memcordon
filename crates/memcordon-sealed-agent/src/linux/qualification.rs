use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    pub spawn_error_reporting_verified: bool,
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
            && self.spawn_error_reporting_verified
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
    super::cgroup::prepare_private_root()?;
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
    let ambiguous_recovery = super::recovery::recover()?;
    let recovery_complete = ambiguous_recovery.is_empty();
    let sacrificial = sacrificial_attempt(b"/usr/bin/true");
    let missing_target = b"/run/memcordon/sealed-qualification-target-must-not-exist";
    let missing_target_path = std::path::Path::new(
        std::str::from_utf8(missing_target).expect("fixed qualification path is UTF-8"),
    );
    match std::fs::symlink_metadata(missing_target_path) {
        Ok(_) => {
            return Err(
                "MCSEALED-PROVIDER-UNAVAILABLE: missing-target qualification path exists"
                    .to_owned(),
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "MCSEALED-PROVIDER-UNAVAILABLE: missing-target qualification readback failed: {error}"
            ));
        }
    }
    let missing_sacrificial = sacrificial_attempt(missing_target);
    let sacrificial_error = sacrificial
        .as_ref()
        .err()
        .map(|error| format!("success-transaction={error}"))
        .or_else(|| {
            missing_sacrificial
                .as_ref()
                .err()
                .map(|error| format!("spawn-error-transaction={error}"))
        });
    let success_verified = sacrificial.as_ref().is_ok_and(|facts| {
        facts.child_status == 0
            && facts.spawn_error_reported
            && facts.exec_status == super::launch::TargetExecStatus::Succeeded
    });
    let spawn_error_verified = missing_sacrificial.as_ref().is_ok_and(|facts| {
        facts.child_status == 127
            && facts.spawn_error_reported
            && matches!(
                facts.exec_status,
                super::launch::TargetExecStatus::Failed {
                    class: super::launch::ExecFailureClass::NotFound,
                    os_code: libc::ENOENT
                }
            )
            && facts.cgroup_empty
            && facts.init_reaped
            && facts.guardian_reaped
            && facts.boundary_retired
    });
    let qualified = success_verified && spawn_error_verified;
    let digest = sacrificial
        .as_ref()
        .ok()
        .zip(missing_sacrificial.as_ref().ok())
        .map(|(facts, missing)| {
            Sha256::digest(format!("memcordon-sealed-agent-v1:{facts:?}:{missing:?}").as_bytes())
        });
    let receipt = QualificationReceipt {
        schema_version: 1,
        mechanism: "linux-pid-namespace-cgroup-v1".to_owned(),
        provider_identity: "memcordon-sealed-agent-v1".to_owned(),
        receipt_digest: digest
            .map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect())
            .unwrap_or_default(),
        unified_cgroup_v2: true,
        private_cgroup_subtree: true,
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
        spawn_error_reporting_verified: spawn_error_verified,
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
        let mut causes = Vec::new();
        if !ambiguous_recovery.is_empty() {
            let examples = ambiguous_recovery
                .iter()
                .take(16)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",");
            causes.push(format!(
                "recovery-ambiguous-count={}; examples={examples}",
                ambiguous_recovery.len()
            ));
        }
        if let Some(error) = sacrificial_error {
            causes.push(format!("sacrificial-error={error}"));
        }
        if causes.is_empty() {
            causes.push(
                "qualification predicates were incomplete without a native phase error".to_owned(),
            );
        }
        Err(format!(
            "MCSEALED-PROVIDER-UNAVAILABLE: receipt={}; {}",
            receipt.render(),
            causes.join("; "),
        ))
    }
}

fn sacrificial_attempt(program: &[u8]) -> Result<super::launch::TerminalFacts, String> {
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
        program: program.to_vec(),
        arguments: Vec::new(),
        environment: Vec::new(),
        policy: LaunchPolicyV1 {
            memory_limit_bytes: None,
            swap_limit: SwapLimit::Bytes(0),
            absolute_deadline_millis: Some(
                super::clock::monotonic_millis()?.saturating_add(30_000),
            ),
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
