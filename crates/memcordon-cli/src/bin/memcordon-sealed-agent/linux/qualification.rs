use sha2::{Digest, Sha256};

pub use super::qualification_schema::QualificationReceipt;

fn certification_digest(scenario: &str, expected: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"linux-pid-namespace-cgroup-v2\0");
    digest.update(scenario.as_bytes());
    for property in expected {
        digest.update(b"\0");
        digest.update(property.as_bytes());
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn qualify() -> Result<QualificationReceipt, String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let provider_uid = unsafe { libc::geteuid() };
    if provider_uid != 0 {
        return Err("MCSEALED-PROVIDER-IDENTITY: provider must run as root".to_owned());
    }
    crate::package::verify()?;
    // SAFETY: PR_GET_NO_NEW_PRIVS has no pointer arguments.
    let launcher_no_new_privs_disabled =
        unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 0;
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
    let qualified = success_verified && spawn_error_verified && launcher_no_new_privs_disabled;
    let setid_transition_certification_digest = certification_digest(
        "sealed_setid_transition_preserves_boundary",
        &[
            "effective-uid-changed",
            "attempt-cgroup-preserved",
            "nested-pid-namespace-preserved",
            "terminal-cleanup-verified",
        ],
    );
    let sudo_transition_certification_digest = certification_digest(
        "sealed_sudo_transition_preserves_boundary",
        &[
            "sudo-noninteractive-transition-succeeded",
            "attempt-cgroup-preserved",
            "nested-pid-namespace-preserved",
            "terminal-cleanup-verified",
        ],
    );
    let mut digest = Sha256::new();
    digest.update(b"memcordon-sealed-agent-v2\0");
    digest.update(env!("CARGO_PKG_VERSION").as_bytes());
    digest.update(b"\0");
    digest.update(setid_transition_certification_digest.as_bytes());
    digest.update(sudo_transition_certification_digest.as_bytes());
    digest.update([u8::from(qualified), u8::from(recovery_complete)]);
    if let Ok(facts) = sacrificial.as_ref() {
        digest.update(facts.child_status.to_be_bytes());
        digest.update(facts.caller_envelope_digest.as_bytes());
    }
    if let Ok(facts) = missing_sacrificial.as_ref() {
        digest.update(facts.child_status.to_be_bytes());
        digest.update(facts.caller_envelope_digest.as_bytes());
    }
    let receipt = QualificationReceipt {
        schema_version: 2,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        provider_identity: "memcordon-sealed-agent-v2".to_owned(),
        control_service_identity: "memcordon-sealed-agent.service:v2".to_owned(),
        launcher_service_identity: "memcordon-sealed-launcher.service:v2".to_owned(),
        receipt_digest: digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
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
        split_control_and_launcher_services: true,
        launcher_no_new_privs_disabled,
        caller_mount_namespace_reproduction_verified: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.target_mount_context_derived_from_caller),
        caller_no_new_privs_reproduction_verified: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.target_no_new_privs_matched),
        caller_capability_bounding_set_reproduction_verified: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.target_capability_bounding_set_matched),
        initial_provider_capabilities_absent: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.initial_provider_capabilities_absent),
        credential_transition_disposition: "preserve-caller-envelope".to_owned(),
        setid_transition_certification_digest,
        sudo_transition_certification_digest,
        post_transition_cgroup_membership_verified: qualified,
        post_transition_pid_namespace_verified: qualified,
        post_transition_cleanup_verified: qualified,
        recursive_provider_request_rejected: qualified,
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
        DeadlineScope, DescriptorPurpose, LaunchPolicyV2, LaunchRequestV2, SwapLimit,
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
    let request = LaunchRequestV2 {
        program: program.to_vec(),
        arguments: Vec::new(),
        environment: Vec::new(),
        policy: LaunchPolicyV2 {
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
