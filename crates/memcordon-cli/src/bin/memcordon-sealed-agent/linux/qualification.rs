pub use memcordon_core::runtime_readiness::ReadinessObservation;

/// Executed as a sacrificial native target under the inherited, package-verified
/// systemd address-family filter. It deliberately makes no stronger claim about
/// alternate kernel networking interfaces or inherited descriptors.
pub fn workload_profile_probe() -> Result<(), String> {
    unix_socket_probe()?;
    for family in [libc::AF_INET, libc::AF_INET6] {
        // SAFETY: socket has no pointer arguments. Capture errno before cleanup.
        let descriptor = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let error = std::io::Error::last_os_error().raw_os_error();
        if descriptor >= 0 {
            // SAFETY: unexpected successful descriptor is still owned by the probe.
            unsafe { libc::close(descriptor) };
            return Err("baseline INET denial was bypassed".into());
        }
        if error != Some(libc::EAFNOSUPPORT) {
            return Err("baseline INET denial errno changed".into());
        }
    }
    Ok(())
}

fn unix_socket_probe() -> Result<(), String> {
    for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM, libc::SOCK_SEQPACKET] {
        // SAFETY: socket has only scalar arguments; a successful descriptor is closed below.
        let descriptor = unsafe { libc::socket(libc::AF_UNIX, kind | libc::SOCK_CLOEXEC, 0) };
        if descriptor < 0 {
            return Err("baseline UNIX socket creation failed".into());
        }
        // SAFETY: descriptor belongs exclusively to this probe.
        unsafe { libc::close(descriptor) };
        let mut pair = [-1; 2];
        // SAFETY: pair provides the required two initialized descriptor slots.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                kind | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        } != 0
        {
            return Err("baseline UNIX socketpair failed".into());
        }
        for descriptor in pair {
            // SAFETY: successful socketpair transfers both descriptors to this probe.
            unsafe { libc::close(descriptor) };
        }
    }
    Ok(())
}

#[cfg(feature = "private-tcp")]
pub fn network_workload_profile_probe() -> Result<(), String> {
    use crate::network_readiness::{Family, validate_creation};
    unix_socket_probe()?;
    validate_creation(Family::Unix, Ok(()), libc::EAFNOSUPPORT)?;
    for (family, domain, kind, protocol) in [
        (Family::Ipv4, libc::AF_INET, libc::SOCK_STREAM, 0),
        (
            Family::RouteNetlink,
            libc::AF_NETLINK,
            libc::SOCK_RAW,
            libc::NETLINK_ROUTE,
        ),
        (Family::Ipv6, libc::AF_INET6, libc::SOCK_STREAM, 0),
    ] {
        // SAFETY: scalar native socket operation under the inherited unit filter.
        let descriptor = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
        let outcome = if descriptor < 0 {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .expect("failed socket has errno"))
        } else {
            // SAFETY: this probe exclusively owns the successful socket.
            unsafe { libc::close(descriptor) };
            Ok(())
        };
        validate_creation(family, outcome, libc::EAFNOSUPPORT)?;
    }
    Ok(())
}

pub fn observe_readiness() -> Result<ReadinessObservation, String> {
    verify_provider_identity()?;
    crate::package::verify()?;
    observe_after_package_verification()
}

#[cfg(feature = "private-tcp")]
pub fn observe_network_readiness() -> Result<ReadinessObservation, String> {
    verify_provider_identity()?;
    crate::package::verify()?;
    observe_selected_after_package_verification(true)
}

#[cfg(feature = "test-support")]
pub(crate) fn observe_after_package_verification_for_test() -> Result<ReadinessObservation, String>
{
    verify_provider_identity()?;
    observe_after_package_verification()
}

fn verify_provider_identity() -> Result<(), String> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let provider_uid = unsafe { libc::geteuid() };
    if provider_uid != 0 {
        return Err("MCSEALED-PROVIDER-IDENTITY: provider must run as root".to_owned());
    }
    Ok(())
}

fn observe_after_package_verification() -> Result<ReadinessObservation, String> {
    observe_selected_after_package_verification(false)
}

fn observe_selected_after_package_verification(
    network: bool,
) -> Result<ReadinessObservation, String> {
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
    require_unambiguous_recovery(&ambiguous_recovery)?;
    let recovery_complete = true;
    let sacrificial = sacrificial_attempt(b"/usr/bin/true");
    use std::os::unix::ffi::OsStrExt;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let profile_probe = sacrificial_attempt_with_arguments(
        executable.as_os_str().as_bytes(),
        vec![if network {
            b"network-workload-profile-probe".to_vec()
        } else {
            b"workload-profile-probe".to_vec()
        }],
    );
    let profile_verified = profile_probe.as_ref().is_ok_and(|facts| {
        facts.child_status == Some(0)
            && facts.exec_status == super::launch::TargetExecStatus::Succeeded
            && facts.cgroup_empty
            && facts.init_reaped
            && facts.guardian_reaped
            && facts.boundary_retired
    });
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
        facts.child_status == Some(0)
            && facts.spawn_error_reported
            && facts.exec_status == super::launch::TargetExecStatus::Succeeded
    });
    let spawn_error_verified = missing_sacrificial.as_ref().is_ok_and(|facts| {
        facts.child_status == Some(127)
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
    let mut observation = ReadinessObservation {
        format: if network {
            "memcordon.network-launcher-readiness"
        } else {
            "memcordon.runtime-readiness"
        }
        .into(),
        revision: 1,
        workload_profile: if network {
            crate::network_readiness::profile()
        } else {
            memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate.reference()
        },
        workload_profile_probe_verified: profile_verified,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        provider_identity: "memcordon-sealed-agent-v2".to_owned(),
        control_service_identity: "memcordon-sealed-agent.service:v2".to_owned(),
        launcher_service_identity: if network {
            "memcordon-sealed-network-launcher.service:v2"
        } else {
            "memcordon-sealed-launcher.service:v2"
        }
        .to_owned(),
        observation_digest: String::new(),
        success_child_status: sacrificial
            .as_ref()
            .ok()
            .and_then(|facts| facts.child_status),
        missing_target_child_status: missing_sacrificial
            .as_ref()
            .ok()
            .and_then(|facts| facts.child_status),
        profile_child_status: profile_probe
            .as_ref()
            .ok()
            .and_then(|facts| facts.child_status),
        caller_envelope_digest: sacrificial
            .as_ref()
            .ok()
            .map(|facts| facts.caller_envelope_digest.clone()),
        unified_cgroup_v2: true,
        private_cgroup_subtree: true,
        clone3,
        clone3_into_cgroup: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.assignment_verified),
        pid_namespace: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.namespaces_verified),
        mount_namespace: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.namespaces_verified),
        cgroup_namespace: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.namespaces_verified),
        pidfd: pidfd_available,
        close_range,
        guardian_outside_boundary: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.guardian_ready_before_authorization),
        target_gated: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.guardian_ready_before_authorization),
        assignment_verified: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.assignment_verified),
        inherited_descriptors_verified: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.descriptors_verified),
        spawn_error_reporting_verified: spawn_error_verified,
        frontend_loss_authority_verified: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.frontend_loss_authority_verified),
        cgroup_kill: sacrificial
            .as_ref()
            .is_ok_and(|facts| facts.cgroup_kill_invoked),
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
    };
    observation.observation_digest = observation.digest_facts()?;
    let complete = if network {
        crate::network_readiness::complete(&observation)
    } else {
        observation.complete()
    };
    if success_verified && complete {
        Ok(observation)
    } else {
        let mut causes = Vec::new();
        if let Some(error) = sacrificial_error {
            causes.push(format!("sacrificial-error={error}"));
        }
        if causes.is_empty() {
            causes.push(
                "readiness observations were incomplete without a native phase error".to_owned(),
            );
        }
        Err(format!(
            "MCSEALED-PROVIDER-UNAVAILABLE: observation={}; {}",
            observation.render(),
            causes.join("; "),
        ))
    }
}

pub(crate) fn require_unambiguous_recovery(ambiguous_recovery: &[String]) -> Result<(), String> {
    if ambiguous_recovery.is_empty() {
        return Ok(());
    }
    let examples = ambiguous_recovery
        .iter()
        .take(16)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",");
    Err(format!(
        "MCSEALED-PROVIDER-UNAVAILABLE: recovery-ambiguous-count={}; examples={examples}",
        ambiguous_recovery.len()
    ))
}

fn sacrificial_attempt(program: &[u8]) -> Result<super::launch::TerminalFacts, String> {
    sacrificial_attempt_with_arguments(program, Vec::new())
}

fn sacrificial_attempt_with_arguments(
    program: &[u8],
    arguments: Vec<Vec<u8>>,
) -> Result<super::launch::TerminalFacts, String> {
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
        restart_attempt: 0,
        workload_contract: None,
        program: program.to_vec(),
        arguments,
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
