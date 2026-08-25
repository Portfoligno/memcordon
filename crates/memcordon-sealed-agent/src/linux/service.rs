use std::io;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};

use sha2::{Digest, Sha256};

use crate::protocol::{Frame, MessageKind, write_frame};
use crate::rejection::RejectionV1;

pub fn serve() -> Result<(), String> {
    super::startup::clear()?;
    configure_subreaper()?;
    let qualification = super::launcher::probe().map_err(|error| {
        record_startup_failure(super::startup::StartupPhase::Qualification, &error)
    })?;
    let listener = activated_listener().map_err(|error| {
        let error = format!("MCSEALED-SOCKET-ACTIVATION: {error}");
        record_startup_failure(super::startup::StartupPhase::SocketActivation, &error)
    })?;
    super::startup::clear()?;
    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                reap_workers();
                wait_for_connection(&listener)?;
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let worker = unsafe { libc::fork() };
        if worker == -1 {
            return Err(format!(
                "MCSEALED-PROVIDER-WORKER: {}",
                io::Error::last_os_error()
            ));
        }
        if worker == 0 {
            drop(listener);
            if let Err(error) = stream.set_nonblocking(false) {
                eprintln!("sealed provider worker could not configure stream: {error}");
                // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
                unsafe { libc::_exit(125) };
            }
            let code = match handle(&mut stream, &qualification) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("sealed provider rejected request: {error}");
                    125
                }
            };
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::_exit(code) };
        }
        drop(stream);
        reap_workers();
    }
}

fn configure_subreaper() -> Result<(), String> {
    // SAFETY: prctl receives the documented scalar PR_SET_CHILD_SUBREAPER arguments.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(format!(
            "MCSEALED-PROVIDER-SUBREAPER: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn record_startup_failure(phase: super::startup::StartupPhase, error: &str) -> String {
    match super::startup::record(phase, error) {
        Ok(()) => error.to_owned(),
        Err(record_error) => format!("{error}; {record_error}"),
    }
}

fn reap_workers() {
    loop {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if result <= 0 {
            break;
        }
    }
}

fn wait_for_connection(listener: &UnixListener) -> Result<(), String> {
    let mut pollfd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let status = unsafe { libc::poll(&raw mut pollfd, 1, 1_000) };
    if status == -1 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.to_string());
        }
    }
    Ok(())
}

fn activated_listener() -> Result<UnixListener, String> {
    const SYSTEMD_LISTEN_FD: RawFd = 3;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    Ok(listener)
}

fn handle(
    stream: &mut UnixStream,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<(), String> {
    let credentials = peer_credentials(stream)?;
    if credentials.uid == u32::MAX {
        return Err("MCSEALED-PIPE-AUTH: invalid peer credentials".to_owned());
    }
    let groups = peer_groups(credentials.pid)?;
    authorize_peer(credentials, &groups)?;
    let (request, descriptors) = super::transport::receive(stream)?;
    let response = match request.kind {
        MessageKind::Probe => probe_response(&request, descriptors.len(), qualification)?,
        MessageKind::Launch => {
            match launch_response(request.clone(), descriptors, credentials, groups) {
                Ok(response) => response,
                Err(rejection) => {
                    journal_rejection(request.attempt_id, &rejection);
                    rejected(&request, &rejection)?
                }
            }
        }
        _ => rejected_text(
            &request,
            "MCSEALED-AUTHORIZATION",
            "MCSEALED-AUTHORIZATION: launch protocol requires the native descriptor transaction",
        )?,
    };
    write_frame(stream, &response).map_err(|error| error.to_string())
}

fn probe_response(
    request: &Frame,
    descriptor_count: usize,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<Frame, String> {
    if descriptor_count != 0 {
        return rejected_text(
            request,
            "MCSEALED-PROVIDER-REJECTION",
            "MCSEALED-PROVIDER-REJECTION: probe must not carry descriptors",
        );
    }
    Ok(Frame {
        kind: MessageKind::ProbeReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: qualification.render().into_bytes(),
    })
}

#[cfg(feature = "test-support")]
pub fn cached_probe_response_for_test(
    request: &Frame,
    descriptor_count: usize,
    qualification: &super::qualification::QualificationReceipt,
) -> Frame {
    probe_response(request, descriptor_count, qualification)
        .expect("fixed probe rejection must fit the bounded protocol")
}

fn launch_response(
    request: Frame,
    descriptors: Vec<std::os::fd::OwnedFd>,
    credentials: PeerCredentials,
    groups: Vec<libc::gid_t>,
) -> Result<Frame, RejectionV1> {
    let _launch_lease = acquire_shared_package_lease()
        .map_err(|error| RejectionV1::request_error("MCSEALED-PACKAGE-LEASE", &error))?;
    let launch = crate::request::decode_launch_request(&request.payload).map_err(|error| {
        RejectionV1::request_error(
            "MCSEALED-LAUNCH-DECODE",
            &format!("invalid launch request: {error:?}"),
        )
    })?;
    if descriptors.len() != 5 {
        return Err(RejectionV1::request_error(
            "MCSEALED-LAUNCH-DESCRIPTOR-SET",
            "exact public descriptor inventory required",
        ));
    }
    if peer_inside_active_attempt(credentials.pid).map_err(|error| {
        RejectionV1::request_error("MCSEALED-RECURSIVE-PROVIDER-REQUEST", &error)
    })? {
        return Err(RejectionV1::request_error(
            "MCSEALED-RECURSIVE-PROVIDER-REQUEST",
            "caller is already inside an active sealed attempt",
        ));
    }
    let captured = super::envelope::capture(
        credentials.pid,
        credentials.uid,
        credentials.gid,
        &groups,
        descriptors[0].as_fd(),
    )
    .map_err(|error| RejectionV1::request_error("MCSEALED-CALLER-ENVELOPE-CAPTURE", &error))?;
    // SAFETY: getpid returns this single request worker's positive process id.
    let control_process_id = unsafe { libc::getpid() };
    let control_process_start_time = super::envelope::process_start_time(control_process_id)
        .map_err(|error| {
            RejectionV1::request_error("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION", &error)
        })?;
    let request_digest: [u8; 32] = Sha256::digest(&request.payload).into();
    let broker = crate::request::LaunchBrokerRequestV2::authenticated(
        request.attempt_id,
        request_digest,
        control_process_id,
        control_process_start_time,
        launch,
        captured.envelope,
        super::launcher::broker_descriptor_manifest(),
    )
    .map_err(|error| {
        RejectionV1::request_error(
            "MCSEALED-LAUNCHER-REQUEST-BINDING",
            &format!("could not bind broker request: {error:?}"),
        )
    })?;
    let record_identity = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let _durable_record = super::attempt::AttemptRecord::create_v2(
        record_identity,
        credentials.pid,
        broker.caller.digest_hex(),
    )
    .map_err(|error| RejectionV1::request_error("MCSEALED-RECORD-ALLOCATE", &error))?;
    let descriptor_fds = descriptors
        .iter()
        .map(AsRawFd::as_raw_fd)
        .chain([
            captured.mount_namespace.as_raw_fd(),
            captured.root.as_raw_fd(),
        ])
        .collect::<Vec<_>>();
    super::launcher::launch(&request, &broker, &descriptor_fds).map_err(|error| {
        RejectionV1::request_error("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION", &error)
    })
}

pub(crate) fn terminal_payload(facts: &super::launch::TerminalFacts) -> Vec<u8> {
    let (exec_status, exec_os_code) = match facts.exec_status {
        super::launch::TargetExecStatus::Succeeded => ("success", "none".to_owned()),
        super::launch::TargetExecStatus::Failed { class, os_code } => {
            (class.receipt_name(), os_code.to_string())
        }
    };
    format!(
        "schema-version=2\nmechanism=linux-pid-namespace-cgroup-v2\nstatus={}\nexec-status={}\nexec-os-code={}\nspawn-error-reported={}\ntarget-pid={}\nauthorization-offset-millis={}\nmemory-limit-exceeded={}\ndeadline-exceeded={}\nassignment-verified={}\nnamespaces-verified={}\ntarget-initial-credentials-verified={}\ninitial-provider-capabilities-absent={}\ncaller-envelope-digest={}\ncaller-no-new-privs={}\ntarget-no-new-privs-matched={}\ncaller-capability-bounding-set-digest={}\ntarget-capability-bounding-set-matched={}\ncaller-mount-namespace-digest={}\ntarget-mount-context-derived-from-caller={}\ncredential-transition-disposition=preserve-caller-envelope\nboundary-independent-of-credentials={}\ndescriptors-verified={}\nwritable-ancestor-cgroup-denied={}\nparent-namespace-handles-denied={}\nrecursive-provider-request-denied={}\nguardian-ready-before-authorization={}\nfrontend-loss-authority-verified={}\ncgroup-kill-invoked={}\ncgroup-empty={}\ninit-reaped={}\nguardian-reaped={}\nboundary-retired={}\n",
        facts.child_status,
        exec_status,
        exec_os_code,
        facts.spawn_error_reported,
        facts.target_pid,
        facts.authorization_offset_millis,
        facts.memory_limit_exceeded,
        facts.deadline_exceeded,
        facts.assignment_verified,
        facts.namespaces_verified,
        facts.target_initial_credentials_verified,
        facts.initial_provider_capabilities_absent,
        facts.caller_envelope_digest,
        facts.caller_no_new_privs,
        facts.target_no_new_privs_matched,
        facts.caller_capability_bounding_set_digest,
        facts.target_capability_bounding_set_matched,
        facts.caller_mount_namespace_digest,
        facts.target_mount_context_derived_from_caller,
        facts.boundary_independent_of_credentials,
        facts.descriptors_verified,
        facts.writable_ancestor_cgroup_denied,
        facts.parent_namespace_handles_denied,
        facts.recursive_provider_request_denied,
        facts.guardian_ready_before_authorization,
        facts.frontend_loss_authority_verified,
        facts.cgroup_kill_invoked,
        facts.cgroup_empty,
        facts.init_reaped,
        facts.guardian_reaped,
        facts.boundary_retired
    )
    .into_bytes()
}

#[cfg(feature = "test-support")]
pub fn terminal_payload_for_test(facts: &super::launch::TerminalFacts) -> Vec<u8> {
    terminal_payload(facts)
}

fn rejected(request: &Frame, rejection: &RejectionV1) -> Result<Frame, String> {
    Ok(Frame {
        kind: MessageKind::Rejected,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: rejection.encode()?,
    })
}

fn rejected_text(request: &Frame, code: &str, detail: &str) -> Result<Frame, String> {
    rejected(request, &RejectionV1::request_error(code, detail))
}

fn journal_rejection(attempt_id: [u8; 16], rejection: &RejectionV1) {
    let attempt = attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let diagnostic = serde_json::json!({
        "schema_version": 1,
        "event": "sealed-launch-rejected",
        "attempt_id": attempt,
        "code": rejection.code,
        "phase": rejection.phase,
        "target_created": rejection.target_created,
        "target_released": rejection.target_released,
        "cleanup_attempted": rejection.cleanup.attempted,
        "workload_empty": rejection.cleanup.workload_empty,
        "helpers_reaped": rejection.cleanup.helpers_reaped,
        "boundary_retired": rejection.cleanup.sealed_boundary_retired,
    });
    eprintln!("sealed provider launch rejection: {diagnostic}");
}

pub(crate) const PACKAGE_LEASE: &str = "/run/memcordon-sealed-package.lock";
const LEGACY_PACKAGE_LEASE: &str = "/run/memcordon/sealed-package.lock";

#[derive(Clone, Copy)]
enum LeaseAccess {
    SharedExisting,
    ExclusiveCreate,
}

pub fn acquire_shared_package_lease() -> Result<std::fs::File, String> {
    acquire_lease(PACKAGE_LEASE, LeaseAccess::SharedExisting)
}

pub fn acquire_package_lease() -> Result<std::fs::File, String> {
    acquire_lease(PACKAGE_LEASE, LeaseAccess::ExclusiveCreate)
}

pub fn acquire_legacy_package_lease() -> Result<std::fs::File, String> {
    acquire_lease(LEGACY_PACKAGE_LEASE, LeaseAccess::ExclusiveCreate)
}

pub fn acquire_qualification_lease() -> Result<std::fs::File, String> {
    acquire_lease(PACKAGE_LEASE, LeaseAccess::ExclusiveCreate).map_err(|error| {
        format!("MCSEALED-QUALIFICATION-LEASE: provider attempt is active: {error}")
    })
}

fn acquire_lease(path: &str, access: LeaseAccess) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let operation = match access {
        LeaseAccess::SharedExisting => libc::LOCK_SH | libc::LOCK_NB,
        LeaseAccess::ExclusiveCreate => {
            options.write(true).create(true).truncate(false).mode(0o600);
            libc::LOCK_EX | libc::LOCK_NB
        }
    };
    let file = options
        .open(path)
        .map_err(|error| format!("MCSEALED-PACKAGE-LEASE: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("MCSEALED-PACKAGE-LEASE: {error}"))?;
    if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o600 {
        return Err("MCSEALED-PACKAGE-LEASE: unsafe lock-file identity or mode".to_owned());
    }
    // SAFETY: `file` owns a live descriptor for the duration of the advisory lock; flock has no
    // pointer arguments and reports contention/error without changing Rust ownership.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == -1 {
        return Err(format!(
            "MCSEALED-PACKAGE-LEASE: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

#[derive(Clone, Copy)]
struct PeerCredentials {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, String> {
    let mut value = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>())
        .map_err(|_| "credential size overflow".to_owned())?;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    if status == -1 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(PeerCredentials {
        pid: value.pid,
        uid: value.uid,
        gid: value.gid,
    })
}

fn peer_groups(pid: libc::pid_t) -> Result<Vec<libc::gid_t>, String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| error.to_string())?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:\t"))
        .ok_or_else(|| "peer groups unavailable".to_owned())?
        .split_ascii_whitespace()
        .map(|value| value.parse().map_err(|_| "invalid peer group".to_owned()))
        .collect()
}

const MAX_PROC_CGROUP_BYTES: usize = 64 * 1024;

pub fn cgroup_membership_is_sealed(input: &str) -> Result<bool, String> {
    if input.len() > MAX_PROC_CGROUP_BYTES {
        return Err("recursive provider cgroup membership exceeds the bounded input".to_owned());
    }
    if input.is_empty() || !input.ends_with('\n') || input.as_bytes().contains(&0) {
        return Err("recursive provider cgroup membership is not canonical text".to_owned());
    }
    let mut unified_membership = None;
    for line in input.lines() {
        let (hierarchy, rest) = line
            .split_once(':')
            .ok_or_else(|| "recursive provider cgroup membership is malformed".to_owned())?;
        let (controllers, path) = rest
            .split_once(':')
            .ok_or_else(|| "recursive provider cgroup membership is malformed".to_owned())?;
        if hierarchy.is_empty()
            || !hierarchy.bytes().all(|byte| byte.is_ascii_digit())
            || path.is_empty()
            || !path.starts_with('/')
        {
            return Err("recursive provider cgroup membership is malformed".to_owned());
        }
        if controllers.is_empty() && unified_membership.replace(path).is_some() {
            return Err("recursive provider cgroup membership repeats cgroup v2".to_owned());
        }
    }
    let path = unified_membership
        .ok_or_else(|| "recursive provider cgroup membership omits cgroup v2".to_owned())?;
    Ok(std::path::Path::new(path)
        .components()
        .any(|component| component.as_os_str() == "memcordon-sealed"))
}

pub fn namespace_membership_matches(
    peer: [crate::request::NamespaceIdentity; 3],
    member: [crate::request::NamespaceIdentity; 3],
) -> bool {
    peer == member
}

fn namespace_identity(metadata: &std::fs::Metadata) -> crate::request::NamespaceIdentity {
    crate::request::NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn peer_inside_active_attempt(pid: libc::pid_t) -> Result<bool, String> {
    peer_inside_active_attempt_at(
        pid,
        std::path::Path::new("/proc"),
        std::path::Path::new(super::CGROUP_ROOT),
    )
}

#[cfg(feature = "test-support")]
pub fn peer_inside_active_attempt_for_test(
    pid: libc::pid_t,
    proc_root: &std::path::Path,
    cgroup_root: &std::path::Path,
) -> Result<bool, String> {
    peer_inside_active_attempt_at(pid, proc_root, cgroup_root)
}

fn peer_inside_active_attempt_at(
    pid: libc::pid_t,
    proc_root: &std::path::Path,
    cgroup_root: &std::path::Path,
) -> Result<bool, String> {
    let process = proc_root.join(pid.to_string());
    let cgroup = std::fs::read_to_string(process.join("cgroup"))
        .map_err(|error| format!("recursive provider cgroup readback failed: {error}"))?;
    if cgroup_membership_is_sealed(&cgroup)? {
        return Ok(true);
    }
    let peer_namespaces = ["pid", "mnt", "cgroup"]
        .map(|kind| std::fs::metadata(process.join("ns").join(kind)))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("recursive provider namespace readback failed: {error}"))?;
    let peer_namespaces = std::array::from_fn(|index| {
        namespace_identity(
            peer_namespaces
                .get(index)
                .expect("three peer namespaces were captured"),
        )
    });
    match std::fs::symlink_metadata(cgroup_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(
                "recursive provider inventory root is not a no-follow directory".to_owned(),
            );
        }
        Err(error) => return Err(format!("recursive provider inventory root failed: {error}")),
    }
    let attempts = std::fs::read_dir(cgroup_root)
        .map_err(|error| format!("recursive provider inventory failed: {error}"))?;
    for attempt in attempts {
        let attempt = match attempt {
            Ok(attempt) => attempt,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "recursive provider inventory entry failed: {error}"
                ));
            }
        };
        let attempt = match super::cgroup::classify_attempt_root_entry(&attempt) {
            Ok(super::cgroup::AttemptRootEntry::KernelControl) => continue,
            Ok(super::cgroup::AttemptRootEntry::Attempt { path, .. }) => path,
            Ok(super::cgroup::AttemptRootEntry::InvalidDirectory(name)) => {
                return Err(format!(
                    "recursive provider inventory contained invalid attempt directory {}",
                    name.to_string_lossy()
                ));
            }
            Ok(super::cgroup::AttemptRootEntry::Unsafe(name)) => {
                return Err(format!(
                    "recursive provider inventory contained unsafe entry {}",
                    name.to_string_lossy()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "recursive provider inventory entry classification failed: {error}"
                ));
            }
        };
        let members = match std::fs::read_to_string(attempt.join("cgroup.procs")) {
            Ok(members) => members,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "recursive provider attempt membership readback failed: {error}"
                ));
            }
        };
        for member in members.lines() {
            let member = member
                .parse::<libc::pid_t>()
                .map_err(|_| "recursive provider inventory contained an invalid pid".to_owned())?;
            let member = proc_root.join(member.to_string());
            let mut metadata = Vec::with_capacity(3);
            for kind in ["pid", "mnt", "cgroup"] {
                match std::fs::metadata(member.join("ns").join(kind)) {
                    Ok(value) => metadata.push(value),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        metadata.clear();
                        break;
                    }
                    Err(error) => {
                        return Err(format!(
                            "recursive provider member namespace readback failed: {error}"
                        ));
                    }
                }
            }
            if metadata.len() == 3 {
                let member_namespaces =
                    std::array::from_fn(|index| namespace_identity(&metadata[index]));
                if namespace_membership_matches(peer_namespaces, member_namespaces) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn authorize_peer(credentials: PeerCredentials, groups: &[libc::gid_t]) -> Result<(), String> {
    let endpoint = std::fs::symlink_metadata(crate::linux::SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-PIPE-AUTH: endpoint metadata unavailable: {error}"))?;
    if !endpoint.file_type().is_socket()
        || endpoint.uid() != 0
        || endpoint.gid() == 0
        || endpoint.mode() & 0o007 != 0
    {
        return Err("MCSEALED-PIPE-AUTH: endpoint authorization identity is unsafe".to_owned());
    }
    if peer_is_authorized(credentials.uid, credentials.gid, groups, endpoint.gid()) {
        Ok(())
    } else {
        Err("MCSEALED-PIPE-AUTH: caller is not in the provider access group".to_owned())
    }
}

fn peer_is_authorized(
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
    allowed_gid: libc::gid_t,
) -> bool {
    uid == 0 || gid == allowed_gid || groups.contains(&allowed_gid)
}

#[cfg(feature = "test-support")]
pub fn peer_is_authorized_for_test(
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
    allowed_gid: libc::gid_t,
) -> bool {
    peer_is_authorized(uid, gid, groups, allowed_gid)
}
