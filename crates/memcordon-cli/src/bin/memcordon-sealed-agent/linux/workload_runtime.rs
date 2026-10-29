//! Current request ingress and its original authenticated native transaction.
use crate::protocol::{Frame, MessageKind};
use memcordon_core::workload_request::{
    WorkloadRejectionCodeV1, WorkloadRejectionV1, WorkloadStartV1,
};
use serde::{Deserialize, Serialize};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadBrokerV1 {
    format: String,
    revision: u32,
    start: WorkloadStartV1,
    native_broker: Vec<u8>,
    setup_cutoff_nanos: u64,
}
fn random_identity() -> Result<[u8; 16], String> {
    let mut bytes = [0; 16];
    let mut filled = 0;
    while filled != bytes.len() {
        // SAFETY: the remaining initialized output buffer is writable for its exact size.
        let count = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.to_string());
        }
        if count == 0 {
            return Err("native randomness returned an empty read".into());
        }
        filled = filled
            .checked_add(usize::try_from(count).map_err(|_| "native random length overflow")?)
            .ok_or("native random length overflow")?;
    }
    Ok(bytes)
}
fn rejection(
    request: &Frame,
    code: WorkloadRejectionCodeV1,
    detail: &str,
) -> Result<Frame, String> {
    let detail = memcordon_core::BoundedText::new(detail).unwrap_or_else(|_| {
        memcordon_core::BoundedText::new("native rejection detail exceeds bounded projection")
            .expect("fixed bounded detail")
    });
    Ok(Frame {
        kind: MessageKind::WorkloadRejected,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&WorkloadRejectionV1 {
            format: "memcordon.workload-rejection".into(),
            revision: 1,
            code,
            detail,
        })
        .map_err(|e| e.to_string())?,
    })
}

pub(super) fn forward_public(
    frontend: &mut UnixStream,
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    pid: i32,
    uid: u32,
    gid: u32,
    groups: &[u32],
    mut setup_cutoff_nanos: u64,
) -> Result<(), String> {
    let setup = (|| -> Result<_, (WorkloadRejectionCodeV1, String)> {
        let malformed = |e: String| (WorkloadRejectionCodeV1::MalformedRequest, e);
        if !cfg!(feature = "private-tcp")
            || descriptors.len() != 5
            || request.kind != MessageKind::WorkloadStart
        {
            return Err(malformed(
                "selected current runtime and exact five native descriptors required".into(),
            ));
        }
        let start =
            WorkloadStartV1::parse(&request.payload).map_err(|e| malformed(e.to_string()))?;
        let launch = crate::request::decode_launch_request(&start.native_launch)
            .map_err(|e| malformed(format!("native invocation: {e:?}")))?;
        if let Some(absolute) = launch.policy.absolute_deadline_millis {
            setup_cutoff_nanos = setup_cutoff_nanos.min(
                absolute
                    .checked_mul(1_000_000)
                    .ok_or_else(|| malformed("absolute native deadline exceeds range".into()))?,
            );
        }
        super::image_elf_closure::validate_initial_environment(&launch)
            .map_err(|detail| (WorkloadRejectionCodeV1::UnsupportedRequirement, detail))?;
        if launch.descriptors != super::launcher::broker_descriptor_manifest()[..5] {
            return Err(malformed("native descriptor purposes differ".into()));
        }
        let package = super::service::acquire_shared_package_lease()
            .map_err(|e| (WorkloadRejectionCodeV1::NativeUnavailable, e))?;
        let account = super::workload_account::verify()
            .map_err(|e| (WorkloadRejectionCodeV1::NativeUnavailable, e))?;
        if account.uid() == uid
            || super::service::peer_inside_active_attempt(pid)
                .map_err(|e| (WorkloadRejectionCodeV1::CallerIdentityMismatch, e))?
        {
            return Err((
                WorkloadRejectionCodeV1::CallerIdentityMismatch,
                "managed target cannot become a public caller".into(),
            ));
        }
        let captured = super::envelope::capture(pid, uid, gid, groups, descriptors[0].as_fd())
            .map_err(|e| (WorkloadRejectionCodeV1::CallerIdentityMismatch, e))?;
        let frontend_identity =
            super::native_process::ProcessIdentityV4::observe(pid, descriptors[4].as_fd())
                .map_err(|e| (WorkloadRejectionCodeV1::CallerIdentityMismatch, e))?;
        if frontend_identity.start_time != captured.envelope.process_start_time {
            return Err((
                WorkloadRejectionCodeV1::CallerIdentityMismatch,
                "original frontend process birth changed".into(),
            ));
        }
        let assigned = Frame {
            kind: MessageKind::WorkloadBrokerStart,
            nonce: random_identity()
                .map_err(|e| (WorkloadRejectionCodeV1::NativeUnavailable, e))?,
            attempt_id: random_identity()
                .map_err(|e| (WorkloadRejectionCodeV1::NativeUnavailable, e))?,
            payload: Vec::new(),
        };
        // SAFETY: getpid returns this actual accepted-connection control worker.
        let control = unsafe { libc::getpid() };
        let (broker, _) = crate::request::LaunchBrokerRequestV2::authenticated_private(
            assigned.attempt_id,
            &request.payload,
            control,
            super::envelope::process_start_time(control).map_err(malformed)?,
            launch,
            captured.envelope,
            super::launcher::broker_descriptor_manifest(),
        )
        .map_err(|e| malformed(format!("native caller transaction: {e:?}")))?;
        let envelope = WorkloadBrokerV1 {
            format: "memcordon.workload-broker".into(),
            revision: 1,
            start,
            native_broker: crate::request::encode_launch_broker_request(&broker)
                .map_err(|e| malformed(format!("native broker encoding: {e:?}")))?,
            setup_cutoff_nanos,
        };
        let mut assigned = assigned;
        assigned.payload = serde_json::to_vec(&envelope).map_err(|e| malformed(e.to_string()))?;
        let fds: Vec<_> = descriptors
            .iter()
            .map(AsRawFd::as_raw_fd)
            .chain([
                captured.mount_namespace.as_raw_fd(),
                captured.root.as_raw_fd(),
            ])
            .collect();
        let remaining =
            setup_cutoff_nanos.saturating_sub(super::clock::monotonic_nanos().map_err(malformed)?);
        if remaining == 0 {
            return Err((
                WorkloadRejectionCodeV1::NativeUnavailable,
                "original setup cutoff expired".into(),
            ));
        }
        let broker_stream = super::launcher::connect_workload_until(
            assigned.attempt_id,
            assigned.nonce,
            std::time::Instant::now() + std::time::Duration::from_nanos(remaining),
        )
        .map_err(|e| (WorkloadRejectionCodeV1::NativeUnavailable, e))?;
        let mut bytes = Vec::new();
        crate::protocol::write_frame(&mut bytes, &assigned)
            .map_err(|e| malformed(e.to_string()))?;
        // These original objects outlive native dispatch and the complete relay.
        Ok((
            package,
            captured.mount_namespace,
            captured.root,
            broker_stream,
            assigned,
            bytes,
            fds,
        ))
    })();
    let (_package, _mount, _root, mut broker, assigned, bytes, fds) = match setup {
        Ok(value) => value,
        Err((code, detail)) => {
            return write_frame_until(
                frontend,
                &rejection(request, code, &detail)?,
                Instant::now() + Duration::from_secs(1),
            );
        }
    };
    // A dispatch failure is uncertain. It must never become a preallocation refusal.
    super::transport::send_until(&broker, &bytes, &fds, ingress_cutoff(setup_cutoff_nanos)?)?;
    proxy(frontend, &mut broker, &assigned, setup_cutoff_nanos)
}

fn proxy(
    frontend: &mut UnixStream,
    broker: &mut UnixStream,
    assigned: &Frame,
    setup_cutoff_nanos: u64,
) -> Result<(), String> {
    let mut input_complete = false;
    let mut frontend_closed = false;
    let mut frontend_input_done = false;
    let mut prepared_sent = false;
    let mut prepared_acknowledged = false;
    loop {
        if !prepared_acknowledged && super::clock::monotonic_nanos()? >= setup_cutoff_nanos {
            let _ = broker.shutdown(std::net::Shutdown::Write);
            return Err("original workload ingress cutoff expired after native dispatch".into());
        }
        let mut polls = [
            libc::pollfd {
                fd: broker.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if frontend_closed || frontend_input_done {
                    -1
                } else {
                    frontend.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two initialized live socket poll records, with a finite wait.
        if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 100) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.to_string());
        }
        if polls[1].revents != 0 {
            let allowance = if prepared_acknowledged {
                Duration::from_secs(1)
            } else {
                Duration::from_nanos(
                    setup_cutoff_nanos.saturating_sub(super::clock::monotonic_nanos()?),
                )
            };
            let cutoff = Instant::now()
                .checked_add(allowance)
                .ok_or("workload relay cutoff exceeds native range")?;
            let frame = match super::workload_inputs::read_frame_until(frontend, cutoff) {
                Ok(frame) => frame,
                Err(_) => {
                    broker
                        .shutdown(std::net::Shutdown::Write)
                        .map_err(|e| e.to_string())?;
                    frontend_closed = true;
                    continue;
                }
            };
            if frame.nonce != assigned.nonce || frame.attempt_id != assigned.attempt_id {
                broker
                    .shutdown(std::net::Shutdown::Write)
                    .map_err(|e| e.to_string())?;
                return Err("workload frontend crossed original native session".into());
            }
            if input_complete && !prepared_acknowledged {
                if frame.kind == MessageKind::WorkloadPreparedAck && prepared_sent {
                    write_frame_until(broker, &frame, cutoff)?;
                    prepared_acknowledged = true;
                } else if frame.kind == MessageKind::WorkloadCancel && frame.payload.is_empty() {
                    write_frame_until(broker, &frame, cutoff)?;
                    frontend_input_done = true;
                } else {
                    return Err("original prepared phase accepts only its exact acknowledgment or owner cancellation".into());
                }
            } else if prepared_acknowledged {
                if frame.kind != MessageKind::WorkloadCancel || !frame.payload.is_empty() {
                    broker
                        .shutdown(std::net::Shutdown::Write)
                        .map_err(|e| e.to_string())?;
                    return Err("only owner cancellation is accepted after complete input".into());
                }
                // The authenticated v5 cancellation becomes the existing private
                // native-owner control byte on this exclusive broker connection.
                loop {
                    if Instant::now() >= cutoff {
                        return Err("original cancellation delivery cutoff exhausted".into());
                    }
                    let byte = [1_u8];
                    let sent = unsafe {
                        libc::send(
                            broker.as_raw_fd(),
                            byte.as_ptr().cast(),
                            byte.len(),
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    };
                    if sent == 1 {
                        break;
                    }
                    let error = std::io::Error::last_os_error();
                    if sent == 0
                        || !matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        )
                    {
                        return Err(error.to_string());
                    }
                    std::thread::sleep(
                        Duration::from_millis(1)
                            .min(cutoff.saturating_duration_since(Instant::now())),
                    );
                }
                frontend_input_done = true;
            } else {
                if !matches!(
                    frame.kind,
                    MessageKind::WorkloadManifestChunk
                        | MessageKind::WorkloadMemberChunk
                        | MessageKind::WorkloadInputComplete
                        | MessageKind::WorkloadCancel
                ) {
                    return Err("unexpected workload input phase message".into());
                }
                input_complete = frame.kind == MessageKind::WorkloadInputComplete;
                write_frame_until(broker, &frame, cutoff)?;
            }
        }
        if polls[0].revents != 0 {
            let frame_cutoff = if prepared_acknowledged {
                Instant::now() + Duration::from_secs(1)
            } else {
                ingress_cutoff(setup_cutoff_nanos)?.min(Instant::now() + Duration::from_secs(1))
            };
            let frame = super::workload_inputs::read_frame_until(broker, frame_cutoff)?;
            if frame.nonce != assigned.nonce || frame.attempt_id != assigned.attempt_id {
                return Err("native workload response association differs".into());
            }
            if !matches!(
                frame.kind,
                MessageKind::WorkloadProgress
                    | MessageKind::WorkloadPrepared
                    | MessageKind::WorkloadOutputInventory
                    | MessageKind::WorkloadOutputChunk
                    | MessageKind::WorkloadTerminal
                    | MessageKind::WorkloadRejected
            ) {
                return Err("unexpected native workload response phase".into());
            }
            if frame.kind == MessageKind::WorkloadPrepared {
                if !input_complete || prepared_sent || prepared_acknowledged {
                    return Err(
                        "native prepared observation repeated or preceded complete input".into(),
                    );
                }
                prepared_sent = true;
            }
            if !frontend_closed {
                write_frame_until(frontend, &frame, frame_cutoff)?;
            }
            if matches!(
                frame.kind,
                MessageKind::WorkloadTerminal | MessageKind::WorkloadRejected
            ) {
                return Ok(());
            }
        }
    }
}

fn ingress_cutoff(nanos: u64) -> Result<Instant, String> {
    let remaining = nanos.saturating_sub(super::clock::monotonic_nanos()?);
    if remaining == 0 {
        return Err("original workload ingress cutoff exhausted".into());
    }
    Instant::now()
        .checked_add(Duration::from_nanos(remaining))
        .ok_or_else(|| "workload ingress cutoff exceeds native range".into())
}

pub(super) fn protected_directory(
    path: &std::path::Path,
    create: bool,
) -> Result<std::fs::File, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|e| e.to_string())?;
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            if component == std::path::Component::RootDir {
                continue;
            }
            return Err("unsafe fixed workload state path".into());
        };
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
        if create
            && unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        use std::os::fd::FromRawFd;
        parent = unsafe { std::fs::File::from_raw_fd(raw) };
        let metadata = parent.metadata().map_err(|e| e.to_string())?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("workload state ancestor custody differs".into());
        }
    }
    Ok(parent)
}
pub(super) fn create_input_staging(attempt: &str) -> Result<std::fs::File, String> {
    let parent = protected_directory(
        std::path::Path::new(super::workload_attempt::INPUT_ROOT),
        true,
    )?;
    if !super::cgroup::valid_attempt_identity(attempt) {
        return Err("invalid assigned input staging identity".into());
    }
    let name = std::ffi::CString::new(attempt).map_err(|e| e.to_string())?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let path = super::workload_attempt::input_path(attempt)?;
    let file = protected_directory(&path, false)?;
    parent.sync_all().map_err(|e| e.to_string())?;
    Ok(file)
}
pub(super) fn create_export_directory(parent: &std::fs::File) -> Result<std::fs::File, String> {
    use std::os::fd::FromRawFd;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), c"exports".as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c"exports".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(raw) })
}
pub(super) fn retire_input_staging(
    root: std::fs::File,
    attempt: &str,
    deadline: Instant,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    fn clear(
        directory: &std::fs::File,
        remaining: &mut usize,
        deadline: Instant,
    ) -> Result<(), String> {
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let held = std::path::Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string());
        for entry in std::fs::read_dir(held).map_err(|e| e.to_string())? {
            if Instant::now() >= deadline {
                return Err("original input retirement cutoff expired".into());
            }
            *remaining = remaining
                .checked_sub(1)
                .ok_or("input retirement inventory bound exceeded")?;
            let entry = entry.map_err(|e| e.to_string())?;
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if metadata.uid() != 0 {
                return Err("input retirement entry custody differs".into());
            }
            let name =
                std::ffi::CString::new(entry.file_name().as_bytes()).map_err(|e| e.to_string())?;
            let flags = if metadata.is_dir() {
                let raw = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw < 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                let child = unsafe { std::fs::File::from_raw_fd(raw) };
                let current = child.metadata().map_err(|e| e.to_string())?;
                if (current.dev(), current.ino()) != (metadata.dev(), metadata.ino())
                    || current.mode() & 0o077 != 0
                {
                    return Err("input retirement directory inode changed".into());
                }
                clear(&child, remaining, deadline)?;
                libc::AT_REMOVEDIR
            } else if (metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o022 == 0)
                || metadata.file_type().is_symlink()
            {
                0
            } else {
                return Err("input retirement found unexpected native object".into());
            };
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        directory.sync_all().map_err(|e| e.to_string())
    }
    if !super::cgroup::valid_attempt_identity(attempt) {
        return Err("invalid original input retirement identity".into());
    }
    clear(&root, &mut (2 * 16384 * 65 + 128), deadline)?;
    let parent = protected_directory(
        std::path::Path::new(super::workload_attempt::INPUT_ROOT),
        false,
    )?;
    let named = protected_directory(&super::workload_attempt::input_path(attempt)?, false)?;
    let a = root.metadata().map_err(|e| e.to_string())?;
    let b = named.metadata().map_err(|e| e.to_string())?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err("original input staging inode changed before retirement".into());
    }
    let name = std::ffi::CString::new(attempt).map_err(|e| e.to_string())?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    drop(named);
    drop(root);
    parent.sync_all().map_err(|e| e.to_string())
}

pub(super) fn execute_brokered(
    stream: &mut UnixStream,
    frame: &Frame,
    descriptors: Vec<OwnedFd>,
    control_pid: i32,
    control_birth: u64,
) -> Result<Frame, String> {
    use super::native_process::{PrivateAttemptPhase, ProcessIdentityV4};
    use memcordon_core::result_v3::*;
    use std::os::fd::FromRawFd;
    let setup = (|| -> Result<_, String> {
        if frame.kind != MessageKind::WorkloadBrokerStart || descriptors.len() != 7 {
            return Err("current workload requires exact authenticated native resources".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&frame.payload)?;
        let envelope: WorkloadBrokerV1 =
            serde_json::from_slice(&frame.payload).map_err(|e| e.to_string())?;
        if envelope.format != "memcordon.workload-broker" || envelope.revision != 1 {
            return Err("unsupported current native broker envelope".into());
        }
        envelope
            .start
            .request
            .validate()
            .map_err(|e| e.to_string())?;
        let broker = crate::request::decode_launch_broker_request(&envelope.native_broker)
            .map_err(|e| format!("native broker request: {e:?}"))?;
        let launch = crate::request::decode_launch_request(&envelope.start.native_launch)
            .map_err(|e| format!("current native launch: {e:?}"))?;
        if broker.attempt_id != frame.attempt_id
            || broker.control_process_id != control_pid
            || broker.control_process_start_time != control_birth
            || broker.launch != launch
            || broker.descriptor_manifest != super::launcher::broker_descriptor_manifest()
        {
            return Err("original native control/invocation association differs".into());
        }
        let account = super::workload_account::verify()?;
        if broker.caller.uid == account.uid() {
            return Err("sandbox account cannot become a workload caller".into());
        }
        super::envelope::verify_live(&broker.caller)?;
        let caller = super::envelope::capture(
            broker.caller.pid,
            broker.caller.uid,
            broker.caller.gid,
            &broker.caller.supplementary_groups,
            descriptors[0].as_fd(),
        )?;
        if caller.envelope != broker.caller
            || !super::envelope::namespace_descriptor_matches(
                descriptors[5].as_fd(),
                broker.caller.mount_namespace_identity,
            )?
            || !super::envelope::descriptor_matches(
                descriptors[6].as_fd(),
                broker.caller.root_identity,
            )?
        {
            return Err("original held caller custody changed".into());
        }
        let frontend = ProcessIdentityV4::observe(broker.caller.pid, descriptors[4].as_fd())?;
        if frontend.start_time != broker.caller.process_start_time {
            return Err("original frontend birth differs".into());
        }
        let pid = unsafe { libc::getpid() };
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let worker_fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let worker = ProcessIdentityV4::observe(pid, worker_fd.as_fd())?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, control_pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let control_fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let control = ProcessIdentityV4::observe(control_pid, control_fd.as_fd())?;
        if control.start_time != control_birth {
            return Err("original authenticated control birth changed".into());
        }
        let provider = super::runtime_manifest::installed_binding()?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|e| e.to_string())?;
        let association = memcordon_core::workload_request::WorkloadAttemptAssociationV1 {
            format: "memcordon.workload-attempt".into(),
            revision: 1,
            attempt: frame.attempt_id,
            challenge: frame.nonce,
            request_sha256: envelope.start.request.digest().map_err(|e| e.to_string())?,
            boot_id: memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
            provider,
            control: memcordon_core::execution_facts::NativeProcessV2 {
                pid: control.pid,
                birth: control.start_time,
            },
        };
        let memcordon_core::workload_request::RuntimeRequestV1::LinuxPrivate {
            inputs, layout, ..
        } = &envelope.start.request.runtime
        else {
            return Err("unsupported Linux runtime requirement".into());
        };
        if launch.program != inputs.entrypoint.as_str().as_bytes() {
            return Err("request entrypoint and actual invocation differ".into());
        }
        let request = WorkloadRequestAssociationV1 {
            request_sha256: association.request_sha256.clone(),
            invocation_sha256: memcordon_core::workload_request::invocation_digest(
                &envelope.start.native_launch,
                envelope.start.working_directory.as_ref(),
            )
            .map_err(|error| error.to_string())?,
            resource_policy_sha256: memcordon_core::workload_request::resource_policy_digest(
                &envelope.start.native_launch,
                envelope.start.attempt_deadline_millis,
            )
            .map_err(|e| e.to_string())?,
            runtime_sha256: Some(inputs.runtime_digest.clone()),
            input_sha256: Some(inputs.input_digest.clone()),
        };
        let now = super::clock::monotonic_nanos()?;
        if envelope.setup_cutoff_nanos <= now
            || envelope.setup_cutoff_nanos
                > now
                    .checked_add(30_000_000_000)
                    .ok_or("native setup cutoff overflow")?
        {
            return Err("original setup cutoff is unavailable or excessive".into());
        }
        let mut allowance = envelope.setup_cutoff_nanos - now;
        if let Some(absolute) = launch.policy.absolute_deadline_millis {
            let remaining = absolute
                .saturating_sub(super::clock::monotonic_millis()?)
                .checked_mul(1_000_000)
                .ok_or("native run deadline overflow")?;
            allowance = allowance.min(remaining);
        }
        let cutoff = Instant::now()
            .checked_add(Duration::from_nanos(allowance))
            .ok_or("native setup cutoff exceeds range")?;
        let attempt: String = frame
            .attempt_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let record = super::workload_attempt::WorkloadAttemptRecordV1 {
            format: "memcordon.private-workload-journal".into(),
            revision: 1,
            attempt_id: memcordon_core::BoundedText::new(&attempt).map_err(str::to_owned)?,
            boot_id: association.boot_id.clone(),
            phase: PrivateAttemptPhase::Allocated,
            release: ReleaseKnowledgeV3::NotReleased,
            cleanup_cutoff_nanos: None,
            cleanup_boot_id: None,
            request_sha256: association.request_sha256.clone(),
            association: association.clone(),
            request: request.clone(),
            native: None,
            outcome: None,
            terminal: None,
            caller_uid: broker.caller.uid,
            frontend,
            worker,
            control,
            intents: super::workload_attempt::AllocationIntentsV1::default(),
            guardian: None,
            namespace_init: None,
            target: None,
            cgroup: None,
            staging: None,
            input_staging: None,
            root: None,
            network_namespace_inode: None,
            output_files: layout.output_files.clone(),
            outstanding: memcordon_core::BoundedVec::default(),
            errors: memcordon_core::BoundedVec::default(),
        };
        Ok((
            envelope.start,
            launch,
            caller,
            account,
            worker_fd,
            control_fd,
            association,
            record,
            cutoff,
        ))
    })();
    let (start, launch, caller, account, worker_fd, _control_fd, association, record, cutoff) =
        match setup {
            Ok(value) => value,
            Err(error) => {
                return rejection(frame, WorkloadRejectionCodeV1::NativeUnavailable, &error);
            }
        };
    let _package = super::service::acquire_shared_package_lease()?;
    let progress = Frame {
        kind: MessageKind::WorkloadProgress,
        nonce: frame.nonce,
        attempt_id: frame.attempt_id,
        payload: serde_json::to_vec(&association).map_err(|e| e.to_string())?,
    };
    write_frame_until(stream, &progress, cutoff)?;
    // The frontend persists the assigned locator before sending its first manifest.
    // No target/native filesystem is allocated before that continuation arrives.
    let mut ready = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    while ready.revents == 0 {
        if Instant::now() >= cutoff {
            return Err("original workload continuation cutoff expired before allocation".into());
        }
        if unsafe { libc::poll(&mut ready, 1, 10) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let receiver = match super::workload_resources::ReceiverSlot::acquire() {
        Ok(receiver) => receiver,
        Err(super::workload_resources::ReceiverSlotError::CapacityUnavailable) => {
            return rejection(
                frame,
                WorkloadRejectionCodeV1::InputCapacityUnavailable,
                "all bounded native image receiver slots are occupied",
            );
        }
        Err(super::workload_resources::ReceiverSlotError::Native(detail)) => {
            return rejection(frame, WorkloadRejectionCodeV1::NativeUnavailable, &detail);
        }
    };
    let directory = match protected_directory(
        std::path::Path::new(super::workload_attempt::JOURNAL_ROOT),
        true,
    ) {
        Ok(directory) => directory,
        Err(error) => return rejection(frame, WorkloadRejectionCodeV1::NativeUnavailable, &error),
    };
    let mut journal =
        match super::workload_attempt::DurableWorkloadAttempt::create(directory, record) {
            Ok(journal) => journal,
            Err(error) => {
                return rejection(frame, WorkloadRejectionCodeV1::NativeUnavailable, &error);
            }
        };
    journal.input_staging_intent()?;
    let attempt = journal.record().attempt_id.as_str().to_owned();
    let staging = create_input_staging(&attempt)?;
    use std::os::unix::fs::MetadataExt;
    let metadata = staging.metadata().map_err(|e| e.to_string())?;
    journal.record_input_staging(super::workload_attempt::DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })?;
    let available = available_footprint(&staging)?;
    let inputs = match super::workload_inputs::receive_framed(
        stream,
        &association,
        cutoff,
        staging,
        &start.request,
        available,
        receiver,
    ) {
        Ok(inputs) => inputs,
        Err(failure) => return intake_failure(frame, journal, failure),
    };
    let mut handles = descriptors.into_iter();
    drop(handles.next());
    let streams = [
        handles.next().ok_or("stdin descriptor absent")?,
        handles.next().ok_or("stdout descriptor absent")?,
        handles.next().ok_or("stderr descriptor absent")?,
    ];
    let frontend = handles.next().ok_or("frontend pidfd absent")?;
    drop(handles);
    let owner = super::private_lifecycle::PrivateAttemptOwner::new(journal)?;
    let terminal = owner.execute_workload(
        stream,
        start,
        launch,
        caller,
        account,
        worker_fd,
        frontend,
        streams,
        association,
        inputs,
        cutoff,
    )?;
    Ok(Frame {
        kind: MessageKind::WorkloadTerminal,
        nonce: frame.nonce,
        attempt_id: frame.attempt_id,
        payload: serde_json::to_vec(&terminal).map_err(|e| e.to_string())?,
    })
}

fn available_footprint(directory: &std::fs::File) -> Result<u64, String> {
    let mut disk = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), disk.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let disk = unsafe { disk.assume_init() };
    let disk_free = disk
        .f_bavail
        .checked_mul(disk.f_frsize)
        .ok_or("available staging space overflow")?;
    let mut memory = std::mem::MaybeUninit::<libc::sysinfo>::uninit();
    if unsafe { libc::sysinfo(memory.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let memory = unsafe { memory.assume_init() };
    let memory_free = memory
        .freeram
        .checked_mul(u64::from(memory.mem_unit))
        .ok_or("available root memory overflow")?;
    // Staging disk and private tmpfs memory are distinct capacities. Charging
    // the combined bound against the smaller capacity is conservative for both.
    Ok(disk_free.min(memory_free))
}
pub(super) fn write_frame_until(
    stream: &mut UnixStream,
    frame: &Frame,
    deadline: Instant,
) -> Result<(), String> {
    struct Until<'a> {
        stream: &'a mut UnixStream,
        deadline: Instant,
    }
    impl std::io::Write for Until<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "original workload delivery cutoff expired",
                ));
            }
            self.stream.set_write_timeout(Some(remaining))?;
            std::io::Write::write(self.stream, bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            std::io::Write::flush(self.stream)
        }
    }
    crate::protocol::write_frame(&mut Until { stream, deadline }, frame).map_err(|e| e.to_string())
}
pub(super) fn send_outputs(
    stream: &mut UnixStream,
    association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    directory: &std::fs::File,
    inventory: &memcordon_core::BoundedVec<memcordon_core::result_v3::WorkloadOutputFileV1, 64>,
    deadline: Instant,
) -> Result<(), String> {
    use std::io::Read;
    let frame = Frame {
        kind: MessageKind::WorkloadOutputInventory,
        nonce: association.challenge,
        attempt_id: association.attempt,
        payload: serde_json::to_vec(inventory).map_err(|e| e.to_string())?,
    };
    write_frame_until(stream, &frame, deadline)?;
    let mut bytes = vec![0; memcordon_core::workload_chunks::OUTPUT_CHUNK_DATA_BYTES];
    for (index, entry) in inventory.as_slice().iter().enumerate() {
        let mut file =
            super::workload_snapshot::open_relative(directory.as_fd(), &entry.path, false)?;
        let mut offset = 0_u64;
        while offset < entry.size {
            let amount = usize::try_from(
                (entry.size - offset).min(u64::try_from(bytes.len()).expect("buffer length fits")),
            )
            .expect("bounded amount fits");
            file.read_exact(&mut bytes[..amount])
                .map_err(|e| e.to_string())?;
            let chunk = memcordon_core::workload_chunks::WorkloadOutputChunkV1 {
                file_index: u32::try_from(index).map_err(|_| "output index overflow")?,
                total: entry.size,
                offset,
                bytes: &bytes[..amount],
            };
            let frame = Frame {
                kind: MessageKind::WorkloadOutputChunk,
                nonce: association.challenge,
                attempt_id: association.attempt,
                payload: chunk.encode()?,
            };
            write_frame_until(stream, &frame, deadline)?;
            offset = offset
                .checked_add(u64::try_from(amount).expect("bounded amount fits"))
                .ok_or("output transfer offset overflow")?;
        }
    }
    Ok(())
}
fn intake_failure(
    frame: &Frame,
    mut journal: super::workload_attempt::DurableWorkloadAttempt,
    failure: super::workload_inputs::InputFailure,
) -> Result<Frame, String> {
    use memcordon_core::result_v3::*;
    let cutoff = journal.begin_cleanup(
        super::clock::monotonic_nanos()?
            .checked_add(10_000_000_000)
            .ok_or("cleanup cutoff overflow")?,
    )?;
    let deadline = Instant::now()
        .checked_add(Duration::from_nanos(
            cutoff.saturating_sub(super::clock::monotonic_nanos()?),
        ))
        .ok_or("cleanup cutoff exceeds native range")?;
    let mut failures = memcordon_core::BoundedVec::default();
    failures
        .try_push(memcordon_core::BoundedText::new(&failure.cause).map_err(str::to_owned)?)
        .map_err(|_| "failure inventory full")?;
    let mut settled = true;
    let attempt = journal.record().attempt_id.as_str().to_owned();
    if let Some(staging) = failure.staging {
        if let Err(error) = retire_input_staging(staging, &attempt, deadline) {
            settled = false;
            failures
                .try_push(memcordon_core::BoundedText::new(&error).map_err(str::to_owned)?)
                .map_err(|_| "failure inventory full")?;
        }
    }
    if let Some(charge) = failure.footprint {
        if settled {
            if let Err(error) = charge.retire() {
                settled = false;
                failures
                    .try_push(memcordon_core::BoundedText::new(&error).map_err(str::to_owned)?)
                    .map_err(|_| "failure inventory full")?;
            }
        }
    } else {
        let path = std::path::Path::new(super::workload_resources::RESOURCE_ROOT).join(&attempt);
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => settled = false,
        }
    }
    let mut obligations = memcordon_core::BoundedVec::default();
    for resource in [
        CleanupResourceV3::Staging,
        CleanupResourceV3::Footprint,
        CleanupResourceV3::Record,
    ] {
        obligations
            .try_push(CleanupObligationV3 { resource, settled })
            .map_err(|_| "cleanup inventory full")?;
    }
    let terminal = LinuxWorkloadTerminalV1 {
        format: LINUX_WORKLOAD_TERMINAL_FORMAT.into(),
        revision: 1,
        association: journal.record().association.clone(),
        request: journal.record().request.clone(),
        release: ReleaseKnowledgeV3::NotReleased,
        native: None,
        outcome: NativeWorkloadOutcomeV1::SetupFailure,
        cleanup: CleanupV3 {
            state: if settled {
                memcordon_core::execution_facts::CleanupStateV1::Complete
            } else {
                memcordon_core::execution_facts::CleanupStateV1::Incomplete
            },
            obligations,
        },
        output_delivery: OutputDeliveryStateV3::Incomplete,
        failures,
    };
    journal.finish(terminal.clone())?;
    Ok(Frame {
        kind: MessageKind::WorkloadTerminal,
        nonce: frame.nonce,
        attempt_id: frame.attempt_id,
        payload: serde_json::to_vec(&terminal).map_err(|e| e.to_string())?,
    })
}
