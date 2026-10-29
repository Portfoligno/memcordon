//! Original-process capture and settlement for current workload requests.
use super::linux_request_fixture::{CallerRequestFixture, CallerSession};
use crate::linux_consumer_readiness::HeldLinuxProcess;
use crate::{CiError, Result};
use memcordon_core::result_v3::{LinuxWorkloadTerminalV1, ResultV3};
use memcordon_core::workload_request::WorkloadAttemptAssociationV1;
use memcordon_core::{DiagnosticSha256, PublicProviderBindingV1};
use memcordon_testkit::ObservedOutput;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub struct LaunchInput<'a> {
    pub extra_descriptor: Option<&'a File>,
    pub lifetime: memcordon_core::Lifetime,
    pub controller_directory: &'a Path,
    pub observation_directory: Option<&'a Path>,
    pub stdin: Option<&'a File>,
    pub interactive: bool,
    pub caller: &'a CallerSession,
    pub fixture: &'a CallerRequestFixture,
    pub directory: &'a Path,
    pub provider: &'a PublicProviderBindingV1,
    pub entrypoint: &'a OsStr,
    pub arguments: &'a [OsString],
    pub memory: &'a OsStr,
    pub deadline: &'a OsStr,
    pub output_directory: Option<&'a Path>,
    pub work_cutoff: Instant,
    pub cleanup_cutoff: Instant,
}

/// The subprocess supervisor owns its original Child until actual reap; the
/// native observer holds a pidfd acquired from that Child before its sole wait.
/// Persisted locators never construct either native owner.
pub struct RequestLaunch {
    caller: CallerSession,
    directory: File,
    path: PathBuf,
    request: DiagnosticSha256,
    bundle_identity: (u64, u64),
    provider: PublicProviderBindingV1,
    cleanup_cutoff: Instant,
    observer: Receiver<std::result::Result<HeldLinuxProcess, String>>,
    frontend: Option<HeldLinuxProcess>,
    capture: Option<JoinHandle<Result<ObservedOutput>>>,
    observed: Option<ObservedOutput>,
    input: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    snapshots: Receiver<memcordon_testkit::OutputSnapshot>,
    snapshot: Option<memcordon_testkit::OutputSnapshot>,
    recoveries: std::sync::atomic::AtomicU64,
}

pub struct RecoveryObservation {
    pub terminal: LinuxWorkloadTerminalV1,
    pub process: ObservedOutput,
    pub raw_terminal: Vec<u8>,
}

impl RequestLaunch {
    pub fn retire_bundle_exact(&self, fixture: &CallerRequestFixture) -> Result<()> {
        if self.capture.is_some()
            || self.observed.is_none()
            || self.request != fixture.request_sha256
            || self.bundle_identity != fixture.bundle_identity()?
        {
            return Err(CiError::Message(
                "bundle retirement requires original settled frontend capture and exact request"
                    .into(),
            ));
        }
        fixture.retire_bundle_exact()
    }
    pub fn start(input: LaunchInput<'_>) -> Result<Self> {
        Self::start_inner(input, None, None)
    }
    pub fn start_with_loader_path(input: LaunchInput<'_>, path: &Path) -> Result<Self> {
        Self::start_inner(input, Some(path), None)
    }
    pub fn start_with_copy_observer(
        input: LaunchInput<'_>,
        observer: Box<dyn FnOnce(&std::process::Child) -> Result<()> + Send>,
    ) -> Result<Self> {
        if input.interactive || input.stdin.is_some() || input.extra_descriptor.is_some() {
            return Err(CiError::Message(
                "copy observer requires an ordinary noninteractive original frontend".into(),
            ));
        }
        Self::start_inner(input, None, Some(observer))
    }
    fn start_inner(
        input: LaunchInput<'_>,
        loader_path: Option<&Path>,
        copy_observer: Option<Box<dyn FnOnce(&std::process::Child) -> Result<()> + Send>>,
    ) -> Result<Self> {
        let bundle_identity = input.fixture.bundle_identity()?;
        let extra = input.extra_descriptor.map(File::try_clone).transpose()?;
        let extra_identity=extra.as_ref().map(|file|->std::io::Result<serde_json::Value>{let metadata=file.metadata()?;let flags=rustix::fs::fcntl_getfl(file).map_err(std::io::Error::from)?.bits();Ok(serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"mode":metadata.mode(),"uid":metadata.uid(),"flags":flags,"target_descriptor":128}))}).transpose()?;
        use std::os::unix::fs::FileTypeExt;
        let native_socket_stdin = input
            .stdin
            .map(|file| {
                file.metadata()
                    .map(|metadata| metadata.file_type().is_socket())
            })
            .transpose()?
            .unwrap_or(false);
        let stdin_identity = if native_socket_stdin {
            let metadata = input.stdin.expect("held socket stdin").metadata()?;
            Some(
                serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"mode":metadata.mode(),"uid":metadata.uid(),"flags":rustix::fs::fcntl_getfl(input.stdin.expect("held socket stdin")).map_err(std::io::Error::from)?.bits(),"target_descriptor":0}),
            )
        } else {
            None
        };
        let controller = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(input.controller_directory)?;
        let metadata = controller.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "original frontend controller directory custody differs".into(),
            ));
        }
        let creator_pid = std::process::id();
        let creator_birth = crate::linux_consumer_readiness::process_birth(creator_pid)
            .map_err(CiError::Message)?;
        let creator =
            HeldLinuxProcess::acquire(creator_pid, creator_birth).map_err(CiError::Message)?;
        let original = serde_json::json!({"format":"memcordon.current-original-frontend","revision":1,"provider":input.provider,"request_sha256":input.fixture.request_sha256,"caller_uid":input.caller.uid,"caller_gid":input.caller.gid,"installed_cli":input.caller.installed_cli,"creator":{"pid":creator_pid,"birth":creator_birth}});
        write_record(
            &controller,
            "frontend-creation-intent.json",
            &serde_json::to_vec(&original)?,
        )?;
        controller.sync_all()?;
        if Instant::now() >= input.work_cutoff
            || input.work_cutoff >= input.cleanup_cutoff
            || !input.directory.is_absolute()
        {
            return Err(CiError::Message(
                "request fixture original phase cutoff/path invalid".into(),
            ));
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(input.directory)?;
        if directory.metadata()?.uid() != input.caller.uid {
            return Err(CiError::Message(
                "request launch directory caller differs".into(),
            ));
        }
        let mut command = input
            .caller
            .command(input.directory, input.work_cutoff)?
            .arg(input.memory)
            .arg(input.deadline)
            .arg("--lifetime")
            .arg(match input.lifetime {
                memcordon_core::Lifetime::Command => "command",
                memcordon_core::Lifetime::Workload => "workload",
            })
            .arg("--sealed")
            .arg("--workload-request")
            .arg(&input.fixture.request)
            .arg("--workload-input")
            .arg(&input.fixture.bundle)
            .arg("--workload-observation")
            .arg(input.directory.join("workload-observation.json"))
            .arg("--image-entrypoint")
            .arg(input.entrypoint)
            .arg("--report-format")
            .arg("result-v3")
            .arg("--report")
            .arg(input.directory.join("workload-result.json"))
            .output_limit(32 * 1024 * 1024);
        if let Some(path) = loader_path {
            command = command.workload_loader_path(path);
        }
        if let Some(output) = input.output_directory {
            command = command.arg("--workload-output").arg(output);
        }
        if let Some(directory) = input.observation_directory {
            command = command
                .arg("--workload-observation-directory")
                .arg(directory);
        }
        command = command.arg("--").args(input.arguments.iter().cloned());
        write_record(
            &directory,
            "launch-intent.json",
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.request-fixture-launch-intent","revision":1,
                "request_sha256":input.fixture.request_sha256,"provider":input.provider,
                "native_cleanup":"pending-actual-observation"
            }))?,
        )?;
        let stdin = input.stdin.map(File::try_clone).transpose()?;
        if input.interactive && stdin.is_some() {
            return Err(CiError::Message(
                "interactive and finite fixture input cannot be combined".into(),
            ));
        }
        let (input_sender, input_receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(4);
        let (snapshot_sender, snapshots) = std::sync::mpsc::sync_channel(1);
        let interactive = input.interactive;
        let work_cutoff = input.work_cutoff;
        let (sender, observer) = std::sync::mpsc::sync_channel(1);
        let capture = std::thread::spawn(move || {
            let observe = |child: &std::process::Child| {
                let held = crate::linux_consumer_readiness::process_birth(child.id())
                    .and_then(|birth| HeldLinuxProcess::acquire(child.id(), birth))
                    .and_then(|mut held| {
                        held.verify_parent(&creator)?;
                        Ok(held)
                    });
                let observed_error = held.as_ref().err().cloned();
                if let Ok(held) = &held {
                    let mut record = original.clone();
                    for (name, expected, descriptor) in [
                        ("extra_descriptor", extra_identity.as_ref(), 128),
                        ("stdin_descriptor", stdin_identity.as_ref(), 0),
                    ] {
                        if let Some(expected) = expected {
                            let observed =
                                std::fs::metadata(format!("/proc/{}/fd/{descriptor}", child.id()))?;
                            if expected["device"] != observed.dev()
                                || expected["inode"] != observed.ino()
                                || expected["mode"] != observed.mode()
                            {
                                return Err(CiError::Message(
                                    "original frontend descriptor differs from retained source"
                                        .into(),
                                ));
                            }
                            record[name] = expected.clone();
                            let fdinfo = std::fs::read_to_string(format!(
                                "/proc/{}/fdinfo/{descriptor}",
                                child.id()
                            ))?;
                            let flags = fdinfo
                                .lines()
                                .find_map(|line| line.strip_prefix("flags:"))
                                .ok_or_else(|| {
                                    CiError::Message(
                                        "original frontend native descriptor flags absent".into(),
                                    )
                                })?;
                            let flags = u64::from_str_radix(flags.trim(), 8)
                                .map_err(|error| CiError::Message(error.to_string()))?;
                            if flags & !(libc::O_CLOEXEC as u64)
                                != expected["flags"].as_u64().ok_or_else(|| {
                                    CiError::Message("held source descriptor flags absent".into())
                                })?
                            {
                                return Err(CiError::Message(
                                    "original frontend descriptor flags differ from held source"
                                        .into(),
                                ));
                            }
                            record[name]["fdinfo"] = fdinfo.into();
                        }
                    }
                    record["process"] =
                        serde_json::json!({"pid":held.process_id,"birth":held.birth});
                    write_record(
                        &controller,
                        "original-frontend.json",
                        &serde_json::to_vec(&record)?,
                    )?;
                    controller.sync_all()?;
                }
                sender.send(held).map_err(|_| {
                    CiError::Message("original frontend observer receiver lost".into())
                })?;
                match observed_error {
                    Some(error) => Err(CiError::Message(error)),
                    None => Ok(()),
                }
            };
            if interactive {
                command.output_quiet_with_creation_and_io_descriptor(
                    extra.as_ref(),
                    observe,
                    move |_, stdin, snapshot| {
                        snapshot_sender.send(snapshot).map_err(|_| {
                            std::io::Error::other("original fixture snapshot controller lost")
                        })?;
                        let mut stdin = stdin.ok_or_else(|| {
                            std::io::Error::other("original fixture stdin absent")
                        })?;
                        let flags =
                            rustix::fs::fcntl_getfl(&stdin).map_err(std::io::Error::from)?;
                        rustix::fs::fcntl_setfl(&stdin, flags | rustix::fs::OFlags::NONBLOCK)
                            .map_err(std::io::Error::from)?;
                        loop {
                            let remaining = work_cutoff.saturating_duration_since(Instant::now());
                            if remaining.is_zero() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "original fixture input cutoff expired",
                                ));
                            }
                            let bytes = match input_receiver
                                .recv_timeout(remaining.min(Duration::from_millis(10)))
                            {
                                Ok(bytes) => bytes,
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                    return Ok(());
                                }
                            };
                            let mut offset = 0;
                            while offset < bytes.len() {
                                if Instant::now() >= work_cutoff {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        "original fixture gate write cutoff expired",
                                    ));
                                }
                                match stdin.write(&bytes[offset..]) {
                                    Ok(0) => {
                                        return Err(std::io::Error::new(
                                            std::io::ErrorKind::WriteZero,
                                            "original fixture stdin closed",
                                        ));
                                    }
                                    Ok(written) => offset += written,
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::WouldBlock =>
                                    {
                                        std::thread::sleep(Duration::from_millis(1))
                                    }
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::Interrupted => {}
                                    Err(error) => return Err(error),
                                }
                            }
                        }
                    },
                )
            } else {
                match stdin {
                    Some(supplied) if native_socket_stdin => command
                        .output_quiet_with_native_socket_stdin_and_creation(
                            &supplied,
                            extra.as_ref(),
                            observe,
                        ),
                    Some(supplied) => command.output_quiet_with_creation_and_io_descriptor(
                        extra.as_ref(),
                        observe,
                        move |_, stdin, _| {
                            let size = supplied.metadata()?.len();
                            if size > 65536 {
                                return Err(std::io::Error::other(
                                    "finite original fixture input exceeds bound",
                                ));
                            }
                            let mut stdin = stdin.ok_or_else(|| {
                                std::io::Error::other("finite fixture native stdin absent")
                            })?;
                            if std::io::copy(&mut supplied.take(size + 1), &mut stdin)? != size {
                                return Err(std::io::Error::other(
                                    "finite original fixture input length changed",
                                ));
                            }
                            Ok(())
                        },
                    ),
                    None if extra.is_some() => command
                        .output_quiet_with_creation_and_io_descriptor(
                            extra.as_ref(),
                            observe,
                            |_, _, _| Ok(()),
                        ),
                    None => match copy_observer {
                        Some(observer) => {
                            command.output_quiet_with_exec_release_observation(observe, observer)
                        }
                        None => command.output_quiet_with_exec_observation(observe),
                    },
                }
            }
        });
        // There are no fallible operations after spawn that could discard the
        // supervisor or original observer while remote native cleanup is due.
        Ok(Self {
            caller: input.caller.clone(),
            directory,
            path: input.directory.into(),
            request: input.fixture.request_sha256.clone(),
            bundle_identity,
            provider: input.provider.clone(),
            cleanup_cutoff: input.cleanup_cutoff,
            observer,
            frontend: None,
            capture: Some(capture),
            observed: None,
            input: if interactive {
                Some(input_sender)
            } else {
                None
            },
            snapshots,
            snapshot: None,
            recoveries: std::sync::atomic::AtomicU64::new(0),
        })
    }
    pub fn snapshot_until(&mut self, cutoff: Instant) -> Result<memcordon_testkit::OutputSnapshot> {
        if self.snapshot.is_none() {
            let remaining = cutoff
                .min(self.cleanup_cutoff)
                .saturating_duration_since(Instant::now());
            self.snapshot = Some(self.snapshots.recv_timeout(remaining).map_err(|e| {
                CiError::Message(format!("original fixture capture snapshot absent: {e}"))
            })?);
        }
        Ok(self
            .snapshot
            .as_ref()
            .expect("actual snapshot retained")
            .clone())
    }
    pub fn send_input(&self, bytes: Vec<u8>) -> Result<()> {
        if bytes.len() > 65536 {
            return Err(CiError::Message("fixture gate input exceeds bound".into()));
        }
        self.input
            .as_ref()
            .ok_or_else(|| CiError::Message("interactive fixture input is closed".into()))?
            .try_send(bytes)
            .map_err(|e| CiError::Message(format!("original fixture gate queue unavailable: {e}")))
    }
    pub fn close_input(&mut self) {
        self.input.take();
    }
    pub fn capture_finished(&self) -> bool {
        self.capture
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
    }

    pub fn retain_frontend(&mut self, cutoff: Instant) -> Result<&HeldLinuxProcess> {
        if self.frontend.is_none() {
            let remaining = cutoff
                .min(self.cleanup_cutoff)
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    CiError::Message("original frontend observation cutoff exhausted".into())
                })?;
            self.frontend = Some(
                self.observer
                    .recv_timeout(remaining)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .map_err(CiError::Message)?,
            );
        }
        Ok(self.frontend.as_ref().expect("original frontend retained"))
    }

    pub fn association(&self) -> Result<WorkloadAttemptAssociationV1> {
        let bytes = read_record(
            &self.directory,
            "workload-observation.json",
            64 * 1024,
            self.caller.uid,
        )?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        let association: WorkloadAttemptAssociationV1 = serde_json::from_slice(&bytes)?;
        association
            .validate()
            .map_err(|error| CiError::Message(error.to_string()))?;
        if association.request_sha256 != self.request || association.provider != self.provider {
            return Err(CiError::Message(
                "original provider/request locator association differs".into(),
            ));
        }
        Ok(association)
    }

    pub fn capture_until(&mut self, cutoff: Instant) -> Result<&ObservedOutput> {
        while self
            .capture
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            let now = Instant::now();
            if now >= cutoff.min(self.cleanup_cutoff) {
                return Err(CiError::Message(
                    "original request capture cutoff exhausted; recovery remains due".into(),
                ));
            }
            std::thread::sleep(
                Duration::from_millis(10).min(cutoff.min(self.cleanup_cutoff) - now),
            );
        }
        if let Some(worker) = self.capture.take() {
            let observed = worker.join().map_err(|_| {
                CiError::Message(
                    "original frontend supervisor panicked; native cleanup unresolved".into(),
                )
            })??;
            self.observed = Some(observed);
            let retained = self
                .observed
                .as_ref()
                .expect("actual capture retained before publication");
            write_record(&self.directory, "stdout.bin", &retained.stdout)?;
            write_record(&self.directory, "stderr.bin", &retained.stderr)?;
        }
        self.observed
            .as_ref()
            .ok_or_else(|| CiError::Message("original frontend capture absent".into()))
    }

    /// Settle the original supervisor after an actor error. This does not claim
    /// that a later package drain reaped the original frontend or its readers.
    pub fn cancel_and_settle(&mut self, cutoff: Instant) -> Result<serde_json::Value> {
        let cutoff = cutoff.min(self.cleanup_cutoff);
        self.close_input();
        let mut failure = None;
        let mut frontend = None;
        let mut interrupted = false;
        match self.retain_frontend(cutoff) {
            Ok(process) => {
                frontend =
                    Some(serde_json::json!({"pid":process.process_id,"birth":process.birth}));
                match process.exited() {
                    Ok(true) => {}
                    Ok(false) => match process.signal_interrupt() {
                        Ok(Ok(())) => interrupted = true,
                        Ok(Err(code)) => {
                            failure = Some(format!("original frontend interrupt failed: {code}"))
                        }
                        Err(error) => failure = Some(error),
                    },
                    Err(error) => failure = Some(error),
                }
            }
            Err(error) => failure = Some(error.to_string()),
        }
        // Drain/join even if signalling failed; the primary actor error must
        // not bypass the existing Child owner and actual capture readers.
        let capture = self.capture_until(cutoff);
        let receipt = match capture {
            Ok(capture) => {
                use std::os::unix::process::ExitStatusExt;
                serde_json::json!({"format":"memcordon.current-request-settlement","revision":1,"frontend":frontend,"interrupt_sent":interrupted,
                    "raw_wait_status":capture.status.into_raw(),"stdout_sha256":super::artifacts::checksum(&capture.stdout),"stderr_sha256":super::artifacts::checksum(&capture.stderr),"signal_failure":failure})
            }
            Err(error) => {
                return Err(CiError::Message(match failure {
                    Some(first) => format!("{first}; original supervisor settlement: {error}"),
                    None => error.to_string(),
                }));
            }
        };
        write_record(
            &self.directory,
            "cleanup-settlement.json",
            &serde_json::to_vec(&receipt)?,
        )?;
        if let Some(error) = failure {
            return Err(CiError::Message(error));
        }
        Ok(receipt)
    }

    pub fn result(&mut self) -> Result<ResultV3> {
        if self.frontend.is_none() {
            self.frontend = Some(
                self.observer
                    .try_recv()
                    .map_err(|error| {
                        CiError::Message(format!(
                            "original native frontend observation absent: {error}"
                        ))
                    })?
                    .map_err(CiError::Message)?,
            );
        }
        let association = self.association()?;
        let result = ResultV3::parse(&read_record(
            &self.directory,
            "workload-result.json",
            memcordon_core::execution_facts::RESULT_MAX_BYTES,
            self.caller.uid,
        )?)
        .map_err(CiError::Message)?;
        if result.workload_attempt.as_ref() != Some(&association)
            || result.provider.as_ref() != Some(&self.provider)
            || result
                .request
                .as_ref()
                .map(|request| &request.request_sha256)
                != Some(&self.request)
        {
            return Err(CiError::Message(
                "result belongs to a different original attempt or request".into(),
            ));
        }
        if let memcordon_core::result_v3::RuntimeExecutionV3::LinuxPrivate { native, .. } =
            &result.runtime
        {
            let frontend = self
                .frontend
                .as_ref()
                .expect("original native frontend retained");
            if native.caller.pid != frontend.process_id
                || native.caller.birth != frontend.birth
                || native.caller_uid != self.caller.uid
                || native.boot_id != association.boot_id
            {
                return Err(CiError::Message(
                    "result native caller does not match the original held frontend".into(),
                ));
            }
        }
        Ok(result)
    }

    /// This invokes the authenticated native cleanup endpoint. It returns a
    /// separate factual carrier, never a recreated original invocation result.
    pub fn recover(&self) -> Result<RecoveryObservation> {
        let association = self.association()?;
        let ordinal = self
            .recoveries
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |value| (value < 16).then_some(value + 1),
            )
            .map_err(|_| {
                CiError::Message("original attempt recovery invocation count exceeds bound".into())
            })?;
        let report = if ordinal == 0 {
            "workload-recovery.json".into()
        } else {
            format!("workload-recovery-{ordinal}.json")
        };
        let observed = self
            .caller
            .command(&self.path, self.cleanup_cutoff)?
            .arg("workload")
            .arg("recover")
            .arg("--observation")
            .arg(self.path.join("workload-observation.json"))
            .arg("--report")
            .arg(self.path.join(&report))
            .output()?;
        let stdout = if ordinal == 0 {
            "recovery-stdout.bin".into()
        } else {
            format!("recovery-{ordinal}-stdout.bin")
        };
        let stderr = if ordinal == 0 {
            "recovery-stderr.bin".into()
        } else {
            format!("recovery-{ordinal}-stderr.bin")
        };
        write_record(&self.directory, &stdout, &observed.stdout)?;
        write_record(&self.directory, &stderr, &observed.stderr)?;
        let raw_terminal = read_record(
            &self.directory,
            &report,
            memcordon_core::execution_facts::RESULT_MAX_BYTES,
            self.caller.uid,
        )?;
        let terminal = LinuxWorkloadTerminalV1::parse(&raw_terminal).map_err(CiError::Message)?;
        if terminal.association != association || terminal.request.request_sha256 != self.request {
            return Err(CiError::Message(
                "native recovery carrier belongs to another original attempt".into(),
            ));
        }
        // Keep native cleanup knowledge and the recovery process status
        // independent, including when a valid carrier accompanies a failure.
        Ok(RecoveryObservation {
            terminal,
            process: observed,
            raw_terminal,
        })
    }
}

fn read_record(directory: &File, name: &str, ceiling: usize, uid: u32) -> Result<Vec<u8>> {
    let file = File::from(
        rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.nlink() != 1 {
        return Err(CiError::Message(
            "caller observation is not its original regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(ceiling as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > ceiling {
        return Err(CiError::Message(
            "caller observation byte ceiling exceeded".into(),
        ));
    }
    Ok(bytes)
}

fn write_record(directory: &File, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = File::from(
        rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(std::io::Error::from)?,
    );
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
