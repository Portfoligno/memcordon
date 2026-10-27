//! One later diagnostic observer. It cannot admit or retire workload members.
use super::toolchain_sampling as sampling;
use crate::{
    windows_installed_cases::{InstalledWindowsPayload, WorkloadDiagnosticInput},
    windows_readiness_adapter::{self as artifacts, HeldWindowsArtifact},
};
use memcordon_testkit::{
    WindowsThreadActivitySample, WindowsWaitObserver, WindowsWaitObserverSnapshot,
};
use memcordon_windows_loader_lab::helper_wait_protocol as wire;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

static UNSETTLED_IMAGES: Mutex<Vec<QualifiedImage>> = Mutex::new(Vec::new());
static IMAGE_HANDOFF: AtomicBool = AtomicBool::new(false);

pub(super) fn observe_transferred() -> io::Result<()> {
    let native = memcordon_testkit::windows_observe_transferred_wait_cleanup();
    let mut images = UNSETTLED_IMAGES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // First observe the retained actual processes/Jobs, then release complete
    // selected materialization contexts only when none remains unresolved.
    if memcordon_testkit::windows_unresolved_wait_owner_count() == 0 {
        images.clear();
    }
    if IMAGE_HANDOFF.load(Ordering::Acquire) {
        return Err(io::Error::other(format!(
            "qualified observer materialization handoff remains failed; retained-contexts={}; native-cleanup-error={:?}",
            images.len(),
            native
                .err()
                .map(|error| (error.kind(), error.raw_os_error()))
        )));
    }
    native
}

struct QualifiedImage {
    selected: WorkloadDiagnosticInput,
    path: PathBuf,
    held: HeldWindowsArtifact,
}
struct Pending {
    hint: sampling::Hint,
    snapshot: WindowsWaitObserverSnapshot,
    trigger: u64,
    midpoint: u64,
    frequency: u64,
}
pub(super) struct Observer {
    image: Option<QualifiedImage>,
    cleanup: Option<Instant>,
    work: Instant,
    directory: PathBuf,
    pending: Option<Pending>,
    attempted: bool,
    owner: Option<WindowsWaitObserver>,
    stream: Option<wire::Stream>,
    request: Option<wire::Request>,
    status: &'static str,
    error: Option<(io::ErrorKind, Option<i32>)>,
    publications: Vec<File>,
    settled: bool,
}
fn fail() -> io::Error {
    io::Error::other("qualified helper wait observer binding differs")
}
fn hash(text: &str) -> io::Result<[u8; 32]> {
    hex::decode(text)
        .map_err(|_| fail())?
        .try_into()
        .map_err(|_| fail())
}
fn identity(value: sampling::Identity) -> wire::Identity {
    wire::Identity {
        pid: value.pid,
        birth: value.birth,
    }
}
fn id_json(value: wire::Identity) -> Value {
    json!({"pid":value.pid,"birth_decimal":value.birth.to_string()})
}

impl Observer {
    pub(super) fn prepare(
        config: &InstalledWindowsPayload,
        directory: &Path,
        work: Instant,
        cleanup: Option<Instant>,
        toolchain: bool,
    ) -> Self {
        let mut state = Self {
            image: None,
            cleanup,
            work,
            directory: directory.into(),
            pending: None,
            attempted: false,
            owner: None,
            stream: None,
            request: None,
            status: "not-started",
            error: None,
            publications: Vec::new(),
            settled: false,
        };
        if !toolchain {
            state.status = "not-toolchain";
            return state;
        }
        if cleanup.is_none() {
            state.status = "unavailable-original-cleanup";
            let _ = state.publish(work);
            return state;
        }
        let result = (|| -> io::Result<QualifiedImage> {
            sampling::live(work)?;
            // This input originates from the existing TargetBundle/materialization
            // or selected Release lease constructor, never a measured arbitrary path.
            let selected = config
                .require_workload_diagnostic()
                .map_err(io::Error::other)?
                .clone();
            sampling::live(work)?;
            let (path, held) = artifacts::prepare_workload_executable(
                &selected.executable.path,
                &selected.executable.sha256,
                &directory.join("native-toolchain-wait-observer"),
            )
            .map_err(io::Error::other)?;
            sampling::live(work)?;
            if held.bytes.len() as u64 != selected.byte_len
                || held.sha256 != selected.executable.sha256
            {
                return Err(fail());
            }
            crate::release::target::validate_executable(&held.bytes, &selected.target)
                .map_err(io::Error::other)?;
            artifacts::verify_named_artifact(&held, &path).map_err(io::Error::other)?;
            sampling::live(work)?;
            Ok(QualifiedImage {
                selected,
                path,
                held,
            })
        })();
        match result {
            Ok(image) => {
                state.image = Some(image);
                state.status = "qualified-not-started";
            }
            Err(error) => state.note("unavailable-qualified-sidecar", &error),
        }
        if let Err(error) = state.publish(work) {
            state.note("unavailable-initial-publication", &error);
        }
        state
    }

    fn note(&mut self, status: &'static str, error: &io::Error) {
        self.status = status;
        self.error
            .get_or_insert((error.kind(), error.raw_os_error()));
    }
    pub(super) fn arm(
        &mut self,
        hint: &sampling::Hint,
        sample: &WindowsThreadActivitySample,
        clock: (u64, u64),
        deadline: Instant,
    ) -> io::Result<()> {
        if self.image.is_none()
            || self.cleanup.is_none()
            || self.pending.is_some()
            || self.attempted
        {
            return Ok(());
        }
        self.work = self.work.min(deadline);
        sampling::live(self.work)?;
        let (trigger, frequency) = memcordon_testkit::windows_performance_counter()?;
        let (cutoff, converted_frequency) =
            memcordon_testkit::windows_native_work_cutoff(self.work)?;
        if frequency != clock.1 || converted_frequency != clock.1 {
            return Err(fail());
        }
        let cutoff = cutoff.min(clock.0);
        let midpoint = trigger
            .checked_add(cutoff.checked_sub(trigger).ok_or_else(fail)? / 2)
            .ok_or_else(fail)?;
        // Capture BEFORE activity.finish releases these same original handles.
        let snapshot = sample.wait_observer_snapshot(self.work)?;
        self.pending = Some(Pending {
            hint: hint.clone(),
            snapshot,
            trigger,
            midpoint,
            frequency,
        });
        self.status = "pending-original-midpoint";
        self.publish(self.work)
    }
    pub(super) fn due(&self) -> io::Result<bool> {
        let Some(pending) = &self.pending else {
            return Ok(false);
        };
        if self.attempted {
            return Ok(false);
        }
        sampling::live(self.work)?;
        let (now, frequency) = memcordon_testkit::windows_performance_counter()?;
        if pending.frequency != frequency {
            return Err(fail());
        }
        Ok(now >= pending.midpoint)
    }
    pub(super) fn launch(
        &mut self,
        latest: io::Result<sampling::Hint>,
        challenge: &[u8],
        clock: (u64, u64),
    ) -> io::Result<()> {
        if self.attempted {
            return Err(fail());
        }
        self.attempted = true;
        let pending = self.pending.take().ok_or_else(fail)?;
        let result = (|| -> io::Result<()> {
            let hint = latest?;
            let expected = pending.hint.survivors.first().ok_or_else(fail)?;
            let helper = hint.survivors.first().ok_or_else(fail)?;
            if hint.compiler != pending.hint.compiler
                || helper != expected
                || hint.sequence < pending.hint.sequence
            {
                return Err(fail());
            }
            let image = self.image.as_ref().ok_or_else(fail)?;
            artifacts::verify_named_artifact(&image.held, &image.path).map_err(io::Error::other)?;
            let cleanup = self.cleanup.ok_or_else(fail)?;
            let (work_cutoff, frequency) =
                memcordon_testkit::windows_native_work_cutoff(self.work)?;
            let (cleanup_cutoff, cleanup_frequency) =
                memcordon_testkit::windows_native_work_cutoff(cleanup)?;
            let (launch, launch_frequency) = memcordon_testkit::windows_performance_counter()?;
            if frequency != clock.1
                || frequency != cleanup_frequency
                || frequency != launch_frequency
            {
                return Err(fail());
            }
            let root = sampling::binding_fixture(&hint)?;
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce).map_err(|error| {
                io::Error::other(format!("observer nonce generation failed: {error}"))
            })?;
            self.status = "starting-selected-worker";
            self.publish(self.work)?;
            let image = self.image.as_ref().ok_or_else(fail)?;
            let mut request = None;
            let owner = WindowsWaitObserver::prepare(
                &image.path,
                image.held.file(),
                pending.snapshot,
                self.work,
                cleanup,
                |inherited| {
                    if inherited.process.pid != helper.identity.pid
                        || inherited.process.birth != helper.identity.birth
                    {
                        return Err(fail());
                    }
                    let value = wire::Request {
                        nonce,
                        challenge_sha256: Sha256::digest(challenge).into(),
                        observer_sha256: hash(&image.selected.executable.sha256)?,
                        helper_sha256: hash(&helper.image_sha256)?,
                        target_machine: match image.selected.target.as_str() {
                            "x86_64-pc-windows-msvc" => 0x8664,
                            "aarch64-pc-windows-msvc" => 0xaa64,
                            _ => return Err(fail()),
                        },
                        root: identity(root),
                        compiler: identity(hint.compiler),
                        helper: identity(helper.identity),
                        helper_parent: identity(helper.parent),
                        process_handle: inherited.process_handle,
                        threads: inherited
                            .threads
                            .iter()
                            .map(|t| wire::Thread {
                                handle: t.handle,
                                tid: t.tid,
                                birth: t.birth,
                            })
                            .collect(),
                        omitted_threads: u32::try_from(inherited.omitted_threads)
                            .map_err(|_| fail())?,
                        frequency,
                        trigger_qpc: pending.trigger,
                        launch_qpc: launch,
                        work_cutoff_qpc: work_cutoff.min(clock.0),
                        cleanup_cutoff_qpc: cleanup_cutoff,
                    };
                    let bytes = value.encode()?;
                    request = Some(value);
                    Ok(bytes)
                },
            )?;
            // Store the actual suspended owner before EVERY fallible post-create step.
            self.owner = Some(owner);
            self.owner.as_mut().expect("stored actual owner").start()?;
            let request = request.ok_or_else(fail)?;
            let child = self
                .owner
                .as_ref()
                .expect("stored actual owner")
                .identity()?;
            self.stream = Some(wire::Stream::new(
                request.clone(),
                wire::Identity {
                    pid: child.pid,
                    birth: child.birth,
                },
            )?);
            self.request = Some(request);
            self.status = "worker-running";
            self.publish(self.work)
        })();
        if let Err(error) = &result {
            if let Some(owner) = &mut self.owner {
                let _ = owner.request_stop();
            }
            self.note("observer-launch-refused", error);
            let _ = self.publish(self.work);
        }
        result
    }
    pub(super) fn poll(&mut self) -> io::Result<()> {
        let Some(owner) = &mut self.owner else {
            return Ok(());
        };
        let result = (|| -> io::Result<bool> {
            let bytes = owner.poll_available(self.work)?;
            if bytes.is_empty() {
                return Ok(false);
            }
            let (now, frequency) = memcordon_testkit::windows_performance_counter()?;
            if self
                .request
                .as_ref()
                .is_none_or(|r| r.frequency != frequency)
            {
                return Err(fail());
            }
            let before = self.stream.as_ref().ok_or_else(fail)?.frames().len();
            self.stream.as_mut().ok_or_else(fail)?.push(&bytes, now)?;
            Ok(self.stream.as_ref().ok_or_else(fail)?.frames().len() != before)
        })();
        match result {
            Err(error) => {
                let _ = owner.request_stop();
                self.note("observer-output-refused", &error);
                Err(error)
            }
            Ok(true) => {
                if self.stream.as_ref().is_some_and(wire::Stream::ended) {
                    self.status = "worker-stream-ended";
                }
                self.publish(self.work)
            }
            Ok(false) => Ok(()),
        }
    }
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if self.status == "not-toolchain" {
            return Ok(());
        }
        if self.owner.is_none() {
            if let Some(cleanup) = self.cleanup {
                let bytes=serde_json::to_vec(&json!({"format":"memcordon.windows-isolated-helper-wait-retirement","revision":1,
                    "diagnostic_only":true,"not_started":true,"selection_pending":self.pending.is_some(),"status":self.status,
                    "no_observer_process_or_job_created":true})).map_err(io::Error::other)?;
                self.publications.push(sampling::publish(
                    &self.directory,
                    &self
                        .directory
                        .join("native-toolchain-helper-wait-retirement.json"),
                    &bytes,
                    cleanup,
                )?);
            }
            return Ok(());
        }
        let owner = self.owner.as_mut().expect("checked owner");
        let cleanup = self.cleanup.ok_or_else(fail)?;
        // No diagnostic result may gate original-family retirement at the caller.
        let result = owner.finish(cleanup);
        if result.is_ok() {
            self.settled = true;
        }
        let observed = match &result {
            Ok(value) => {
                json!({"identity":{"pid":value.identity.pid,"birth_decimal":value.identity.birth.to_string()},
                "native_exit_status":value.native_exit_status,"job_empty":value.job_empty,"forced":value.forced,
                "observed_qpc":value.observed_qpc,"qpc_frequency":value.qpc_frequency})
            }
            Err(error) => {
                json!({"unsettled":true,"kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error()})
            }
        };
        let bytes = serde_json::to_vec(
            &json!({"format":"memcordon.windows-isolated-helper-wait-retirement","revision":1,
            "diagnostic_only":true,"under_original_cleanup":true,"process_and_job":observed,
            "protocol_ended":self.stream.as_ref().is_some_and(wire::Stream::ended)}),
        )
        .map_err(io::Error::other)?;
        let publication = sampling::publish(
            &self.directory,
            &self
                .directory
                .join("native-toolchain-helper-wait-retirement.json"),
            &bytes,
            cleanup,
        );
        match publication {
            Ok(file) => self.publications.push(file),
            Err(error) => {
                if result.is_ok() {
                    return Err(error);
                }
            }
        }
        result.map(|_| ())
    }
    fn publish(&mut self, deadline: Instant) -> io::Result<()> {
        sampling::live(deadline)?;
        // Four setup/status records, at most Begin+64 threads+refusal+End,
        // and one cleanup record. Fragmented bytes never consume a slot.
        if self.publications.len() >= wire::THREAD_BOUND + 8 {
            return Err(io::Error::other("helper wait publication count exhausted"));
        }
        let frames = self.stream.as_ref().map(|s| s.frames()).unwrap_or_default();
        let mut retained = frames.len();
        let bytes = loop {
            let request=self.request.as_ref().map(|r|json!({"root":id_json(r.root),"compiler":id_json(r.compiler),"helper":id_json(r.helper),
                "helper_parent":id_json(r.helper_parent),"helper_sha256":hex::encode(r.helper_sha256),"challenge_sha256":hex::encode(r.challenge_sha256),
                "nonce":r.nonce,"original_frequency":r.frequency,"trigger_qpc":r.trigger_qpc,"launch_qpc":r.launch_qpc,
                "work_cutoff_qpc":r.work_cutoff_qpc,"cleanup_cutoff_qpc":r.cleanup_cutoff_qpc,
                "snapshot_age_at_launch_ticks":r.launch_qpc.checked_sub(r.trigger_qpc),
                "snapshot_age_clock_frequency":r.frequency}));
            let selected=self.image.as_ref().map(|image|json!({"source":image.selected.source,"target":image.selected.target,
                "role":wire::ROLE,"sha256":image.selected.executable.sha256,"byte_len":image.selected.byte_len}));
            let bytes=serde_json::to_vec(&json!({"format":"memcordon.windows-isolated-helper-wait","revision":2,"wire_protocol_version":wire::VERSION,"diagnostic_only":true,
                "compiler_acceptance":false,"wait_cause_claimed":false,"status":self.status,"selected_sidecar":selected,"request_binding":request,
                "not_started":self.owner.is_none(),"reserved_lock_fields_omitted":true,"object_names_omitted":true,
                "error":self.error.map(|(kind,raw)|json!({"kind":format!("{kind:?}"),"raw_os_error":raw})),
                "frames":&frames[..retained],"record_omitted_frames":frames.len()-retained,
                "protocol_ended":self.stream.as_ref().is_some_and(wire::Stream::ended),
                "query_observation_complete":retained==frames.len()&&matches!(frames.last().map(|frame|&frame.result),Some(wire::ResultKind::End{complete:true,..}))})).map_err(io::Error::other)?;
            if bytes.len() <= sampling::RECORD_BOUND {
                break bytes;
            }
            if retained == 0 {
                return Err(fail());
            }
            retained -= 1;
        };
        sampling::live(deadline)?;
        self.publications.push(sampling::publish(
            &self.directory,
            &self.directory.join("native-toolchain-helper-wait.json"),
            &bytes,
            deadline,
        )?);
        Ok(())
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        if self.owner.is_some() && !self.settled {
            IMAGE_HANDOFF.store(true, Ordering::Release);
            if let Some(image) = self.image.take() {
                let mut images = UNSETTLED_IMAGES
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if images.len() >= memcordon_testkit::WINDOWS_WAIT_OBSERVER_BOUND {
                    std::process::abort();
                }
                images.push(image);
            }
            // Transfer native owners only AFTER preserving their complete
            // admitted source and original materialization/ancestor custody.
            drop(self.owner.take());
        }
    }
}
