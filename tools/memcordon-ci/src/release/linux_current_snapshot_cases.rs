//! Original caller files and byte-stream effects for current snapshot cases.
use super::{
    linux_current_installed::{CallerImages, CurrentLinuxCase, CurrentLinuxInput},
    linux_request_fixture::{CallerRequestFixture, CallerSession, CallerSnapshot},
};
use crate::{
    CiError, Result, linux_snapshot_probe::ProbeInput, readiness_identity::SourceIdentity,
};
use memcordon_core::{
    BoundedVec,
    workload_bundle::SnapshotManifestV1,
    workload_files::{ImageEntryV1, RootRelativePath},
};
use memcordon_readiness_verifier::{
    Artifact, CaseKey, CaseRecord, CaseState, EvidenceClass, ProductKey,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::mpsc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub struct InstalledSnapshotObservations {
    pub records: Vec<CaseRecord>,
    pub artifacts: Vec<Artifact>,
    pub primary_error: Option<String>,
}

fn owned_directory(path: &Path, caller: &CallerSession) -> Result<()> {
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        path,
        Some(rustix::process::Uid::from_raw(caller.uid)),
        Some(rustix::process::Gid::from_raw(caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    Ok(())
}
fn file(path: &Path, bytes: &[u8], uid: u32, gid: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    rustix::fs::fchown(
        &file,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )
    .map_err(std::io::Error::from)?;
    Ok(())
}

fn inputs(
    base: &CallerImages,
    caller: &CallerSession,
    directory: &Path,
    bytes: &[u8],
) -> Result<CallerImages> {
    let base = base.minimal();
    let root = directory.join("source");
    owned_directory(&root, caller)?;
    let input = root.join("input");
    owned_directory(&input, caller)?;
    file(&input.join("snapshot.bin"), bytes, caller.uid, caller.gid)?;
    let mut entries = BoundedVec::default();
    entries
        .try_push(ImageEntryV1::Regular {
            path: RootRelativePath::new("input/snapshot.bin".into()).map_err(CiError::Message)?,
            sha256: memcordon_core::hash_bytes(bytes),
            size: bytes.len() as u64,
            executable: false,
        })
        .map_err(|_| CiError::Message("single snapshot input exceeds bound".into()))?;
    let manifest = SnapshotManifestV1 {
        format: "memcordon.workload-snapshot".into(),
        revision: 1,
        target: base.input.target.clone(),
        entries,
        entrypoints: Default::default(),
        library_directories: Default::default(),
    };
    manifest.validate().map_err(CiError::Message)?;
    let manifest_path = directory.join("input-snapshot.json");
    super::source::write_diagnostic_json(&manifest_path, &manifest)?;
    Ok(CallerImages {
        minimal: None,
        runtime: base.runtime.clone(),
        input: manifest,
        runtime_manifest: base.runtime_manifest.clone(),
        input_manifest: manifest_path,
        runtime_source: base.runtime_source.clone(),
        input_source: root,
    })
}

pub(super) struct ProbeRun {
    sender: Option<mpsc::SyncSender<Vec<u8>>>,
    worker: Option<JoinHandle<Result<memcordon_testkit::ObservedOutput>>>,
    snapshot: Option<memcordon_testkit::OutputSnapshot>,
    process: Option<crate::linux_consumer_readiness::HeldLinuxProcess>,
    created: mpsc::Receiver<crate::linux_consumer_readiness::HeldLinuxProcess>,
    snapshots: mpsc::Receiver<memcordon_testkit::OutputSnapshot>,
    request: Vec<u8>,
    receipt: PathBuf,
    work: Instant,
}
impl ProbeRun {
    pub(super) fn start(
        caller: &CallerSession,
        probe: &Path,
        directory: &Path,
        request: &ProbeInput,
        work: Instant,
    ) -> Result<Self> {
        let receipt = directory.join("source-probe.json");
        let mut bytes = serde_json::to_vec(request)?;
        bytes.push(b'\n');
        let supplied = bytes.clone();
        let args: Vec<std::ffi::OsString> = vec![
            "--reuid".into(),
            caller.uid.to_string().into(),
            "--regid".into(),
            caller.gid.to_string().into(),
            "--init-groups".into(),
            "--".into(),
            probe.as_os_str().to_owned(),
            "current-linux-snapshot-probe".into(),
            "--input".into(),
            "-".into(),
            "--output".into(),
            receipt.as_os_str().to_owned(),
        ];
        let command = crate::command::CommandSpec::new(
            "/usr/bin/setpriv",
            directory,
            Duration::from_secs(30),
        )
        .bounded_until(work)
        .cleared_environment()
        .args(args);
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4);
        let (created_tx, created_rx) = mpsc::sync_channel(1);
        let (snapshot_tx, snapshot_rx) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            command.output_quiet_with_creation_and_io(
                |child| {
                    let birth = crate::linux_consumer_readiness::process_birth(child.id())
                        .map_err(CiError::Message)?;
                    let held = crate::linux_consumer_readiness::HeldLinuxProcess::acquire(
                        child.id(),
                        birth,
                    )
                    .map_err(CiError::Message)?;
                    created_tx.send(held).map_err(|_| {
                        CiError::Message("original source probe observer lost".into())
                    })?;
                    Ok(())
                },
                move |_, stdin, snapshot| {
                    snapshot_tx.send(snapshot).map_err(|_| {
                        std::io::Error::other("source probe snapshot observer lost")
                    })?;
                    let mut stdin = stdin.ok_or_else(|| {
                        std::io::Error::other("original source probe stdin absent")
                    })?;
                    stdin.write_all(&supplied)?;
                    stdin.flush()?;
                    loop {
                        let remaining = work.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "original source probe input cutoff exhausted",
                            ));
                        }
                        match rx.recv_timeout(remaining) {
                            Ok(bytes) => {
                                stdin.write_all(&bytes)?;
                                stdin.flush()?;
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "original retained alias gate cutoff exhausted",
                                ));
                            }
                        }
                    }
                    Ok(())
                },
            )
        });
        Ok(Self {
            sender: Some(tx),
            worker: Some(worker),
            snapshot: None,
            process: None,
            created: created_rx,
            snapshots: snapshot_rx,
            request: bytes,
            receipt,
            work,
        })
    }
    fn initialize(&mut self) -> Result<()> {
        if self.process.is_none() {
            self.process = Some(
                self.created
                    .recv_timeout(self.work.saturating_duration_since(Instant::now()))
                    .map_err(|error| {
                        CiError::Message(format!("original source probe creation: {error}"))
                    })?,
            );
        }
        if self.snapshot.is_none() {
            self.snapshot = Some(
                self.snapshots
                    .recv_timeout(self.work.saturating_duration_since(Instant::now()))
                    .map_err(|error| {
                        CiError::Message(format!("original source probe capture: {error}"))
                    })?,
            );
        }
        Ok(())
    }
    pub(super) fn phase(&mut self, phase: &str) -> Result<Value> {
        self.initialize()?;
        loop {
            let bytes = self
                .snapshot
                .as_ref()
                .expect("original capture initialized")
                .stdout()?;
            for line in bytes
                .split_inclusive(|byte| *byte == b'\n')
                .filter(|line| line.ends_with(b"\n"))
            {
                let value: Value = serde_json::from_slice(line)?;
                if value["phase"] == phase {
                    return Ok(value);
                }
            }
            if Instant::now() >= self.work
                || self
                    .worker
                    .as_ref()
                    .is_none_or(|worker| worker.is_finished())
            {
                return Err(CiError::Message(format!(
                    "original source probe phase {phase} absent"
                )));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub(super) fn send(&self, bytes: &[u8]) -> Result<()> {
        self.sender
            .as_ref()
            .ok_or_else(|| CiError::Message("original source alias input closed".into()))?
            .send(bytes.to_vec())
            .map_err(|_| CiError::Message("original source alias input receiver lost".into()))
    }
    pub(super) fn finish(&mut self, cutoff: Instant) -> Result<BTreeMap<String, Vec<u8>>> {
        let initialization = self.initialize();
        self.sender.take();
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            if Instant::now() >= cutoff {
                return Err(CiError::Message(
                    "original source alias supervisor settlement cutoff exhausted".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let observed = self
            .worker
            .take()
            .ok_or_else(|| CiError::Message("source probe already joined".into()))?
            .join()
            .map_err(|_| CiError::Message("source probe supervisor panicked".into()))??;
        initialization?;
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| CiError::Message("original source probe query holder absent".into()))?;
        if !process.exited().map_err(CiError::Message)? {
            return Err(CiError::Message(
                "original source probe child not retired".into(),
            ));
        }
        use std::os::unix::process::ExitStatusExt;
        let wait = json!({"pid":process.process_id,"birth":process.birth,"held_before_input":true,"retired":true,"raw_wait_status":observed.status.into_raw()});
        let result = BTreeMap::from([
            ("probe-input.json".into(), self.request.clone()),
            ("probe-stdout.bin".into(), observed.stdout.clone()),
            ("probe-stderr.bin".into(), observed.stderr.clone()),
            ("probe-wait.json".into(), serde_json::to_vec(&wait)?),
            ("probe-receipt.json".into(), std::fs::read(&self.receipt)?),
        ]);
        crate::command::require_successful_output(
            "actual ordinary caller snapshot file effect",
            &observed,
        )?;
        Ok(result)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_installed(
    _root: &Path,
    identity: &SourceIdentity,
    key: &ProductKey,
    caller: &CallerSession,
    _foreign: &CallerSession,
    probe: &Path,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller_directory: &Path,
    working_directory: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    lease_id: &str,
    work: Instant,
    cleanup: Instant,
) -> InstalledSnapshotObservations {
    let mut observed = InstalledSnapshotObservations {
        records: Vec::new(),
        artifacts: Vec::new(),
        primary_error: None,
    };
    let execution = (|| -> Result<()> {
        for scenario in ["caller-writable-source", "retained-writable-alias"] {
            let controller = controller_directory.join(format!("snapshot-{scenario}"));
            std::fs::create_dir(&controller)?;
            std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))?;
            let source = working_directory.join(format!("snapshot-source-{scenario}"));
            owned_directory(&source, caller)?;
            let mut token = [0_u8; 32];
            getrandom::fill(&mut token).map_err(|error| CiError::Message(error.to_string()))?;
            let changed = token.map(|byte| byte ^ 0xff);
            let selected = inputs(images, caller, &source, &token)?;
            let path = selected.input_source.join("input/snapshot.bin");
            let source_metadata = std::fs::metadata(&path)?;
            let directory = working_directory.join(format!("snapshot-{scenario}"));
            let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
                .into_iter()
                .next()
                .ok_or_else(|| CiError::Message("current fixture recipe absent".into()))?;
            recipe.key.family = "L-SNAPSHOT".into();
            recipe.key.scenario = scenario.into();
            recipe.mode = "snapshot-read-held".into();
            recipe.arguments = vec![hex::encode(token).into()];
            recipe.requirements.clear();
            recipe.output_files.clear();
            let request = ProbeInput {
                format: "memcordon.current-snapshot-probe".into(),
                revision: 1,
                operation: "hold-write".into(),
                path: path.clone(),
                device: source_metadata.dev(),
                inode: source_metadata.ino(),
                offset: 0,
                bytes: changed.to_vec(),
                replacement: None,
                backup: None,
            };
            let actor =
                std::cell::RefCell::new(ProbeRun::start(caller, probe, &source, &request, work)?);
            let experiment = (|| -> Result<CurrentLinuxCase> {
                actor.borrow_mut().phase("opened")?;
                let mut before = |_: &CallerRequestFixture| -> Result<()> {
                    if scenario == "caller-writable-source" {
                        actor.borrow().send(b"W\n")?;
                        actor.borrow_mut().phase("changed")?;
                    }
                    Ok(())
                };
                let mut opened = |_: &mut super::linux_request_launch::RequestLaunch,
                                  _: &CallerRequestFixture|
                 -> Result<()> { Ok(()) };
                let mut intervention =
                    |launch: &mut super::linux_request_launch::RequestLaunch,
                     _: &memcordon_core::workload_request::WorkloadAttemptAssociationV1|
                     -> Result<Value> {
                        loop {
                            let snapshot = launch.snapshot_until(work)?;
                            if snapshot
                                .stdout()?
                                .split_inclusive(|byte| *byte == b'\n')
                                .filter(|line| line.ends_with(b"\n"))
                                .any(|line| {
                                    serde_json::from_slice::<Value>(line)
                                        .is_ok_and(|row| row["operation"] == "snapshot-input-ready")
                                })
                            {
                                break;
                            }
                            if Instant::now() >= work {
                                return Err(CiError::Message(
                                    "original snapshot-read readiness cutoff expired".into(),
                                ));
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        let mutation = if scenario == "retained-writable-alias" {
                            actor.borrow().send(b"W\n")?;
                            actor.borrow_mut().phase("changed")?
                        } else {
                            json!({"already_mutated_before_original_frontend":true})
                        };
                        launch.send_input(b"R\n".to_vec())?;
                        Ok(
                            json!({"format":"memcordon.current-snapshot-mutation","revision":1,"source":mutation}),
                        )
                    };
                super::linux_current_installed::run_recipe_with_source(
                    CurrentLinuxInput {
                        controller_directory: &controller,
                        caller,
                        images: &selected,
                        provider,
                        directory: &directory,
                        work_cutoff: work,
                        cleanup_cutoff: cleanup,
                    },
                    recipe,
                    &mut before,
                    &mut opened,
                    Some(&mut intervention),
                )
            })();
            let release = actor.borrow().send(b"D\n");
            let settled = actor.borrow_mut().finish(cleanup);
            let case = match experiment {
                Ok(case) => case,
                Err(primary) => {
                    return Err(CiError::Message(format!(
                        "{primary}; source helper release: {release:?}; source helper settlement: {:?}",
                        settled.as_ref().err()
                    )));
                }
            };
            release?;
            let helper = settled?;
            let prefix = controller
                .strip_prefix(artifact_root)
                .map_err(|error| CiError::Message(error.to_string()))?
                .to_string_lossy();
            let mut capture = super::linux_current_case_capture::capture(
                &case,
                identity,
                lease_id,
                fixture_source,
                &selected,
                &prefix,
                json!({"format":"memcordon.current-snapshot-source","revision":1,"scenario":scenario,"original_bytes":token,"changed_bytes":changed,"source_uid":caller.uid,"source_gid":caller.gid,"source_device":source_metadata.dev(),"source_inode":source_metadata.ino(),"helper_receipt":format!("{prefix}/source-helper-probe-receipt.json")}),
            )?;
            for (name, bytes) in helper {
                capture
                    .files
                    .insert(format!("{prefix}/source-helper-{name}"), bytes);
            }
            let resolver = |path: &str| {
                capture
                    .files
                    .get(path)
                    .cloned()
                    .ok_or_else(|| format!("snapshot capture absent: {path}"))
            };
            let verification =
                memcordon_readiness_verifier::current::linux_snapshots::verify_observed_case(
                    &capture.evidence,
                    &capture.input,
                    &identity.source_commit,
                    &resolver,
                );
            let (record, artifacts) = super::linux_current_capture::persist_case(
                artifact_root,
                &format!("{prefix}/case.json"),
                &capture.evidence,
                capture.files,
                if verification.is_ok() {
                    CaseState::Passed
                } else {
                    CaseState::Failed
                },
                verification.as_ref().err().cloned(),
            )?;
            observed.records.push(record);
            observed.artifacts.extend(artifacts);
            verification.map_err(CiError::Message)?;
            let ack = caller
                .command(&case.directory, cleanup)?
                .args(["workload", "acknowledge", "--observation"])
                .arg(case.directory.join("workload-observation.json"))
                .output()?;
            crate::command::require_successful_output(
                "settled snapshot evidence acknowledgment",
                &ack,
            )?;
            let ack =
                memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(&ack.stdout)
                    .map_err(|error| CiError::Message(error.to_string()))?;
            if ack.association != case.locator {
                return Err(CiError::Message(
                    "snapshot acknowledgment names another original attempt".into(),
                ));
            }
        }
        run_concurrent(
            identity,
            key,
            caller,
            images,
            provider,
            controller_directory,
            working_directory,
            artifact_root,
            fixture_source,
            lease_id,
            work,
            cleanup,
            &mut observed,
        )?;
        run_substitution(
            identity,
            key,
            caller,
            probe,
            images,
            provider,
            controller_directory,
            working_directory,
            artifact_root,
            fixture_source,
            lease_id,
            work,
            cleanup,
            &mut observed,
        )?;
        run_corruptions(
            identity,
            key,
            caller,
            probe,
            images,
            provider,
            controller_directory,
            working_directory,
            artifact_root,
            fixture_source,
            lease_id,
            work,
            cleanup,
            &mut observed,
        )?;
        Ok(())
    })();
    if let Err(error) = execution {
        let mut primary = error.to_string();
        for (leaf, controller_leaf) in [
            (
                "snapshot-caller-writable-source",
                "snapshot-caller-writable-source",
            ),
            (
                "snapshot-retained-writable-alias",
                "snapshot-retained-writable-alias",
            ),
            (
                "snapshot-concurrent-holder",
                "snapshot-concurrent-same-digest",
            ),
            (
                "snapshot-concurrent-peer",
                "snapshot-concurrent-same-digest/peer",
            ),
            (
                "snapshot-source-fd-substitution",
                "snapshot-source-fd-substitution",
            ),
            ("snapshot-content-mismatch", "snapshot-content-mismatch"),
            (
                "snapshot-source-mutation-during-copy",
                "snapshot-source-mutation-during-copy",
            ),
        ] {
            let directory = working_directory.join(leaf);
            let controller = controller_directory.join(controller_leaf);
            if directory.is_dir() && controller.is_dir() {
                if let Err(secondary) = super::linux_current_lease::retain_case_failure(
                    &directory,
                    &controller,
                    artifact_root,
                    caller.uid,
                    &primary,
                    &mut observed.artifacts,
                ) {
                    primary =
                        format!("{primary}; original snapshot capture retention: {secondary}");
                }
            }
        }
        observed.primary_error = Some(primary);
    }
    observed
}

#[allow(clippy::too_many_arguments)]
fn run_concurrent(
    identity: &SourceIdentity,
    key: &ProductKey,
    caller: &CallerSession,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller_directory: &Path,
    working_directory: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    lease_id: &str,
    work: Instant,
    cleanup: Instant,
    observed: &mut InstalledSnapshotObservations,
) -> Result<()> {
    let controller = controller_directory.join("snapshot-concurrent-same-digest");
    std::fs::create_dir(&controller)?;
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))?;
    let peer_controller = controller.join("peer");
    std::fs::create_dir(&peer_controller)?;
    let source = working_directory.join("snapshot-source-concurrent");
    owned_directory(&source, caller)?;
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token).map_err(|error| CiError::Message(error.to_string()))?;
    let selected = inputs(images, caller, &source, &token)?;
    let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
        .into_iter()
        .next()
        .ok_or_else(|| CiError::Message("current fixture recipe absent".into()))?;
    recipe.key.family = "L-SNAPSHOT".into();
    recipe.key.scenario = "concurrent-same-digest".into();
    recipe.mode = "snapshot-read-held".into();
    recipe.arguments = vec![hex::encode(token).into()];
    recipe.requirements.clear();
    recipe.output_files.clear();
    let peer_recipe = recipe.clone();
    let mut peer_case = None;
    let mut peer_before = Value::Null;
    let mut outer_callback =
        |launch: &mut super::linux_request_launch::RequestLaunch,
         association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1|
         -> Result<Value> {
            wait_ready(launch, work)?;
            let (holder, before) =
                super::linux_current_installed::hold_current_attempt(association, work)?;
            let mut inner_callback=|peer:&mut super::linux_request_launch::RequestLaunch,peer_association:&memcordon_core::workload_request::WorkloadAttemptAssociationV1|->Result<Value>{
            wait_ready(peer,work)?;
            let (peer_held,peer_observation)=super::linux_current_installed::hold_current_attempt(peer_association,work)?;
            let mut other_liveness=Vec::new();let mut this_liveness=Vec::new();
            // Preserve the existing short-circuit checks and retain their results;
            // this adds no native observation or query.
            if association.attempt==peer_association.attempt || association.request_sha256!=peer_association.request_sha256 || holder.iter().any(|process|{let result=process.exited();let dead=result.as_ref().copied().unwrap_or(true);other_liveness.push(json!({"pid":process.process_id,"birth":process.birth,"pidfd_readable":result.as_ref().ok(),"native_error":result.as_ref().err()}));dead}) || peer_held.iter().any(|process|{let result=process.exited();let dead=result.as_ref().copied().unwrap_or(true);this_liveness.push(json!({"pid":process.process_id,"birth":process.birth,"pidfd_readable":result.as_ref().ok(),"native_error":result.as_ref().err()}));dead}) {return Err(CiError::Message("same digest native attempts were not held concurrently".into()));}
            peer_before=peer_observation;
            peer.send_input(b"R\n".to_vec())?;
            Ok(json!({"format":"memcordon.current-snapshot-concurrent","revision":1,"other_association":association,"other_before":before,"other_liveness":other_liveness,"this_liveness":this_liveness}))
        };
            let case = super::linux_current_installed::run_recipe_with_intervention(
                CurrentLinuxInput {
                    controller_directory: &peer_controller,
                    caller,
                    images: &selected,
                    provider,
                    directory: &working_directory.join("snapshot-concurrent-peer"),
                    work_cutoff: work,
                    cleanup_cutoff: cleanup,
                },
                peer_recipe.clone(),
                &mut inner_callback,
            )?;
            let mut holder_after_peer = Vec::new();
            if holder
                .iter()
                .any(|process| {let result=process.exited();let dead=result.as_ref().copied().unwrap_or(true);holder_after_peer.push(json!({"pid":process.process_id,"birth":process.birth,"pidfd_readable":result.as_ref().ok(),"native_error":result.as_ref().err()}));dead})
            {
                return Err(CiError::Message(
                    "original same-digest holder died during peer execution".into(),
                ));
            }
            peer_case = Some(case);
            launch.send_input(b"R\n".to_vec())?;
            Ok(
                json!({"format":"memcordon.current-snapshot-concurrent","revision":1,"before":before,"peer_before":peer_before,"holder_after_peer":holder_after_peer}),
            )
        };
    let case = super::linux_current_installed::run_recipe_with_intervention(
        CurrentLinuxInput {
            controller_directory: &controller,
            caller,
            images: &selected,
            provider,
            directory: &working_directory.join("snapshot-concurrent-holder"),
            work_cutoff: work,
            cleanup_cutoff: cleanup,
        },
        recipe,
        &mut outer_callback,
    )?;
    let peer = peer_case
        .ok_or_else(|| CiError::Message("original concurrent snapshot peer absent".into()))?;
    let prefix = controller
        .strip_prefix(artifact_root)
        .map_err(|error| CiError::Message(error.to_string()))?
        .to_string_lossy();
    let peer_capture = super::linux_current_case_capture::capture(
        &peer,
        identity,
        lease_id,
        fixture_source,
        &selected,
        &format!("{prefix}/peer"),
        json!({"format":"memcordon.current-snapshot-peer","revision":1}),
    )?;
    let peer_evidence_path = format!("{prefix}/peer/evidence.json");
    let mut capture = super::linux_current_case_capture::capture(
        &case,
        identity,
        lease_id,
        fixture_source,
        &selected,
        &prefix,
        json!({"format":"memcordon.current-snapshot-concurrent","revision":1,"original_bytes":token,"peer_evidence":peer_evidence_path,"peer_input":peer_capture.input}),
    )?;
    capture.files.insert(
        peer_evidence_path,
        serde_json::to_vec(&peer_capture.evidence)?,
    );
    for (path, bytes) in peer_capture.files {
        if capture.files.insert(path, bytes).is_some() {
            return Err(CiError::Message(
                "concurrent snapshot capture collision".into(),
            ));
        }
    }
    let resolver = |path: &str| {
        capture
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| format!("concurrent snapshot artifact absent: {path}"))
    };
    let verification = memcordon_readiness_verifier::current::linux_snapshots::verify_observed_case(
        &capture.evidence,
        &capture.input,
        &identity.source_commit,
        &resolver,
    );
    let (record, artifacts) = super::linux_current_capture::persist_case(
        artifact_root,
        &format!("{prefix}/case.json"),
        &capture.evidence,
        capture.files,
        if verification.is_ok() {
            CaseState::Passed
        } else {
            CaseState::Failed
        },
        verification.as_ref().err().cloned(),
    )?;
    observed.records.push(record);
    observed.artifacts.extend(artifacts);
    verification.map_err(CiError::Message)?;
    for original in [&case, &peer] {
        let ack = caller
            .command(&original.directory, cleanup)?
            .args(["workload", "acknowledge", "--observation"])
            .arg(original.directory.join("workload-observation.json"))
            .output()?;
        crate::command::require_successful_output(
            "concurrent original snapshot acknowledgment",
            &ack,
        )?;
        let ack = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(&ack.stdout)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if ack.association != original.locator {
            return Err(CiError::Message(
                "concurrent ACK original association differs".into(),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_substitution(
    identity: &SourceIdentity,
    key: &ProductKey,
    caller: &CallerSession,
    probe: &Path,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller_directory: &Path,
    working_directory: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    lease_id: &str,
    work: Instant,
    cleanup: Instant,
    observed: &mut InstalledSnapshotObservations,
) -> Result<()> {
    use super::linux_current_phase_gate::NativeReadGate;
    let scenario = "source-fd-substitution";
    let controller = controller_directory.join(format!("snapshot-{scenario}"));
    std::fs::create_dir(&controller)?;
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))?;
    let source = working_directory.join(format!("snapshot-source-{scenario}"));
    owned_directory(&source, caller)?;
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token).map_err(|error| CiError::Message(error.to_string()))?;
    let selected = inputs(images, caller, &source, &token)?;
    let directory = working_directory.join(format!("snapshot-{scenario}"));
    let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
        .into_iter()
        .next()
        .ok_or_else(|| CiError::Message("current fixture recipe absent".into()))?;
    recipe.key.family = "L-SNAPSHOT".into();
    recipe.key.scenario = scenario.into();
    recipe.mode = "snapshot-read".into();
    recipe.arguments = vec![hex::encode(token).into()];
    recipe.requirements.clear();
    recipe.output_files.clear();
    let actor = std::cell::RefCell::new(None::<ProbeRun>);
    let gate = std::cell::RefCell::new(None::<NativeReadGate>);
    let proof = std::cell::RefCell::new(Value::Null);
    let helper = std::cell::RefCell::new(BTreeMap::new());
    let mut before = |fixture: &CallerRequestFixture| -> Result<()> {
        let original = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&fixture.bundle)?;
        let metadata = original.metadata()?;
        let replacement = directory.join("replacement.mci");
        let mut bytes = super::artifacts::read_file(&fixture.bundle)?;
        let last = bytes
            .last_mut()
            .ok_or_else(|| CiError::Message("original bundle empty".into()))?;
        *last ^= 0xff;
        file(&replacement, &bytes, caller.uid, caller.gid)?;
        let request = ProbeInput {
            format: "memcordon.current-snapshot-probe".into(),
            revision: 1,
            operation: "hold-substitute".into(),
            path: fixture.bundle.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            offset: 0,
            bytes: Vec::new(),
            replacement: Some(replacement),
            backup: Some(directory.join("original-held.mci")),
        };
        let mut original_actor = ProbeRun::start(caller, probe, &source, &request, work)?;
        original_actor.phase("opened")?;
        *gate.borrow_mut() = Some(NativeReadGate::on_file(&original, caller.uid, work)?);
        *actor.borrow_mut() = Some(original_actor);
        Ok(())
    };
    let mut opened = |launch: &mut super::linux_request_launch::RequestLaunch,
                      _: &CallerRequestFixture|
     -> Result<()> {
        let frontend = launch.retain_frontend(work)?;
        let mut permission = gate
            .borrow()
            .as_ref()
            .ok_or_else(|| CiError::Message("original bundle permission observer absent".into()))?
            .wait_for(frontend)?;
        if permission.process_id != frontend.process_id {
            return Err(CiError::Message(
                "bundle open event belongs to another actual process".into(),
            ));
        }
        actor
            .borrow()
            .as_ref()
            .expect("original source actor retained")
            .send(b"W\n")?;
        let changed = actor
            .borrow_mut()
            .as_mut()
            .expect("source actor retained")
            .phase("changed")?;
        permission.allow()?;
        let event = permission.observation();
        drop(permission);
        gate.borrow_mut().take();
        let frontend_identity = (frontend.process_id, frontend.birth);
        loop {
            let locator = launch.association();
            if let Ok(locator) = locator {
                let path = directory
                    .join("provider-observations")
                    .join(format!("{}.prepared.json", hex::encode(locator.attempt)));
                if path.try_exists()? {
                    break;
                }
            }
            if launch.capture_finished() || Instant::now() >= work {
                return Err(CiError::Message(
                    "original FD substitution did not reach native Prepared".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        actor
            .borrow()
            .as_ref()
            .expect("source actor retained")
            .send(b"D\n")?;
        *helper.borrow_mut() = actor
            .borrow_mut()
            .as_mut()
            .expect("source actor retained")
            .finish(cleanup)?;
        *proof.borrow_mut() = json!({"format":"memcordon.current-snapshot-substitution","revision":1,"permission":event,"frontend":{"pid":frontend_identity.0,"birth":frontend_identity.1},"changed":changed});
        Ok(())
    };
    let execution = super::linux_current_installed::run_recipe_with_source(
        CurrentLinuxInput {
            controller_directory: &controller,
            caller,
            images: &selected,
            provider,
            directory: &directory,
            work_cutoff: work,
            cleanup_cutoff: cleanup,
        },
        recipe,
        &mut before,
        &mut opened,
        None,
    );
    gate.borrow_mut().take();
    let case = match execution {
        Ok(case) => case,
        Err(primary) => {
            if let Some(actor) = actor.borrow_mut().as_mut() {
                let _ = actor.send(b"D\n");
                let secondary = actor.finish(cleanup);
                return Err(CiError::Message(format!(
                    "{primary}; original substitution helper settlement: {:?}",
                    secondary.as_ref().err()
                )));
            }
            return Err(primary);
        }
    };
    let prefix = controller
        .strip_prefix(artifact_root)
        .map_err(|error| CiError::Message(error.to_string()))?
        .to_string_lossy();
    let mut capture = super::linux_current_case_capture::capture(
        &case,
        identity,
        lease_id,
        fixture_source,
        &selected,
        &prefix,
        json!({"format":"memcordon.current-snapshot-substitution","revision":1,"original_bytes":token,"proof":proof.into_inner(),"helper_receipt":format!("{prefix}/source-helper-probe-receipt.json")}),
    )?;
    for (name, bytes) in helper.into_inner() {
        capture
            .files
            .insert(format!("{prefix}/source-helper-{name}"), bytes);
    }
    persist_success(
        caller,
        &case,
        &controller,
        artifact_root,
        &identity.source_commit,
        capture,
        cleanup,
        observed,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_corruptions(
    identity: &SourceIdentity,
    key: &ProductKey,
    caller: &CallerSession,
    probe: &Path,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller_directory: &Path,
    working_directory: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    lease_id: &str,
    work: Instant,
    cleanup: Instant,
    observed: &mut InstalledSnapshotObservations,
) -> Result<()> {
    use super::linux_current_phase_gate::NativeReadGate;
    use std::os::unix::process::ExitStatusExt;
    for scenario in ["content-mismatch", "source-mutation-during-copy"] {
        let controller = controller_directory.join(format!("snapshot-{scenario}"));
        std::fs::create_dir(&controller)?;
        std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))?;
        let source = working_directory.join(format!("snapshot-source-{scenario}"));
        owned_directory(&source, caller)?;
        let directory = working_directory.join(format!("snapshot-{scenario}"));
        owned_directory(&directory, caller)?;
        let mut token = [0_u8; 32];
        getrandom::fill(&mut token).map_err(|error| CiError::Message(error.to_string()))?;
        let changed = token.map(|byte| byte ^ 0xff);
        let selected = inputs(images, caller, &source, &token)?;
        let mut roots = BoundedVec::default();
        roots
            .try_push(memcordon_core::workload_files::WritableRootV1 {
                id: memcordon_core::identifiers::LogicalId::new("work".into())
                    .map_err(CiError::Message)?,
                path: RootRelativePath::new("work".into()).map_err(CiError::Message)?,
                byte_limit: std::num::NonZeroU64::new(8 * 1024 * 1024).expect("finite work budget"),
                generated_execution: false,
            })
            .map_err(|_| CiError::Message("single writable snapshot root exceeds bound".into()))?;
        let fixture = CallerRequestFixture::pack(
            caller,
            &directory,
            CallerSnapshot {
                manifest: &selected.runtime,
                manifest_path: &selected.runtime_manifest,
                source_root: &selected.runtime_source,
            },
            CallerSnapshot {
                manifest: &selected.input,
                manifest_path: &selected.input_manifest,
                source_root: &selected.input_source,
            },
            memcordon_core::identifiers::LogicalId::new("owned-readiness".into())
                .map_err(CiError::Message)?,
            memcordon_core::workload_request::PrivateRootLayoutV1 {
                writable_roots: roots,
                output_files: Default::default(),
            },
            Default::default(),
            work,
        )?;
        let bundle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&fixture.bundle)?;
        let metadata = bundle.metadata()?;
        let original_bundle = super::artifacts::read_file(&fixture.bundle)?;
        let request = ProbeInput {
            format: "memcordon.current-snapshot-probe".into(),
            revision: 1,
            operation: "hold-write".into(),
            path: fixture.bundle.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            offset: metadata
                .len()
                .checked_sub(token.len() as u64)
                .ok_or_else(|| CiError::Message("bundle lacks declared input bytes".into()))?,
            bytes: changed.to_vec(),
            replacement: None,
            backup: None,
        };
        let mut actor = ProbeRun::start(caller, probe, &source, &request, work)?;
        actor.phase("opened")?;
        let gate = if scenario == "source-mutation-during-copy" {
            Some(NativeReadGate::on_file(&bundle, caller.uid, work)?)
        } else {
            actor.send(b"W\n")?;
            actor.phase("changed")?;
            None
        };
        let observation = directory.join("provider-observations");
        owned_directory(&observation, caller)?;
        let (memory, memory_bytes) = super::linux_snapshot_budget::memory_budget(
            &selected.runtime,
            &selected.input,
            128 * 1024 * 1024,
        )?;
        let arguments = vec![
            std::ffi::OsString::from("snapshot-read"),
            hex::encode(token).into(),
            hex::encode(token).into(),
        ];
        let mut actor = Some(actor);
        let (copy_tx, copy_rx) = mpsc::sync_channel(1);
        let copy_observer: Option<Box<dyn FnOnce(&std::process::Child) -> Result<()> + Send>> =
            if let Some(gate) = gate {
                let bundle = bundle.try_clone()?;
                let directory = directory.clone();
                let original_actor = actor.take().expect("retained original source actor");
                Some(Box::new(move |child| {
                    let result = copy_boundary(
                        child,
                        gate,
                        bundle,
                        original_actor,
                        &directory,
                        work,
                        cleanup,
                    );
                    let failure = result.as_ref().err().map(ToString::to_string);
                    copy_tx
                        .send(result.map_err(|error| error.to_string()))
                        .map_err(|_| {
                            CiError::Message("original copy observer receiver lost".into())
                        })?;
                    match failure {
                        Some(error) => Err(CiError::Message(error)),
                        None => Ok(()),
                    }
                }))
            } else {
                None
            };
        let launch_input = super::linux_request_launch::LaunchInput {
            extra_descriptor: None,
            lifetime: memcordon_core::Lifetime::Command,
            controller_directory: &controller,
            observation_directory: Some(&observation),
            stdin: None,
            interactive: false,
            caller,
            fixture: &fixture,
            directory: &directory,
            provider,
            entrypoint: std::ffi::OsStr::new("owned-readiness"),
            arguments: &arguments,
            memory: &memory,
            deadline: std::ffi::OsStr::new("+10s"),
            output_directory: None,
            work_cutoff: work,
            cleanup_cutoff: cleanup,
        };
        let mut launch = match copy_observer {
            Some(observer) => super::linux_request_launch::RequestLaunch::start_with_copy_observer(
                launch_input,
                observer,
            )?,
            None => super::linux_request_launch::RequestLaunch::start(launch_input)?,
        };
        let execution = (|| -> Result<_> {
            let frontend = launch.retain_frontend(work)?;
            let frontend_identity = (frontend.process_id, frontend.birth);
            launch.close_input();
            let captured = launch.capture_until(cleanup)?;
            let stdout = captured.stdout.clone();
            let stderr = captured.stderr.clone();
            let wait = json!({"process":{"pid":frontend_identity.0,"birth":frontend_identity.1},"raw_wait_status":captured.status.into_raw(),"status":captured.status.code(),"held_before_input":true,"retired":true});
            let result = launch.result()?;
            let association = launch.association()?;
            let recovery = launch.recover()?;
            let (phase, helper) = if let Some(actor) = actor.as_mut() {
                actor.send(b"D\n")?;
                (Value::Null, actor.finish(cleanup)?)
            } else {
                copy_rx
                    .recv_timeout(cleanup.saturating_duration_since(Instant::now()))
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .map_err(CiError::Message)?
            };
            let prepared = observation.join(format!(
                "{}.prepared.json",
                hex::encode(association.attempt)
            ));
            if prepared.try_exists()? {
                return Err(CiError::Message(
                    "corrupted snapshot reached native Prepared".into(),
                ));
            }
            let start = std::fs::read(
                observation.join(format!("{}.start.json", hex::encode(association.attempt))),
            )?;
            Ok((
                phase,
                stdout,
                stderr,
                wait,
                result,
                association,
                recovery.raw_terminal,
                helper,
                start,
            ))
        })();
        let (phase, stdout, stderr, wait, result, association, recovery, helper, start) =
            match execution {
                Ok(value) => value,
                Err(primary) => {
                    let settlement = launch.cancel_and_settle(cleanup);
                    let helper = if let Some(actor) = actor.as_mut() {
                        let _ = actor.send(b"D\n");
                        actor.finish(cleanup).map(|_| ())
                    } else {
                        Ok(())
                    };
                    return Err(CiError::Message(format!(
                        "{primary}; original corrupt-input settlement: {:?}; caller source settlement: {:?}",
                        settlement.as_ref().err(),
                        helper.as_ref().err()
                    )));
                }
            };
        let prefix = controller
            .strip_prefix(artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_string_lossy();
        let mut files = BTreeMap::new();
        let mut put = |leaf: &str, bytes: Vec<u8>| {
            let path = format!("{prefix}/{leaf}");
            files.insert(path.clone(), bytes);
            path
        };
        let selected_fixture =
            super::artifacts::read_file(&selected.runtime_source.join("bin/owned-readiness"))?;
        let fixture_sha256 = super::artifacts::checksum(&selected_fixture);
        let fixture_path = put("fixture.bin", selected_fixture);
        let case_key = CaseKey {
            target: key.target.clone(),
            channel: Some(key.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: "L-SNAPSHOT".into(),
            scenario: scenario.into(),
        };
        let input = json!({"format":"memcordon.current-snapshot-negative-input","revision":1,"run_id":identity.run_id,"key":case_key,"provider":provider,"working_directory":null,"target_argv":memcordon_readiness_verifier::NativeArguments::UnixBytes(arguments.iter().map(|value|{use std::os::unix::ffi::OsStrExt;value.as_bytes().to_vec()}).collect()),"memory_bytes":memory_bytes,"deadline_millis":10000,"lifetime":"command"});
        let input_bytes = serde_json::to_vec(&input)?;
        let input_sha256 = super::artifacts::checksum(&input_bytes);
        let input_path = put("input.json", input_bytes);
        let request = put("request.json", std::fs::read(&fixture.request)?);
        let start_path = put("start.json", start);
        let result_path = put("result.json", serde_json::to_vec(&result)?);
        let association_path = put("association.json", serde_json::to_vec(&association)?);
        let recovery_path = put("recovery.json", recovery);
        let stdout_path = put("stdout.bin", stdout);
        let stderr_path = put("stderr.bin", stderr);
        let frontend = put(
            "frontend.json",
            std::fs::read(controller.join("original-frontend.json"))?,
        );
        let original_bundle_path = put("original-bundle.mci", original_bundle);
        let changed_bundle_path = put(
            "changed-bundle.mci",
            super::artifacts::read_file(&fixture.bundle)?,
        );
        let semantic = put(
            "semantic.json",
            serde_json::to_vec(
                &json!({"format":"memcordon.current-snapshot-negative","revision":1,"scenario":scenario,"original_bytes":token,"changed_bytes":changed,"bundle_length":metadata.len(),"original_bundle":original_bundle_path,"changed_bundle":changed_bundle_path,"request":request,"start":start_path,"frontend":frontend,"wait":wait,"phase":phase,"prepared_observed":false,"helper_receipt":format!("{prefix}/source-helper-probe-receipt.json"),"runtime_snapshot":selected.runtime,"input_snapshot":selected.input}),
            )?,
        );
        for (name, bytes) in helper {
            put(&format!("source-helper-{name}"), bytes);
        }
        let evidence = memcordon_readiness_verifier::current::CaseEvidenceV2 {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 2,
            key: case_key,
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: Some(lease_id.into()),
            fixture: fixture_path,
            fixture_source: fixture_source.into(),
            fixture_sha256,
            fixture_source_sha256: identity.source_tree_sha256.clone(),
            input: input_path,
            input_sha256,
            invocation: start_path,
            request: Some(request),
            raw_result: Some(result_path),
            attempt_observation: Some(association_path),
            authenticated_terminal: None,
            recovery: Some(recovery_path.clone()),
            stdout: stdout_path,
            stderr: stderr_path,
            outputs: Vec::new(),
            native_observation: semantic.clone(),
            retirement: recovery_path,
            semantic_observation: semantic,
            component_recipe_id: None,
        };
        let resolver = |path: &str| {
            files
                .get(path)
                .cloned()
                .ok_or_else(|| format!("snapshot negative artifact absent: {path}"))
        };
        let verification =
            memcordon_readiness_verifier::current::linux_snapshots::verify_observed_case(
                &evidence,
                &input,
                &identity.source_commit,
                &resolver,
            );
        let (record, artifacts) = super::linux_current_capture::persist_case(
            artifact_root,
            &format!("{prefix}/case.json"),
            &evidence,
            files,
            if verification.is_ok() {
                CaseState::Passed
            } else {
                CaseState::Failed
            },
            verification.as_ref().err().cloned(),
        )?;
        observed.records.push(record);
        observed.artifacts.extend(artifacts);
        verification.map_err(CiError::Message)?;
        let ack = caller
            .command(&directory, cleanup)?
            .args(["workload", "acknowledge", "--observation"])
            .arg(directory.join("workload-observation.json"))
            .output()?;
        crate::command::require_successful_output(
            "rejected snapshot evidence acknowledgment",
            &ack,
        )?;
        let ack = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(&ack.stdout)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if ack.association != association {
            return Err(CiError::Message(
                "corruption ACK differs from original association".into(),
            ));
        }
        launch.retire_bundle_exact(&fixture)?;
    }
    Ok(())
}

fn copy_boundary(
    child: &std::process::Child,
    gate: super::linux_current_phase_gate::NativeReadGate,
    bundle: std::fs::File,
    mut actor: ProbeRun,
    directory: &Path,
    work: Instant,
    cleanup: Instant,
) -> Result<(Value, BTreeMap<String, Vec<u8>>)> {
    let execution = (|| -> Result<Value> {
        let birth =
            crate::linux_consumer_readiness::process_birth(child.id()).map_err(CiError::Message)?;
        let frontend =
            crate::linux_consumer_readiness::HeldLinuxProcess::acquire(child.id(), birth)
                .map_err(CiError::Message)?;
        let mut permission = gate.wait_for(&frontend)?;
        if permission.process_id != child.id() {
            return Err(CiError::Message(
                "copy permission event differs from original Child".into(),
            ));
        }
        let mut trace = super::linux_current_phase_gate::NativeTraceStop::attach(
            frontend,
            &mut permission,
            work,
        )?;
        let locator_path = directory.join("workload-observation.json");
        let read = trace.after_source_read(&bundle, 65536, || locator_path.is_file())?;
        let association: memcordon_core::workload_request::WorkloadAttemptAssociationV1 =
            serde_json::from_slice(&std::fs::read(&locator_path)?)?;
        association
            .validate()
            .map_err(|error| CiError::Message(error.to_string()))?;
        let journal_path = Path::new("/var/lib/memcordon/workload-attempts")
            .join(hex::encode(association.attempt));
        let journal = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(journal_path)?;
        let metadata = journal.metadata()?;
        if metadata.uid() != 0
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > 512 * 1024
        {
            return Err(CiError::Message(
                "copy boundary lost protected native journal custody".into(),
            ));
        }
        let mut raw = Vec::new();
        (&journal).take(512 * 1024 + 1).read_to_end(&mut raw)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&raw)
            .map_err(CiError::Message)?;
        let record: Value = serde_json::from_slice(&raw)?;
        if record["association"] != serde_json::to_value(&association)?
            || !record["native"].is_null()
        {
            return Err(CiError::Message(
                "source mutation did not hold original pre-execution intake".into(),
            ));
        }
        actor.send(b"W\n")?;
        let changed = actor.phase("changed")?;
        let phase = json!({"format":"memcordon.current-snapshot-copy-boundary","revision":1,"permission":permission.observation(),"read":read,"journal":record,"journal_custody":{"uid":metadata.uid(),"mode":metadata.mode(),"device":metadata.dev(),"inode":metadata.ino(),"links":metadata.nlink()},"changed":changed,"original_child_wait_not_started":true});
        trace.detach()?;
        Ok(phase)
    })();
    drop(gate);
    let release = actor.send(b"D\n");
    let settled = actor.finish(cleanup);
    match execution {
        Ok(phase) => {
            release?;
            Ok((phase, settled?))
        }
        Err(primary) => Err(CiError::Message(format!(
            "{primary}; source mutation helper release: {release:?}; settlement: {:?}",
            settled.as_ref().err()
        ))),
    }
}

fn persist_success(
    caller: &CallerSession,
    case: &CurrentLinuxCase,
    controller: &Path,
    artifact_root: &Path,
    source_commit: &str,
    capture: super::linux_current_case_capture::CapturedCase,
    cleanup: Instant,
    observed: &mut InstalledSnapshotObservations,
) -> Result<()> {
    let resolver = |path: &str| {
        capture
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| format!("snapshot artifact absent: {path}"))
    };
    let verification = memcordon_readiness_verifier::current::linux_snapshots::verify_observed_case(
        &capture.evidence,
        &capture.input,
        source_commit,
        &resolver,
    );
    let prefix = controller
        .strip_prefix(artifact_root)
        .map_err(|error| CiError::Message(error.to_string()))?
        .to_string_lossy();
    let (record, artifacts) = super::linux_current_capture::persist_case(
        artifact_root,
        &format!("{prefix}/case.json"),
        &capture.evidence,
        capture.files,
        if verification.is_ok() {
            CaseState::Passed
        } else {
            CaseState::Failed
        },
        verification.as_ref().err().cloned(),
    )?;
    observed.records.push(record);
    observed.artifacts.extend(artifacts);
    verification.map_err(CiError::Message)?;
    let ack = caller
        .command(&case.directory, cleanup)?
        .args(["workload", "acknowledge", "--observation"])
        .arg(case.directory.join("workload-observation.json"))
        .output()?;
    crate::command::require_successful_output("original snapshot acknowledgment", &ack)?;
    let ack = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(&ack.stdout)
        .map_err(|error| CiError::Message(error.to_string()))?;
    if ack.association != case.locator {
        return Err(CiError::Message(
            "snapshot acknowledgment names another original attempt".into(),
        ));
    }
    Ok(())
}

fn wait_ready(
    launch: &mut super::linux_request_launch::RequestLaunch,
    work: Instant,
) -> Result<()> {
    loop {
        let snapshot = launch.snapshot_until(work)?;
        if snapshot
            .stdout()?
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| line.ends_with(b"\n"))
            .any(|line| {
                serde_json::from_slice::<Value>(line)
                    .is_ok_and(|row| row["operation"] == "snapshot-input-ready")
            })
        {
            return Ok(());
        }
        if Instant::now() >= work {
            return Err(CiError::Message(
                "original snapshot target readiness cutoff expired".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
