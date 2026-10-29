//! Distinct current isolation experiments with original held host resources.
use super::{
    linux_current_installed::{CallerImages, CurrentLinuxInput, run_recipe},
    linux_request_fixture::CallerSession,
};
use crate::{CiError, Result, readiness_identity::SourceIdentity};
use memcordon_readiness_verifier::{Artifact, CaseRecord, CaseState, ProductKey};
use std::{os::fd::AsFd, path::Path, time::Instant};

pub struct InstalledIsolationObservations {
    pub records: Vec<CaseRecord>,
    pub artifacts: Vec<Artifact>,
    pub primary_error: Option<String>,
}

struct Recorder<'a> {
    identity: &'a SourceIdentity,
    caller: &'a CallerSession,
    images: &'a CallerImages,
    artifact_root: &'a Path,
    fixture_source: &'a str,
    lease_id: &'a str,
    cleanup: Instant,
}
impl Recorder<'_> {
    fn retain(
        &self,
        case: &super::linux_current_installed::CurrentLinuxCase,
        directory: &Path,
        extra: serde_json::Value,
        observed: &mut InstalledIsolationObservations,
    ) -> Result<()> {
        self.retain_nested(
            case,
            directory,
            extra,
            std::collections::BTreeMap::new(),
            observed,
        )
    }
    fn retain_nested(
        &self,
        case: &super::linux_current_installed::CurrentLinuxCase,
        directory: &Path,
        extra: serde_json::Value,
        additional: std::collections::BTreeMap<String, Vec<u8>>,
        observed: &mut InstalledIsolationObservations,
    ) -> Result<()> {
        let prefix = directory
            .strip_prefix(self.artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_string_lossy();
        let mut capture = super::linux_current_case_capture::capture(
            case,
            self.identity,
            self.lease_id,
            self.fixture_source,
            self.images,
            &prefix,
            extra,
        )?;
        for (path, bytes) in additional {
            if capture.files.insert(path, bytes).is_some() {
                return Err(CiError::Message(
                    "isolation nested artifact collides with original capture".into(),
                ));
            }
        }
        let resolver = |path: &str| {
            capture
                .files
                .get(path)
                .cloned()
                .ok_or_else(|| format!("isolation capture absent: {path}"))
        };
        let verification =
            memcordon_readiness_verifier::current::linux_isolation::verify_observed_case(
                &capture.evidence,
                &capture.input,
                &self.identity.source_commit,
                &resolver,
            );
        let (record, artifacts) = super::linux_current_capture::persist_case(
            self.artifact_root,
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
        let acknowledgment = self
            .caller
            .command(&case.directory, self.cleanup)?
            .args(["workload", "acknowledge", "--observation"])
            .arg(case.directory.join("workload-observation.json"))
            .output()?;
        crate::command::require_successful_output(
            "settled isolation evidence acknowledgment",
            &acknowledgment,
        )?;
        let acknowledgment = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(
            &acknowledgment.stdout,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if acknowledgment.association != case.locator {
            return Err(CiError::Message(
                "isolation acknowledgment names another original attempt".into(),
            ));
        }
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
fn run_pairs(
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
    observed: &mut InstalledIsolationObservations,
) -> Result<()> {
    let recorder = Recorder {
        identity,
        caller,
        images,
        artifact_root,
        fixture_source,
        lease_id,
        cleanup,
    };
    for (family, scenario, kind) in [
        ("L-MIX-04", "cross-attempt", "tcp"),
        ("L-ISO-03", "other-attempt-abstract", "abstract"),
        ("L-ISO-06", "same-sandbox-uid-cross-attempt", "tcp"),
        ("L-ISO-06", "foreign-resource-handle", "proc-fd"),
        ("L-ISO-06", "stale-resource-owner", "tcp"),
    ] {
        let work = work.min(
            Instant::now()
                .checked_add(std::time::Duration::from_secs(30))
                .ok_or_else(|| {
                    CiError::Message("original pair observation cutoff overflow".into())
                })?,
        );
        let directory = controller_directory.join(format!("isolation-{scenario}"));
        std::fs::create_dir(&directory)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let peer_controller = directory.join("peer-controller");
        std::fs::create_dir(&peer_controller)?;
        std::fs::set_permissions(&peer_controller, std::fs::Permissions::from_mode(0o700))?;
        let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
            .into_iter()
            .find(|recipe| {
                recipe.key.family == "L-ISO-03" && recipe.key.scenario == "own-abstract-positive"
            })
            .ok_or_else(|| {
                CiError::Message("current abstract listener requirements absent".into())
            })?;
        recipe.key.family = family.into();
        recipe.key.scenario = scenario.into();
        recipe.mode = "isolation-listener".into();
        recipe.arguments.clear();
        recipe.requirements.push(
            memcordon_core::workload_requirements::RequirementRequestV1::TcpListener {
                id: memcordon_core::identifiers::LogicalId::new("isolation-tcp".into())
                    .map_err(|error| CiError::Message(error.to_string()))?,
                local_port: memcordon_core::workload_requirements::LocalPortRequestV1::KernelAssigned,
                peer: memcordon_core::workload_requirements::PrivatePeerRequestV1::DynamicLoopbackWithinThisAttempt,
            },
        );
        let mut peer_recipe = recipe.clone();
        peer_recipe.mode = "isolation-peer".into();
        let mut peer_case = None;
        let mut stale_files: Option<std::collections::BTreeMap<String, Vec<u8>>> = None;
        let mut callback =
            |launch: &mut super::linux_request_launch::RequestLaunch,
             association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1|
             -> Result<serde_json::Value> {
                let ready = loop {
                    let snapshot = launch.snapshot_until(work)?;
                    let mut ready = None;
                    for line in snapshot
                        .stdout()?
                        .split_inclusive(|byte| *byte == b'\n')
                        .filter(|line| line.ends_with(b"\n"))
                    {
                        let row: serde_json::Value = serde_json::from_slice(line)?;
                        if row["operation"] == "isolation-listener-ready" {
                            if ready.replace(row).is_some() {
                                return Err(CiError::Message("listener ready duplicated".into()));
                            }
                        }
                    }
                    if let Some(ready) = ready {
                        break ready;
                    }
                    if Instant::now() >= work {
                        return Err(CiError::Message(
                            "original listener endpoint observation cutoff exhausted".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                };
                let (held, before) =
                    super::linux_current_installed::hold_current_attempt(association, work)?;
                let endpoint = if kind == "proc-fd" {
                    let pid = before["native"]["target"]["pid"].as_u64().ok_or_else(|| {
                        CiError::Message("original foreign native target PID absent".into())
                    })?;
                    let descriptor = ready["observation"]["tcp_descriptor"]
                        .as_u64()
                        .filter(|value| *value >= 3)
                        .ok_or_else(|| {
                            CiError::Message("original native listener descriptor absent".into())
                        })?;
                    format!("/proc/{pid}/fd/{descriptor}")
                } else if kind == "tcp" {
                    ready["observation"]["tcp"]
                        .as_str()
                        .ok_or_else(|| CiError::Message("listener TCP endpoint absent".into()))?
                        .to_owned()
                } else {
                    let bytes = ready["observation"]["abstract_name"]
                        .as_array()
                        .ok_or_else(|| {
                            CiError::Message("listener abstract endpoint absent".into())
                        })?
                        .iter()
                        .map(|value| {
                            value
                                .as_u64()
                                .and_then(|value| u8::try_from(value).ok())
                                .ok_or_else(|| {
                                    CiError::Message("abstract endpoint byte invalid".into())
                                })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    String::from_utf8(bytes).map_err(|error| CiError::Message(error.to_string()))?
                };
                let foreign_descriptor = if kind == "proc-fd" {
                    use std::os::unix::fs::MetadataExt;
                    let native = std::fs::metadata(&endpoint)?;
                    Some(
                        serde_json::json!({"path":endpoint,"device":native.dev(),"inode":native.ino(),"mode":native.mode(),"uid":native.uid()}),
                    )
                } else {
                    None
                };
                peer_recipe.arguments = vec![kind.into(), endpoint.clone().into()];
                let peer = run_recipe(
                    CurrentLinuxInput {
                        controller_directory: &peer_controller,
                        caller,
                        images,
                        provider,
                        directory: &working_directory.join(format!("isolation-{scenario}-peer")),
                        work_cutoff: work,
                        cleanup_cutoff: cleanup,
                    },
                    peer_recipe.clone(),
                )?;
                if scenario == "stale-resource-owner" {
                    use std::os::unix::process::ExitStatusExt;
                    let name = hex::encode(peer.locator.attempt);
                    let paths = [
                        std::path::PathBuf::from("/var/lib/memcordon/workload-inputs").join(&name),
                        std::path::PathBuf::from("/run/memcordon")
                            .join(format!("private-root-{name}")),
                        std::path::PathBuf::from("/var/lib/memcordon/workload-resources")
                            .join(&name),
                        std::path::PathBuf::from("/sys/fs/cgroup/memcordon-sealed").join(&name),
                    ];
                    let census = || -> Result<Vec<serde_json::Value>> {
                        paths.iter().map(|path|match std::fs::symlink_metadata(path){Err(error)if error.raw_os_error()==Some(libc::ENOENT)=>Ok(serde_json::json!({"path":path,"absent":true,"errno":libc::ENOENT})),Err(error)=>Err(error.into()),Ok(_)=>Err(CiError::Message("original retired peer still has native resource owner path".into()))}).collect()
                    };
                    let absent_before = census()?;
                    let report = peer.directory.join("stale-native-recovery.json");
                    let mut child = None;
                    let process = caller
                        .command(&peer.directory, work)?
                        .args(["workload", "recover", "--observation"])
                        .arg(peer.directory.join("workload-observation.json"))
                        .arg("--report")
                        .arg(&report)
                        .output_quiet_with_exec_observation(|native| {
                            let birth = crate::linux_consumer_readiness::process_birth(native.id())
                                .map_err(CiError::Message)?;
                            child = Some(
                                crate::linux_consumer_readiness::HeldLinuxProcess::acquire(
                                    native.id(),
                                    birth,
                                )
                                .map_err(CiError::Message)?,
                            );
                            Ok(())
                        })?;
                    let retention = (|| -> Result<()> {
                        for (leaf, bytes) in [
                            ("stale-recovery-stdout.bin", process.stdout.as_slice()),
                            ("stale-recovery-stderr.bin", process.stderr.as_slice()),
                        ] {
                            super::linux_current_package::retain_raw(
                                artifact_root,
                                &directory.join(leaf),
                                bytes,
                                &mut observed.artifacts,
                            )?;
                        }
                        match std::fs::read(&report) {
                            Ok(bytes) => {
                                super::linux_current_package::retain_raw(
                                    artifact_root,
                                    &directory.join("stale-recovery-original.json"),
                                    &bytes,
                                    &mut observed.artifacts,
                                )?;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error.into()),
                        }
                        Ok(())
                    })();
                    crate::command::require_successful_retained_output(
                        "actual original retired peer cleanup observation",
                        &process,
                        retention,
                    )?;
                    let child = child.ok_or_else(|| {
                        CiError::Message("original stale recovery child absent".into())
                    })?;
                    if !child.exited().map_err(CiError::Message)? {
                        return Err(CiError::Message(
                            "original stale recovery child not reaped".into(),
                        ));
                    }
                    let raw = std::fs::read(&report)?;
                    let terminal = memcordon_core::result_v3::LinuxWorkloadTerminalV1::parse(&raw)
                        .map_err(CiError::Message)?;
                    if terminal.association != peer.locator {
                        return Err(CiError::Message(
                            "stale cleanup selected another original attempt".into(),
                        ));
                    }
                    let absent_after = census()?;
                    stale_files = Some(std::collections::BTreeMap::from([
                        ("terminal.json".into(), raw),
                        ("stdout.bin".into(), process.stdout),
                        ("stderr.bin".into(), process.stderr),
                        (
                            "observation.json".into(),
                            serde_json::to_vec(
                                &serde_json::json!({"format":"memcordon.current-stale-resource-observation","revision":1,"association":peer.locator,"resources_before":absent_before,"resources_after":absent_after,"child":{"pid":child.process_id,"birth":child.birth,"held_before_input":true,"retired":true,"raw_wait_status":process.status.into_raw()},"caller_uid":caller.uid,"caller_gid":caller.gid}),
                            )?,
                        ),
                    ]));
                }
                let after = held
                    .iter()
                    .map(|process| {
                        if process.exited().map_err(CiError::Message)? {
                            return Err(CiError::Message(
                                "original listener owner exited during peer attempt".into(),
                            ));
                        }
                        process.live_snapshot().map_err(CiError::Message)
                    })
                    .collect::<Result<Vec<_>>>()?;
                peer_case = Some(peer);
                launch.send_input(b"R".to_vec())?;
                Ok(
                    serde_json::json!({"format":"memcordon.current-isolation-pair-intervention","revision":1,"original_association":association,"ready":ready,"kind":kind,"endpoint":endpoint,"foreign_descriptor":foreign_descriptor,"before":before,"after":after}),
                )
            };
        let holder = super::linux_current_installed::run_recipe_with_intervention(
            CurrentLinuxInput {
                controller_directory: &directory,
                caller,
                images,
                provider,
                directory: &working_directory.join(format!("isolation-{scenario}-holder")),
                work_cutoff: work,
                cleanup_cutoff: cleanup,
            },
            recipe,
            &mut callback,
        )?;
        drop(callback);
        let peer =
            peer_case.ok_or_else(|| CiError::Message("original peer invocation absent".into()))?;
        let prefix = directory
            .strip_prefix(artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_string_lossy();
        let mut nested = super::linux_current_case_capture::capture(
            &peer,
            identity,
            lease_id,
            fixture_source,
            images,
            &format!("{prefix}/peer"),
            serde_json::Value::Null,
        )?;
        let peer_evidence = format!("{prefix}/peer/case.json");
        nested
            .files
            .insert(peer_evidence.clone(), serde_json::to_vec(&nested.evidence)?);
        let mut stale = std::collections::BTreeMap::new();
        if let Some(captures) = stale_files {
            for (leaf, bytes) in captures {
                let path = format!("{prefix}/stale/{leaf}");
                stale.insert(leaf, path.clone());
                nested.files.insert(path, bytes);
            }
        }
        let extra = serde_json::json!({"format":"memcordon.current-isolation-pair","revision":1,"kind":kind,"peer_case":peer_evidence,"peer_input":nested.evidence.input,"stale":stale});
        recorder.retain_nested(&holder, &directory, extra, nested.files, observed)?;
        let acknowledgment = caller
            .command(&peer.directory, cleanup)?
            .args(["workload", "acknowledge", "--observation"])
            .arg(peer.directory.join("workload-observation.json"))
            .output()?;
        crate::command::require_successful_output(
            "settled isolation peer acknowledgment",
            &acknowledgment,
        )?;
        let ack = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(
            &acknowledgment.stdout,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if ack.association != peer.locator {
            return Err(CiError::Message(
                "peer acknowledgment names another attempt".into(),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_socket_import_refusals(
    identity: &SourceIdentity,
    key: &ProductKey,
    caller: &CallerSession,
    images: &CallerImages,
    controller_directory: &Path,
    working_directory: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    lease_id: &str,
    work: Instant,
    observed: &mut InstalledIsolationObservations,
) -> Result<()> {
    use memcordon_readiness_verifier::{CaseKey, EvidenceClass, current::CaseEvidenceV2};
    use std::{
        io::Write,
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixListener,
            process::ExitStatusExt,
        },
    };
    for scenario in [
        "input-socket",
        "imported-socket",
        "host-tree-mount-import-rejected",
    ] {
        let controller = controller_directory.join(format!("isolation-{scenario}"));
        std::fs::create_dir(&controller)?;
        std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))?;
        let directory = working_directory.join(format!("isolation-{scenario}"));
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        rustix::fs::chown(
            &directory,
            Some(rustix::process::Uid::from_raw(caller.uid)),
            Some(rustix::process::Gid::from_raw(caller.gid)),
        )
        .map_err(std::io::Error::from)?;
        let input_root = directory.join("source");
        std::fs::create_dir(&input_root)?;
        std::fs::set_permissions(&input_root, std::fs::Permissions::from_mode(0o755))?;
        let host_tree = directory.join("host-tree");
        let mut tree_marker = [0u8; 32];
        if scenario == "host-tree-mount-import-rejected" {
            std::fs::create_dir(&host_tree)?;
            std::fs::set_permissions(&host_tree, std::fs::Permissions::from_mode(0o755))?;
            getrandom::fill(&mut tree_marker)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let mut marker = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(host_tree.join("marker.bin"))?;
            marker.write_all(&tree_marker)?;
            marker.sync_all()?;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(input_root.join("socket"))?
                .sync_all()?;
        }
        let actual = if scenario == "input-socket" {
            input_root.join("socket")
        } else if scenario == "host-tree-mount-import-rejected" {
            host_tree.join("outside.sock")
        } else {
            directory.join("outside.sock")
        };
        let socket = UnixListener::bind(&actual)?;
        std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o666))?;
        rustix::fs::chown(
            &actual,
            Some(rustix::process::Uid::from_raw(caller.uid)),
            Some(rustix::process::Gid::from_raw(caller.gid)),
        )
        .map_err(std::io::Error::from)?;
        if scenario == "imported-socket" {
            std::os::unix::fs::symlink(&actual, input_root.join("socket"))?;
        }
        let member = std::fs::symlink_metadata(input_root.join("socket"))?;
        let held = std::fs::symlink_metadata(&actual)?;
        let descriptor = rustix::fs::fstat(socket.as_fd()).map_err(std::io::Error::from)?;
        let mut manifest = images.input.clone();
        manifest.entries = Default::default();
        manifest
            .entries
            .try_push(memcordon_core::workload_files::ImageEntryV1::Regular {
                path: memcordon_core::workload_files::RootRelativePath::new("socket".into())
                    .map_err(CiError::Message)?,
                sha256: memcordon_core::hash_bytes(b""),
                size: 0,
                executable: false,
            })
            .map_err(|_| {
                CiError::Message("single socket source manifest exceeds current bound".into())
            })?;
        manifest.entrypoints = Default::default();
        manifest.library_directories = Default::default();
        manifest.validate().map_err(CiError::Message)?;
        let manifest_bytes = manifest.canonical_bytes().map_err(CiError::Message)?;
        let manifest_path = directory.join("input.json");
        let spec_path = directory.join("pack.json");
        let output = directory.join("forbidden.mci");
        let mut spec = serde_json::json!({"runtime":{"manifest":images.runtime_manifest,"root":images.runtime_source},"input":{"manifest":manifest_path,"root":input_root}});
        if scenario == "host-tree-mount-import-rejected" {
            spec["host_tree"] =
                serde_json::json!({"source":host_tree,"mount_target":"/imported-host"});
        }
        for (path, bytes) in [
            (&manifest_path, manifest_bytes.clone()),
            (&spec_path, serde_json::to_vec(&spec)?),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        let watcher = super::linux_current_phase_gate::NativeNamespaceWatch::new(&[
            ("journal", Path::new("/var/lib/memcordon/workload-attempts")),
            (
                "input-staging",
                Path::new("/var/lib/memcordon/workload-inputs"),
            ),
            (
                "footprint",
                Path::new("/var/lib/memcordon/workload-resources"),
            ),
            ("root-staging", Path::new("/run/memcordon")),
            ("cgroup", Path::new("/sys/fs/cgroup/memcordon-sealed")),
        ])?;
        let before = watcher.snapshot()?;
        let mut child = None;
        let arguments: Vec<std::ffi::OsString> = vec![
            "workload".into(),
            "pack".into(),
            "--spec".into(),
            spec_path.as_os_str().to_owned(),
            "--output".into(),
            output.as_os_str().to_owned(),
        ];
        let process = caller
            .command(&directory, work)?
            .args(&arguments)
            .output_quiet_with_exec_observation(|native| {
                let birth = crate::linux_consumer_readiness::process_birth(native.id())
                    .map_err(CiError::Message)?;
                child = Some(
                    crate::linux_consumer_readiness::HeldLinuxProcess::acquire(native.id(), birth)
                        .map_err(CiError::Message)?,
                );
                Ok(())
            })?;
        let child = child
            .ok_or_else(|| CiError::Message("original packing child observation absent".into()))?;
        for (leaf, bytes) in [
            ("packing-original-stdout.bin", process.stdout.as_slice()),
            ("packing-original-stderr.bin", process.stderr.as_slice()),
        ] {
            super::linux_current_package::retain_raw(
                artifact_root,
                &controller.join(leaf),
                bytes,
                &mut observed.artifacts,
            )?;
        }
        super::linux_current_package::retain_raw(
            artifact_root,
            &controller.join("packing-original-wait.json"),
            &serde_json::to_vec(
                &serde_json::json!({"pid":child.process_id,"birth":child.birth,"raw_wait_status":process.status.into_raw(),"kernel_exec_stop_observed":true}),
            )?,
            &mut observed.artifacts,
        )?;
        let retired = child.exited().map_err(CiError::Message)?;
        let after = watcher.snapshot()?;
        let events = watcher.drain()?;
        let named = std::fs::symlink_metadata(&actual)?;
        if named.dev() != held.dev() || named.ino() != held.ino() || named.nlink() != 1 {
            return Err(CiError::Message(
                "original source socket identity changed during packing".into(),
            ));
        }
        let prefix = controller
            .strip_prefix(artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_string_lossy();
        let mut files = std::collections::BTreeMap::new();
        let mut put = |leaf: &str, bytes: Vec<u8>| {
            let path = format!("{prefix}/{leaf}");
            files.insert(path.clone(), bytes);
            path
        };
        let fixture_bytes = super::artifacts::read_file(&caller.installed_cli)?;
        let fixture_sha256 = super::artifacts::checksum(&fixture_bytes);
        let fixture = put("cli.bin", fixture_bytes);
        let key = CaseKey {
            target: key.target.clone(),
            channel: Some(key.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: "L-ISO-02".into(),
            scenario: scenario.into(),
        };
        let input = serde_json::json!({"format":"memcordon.current-socket-import-input","revision":1,"key":key,"run_id":identity.run_id,"scenario":scenario});
        let input_bytes = serde_json::to_vec(&input)?;
        let input_sha256 = super::artifacts::checksum(&input_bytes);
        let input_path = put("input.json", input_bytes);
        let invocation = put(
            "invocation.json",
            serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.current-socket-import-invocation","revision":1,"installed_cli":caller.installed_cli,"caller_uid":caller.uid,"caller_gid":caller.gid,"arguments":memcordon_readiness_verifier::NativeArguments::UnixBytes(arguments.iter().map(|value|{use std::os::unix::ffi::OsStrExt;value.as_bytes().to_vec()}).collect()),"child":{"pid":child.process_id,"birth":child.birth,"held_before_input":true,"retired":retired,"raw_wait_status":process.status.into_raw()},"output_present":output.try_exists()?}),
            )?,
        );
        let stdout = put("stdout.bin", process.stdout);
        let stderr = put("stderr.bin", process.stderr);
        let namespaces = put(
            "namespaces.json",
            serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.current-import-native-observation","revision":1,"before":before,"after":after,"events":events}),
            )?,
        );
        let manifest_path = put("snapshot.json", manifest_bytes);
        let spec_path = put("pack.json", serde_json::to_vec(&spec)?);
        let semantic = put(
            "semantic.json",
            serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.current-socket-import-refusal","revision":1,"scenario":scenario,"snapshot":manifest_path,"pack_spec":spec_path,"socket":{"path":actual,"device":held.dev(),"inode":held.ino(),"uid":held.uid(),"mode":held.mode(),"links":held.nlink(),"descriptor_inode":descriptor.st_ino},"source_member":{"mode":member.mode(),"uid":member.uid(),"inode":member.ino(),"symlink_target":if scenario=="imported-socket"{Some(std::fs::read_link(input_root.join("socket"))?)}else{None}},"host_tree":if scenario=="host-tree-mount-import-rejected" {let held=std::fs::metadata(&host_tree)?;serde_json::json!({"path":host_tree,"device":held.dev(),"inode":held.ino(),"uid":held.uid(),"mode":held.mode(),"marker_bytes":tree_marker,"after_bytes":std::fs::read(host_tree.join("marker.bin"))?})}else{serde_json::Value::Null}}),
            )?,
        );
        let evidence = CaseEvidenceV2 {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 2,
            key,
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: Some(lease_id.into()),
            fixture,
            fixture_source: fixture_source.into(),
            fixture_sha256,
            fixture_source_sha256: identity.source_tree_sha256.clone(),
            input: input_path,
            input_sha256,
            invocation,
            request: None,
            raw_result: None,
            attempt_observation: None,
            authenticated_terminal: None,
            recovery: None,
            stdout,
            stderr,
            outputs: Vec::new(),
            native_observation: namespaces.clone(),
            retirement: namespaces,
            semantic_observation: semantic,
            component_recipe_id: None,
        };
        let verification =
            memcordon_readiness_verifier::current::linux_isolation::verify_observed_case(
                &evidence,
                &input,
                &identity.source_commit,
                &|path| {
                    files
                        .get(path)
                        .cloned()
                        .ok_or_else(|| format!("packing refusal capture absent: {path}"))
                },
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
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_descriptor_cases(
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
    observed: &mut InstalledIsolationObservations,
) -> Result<()> {
    use std::{
        io::{Read, Write},
        os::{
            fd::OwnedFd,
            unix::{
                fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
                net::UnixStream,
            },
        },
    };
    let recorder = Recorder {
        identity,
        caller,
        images,
        artifact_root,
        fixture_source,
        lease_id,
        cleanup,
    };
    for scenario in ["opath", "extra-host-fd", "stdio-host-socket"] {
        let controller = controller_directory.join(format!("isolation-{scenario}"));
        std::fs::create_dir(&controller)?;
        std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))?;
        let mut token = [0u8; 32];
        getrandom::fill(&mut token).map_err(|error| CiError::Message(error.to_string()))?;
        let source = working_directory.join(format!("isolation-{scenario}-host.bin"));
        let descriptor;
        let mut peer = None;
        if scenario == "opath" {
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&source)?;
            output.write_all(&token)?;
            output.sync_all()?;
            drop(output);
            descriptor = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&source)?;
            if std::fs::read(&source)? != token {
                return Err(CiError::Message(
                    "original O_PATH host object positive differs".into(),
                ));
            }
        } else {
            let (mut receiver, mut sender) = UnixStream::pair()?;
            let remaining = work
                .saturating_duration_since(Instant::now())
                .min(std::time::Duration::from_secs(3));
            if remaining.is_zero() {
                return Err(CiError::Message(
                    "original descriptor positive IO cutoff exhausted".into(),
                ));
            }
            sender.set_write_timeout(Some(remaining))?;
            receiver.set_read_timeout(Some(remaining))?;
            sender.write_all(&token)?;
            let mut received = [0u8; 32];
            receiver.read_exact(&mut received)?;
            if received != token {
                return Err(CiError::Message(
                    "original hostile socket positive bytes differ".into(),
                ));
            }
            sender.shutdown(std::net::Shutdown::Write)?;
            descriptor = std::fs::File::from(OwnedFd::from(receiver));
            peer = Some(sender);
        }
        let before = descriptor.metadata()?;
        let source_flags = rustix::fs::fcntl_getfl(&descriptor)
            .map_err(std::io::Error::from)?
            .bits();
        let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
            .into_iter()
            .find(|recipe| {
                if scenario == "opath" {
                    recipe.key.family == "L-ISO-04" && recipe.key.scenario == "opath"
                } else {
                    recipe.key.family == "L-ISO-05" && recipe.key.scenario == scenario
                }
            })
            .ok_or_else(|| CiError::Message("current descriptor recipe absent".into()))?;
        if scenario == "opath" {
            recipe.mode = "outside-file".into();
            recipe.arguments = vec!["opath".into(), source.as_os_str().to_owned(), "128".into()];
        } else {
            recipe.mode = "descriptor-isolation".into();
            recipe.arguments.clear();
        }
        let case = super::linux_current_installed::run_recipe_with_descriptors(
            CurrentLinuxInput {
                controller_directory: &controller,
                caller,
                images,
                provider,
                directory: &working_directory.join(format!("isolation-{scenario}")),
                work_cutoff: work,
                cleanup_cutoff: cleanup,
            },
            recipe,
            if scenario == "stdio-host-socket" {
                None
            } else {
                Some(&descriptor)
            },
            if scenario == "stdio-host-socket" {
                Some(&descriptor)
            } else {
                None
            },
        )?;
        let after = descriptor.metadata()?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.mode() != after.mode()
        {
            return Err(CiError::Message(
                "original hostile descriptor identity changed".into(),
            ));
        }
        if scenario == "opath" && std::fs::read(&source)? != token {
            return Err(CiError::Message(
                "original O_PATH host bytes changed".into(),
            ));
        }
        let original = controller.join("original-frontend.json");
        let held = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&original)?;
        let metadata = held.metadata()?;
        if metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > 1024 * 1024
        {
            return Err(CiError::Message(
                "original frontend descriptor observation custody differs".into(),
            ));
        }
        let mut original_bytes = Vec::new();
        held.take(1024 * 1024 + 1)
            .read_to_end(&mut original_bytes)?;
        let prefix = controller
            .strip_prefix(artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_string_lossy();
        let original_path = format!("{prefix}/frontend-native.json");
        let extra = serde_json::json!({"format":"memcordon.current-isolation-descriptor","revision":1,"scenario":scenario,"frontend":original_path,"source":{"device":before.dev(),"inode":before.ino(),"mode":before.mode(),"uid":before.uid(),"links":before.nlink(),"flags":source_flags},"source_path":if scenario=="opath"{Some(&source)}else{None},"positive_bytes":token,"held_across_invocation":true});
        recorder.retain_nested(
            &case,
            &controller,
            extra,
            std::collections::BTreeMap::from([(original_path, original_bytes)]),
            observed,
        )?;
        drop(peer);
        if scenario == "opath" {
            let named = std::fs::symlink_metadata(&source)?;
            if (named.dev(), named.ino()) != (before.dev(), before.ino()) {
                return Err(CiError::Message(
                    "original O_PATH source path changed before retirement".into(),
                ));
            }
            std::fs::remove_file(&source)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_installed(
    root: &Path,
    identity: &SourceIdentity,
    key: &ProductKey,
    caller: &CallerSession,
    _foreign: &CallerSession,
    _probe: &Path,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller_directory: &Path,
    working_directory: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    lease_id: &str,
    work: Instant,
    cleanup: Instant,
) -> InstalledIsolationObservations {
    let mut observed = InstalledIsolationObservations {
        records: Vec::new(),
        artifacts: Vec::new(),
        primary_error: None,
    };
    let operation = (|| -> Result<()> {
        if !root.is_absolute() || work >= cleanup {
            return Err(CiError::Message(
                "isolation original source/cutoff context invalid".into(),
            ));
        }
        let images = images.minimal();
        let recorder = Recorder {
            identity,
            caller,
            images,
            artifact_root,
            fixture_source,
            lease_id,
            cleanup,
        };
        for scenario in ["host-tcp", "nonloopback"] {
            // The live host listener is held across the entire private invocation;
            // a denied connect to an unbound address would not establish isolation.
            let address = if scenario == "host-tcp" {
                std::net::Ipv4Addr::LOCALHOST
            } else {
                // UDP connect selects an actual host route without sending data.
                let route = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
                route.connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 9))?;
                match route.local_addr()?.ip() {
                    std::net::IpAddr::V4(address)
                        if !address.is_loopback() && !address.is_unspecified() =>
                    {
                        address
                    }
                    _ => {
                        return Err(CiError::Message(
                            "host has no native nonloopback IPv4 route".into(),
                        ));
                    }
                }
            };
            let listener = std::net::TcpListener::bind((address, 0))?;
            let address = listener.local_addr()?;
            listener.set_nonblocking(true)?;
            let remaining = work.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CiError::Message(
                    "original isolation work cutoff exhausted".into(),
                ));
            }
            let positive = std::net::TcpStream::connect_timeout(
                &address,
                remaining.min(std::time::Duration::from_secs(3)),
            )?;
            let (accepted, peer) = listener.accept()?;
            if peer != positive.local_addr()? {
                return Err(CiError::Message(
                    "host positive accepted another native peer".into(),
                ));
            }
            drop(positive);
            drop(accepted);
            let metadata = rustix::fs::fstat(listener.as_fd()).map_err(std::io::Error::from)?;
            let namespace = std::fs::read_link("/proc/self/ns/net")?;
            let directory = controller_directory.join(format!("isolation-{scenario}"));
            std::fs::create_dir(&directory)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
                .into_iter()
                .find(|recipe| recipe.key.family == "L-ISO-01" && recipe.key.scenario == scenario)
                .ok_or_else(|| CiError::Message("current host TCP recipe absent".into()))?;
            recipe.mode = "isolation-peer".into();
            recipe.arguments = vec!["tcp".into(), address.to_string().into()];
            let case = run_recipe(
                CurrentLinuxInput {
                    controller_directory: &directory,
                    caller,
                    images,
                    provider,
                    directory: &working_directory.join(format!("isolation-{scenario}")),
                    work_cutoff: work,
                    cleanup_cutoff: cleanup,
                },
                recipe,
            )?;
            let queue_error = match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    error.raw_os_error()
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    return Err(CiError::Message(
                        "private target reached original host listener".into(),
                    ));
                }
            };
            let extra = serde_json::json!({"format":"memcordon.current-isolation-host","revision":1,"scenario":scenario,"address":address.to_string(),"positive_peer":peer.to_string(),"socket_device":metadata.st_dev,"socket_inode":metadata.st_ino,"network_namespace":namespace,"native_accept_errno":queue_error,"held_across_invocation":true});
            recorder.retain(&case, &directory, extra, &mut observed)?;
        }
        {
            use std::os::unix::{
                fs::{MetadataExt, PermissionsExt},
                net::{UnixListener, UnixStream},
            };
            let socket = working_directory.join("isolation-host-temp.sock");
            let listener = UnixListener::bind(&socket)?;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
            listener.set_nonblocking(true)?;
            let positive = UnixStream::connect(&socket)?;
            let (accepted, _) = listener.accept()?;
            drop(positive);
            drop(accepted);
            let held = std::fs::symlink_metadata(&socket)?;
            let fd = rustix::fs::fstat(listener.as_fd()).map_err(std::io::Error::from)?;
            let directory = controller_directory.join("isolation-host-temp-socket");
            std::fs::create_dir(&directory)?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
                .into_iter()
                .find(|recipe| {
                    recipe.key.family == "L-ISO-02" && recipe.key.scenario == "host-temp-socket"
                })
                .ok_or_else(|| CiError::Message("current host socket recipe absent".into()))?;
            recipe.arguments = vec![socket.as_os_str().to_owned()];
            let case = run_recipe(
                CurrentLinuxInput {
                    controller_directory: &directory,
                    caller,
                    images,
                    provider,
                    directory: &working_directory.join("isolation-host-temp-socket"),
                    work_cutoff: work,
                    cleanup_cutoff: cleanup,
                },
                recipe,
            )?;
            let errno = match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    error.raw_os_error()
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    return Err(CiError::Message(
                        "target reached live host Unix listener".into(),
                    ));
                }
            };
            let named = std::fs::symlink_metadata(&socket)?;
            if named.dev() != held.dev()
                || named.ino() != held.ino()
                || named.mode() != held.mode()
                || named.nlink() != 1
            {
                return Err(CiError::Message("host socket inode custody changed".into()));
            }
            let extra = serde_json::json!({"format":"memcordon.current-isolation-host-path","revision":1,"scenario":"host-temp-socket","path":socket,"device":held.dev(),"inode":held.ino(),"mode":held.mode(),"uid":held.uid(),"links":held.nlink(),"descriptor_inode":fd.st_ino,"positive_connection_observed":true,"native_accept_errno":errno,"held_across_invocation":true});
            recorder.retain(&case, &directory, extra, &mut observed)?;
            std::fs::remove_file(&socket)?;
        }
        {
            use std::io::{Read, Write};
            use std::os::{
                linux::net::SocketAddrExt,
                unix::net::{SocketAddr, UnixListener, UnixStream},
            };
            let mut token = [0u8; 32];
            getrandom::fill(&mut token).map_err(|error| CiError::Message(error.to_string()))?;
            let name = format!("memcordon-host-{}", hex::encode(token));
            let address = SocketAddr::from_abstract_name(name.as_bytes())?;
            let listener = UnixListener::bind_addr(&address)?;
            listener.set_nonblocking(true)?;
            let mut positive = UnixStream::connect_addr(&address)?;
            let (mut receiver, _) = listener.accept()?;
            let remaining = work
                .saturating_duration_since(Instant::now())
                .min(std::time::Duration::from_secs(3));
            if remaining.is_zero() {
                return Err(CiError::Message(
                    "original host listener work cutoff exhausted".into(),
                ));
            }
            positive.set_write_timeout(Some(remaining))?;
            receiver.set_read_timeout(Some(remaining))?;
            positive.write_all(&token)?;
            let mut received = [0u8; 32];
            receiver.read_exact(&mut received)?;
            if received != token {
                return Err(CiError::Message(
                    "host abstract positive bytes differ".into(),
                ));
            }
            drop(positive);
            drop(receiver);
            let metadata = rustix::fs::fstat(listener.as_fd()).map_err(std::io::Error::from)?;
            let directory = controller_directory.join("isolation-host-abstract");
            std::fs::create_dir(&directory)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
                .into_iter()
                .find(|recipe| {
                    recipe.key.family == "L-ISO-03" && recipe.key.scenario == "host-abstract"
                })
                .ok_or_else(|| CiError::Message("current host abstract recipe absent".into()))?;
            recipe.mode = "isolation-peer".into();
            recipe.arguments = vec!["abstract".into(), name.clone().into()];
            let case = run_recipe(
                CurrentLinuxInput {
                    controller_directory: &directory,
                    caller,
                    images,
                    provider,
                    directory: &working_directory.join("isolation-host-abstract"),
                    work_cutoff: work,
                    cleanup_cutoff: cleanup,
                },
                recipe,
            )?;
            let errno = match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    error.raw_os_error()
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    return Err(CiError::Message(
                        "target reached original host abstract socket".into(),
                    ));
                }
            };
            let extra = serde_json::json!({"format":"memcordon.current-isolation-host-abstract","revision":1,"name":name,"positive_bytes":received,"descriptor_inode":metadata.st_ino,"network_namespace":std::fs::read_link("/proc/self/ns/net")?,"native_accept_errno":errno,"held_across_invocation":true});
            recorder.retain(&case, &directory, extra, &mut observed)?;
        }
        for scenario in [
            "symlink",
            "dotdot",
            "proc-root",
            "proc-cwd",
            "proc-fd",
            "hardlink",
            "mount-alias",
            "no-host-proc-import",
        ] {
            use std::{
                io::Write,
                os::{
                    fd::AsRawFd,
                    unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
                },
            };
            let directory = controller_directory.join(format!("isolation-{scenario}"));
            std::fs::create_dir(&directory)?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let source = working_directory.join(format!("isolation-{scenario}-host.bin"));
            let mut marker = [0u8; 32];
            getrandom::fill(&mut marker).map_err(|error| CiError::Message(error.to_string()))?;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o444)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&source)?;
            file.write_all(&marker)?;
            file.sync_all()?;
            let held = file.metadata()?;
            let host_pid = std::process::id();
            let host_birth = crate::linux_consumer_readiness::process_birth(host_pid)
                .map_err(CiError::Message)?;
            let probe = match scenario {
                "proc-root" | "no-host-proc-import" => {
                    std::path::PathBuf::from(format!("/proc/{host_pid}/root{}", source.display()))
                }
                "proc-cwd" => std::path::PathBuf::from(format!(
                    "/proc/{host_pid}/cwd/{}{}",
                    "../".repeat(128),
                    source.to_string_lossy().trim_start_matches('/')
                )),
                "proc-fd" => {
                    std::path::PathBuf::from(format!("/proc/{host_pid}/fd/{}", file.as_raw_fd()))
                }
                _ => source.clone(),
            };
            if std::fs::read(&probe)? != marker {
                return Err(CiError::Message(
                    "actual host counterpart cannot read original marker".into(),
                ));
            }
            let mut recipe = super::linux_current_inputs::owned_fixture_recipes(key)?
                .into_iter()
                .find(|recipe| {
                    recipe.key.family == "L-ISO-04"
                        && recipe.key.scenario
                            == if scenario == "no-host-proc-import" {
                                "proc-root"
                            } else {
                                scenario
                            }
                })
                .ok_or_else(|| CiError::Message("current outside-path recipe absent".into()))?;
            recipe.mode = "isolation-path".into();
            recipe.arguments = vec![
                scenario.into(),
                source.as_os_str().to_owned(),
                probe.as_os_str().to_owned(),
            ];
            if scenario == "no-host-proc-import" {
                recipe.key.family = "L-ISO-06".into();
                recipe.key.scenario = scenario.into();
                recipe.mode = "isolation-proc".into();
                recipe.arguments = vec![
                    host_pid.to_string().into(),
                    host_birth.to_string().into(),
                    probe.as_os_str().to_owned(),
                ];
            }
            let case = run_recipe(
                CurrentLinuxInput {
                    controller_directory: &directory,
                    caller,
                    images,
                    provider,
                    directory: &working_directory.join(format!("isolation-{scenario}")),
                    work_cutoff: work,
                    cleanup_cutoff: cleanup,
                },
                recipe,
            )?;
            let named = std::fs::symlink_metadata(&source)?;
            if named.dev() != held.dev()
                || named.ino() != held.ino()
                || named.nlink() != 1
                || std::fs::read(&source)? != marker
            {
                return Err(CiError::Message(
                    "original host marker changed during isolated open".into(),
                ));
            }
            let extra = serde_json::json!({"format":"memcordon.current-isolation-path","revision":1,"scenario":scenario,"source":source,"probe":probe,"host_pid":host_pid,"host_birth":host_birth,"descriptor":file.as_raw_fd(),"device":held.dev(),"inode":held.ino(),"uid":held.uid(),"mode":held.mode(),"links":held.nlink(),"positive_bytes":marker,"after_bytes":std::fs::read(&source)?,"held_across_invocation":true});
            recorder.retain(&case, &directory, extra, &mut observed)?;
            std::fs::remove_file(&source)?;
        }
        run_socket_import_refusals(
            identity,
            key,
            caller,
            images,
            controller_directory,
            working_directory,
            artifact_root,
            fixture_source,
            lease_id,
            work,
            &mut observed,
        )?;
        run_pairs(
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
        run_descriptor_cases(
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
        Ok(())
    })();
    if let Err(error) = operation {
        let mut primary = error.to_string();
        for scenario in [
            "host-tcp",
            "nonloopback",
            "host-temp-socket",
            "host-abstract",
            "input-socket",
            "imported-socket",
            "host-tree-mount-import-rejected",
            "cross-attempt",
            "other-attempt-abstract",
            "same-sandbox-uid-cross-attempt",
            "foreign-resource-handle",
            "stale-resource-owner",
            "symlink",
            "dotdot",
            "proc-root",
            "proc-cwd",
            "proc-fd",
            "hardlink",
            "mount-alias",
            "no-host-proc-import",
            "opath",
            "extra-host-fd",
            "stdio-host-socket",
        ] {
            let controller = controller_directory.join(format!("isolation-{scenario}"));
            let retention = (|| -> Result<()> {
                if controller.try_exists()? {
                    for (suffix, controller) in [
                        ("", controller.clone()),
                        ("-holder", controller.clone()),
                        ("-peer", controller.join("peer-controller")),
                    ] {
                        let caller_directory =
                            working_directory.join(format!("isolation-{scenario}{suffix}"));
                        if caller_directory.try_exists()? && controller.try_exists()? {
                            super::linux_current_lease::retain_case_failure(
                                &caller_directory,
                                &controller,
                                artifact_root,
                                caller.uid,
                                &primary,
                                &mut observed.artifacts,
                            )?;
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = retention {
                primary = format!("{primary}; original isolation failure capture: {error}");
            }
        }
        observed.primary_error = Some(primary);
    }
    observed
}
