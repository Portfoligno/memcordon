//! Actual current initial-image/loader experiments under the ordinary caller.
use super::{
    artifacts,
    linux_current_inputs::CurrentRecipe,
    linux_current_installed::{
        CallerImages, CurrentLinuxInput, hold_current_attempt, run_recipe_with_source,
    },
    linux_request_fixture::CallerSession,
    source,
};
use crate::{CiError, Result, readiness_identity::SourceIdentity};
use memcordon_core::{
    PublicProviderBindingV1,
    workload_bundle::SnapshotManifestV1,
    workload_files::{ImageEntryV1, RootRelativePath},
};
use memcordon_readiness_verifier::{
    Artifact, CaseKey, CaseRecord, CaseState, EvidenceClass, ProductKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn copy_snapshot(
    source: &Path,
    snapshot: &SnapshotManifestV1,
    destination: &Path,
    caller: &CallerSession,
    cutoff: Instant,
) -> Result<()> {
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    let source = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    for entry in snapshot.entries.as_slice() {
        if Instant::now() >= cutoff {
            return Err(fail("current image copy exhausted original cutoff"));
        }
        if let ImageEntryV1::Regular {
            path,
            sha256,
            size,
            executable,
        } = entry
        {
            let held = opened(&source, path.as_str(), false)?;
            let observed = observe(&held)?;
            if observed["sha256"] != serde_json::to_value(sha256)? || observed["length"] != *size {
                return Err(fail(
                    "current image source changed before independent fixture copy",
                ));
            }
            let target = destination.join(path.as_str());
            fs::create_dir_all(
                target
                    .parent()
                    .ok_or_else(|| fail("image member parent absent"))?,
            )?;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)?;
            std::io::copy(&mut held.take(*size + 1), &mut file)?;
            file.sync_all()?;
            file.set_permissions(fs::Permissions::from_mode(if *executable {
                0o755
            } else {
                0o644
            }))?;
        }
    }
    let mut remaining = 65536;
    super::linux_current_installed::caller_tree(destination, caller, cutoff, &mut remaining)
}
fn rpath_probe(original: &[u8], target: &str) -> Result<(Vec<u8>, Value)> {
    let file = |offset: usize, count: usize| {
        original
            .get(
                offset
                    ..offset
                        .checked_add(count)
                        .ok_or_else(|| fail("ELF mutation extent overflow"))?,
            )
            .ok_or_else(|| fail("ELF mutation extent invalid"))
    };
    let scalar = |offset: usize| -> Result<u64> {
        Ok(u64::from_le_bytes(
            file(offset, 8)?
                .try_into()
                .map_err(|_| fail("ELF mutation scalar absent"))?,
        ))
    };
    if file(0, 6)? != b"\x7fELF\x02\x01" {
        return Err(fail("current RPATH fixture is not native ELF64LE"));
    }
    let offset = usize::try_from(scalar(32)?).map_err(|error| fail(error.to_string()))?;
    let count = usize::from(u16::from_le_bytes(
        file(56, 2)?
            .try_into()
            .map_err(|_| fail("ELF program count absent"))?,
    ));
    if count == 0 || count > 512 {
        return Err(fail("ELF mutation program inventory invalid"));
    }
    let mut dynamic = None;
    for index in 0..count {
        let at = offset
            .checked_add(index * 56)
            .ok_or_else(|| fail("ELF header mutation overflow"))?;
        if u32::from_le_bytes(
            file(at, 4)?
                .try_into()
                .map_err(|_| fail("ELF program kind absent"))?,
        ) == 2
        {
            dynamic = Some((
                usize::try_from(scalar(at + 8)?).map_err(|error| fail(error.to_string()))?,
                usize::try_from(scalar(at + 32)?).map_err(|error| fail(error.to_string()))?,
            ));
        }
    }
    let (dynamic, length) = dynamic.ok_or_else(|| fail("actual fixture has no dynamic table"))?;
    file(dynamic, length)?;
    let mut needed = None;
    let mut end = None;
    for at in (dynamic..dynamic + length).step_by(16) {
        match scalar(at)? {
            1 if needed.is_none() => needed = Some(scalar(at + 8)?),
            0 => {
                end = Some(at);
                break;
            }
            _ => {}
        }
    }
    let end = end.ok_or_else(|| fail("ELF dynamic terminator absent"))?;
    if end.checked_add(32).is_none_or(|end| end > dynamic + length) || scalar(end + 16)? != 0 {
        return Err(fail(
            "actual ELF has no spare dynamic terminator for RPATH probe",
        ));
    }
    let mut probe = original.to_vec();
    probe[end..end + 8].copy_from_slice(&29_u64.to_le_bytes());
    probe[end + 8..end + 16].copy_from_slice(
        &needed
            .ok_or_else(|| fail("actual ELF has no needed dependency string"))?
            .to_le_bytes(),
    );
    let held = std::io::Cursor::new(&probe);
    let elf = memcordon_core::elf_closure::inspect(
        |offset, buffer| {
            use std::io::Read;
            let mut held = held.clone();
            held.set_position(offset);
            held.read_exact(buffer).map_err(|error| error.to_string())
        },
        probe.len() as u64,
        target,
    )
    .map_err(fail)?
    .ok_or_else(|| fail("RPATH probe stopped being native ELF"))?;
    if elf.search_paths.len() != 1 || elf.search_paths[0].starts_with('/') {
        return Err(fail(
            "RPATH probe did not select actual relative dynamic search",
        ));
    }
    Ok((
        probe,
        json!({"offset":end,"old_tag":0,"new_tag":29,"string_offset":needed,"search":elf.search_paths[0]}),
    ))
}
#[expect(
    clippy::too_many_arguments,
    reason = "Actual selected source and original native actor are retained separately"
)]
fn negative(
    identity: &SourceIdentity,
    key: &ProductKey,
    caller: &CallerSession,
    images: &CallerImages,
    provider: &PublicProviderBindingV1,
    controller: &Path,
    working: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    lease_id: &str,
    scenario: &str,
    work: Instant,
    cleanup: Instant,
    observed: &mut InstalledImageObservations,
) -> Result<()> {
    use super::linux_request_fixture::{CallerRequestFixture, CallerSnapshot};
    use super::linux_request_launch::{LaunchInput, RequestLaunch};
    use memcordon_core::{
        BoundedVec, identifiers::LogicalId, workload_request::PrivateRootLayoutV1,
    };
    let directory = working.join(format!("current-loader-{scenario}"));
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        &directory,
        Some(rustix::process::Uid::from_raw(caller.uid)),
        Some(rustix::process::Gid::from_raw(caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    let captures = controller.join(format!("current-loader-{scenario}"));
    fs::create_dir(&captures)?;
    fs::set_permissions(&captures, fs::Permissions::from_mode(0o700))?;
    let observer = directory.join("observer");
    fs::create_dir(&observer)?;
    fs::set_permissions(&observer, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        &observer,
        Some(rustix::process::Uid::from_raw(caller.uid)),
        Some(rustix::process::Gid::from_raw(caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    let original_fixture =
        artifacts::read_file(&images.runtime_source.join("bin/owned-readiness"))?;
    let mut runtime = images.runtime.clone();
    let mut input = images.input.clone();
    let mut runtime_root = images.runtime_source.clone();
    let mut input_root = images.input_source.clone();
    let mut mutation = Value::Null;
    let mut probe = Vec::new();
    if scenario == "rpath-injection" {
        runtime_root = directory.join("runtime-source");
        copy_snapshot(
            &images.runtime_source,
            &runtime,
            &runtime_root,
            caller,
            work,
        )?;
        let (changed, details) = rpath_probe(&original_fixture, &key.target)?;
        probe = changed;
        mutation = details;
        fs::write(runtime_root.join("bin/owned-readiness"), &probe)?;
        let mut value = serde_json::to_value(&runtime)?;
        for entry in value["entries"]
            .as_array_mut()
            .ok_or_else(|| fail("runtime entries absent"))?
        {
            if entry["path"] == "bin/owned-readiness" {
                entry["sha256"] = artifacts::checksum(&probe).into();
                entry["size"] = (probe.len() as u64).into();
            }
        }
        runtime = serde_json::from_value(value)?;
        runtime.validate().map_err(fail)?;
    } else if scenario == "loader-config" {
        input_root = directory.join("input-source");
        copy_snapshot(&images.input_source, &input, &input_root, caller, work)?;
        fs::create_dir(input_root.join("etc"))?;
        let config = b"/work/caller-loader-injection.so\n";
        fs::write(input_root.join("etc/ld.so.preload"), config)?;
        rustix::fs::chown(
            input_root.join("etc/ld.so.preload"),
            Some(rustix::process::Uid::from_raw(caller.uid)),
            Some(rustix::process::Gid::from_raw(caller.gid)),
        )
        .map_err(std::io::Error::from)?;
        let mut value = serde_json::to_value(&input)?;
        value["entries"].as_array_mut().ok_or_else(||fail("input entries absent"))?.push(json!({"kind":"regular","path":"etc/ld.so.preload","sha256":artifacts::checksum(config),"size":config.len(),"executable":false}));
        input = serde_json::from_value(value)?;
        input.validate().map_err(fail)?;
        mutation = json!({"path":"etc/ld.so.preload","bytes":config.as_slice()});
    }
    let runtime_manifest = directory.join("runtime.json");
    let input_manifest = directory.join("input.json");
    source::write_diagnostic_json(&runtime_manifest, &runtime)?;
    source::write_diagnostic_json(&input_manifest, &input)?;
    let mut roots = BoundedVec::default();
    roots
        .try_push(memcordon_core::workload_files::WritableRootV1 {
            id: LogicalId::new("work".into()).map_err(fail)?,
            path: RootRelativePath::new("work".into()).map_err(fail)?,
            byte_limit: std::num::NonZeroU64::new(1024 * 1024).expect("finite work"),
            generated_execution: false,
        })
        .map_err(|_| fail("work roots full"))?;
    let fixture = CallerRequestFixture::pack(
        caller,
        &directory,
        CallerSnapshot {
            manifest: &runtime,
            manifest_path: &runtime_manifest,
            source_root: &runtime_root,
        },
        CallerSnapshot {
            manifest: &input,
            manifest_path: &input_manifest,
            source_root: &input_root,
        },
        LogicalId::new("owned-readiness".into()).map_err(fail)?,
        PrivateRootLayoutV1 {
            writable_roots: roots,
            output_files: BoundedVec::default(),
        },
        BoundedVec::default(),
        work,
    )?;
    let (memory, memory_bytes) =
        super::linux_snapshot_budget::memory_budget(&runtime, &input, 128 * 1024 * 1024)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|error| fail(error.to_string()))?;
    let challenge = hex::encode(nonce);
    let arguments = vec![
        "bytes-argv-status".into(),
        challenge.clone().into(),
        "0".into(),
    ];
    let before = super::linux_current_refusals::allocations()?;
    let loader_path = directory.join("empty-loader-directory");
    if scenario == "ld-injection" {
        fs::create_dir(&loader_path)?;
        fs::set_permissions(&loader_path, fs::Permissions::from_mode(0o700))?;
        rustix::fs::chown(
            &loader_path,
            Some(rustix::process::Uid::from_raw(caller.uid)),
            Some(rustix::process::Gid::from_raw(caller.gid)),
        )
        .map_err(std::io::Error::from)?;
    }
    let launch_input = LaunchInput {
        lifetime: memcordon_core::Lifetime::Command,
        controller_directory: &captures,
        observation_directory: Some(&observer),
        interactive: false,
        stdin: None,
        caller,
        fixture: &fixture,
        directory: &directory,
        provider,
        entrypoint: std::ffi::OsStr::new("owned-readiness"),
        arguments: &arguments,
        memory: &memory,
        deadline: std::ffi::OsStr::new("+10s"),
        output_directory: None,
        extra_descriptor: None,
        work_cutoff: work.min(Instant::now() + Duration::from_secs(30)),
        cleanup_cutoff: cleanup,
    };
    let mut launch = if scenario == "ld-injection" {
        RequestLaunch::start_with_loader_path(launch_input, &loader_path)?
    } else {
        RequestLaunch::start(launch_input)?
    };
    let execution = (|| -> Result<()> {
        let frontend = launch.retain_frontend(work)?;
        let frontend_identity = json!({"pid":frontend.process_id,"birth":frontend.birth});
        let output = launch.capture_until(work)?;
        use std::os::unix::process::ExitStatusExt;
        let stdout = output.stdout.clone();
        let stderr = output.stderr.clone();
        let wait = json!({"process":frontend_identity,"status":output.status.code(),"raw_wait_status":output.status.into_raw()});
        let result_bytes = artifacts::read_file(&directory.join("workload-result.json"))?;
        let result = memcordon_core::result_v3::ResultV3::parse(&result_bytes).map_err(fail)?;
        let association = if scenario == "ld-injection" {
            None
        } else {
            Some(launch.association()?)
        };
        let start_path = observer.join(
            association
                .as_ref()
                .map_or("rejected-start.json".into(), |association| {
                    format!("{}.start.json", hex::encode(association.attempt))
                }),
        );
        let start_bytes = artifacts::read_file(&start_path)?;
        let recovery = association.as_ref().map(|_| launch.recover()).transpose()?;
        let journal = association
            .as_ref()
            .map(|association| -> Result<Vec<u8>> {
                let path = Path::new("/var/lib/memcordon/workload-attempts")
                    .join(hex::encode(association.attempt));
                crate::linux_consumer_readiness::measured(&path, 512 * 1024).map_err(fail)
            })
            .transpose()?;
        // Retain the original native and caller bytes durably before ACK can
        // retire the provider's only exact-attempt metadata.
        let retained = captures.join("pre-ack-original");
        fs::create_dir(&retained)?;
        fs::set_permissions(&retained, fs::Permissions::from_mode(0o700))?;
        let mut originals = std::collections::BTreeMap::from([
            ("request.json", fs::read(&fixture.request)?),
            ("start.json", start_bytes.clone()),
            ("result.json", result_bytes.clone()),
            ("stdout.bin", stdout.clone()),
            ("stderr.bin", stderr.clone()),
            (
                "runtime-snapshot.json",
                runtime.canonical_bytes().map_err(fail)?,
            ),
            (
                "input-snapshot.json",
                input.canonical_bytes().map_err(fail)?,
            ),
            (
                "frontend.json",
                fs::read(captures.join("original-frontend.json"))?,
            ),
            ("fixture.bin", original_fixture.clone()),
        ]);
        if let Some(association) = &association {
            originals.insert("attempt.json", serde_json::to_vec(association)?);
        }
        if let Some(recovery) = &recovery {
            originals.insert("recovery.json", recovery.raw_terminal.clone());
        }
        if let Some(journal) = &journal {
            originals.insert("journal.json", journal.clone());
        }
        if !probe.is_empty() {
            originals.insert("probe-image.bin", probe.clone());
        }
        originals.insert("source-selection.json",serde_json::to_vec(&json!({"source":identity,"key":key,"lease_id":lease_id,"scenario":scenario,"provider":provider,"mutation":mutation,"wait":wait}))?);
        for (leaf, bytes) in originals {
            super::linux_current_package::retain_raw(
                artifact_root,
                &retained.join(leaf),
                &bytes,
                &mut observed.artifacts,
            )?;
        }
        File::open(&retained)?.sync_all()?;
        File::open(&captures)?.sync_all()?;
        let ack = if association.is_some() {
            let output = caller
                .command(&directory, cleanup)?
                .args(["workload", "acknowledge", "--observation"])
                .arg(directory.join("workload-observation.json"))
                .output()?;
            crate::command::require_successful_output(
                "original rejected image metadata retirement",
                &output,
            )?;
            Some(output.stdout)
        } else {
            None
        };
        let after = super::linux_current_refusals::allocations()?;
        launch.retire_bundle_exact(&fixture)?;
        let prefix = captures
            .strip_prefix(artifact_root)
            .map_err(|error| fail(error.to_string()))?
            .to_string_lossy();
        let path = |name: &str| format!("{prefix}/{name}");
        let case_key = CaseKey {
            target: key.target.clone(),
            channel: Some(key.channel.clone()),
            family: "L-IMG-02".into(),
            scenario: scenario.into(),
            evidence_class: EvidenceClass::InstalledProduct,
        };
        use std::os::unix::ffi::OsStrExt;
        let input_value = json!({"format":"memcordon.current-linux-image-negative-input","revision":1,"run_id":identity.run_id,"key":case_key,"challenge":challenge,"working_directory":null,"memory_bytes":memory_bytes,"deadline_millis":10000,"lifetime":"command","target_argv":memcordon_readiness_verifier::NativeArguments::UnixBytes(arguments.iter().map(|value|value.as_bytes().to_vec()).collect()),"loader_path":if scenario=="ld-injection"{Some(loader_path.as_os_str().as_bytes())}else{None}});
        let mut files = std::collections::BTreeMap::from([
            (path("fixture.bin"), original_fixture.clone()),
            (path("request.json"), fs::read(&fixture.request)?),
            (path("start.json"), start_bytes),
            (path("result.json"), result_bytes),
            (path("stdout.bin"), stdout),
            (path("stderr.bin"), stderr),
            (path("input.json"), serde_json::to_vec(&input_value)?),
            (
                path("runtime-snapshot.json"),
                runtime.canonical_bytes().map_err(fail)?,
            ),
            (
                path("input-snapshot.json"),
                input.canonical_bytes().map_err(fail)?,
            ),
            (
                path("frontend.json"),
                fs::read(captures.join("original-frontend.json"))?,
            ),
        ]);
        if !probe.is_empty() {
            files.insert(path("probe-image.bin"), probe.clone());
        }
        if let Some(association) = &association {
            files.insert(path("attempt.json"), serde_json::to_vec(association)?);
        }
        if let Some(recovery) = &recovery {
            files.insert(path("recovery.json"), recovery.raw_terminal.clone());
        }
        if let Some(journal) = journal {
            files.insert(path("journal.json"), journal);
        }
        if let Some(ack) = ack {
            files.insert(path("ack.json"), ack);
        }
        let proof = json!({"format":"memcordon.current-linux-image-negative","revision":1,"scenario":scenario,"lease_id":lease_id,"provider":provider,"wait":wait,"before":before,"after":after,"mutation":mutation,"request":path("request.json"),"start":path("start.json"),"runtime_snapshot":path("runtime-snapshot.json"),"input_snapshot":path("input-snapshot.json"),"probe":if probe.is_empty(){None}else{Some(path("probe-image.bin"))},"frontend":path("frontend.json"),"journal":association.as_ref().map(|_|path("journal.json")),"ack":association.as_ref().map(|_|path("ack.json")),"recovery_wait":recovery.as_ref().map(|recovery|json!({"status":recovery.process.status.code(),"raw_wait_status":recovery.process.status.into_raw()}))});
        files.insert(path("negative.json"), serde_json::to_vec(&proof)?);
        let evidence = memcordon_readiness_verifier::current::CaseEvidenceV2 {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 2,
            key: case_key,
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: Some(lease_id.into()),
            fixture: path("fixture.bin"),
            fixture_source: fixture_source.into(),
            fixture_sha256: artifacts::checksum(&original_fixture),
            fixture_source_sha256: identity.source_tree_sha256.clone(),
            input: path("input.json"),
            input_sha256: artifacts::checksum(
                files
                    .get(&path("input.json"))
                    .expect("actual input retained"),
            ),
            invocation: path("start.json"),
            request: Some(path("request.json")),
            raw_result: Some(path("result.json")),
            attempt_observation: association.as_ref().map(|_| path("attempt.json")),
            authenticated_terminal: None,
            recovery: recovery.as_ref().map(|_| path("recovery.json")),
            stdout: path("stdout.bin"),
            stderr: path("stderr.bin"),
            outputs: Vec::new(),
            native_observation: path("negative.json"),
            retirement: path("negative.json"),
            semantic_observation: path("negative.json"),
            component_recipe_id: None,
        };
        let verify = memcordon_readiness_verifier::current::linux_images::verify_observed_case(
            &evidence,
            &input_value,
            &identity.source_commit,
            &|path| {
                files
                    .get(path)
                    .cloned()
                    .ok_or_else(|| format!("negative image capture absent: {path}"))
            },
        );
        let (record, inventory) = super::linux_current_capture::persist_case(
            artifact_root,
            &path("case.json"),
            &evidence,
            files,
            if verify.is_ok() {
                CaseState::Passed
            } else {
                CaseState::Failed
            },
            verify.as_ref().err().cloned(),
        )?;
        observed.records.push(record);
        observed.artifacts.extend(inventory);
        verify.map_err(fail)?;
        let _ = result;
        Ok(())
    })();
    if let Err(primary) = execution {
        let settled = launch.cancel_and_settle(cleanup);
        let retained = super::linux_current_lease::retain_case_failure(
            &directory,
            &captures,
            artifact_root,
            caller.uid,
            &primary.to_string(),
            &mut observed.artifacts,
        );
        let mut detail = primary.to_string();
        if let Err(secondary) = settled {
            detail = format!("{detail}; original image frontend settlement: {secondary}");
        }
        if let Err(secondary) = retained {
            detail = format!("{detail}; original image capture retention: {secondary}");
        }
        return Err(fail(detail));
    }
    Ok(())
}
pub struct InstalledImageObservations {
    pub records: Vec<CaseRecord>,
    pub artifacts: Vec<Artifact>,
    pub primary_error: Option<String>,
}
fn fail(detail: impl Into<String>) -> CiError {
    CiError::Message(detail.into())
}
fn regular<'a>(manifest: &'a SnapshotManifestV1, path: &str) -> Result<&'a ImageEntryV1> {
    let mut selected = RootRelativePath::new(path.into()).map_err(fail)?;
    for _ in 0..64 {
        let entry = manifest
            .entries
            .as_slice()
            .iter()
            .find(|entry| entry.path() == &selected)
            .ok_or_else(|| fail("selected current image member absent"))?;
        match entry {
            ImageEntryV1::Regular { .. } => return Ok(entry),
            ImageEntryV1::Symlink { target, .. } => selected = target.clone(),
        }
    }
    Err(fail("current image dependency alias exceeded bound"))
}
fn observe(file: &File) -> Result<Value> {
    let before = file.metadata()?;
    if !before.is_file() || before.len() > 512 * 1024 * 1024 {
        return Err(fail("held current image is not bounded regular data"));
    }
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut buffer = [0; 65536];
    while offset < before.len() {
        let remaining = usize::try_from((before.len() - offset).min(buffer.len() as u64))
            .map_err(|error| fail(error.to_string()))?;
        let count = file.read_at(&mut buffer[..remaining], offset)?;
        if count == 0 {
            return Err(fail("held current image shortened"));
        }
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    let after = file.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mode(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mode(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(fail("held image changed during native observation"));
    }
    Ok(
        json!({"device":before.dev(),"inode":before.ino(),"uid":before.uid(),"gid":before.gid(),"mode":before.mode(),"links":before.nlink(),"length":before.len(),"sha256":hex::encode(hash.finalize())}),
    )
}
fn opened(root: &File, path: &str, write: bool) -> Result<File> {
    Ok(File::from(
        rustix::fs::openat2(
            root,
            path,
            (if write {
                rustix::fs::OFlags::RDWR
            } else {
                rustix::fs::OFlags::RDONLY
            }) | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS,
        )
        .map_err(std::io::Error::from)?,
    ))
}
fn bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(fail("native image observation exceeds bound"));
    }
    Ok(bytes)
}
fn selected(images: &CallerImages, target: &str, scenario: &str) -> Result<String> {
    let file = File::open(images.runtime_source.join("bin/owned-readiness"))?;
    let elf = memcordon_core::elf_closure::inspect(
        |offset, buffer| {
            file.read_exact_at(buffer, offset)
                .map_err(|error| error.to_string())
        },
        file.metadata()?.len(),
        target,
    )
    .map_err(fail)?
    .ok_or_else(|| fail("selected fixture is not native ELF"))?;
    match scenario {
        "first-image" | "snapshot-writable-alias" => Ok("bin/owned-readiness".into()),
        "interpreter" => Ok(regular(
            &images.runtime,
            elf.interpreter
                .as_deref()
                .ok_or_else(|| fail("actual fixture interpreter absent"))?
                .strip_prefix('/')
                .ok_or_else(|| fail("actual interpreter not root absolute"))?,
        )?
        .path()
        .as_str()
        .into()),
        "shared-library" => {
            let name = elf
                .needed
                .first()
                .ok_or_else(|| fail("actual fixture has no shared library"))?;
            for directory in images.runtime.library_directories.as_slice() {
                let path = format!("{}/{name}", directory.as_str());
                if let Ok(entry) = regular(&images.runtime, &path) {
                    return Ok(entry.path().as_str().into());
                }
            }
            Err(fail(
                "actual fixture shared library is absent from current snapshot",
            ))
        }
        _ => Err(fail("unknown current image observation")),
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Original installed caller, source, product and phase cutoffs remain distinct"
)]
pub fn run_installed(
    root: &Path,
    identity: &SourceIdentity,
    key: &ProductKey,
    caller: &CallerSession,
    probe: &Path,
    images: &CallerImages,
    provider: &PublicProviderBindingV1,
    controller: &Path,
    working: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    lease_id: &str,
    work: Instant,
    cleanup: Instant,
) -> InstalledImageObservations {
    let images = images.minimal();
    let mut observed = InstalledImageObservations {
        records: Vec::new(),
        artifacts: Vec::new(),
        primary_error: None,
    };
    let operation = (|| -> Result<()> {
        for scenario in [
            "first-image",
            "interpreter",
            "shared-library",
            "snapshot-writable-alias",
        ] {
            let case_key = CaseKey {
                target: key.target.clone(),
                channel: Some(key.channel.clone()),
                family: "L-IMG-01".into(),
                scenario: scenario.into(),
                evidence_class: EvidenceClass::InstalledProduct,
            };
            let directory = working.join(format!("current-image-{scenario}"));
            let captures = controller.join(format!("current-image-{scenario}"));
            fs::create_dir(&captures)?;
            fs::set_permissions(&captures, fs::Permissions::from_mode(0o700))?;
            let path = selected(images, &key.target, scenario)?;
            let prefix = captures
                .strip_prefix(artifact_root)
                .map_err(|error| fail(error.to_string()))?
                .to_string_lossy()
                .into_owned();
            let alias_actor =
                std::cell::RefCell::new(None::<super::linux_current_snapshot_cases::ProbeRun>);
            let alias_files =
                std::cell::RefCell::new(std::collections::BTreeMap::<String, Vec<u8>>::new());
            let alias_original = std::cell::Cell::new(0_u8);
            let mut before =
                |_: &super::linux_request_fixture::CallerRequestFixture| -> Result<()> {
                    if scenario != "snapshot-writable-alias" {
                        return Ok(());
                    }
                    let source_path = images.runtime_source.join(&path);
                    let source = fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&source_path)?;
                    let metadata = source.metadata()?;
                    let mut byte = [0_u8; 1];
                    source.read_exact_at(&mut byte, 0)?;
                    alias_original.set(byte[0]);
                    let directory = directory.join("alias-mutation");
                    fs::create_dir(&directory)?;
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
                    std::os::unix::fs::chown(&directory, Some(caller.uid), Some(caller.gid))?;
                    let request = crate::linux_snapshot_probe::ProbeInput {
                        format: "memcordon.current-snapshot-probe".into(),
                        revision: 1,
                        operation: "hold-write".into(),
                        path: source_path,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        offset: 0,
                        bytes: vec![byte[0] ^ 0xff],
                        replacement: None,
                        backup: None,
                    };
                    let actor = super::linux_current_snapshot_cases::ProbeRun::start(
                        caller, probe, &directory, &request, work,
                    )?;
                    *alias_actor.borrow_mut() = Some(actor);
                    alias_actor
                        .borrow_mut()
                        .as_mut()
                        .expect("assigned actor")
                        .phase("opened")?;
                    Ok(())
                };
            let mut source_opened = |_: &mut super::linux_request_launch::RequestLaunch,
                                     _: &super::linux_request_fixture::CallerRequestFixture|
             -> Result<()> { Ok(()) };
            let mut extra = Value::Null;
            let mut callback =
                |launch: &mut super::linux_request_launch::RequestLaunch,
                 association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1|
                 -> Result<Value> {
                    let snapshot = launch.snapshot_until(work)?;
                    loop {
                        let ready = snapshot
                            .stdout()?
                            .split_inclusive(|byte| *byte == b'\n')
                            .filter(|line| line.ends_with(b"\n"))
                            .any(|line| {
                                serde_json::from_slice::<Value>(line)
                                    .is_ok_and(|row| row["operation"] == "image-custody-ready")
                            });
                        if ready {
                            break;
                        }
                        if Instant::now() >= work || launch.capture_finished() {
                            return Err(fail("original current image readiness cutoff exhausted"));
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    let (held, native) = hold_current_attempt(association, work)?;
                    let target = &held[4];
                    let root = File::open(format!("/proc/{}/root", target.process_id))?;
                    let root_meta = root.metadata()?;
                    if Some(root_meta.dev()) != native["root"]["device"].as_u64()
                        || Some(root_meta.ino()) != native["root"]["inode"].as_u64()
                    {
                        return Err(fail("current image query has another original root"));
                    }
                    let protected = opened(&root, &path, false)?;
                    let before = observe(&protected)?;
                    let source_root = fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
                        .open(&images.runtime_source)?;
                    let source_file = opened(&source_root, &path, false)?;
                    let source_before = observe(&source_file)?;
                    let executable = File::open(format!("/proc/{}/exe", target.process_id))?;
                    let mut alias = Value::Null;
                    if scenario == "snapshot-writable-alias" {
                        source::write_json(
                            &captures.join("source-alias-intent.json"),
                            &json!({"path":path,"source":source_before,"original_byte":alias_original.get(),"protected":before}),
                        )?;
                        let mut actor = alias_actor
                            .borrow_mut()
                            .take()
                            .ok_or_else(|| fail("original caller writable alias owner absent"))?;
                        let mutation = (|| -> Result<Value> {
                            actor.send(b"W\n")?;
                            actor.phase("changed")
                        })();
                        let immutable = observe(&protected);
                        let release = actor.send(b"D\n");
                        let mutation_capture = actor.finish(cleanup);
                        // Restoration is a second actual ordinary caller effect,
                        // even if mutation/drain failed; root never rewrites it.
                        let restoration =
                            (|| -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
                                let restore_directory = directory.join("alias-restoration");
                                fs::create_dir(&restore_directory)?;
                                fs::set_permissions(
                                    &restore_directory,
                                    fs::Permissions::from_mode(0o700),
                                )?;
                                std::os::unix::fs::chown(
                                    &restore_directory,
                                    Some(caller.uid),
                                    Some(caller.gid),
                                )?;
                                let restore_request = crate::linux_snapshot_probe::ProbeInput {
                                    format: "memcordon.current-snapshot-probe".into(),
                                    revision: 1,
                                    operation: "write".into(),
                                    path: images.runtime_source.join(&path),
                                    device: source_file.metadata()?.dev(),
                                    inode: source_file.metadata()?.ino(),
                                    offset: 0,
                                    bytes: vec![alias_original.get()],
                                    replacement: None,
                                    backup: None,
                                };
                                let mut actor =
                                    super::linux_current_snapshot_cases::ProbeRun::start(
                                        caller,
                                        probe,
                                        &restore_directory,
                                        &restore_request,
                                        cleanup,
                                    )?;
                                let effect = actor.phase("changed");
                                let settled = actor.finish(cleanup);
                                effect?;
                                settled
                            })();
                        let first_error = mutation
                            .as_ref()
                            .err()
                            .map(ToString::to_string)
                            .or_else(|| immutable.as_ref().err().map(ToString::to_string))
                            .or_else(|| release.as_ref().err().map(ToString::to_string))
                            .or_else(|| mutation_capture.as_ref().err().map(ToString::to_string));
                        for (role, capture) in
                            [("mutation", mutation_capture), ("restoration", restoration)]
                        {
                            match capture {
                                Ok(files) => {
                                    for (name, bytes) in files {
                                        alias_files
                                            .borrow_mut()
                                            .insert(format!("{prefix}/alias-{role}-{name}"), bytes);
                                    }
                                }
                                Err(error) => {
                                    return Err(fail(format!(
                                        "{}; ordinary caller {role} settlement: {error}",
                                        first_error
                                            .as_deref()
                                            .unwrap_or("image alias observation failed")
                                    )));
                                }
                            }
                        }
                        if let Some(error) = first_error {
                            return Err(fail(error));
                        }
                        alias = json!({"changed":observe(&source_file)?,"protected_during_change":immutable?,"restored":observe(&source_file)?,"mutation_receipt":format!("{prefix}/alias-mutation-probe-receipt.json"),"restoration_receipt":format!("{prefix}/alias-restoration-probe-receipt.json")});
                        let mutation_path = alias["mutation_receipt"]
                            .as_str()
                            .expect("assigned receipt");
                        let receipt: Value = serde_json::from_slice(
                            alias_files
                                .borrow()
                                .get(mutation_path)
                                .ok_or_else(|| fail("actual mutation receipt absent"))?,
                        )?;
                        alias["changed"] = receipt["changed"].clone();
                    }
                    extra = json!({"format":"memcordon.linux-current-image-custody","revision":1,"scenario":scenario,"path":path,"root":{"device":root_meta.dev(),"inode":root_meta.ino()},"protected":before,"protected_after":observe(&protected)?,"source":source_before,"alias":alias,"executable":observe(&executable)?,"maps":bounded(&PathBuf::from(format!("/proc/{}/maps",target.process_id)),1024*1024)?,"runtime_canonical":images.runtime.canonical_bytes().map_err(fail)?});
                    drop(protected);
                    drop(root);
                    drop(executable);
                    drop(held);
                    launch.send_input(b"R".to_vec())?;
                    Ok(extra.clone())
                };
            let recipe = CurrentRecipe {
                key: case_key,
                mode: "image-custody".into(),
                arguments: vec![scenario.into(), format!("/{path}").into()],
                requirements: Vec::new(),
                output_files: Vec::new(),
                memory: "+128MiB".into(),
                product_deadline: "+30s".into(),
                observation_limit: Duration::from_secs(30),
            };
            let case = match run_recipe_with_source(
                CurrentLinuxInput {
                    controller_directory: &captures,
                    caller,
                    images,
                    provider,
                    directory: &directory,
                    work_cutoff: work,
                    cleanup_cutoff: cleanup,
                },
                recipe,
                &mut before,
                &mut source_opened,
                Some(&mut callback),
            ) {
                Ok(case) => case,
                Err(error) => {
                    let helper_settlement = alias_actor
                        .borrow_mut()
                        .take()
                        .map(|mut actor| actor.finish(cleanup));
                    let primary = fail(format!(
                        "{error}; original caller alias helper settlement: {:?}",
                        helper_settlement
                            .as_ref()
                            .and_then(|result| result.as_ref().err())
                    ));
                    if let Err(retention) = super::linux_current_lease::retain_case_failure(
                        &directory,
                        &captures,
                        artifact_root,
                        caller.uid,
                        &primary.to_string(),
                        &mut observed.artifacts,
                    ) {
                        return Err(fail(format!(
                            "{primary}; evidence retention also failed: {retention}"
                        )));
                    }
                    return Err(primary);
                }
            };
            let prefix = captures
                .strip_prefix(artifact_root)
                .map_err(|error| fail(error.to_string()))?
                .to_string_lossy();
            let mut capture = super::linux_current_case_capture::capture(
                &case,
                identity,
                lease_id,
                fixture_source,
                images,
                &prefix,
                extra,
            )?;
            for (path, bytes) in alias_files.into_inner() {
                if capture.files.insert(path, bytes).is_some() {
                    return Err(fail("image caller-alias capture path collided"));
                }
            }
            let verify = memcordon_readiness_verifier::current::linux_images::verify_observed_case(
                &capture.evidence,
                &capture.input,
                &identity.source_commit,
                &|path| {
                    capture
                        .files
                        .get(path)
                        .cloned()
                        .ok_or_else(|| format!("current image capture absent: {path}"))
                },
            );
            let (record, inventory) = super::linux_current_capture::persist_case(
                artifact_root,
                &format!("{prefix}/case.json"),
                &capture.evidence,
                capture.files,
                if verify.is_ok() {
                    CaseState::Passed
                } else {
                    CaseState::Failed
                },
                verify.as_ref().err().cloned(),
            )?;
            observed.records.push(record);
            observed.artifacts.extend(inventory);
            verify.map_err(fail)?;
            let ack = caller
                .command(&case.directory, cleanup)?
                .args(["workload", "acknowledge", "--observation"])
                .arg(case.directory.join("workload-observation.json"))
                .output()?;
            super::super::command::require_successful_output(
                "current image original attempt metadata retirement",
                &ack,
            )?;
        }
        for scenario in ["ld-injection", "rpath-injection", "loader-config"] {
            negative(
                identity,
                key,
                caller,
                images,
                provider,
                controller,
                working,
                artifact_root,
                fixture_source,
                lease_id,
                scenario,
                work,
                cleanup,
                &mut observed,
            )?;
        }
        Ok(())
    })();
    if let Err(error) = operation {
        observed.primary_error = Some(error.to_string());
    }
    let _ = root;
    observed
}
