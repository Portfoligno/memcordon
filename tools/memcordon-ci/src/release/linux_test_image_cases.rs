//! Actual current initial-image/loader experiments under the ordinary caller.
use super::{
    artifacts,
    linux_request_fixture::CallerSession,
    linux_test_execution::{CallerImages, TestInput, hold_current_attempt, run_recipe_with_source},
    linux_test_scenarios::{Scenario, ScenarioName},
    source,
};
use crate::{CiError, Result};
use memcordon_core::{
    PublicProviderBindingV1,
    workload_bundle::SnapshotManifestV1,
    workload_files::{ImageEntryV1, RootRelativePath},
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
    super::linux_test_execution::caller_tree(destination, caller, cutoff, &mut remaining)
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
    caller: &CallerSession,
    images: &CallerImages,
    provider: &PublicProviderBindingV1,
    controller: &Path,
    working: &Path,
    scenario: &str,
    work: Instant,
    cleanup: Instant,
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
        let (changed, details) = rpath_probe(&original_fixture, &images.runtime.target)?;
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
    let before = super::linux_test_refusals::allocations()?;
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
    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
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
        let raw = serde_json::to_value(&result)?;
        let request_bytes = fs::read(&fixture.request)?;
        let request = memcordon_core::workload_request::WorkloadRequestV1::parse(&request_bytes)
            .map_err(fail)?;
        if raw["release"] != "not-released"
            || raw["runtime"]["kind"] != "preparation-failed"
            || raw["outcome"]["kind"] != "launch-failure"
            || raw["outcome"]["wrapper_status"] != 125
            || raw["delivery"] != "complete"
            || raw["cleanup"]["state"] != "complete"
            || raw["request"]["request_sha256"]
                != serde_json::to_value(request.digest().map_err(fail)?)?
            || wait["status"] != 125
            || wait["raw_wait_status"] != 125 * 256
            || !stdout.is_empty()
        {
            return Err(fail(
                "loader mutation did not produce its actual prelaunch refusal and complete cleanup",
            ));
        }
        if scenario == "ld-injection" {
            if association.is_some()
                || raw["request_rejection"]["code"] != "unsupported-requirement"
                || !raw["request_rejection"]["detail"]
                    .as_str()
                    .is_some_and(|text| text.contains("initial loader environment"))
                || !raw["workload_attempt"].is_null()
            {
                return Err(fail(
                    "loader environment was not rejected before native allocation",
                ));
            }
        } else {
            let association = association
                .as_ref()
                .ok_or_else(|| fail("actual rejected loader attempt absent"))?;
            let recovery = recovery
                .as_ref()
                .ok_or_else(|| fail("actual rejected loader recovery absent"))?;
            let terminal: Value = serde_json::from_slice(&recovery.raw_terminal)?;
            if raw["workload_attempt"] != serde_json::to_value(association)?
                || raw["provider"] != serde_json::to_value(provider)?
                || terminal["association"] != serde_json::to_value(association)?
                || terminal["release"] != "not-released"
                || !terminal["native"].is_null()
                || terminal["cleanup"]["state"] != "complete"
            {
                return Err(fail(
                    "loader rejection lost its original current attempt/native cleanup relation",
                ));
            }
        }
        let _ = (memory_bytes, stderr, start_bytes, journal, mutation);
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
        let after = super::linux_test_refusals::allocations()?;
        launch.retire_bundle_exact(&fixture)?;
        if before != after {
            return Err(fail("loader refusal left native allocations behind"));
        }
        if let (Some(association), Some(ack)) = (&association, ack) {
            let response = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(&ack)
                .map_err(fail)?;
            if response.association != *association {
                return Err(fail(
                    "loader refusal acknowledgment names another actual attempt",
                ));
            }
        }
        Ok(())
    }));
    let _retirement = crate::cancellation::retirement_scope(cleanup);
    let execution = match execution {
        Ok(result) => result,
        Err(panic) => {
            match launch.cancel_and_settle(cleanup) {
                Ok(_) => {
                    if let Err(error) = launch.retire_bundle_exact(&fixture) {
                        eprintln!("loader input retirement after unwind: {error}");
                    }
                }
                Err(error) => eprintln!("loader native settlement after unwind: {error}"),
            }
            std::panic::resume_unwind(panic)
        }
    };
    if let Err(primary) = execution {
        let settled = launch.cancel_and_settle(cleanup);
        let mut detail = primary.to_string();
        if let Err(secondary) = settled {
            detail = format!("{detail}; loader native settlement: {secondary}");
        }
        return Err(fail(detail));
    }
    Ok(())
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
    _root: &Path,
    caller: &CallerSession,
    probe: &Path,
    images: &CallerImages,
    provider: &PublicProviderBindingV1,
    controller: &Path,
    working: &Path,
    work: Instant,
    cleanup: Instant,
) -> Result<()> {
    let images = images.minimal();
    let operation = (|| -> Result<()> {
        for scenario in [
            "first-image",
            "interpreter",
            "shared-library",
            "snapshot-writable-alias",
        ] {
            let case_key = ScenarioName {
                family: "L-IMG-01".into(),
                scenario: scenario.into(),
            };
            let directory = working.join(format!("current-image-{scenario}"));
            let captures = controller.join(format!("current-image-{scenario}"));
            fs::create_dir(&captures)?;
            fs::set_permissions(&captures, fs::Permissions::from_mode(0o700))?;
            let path = selected(images, &images.runtime.target, scenario)?;
            let prefix = "alias";
            let alias_actor =
                std::cell::RefCell::new(None::<super::linux_test_snapshots::ProbeRun>);
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
                    let actor = super::linux_test_snapshots::ProbeRun::start(
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
                                let mut actor = super::linux_test_snapshots::ProbeRun::start(
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
            let recipe = Scenario {
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
                TestInput {
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
                    return Err(primary);
                }
            };
            super::linux_test_assertions::assert_case_with(&case, |_, result, native| {
                let expected = regular(&images.runtime, &path)?;
                let ImageEntryV1::Regular { sha256, size, .. } = expected else {
                    return Err(fail("selected protected member is not regular"));
                };
                let digest = String::from(sha256.clone());
                if result["outcome"]["kind"] != "completed"
                    || result["outcome"]["native_termination"]["code"] != 0
                    || extra["protected"]["sha256"] != digest
                    || extra["protected"]["length"] != *size
                    || extra["protected"]["uid"] != 0
                    || extra["protected"]["mode"]
                        .as_u64()
                        .is_none_or(|mode| mode & 0o222 != 0)
                    || extra["protected"] != extra["protected_after"]
                    || extra["protected"]["device"] == extra["source"]["device"]
                        && extra["protected"]["inode"] == extra["source"]["inode"]
                    || extra["root"]["device"] != native["root_device"]
                    || extra["root"]["inode"] != native["root_inode"]
                {
                    return Err(fail(
                        "initial protected image/interpreter/library bytes or native custody differ",
                    ));
                }
                if scenario == "snapshot-writable-alias"
                    && (extra["alias"]["changed"]["sha256"] == extra["source"]["sha256"]
                        || extra["alias"]["restored"]["sha256"] != extra["source"]["sha256"]
                        || extra["alias"]["protected_during_change"] != extra["protected"])
                {
                    return Err(fail(
                        "caller writable alias changed the protected executable or was not actually mutated/restored",
                    ));
                }
                Ok(())
            })?;
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
                caller, images, provider, controller, working, scenario, work, cleanup,
            )?;
        }
        Ok(())
    })();
    operation
}
