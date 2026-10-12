//! Actual owned image-import observations. Acceptance belongs to the separate verifier.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memcordon_core::workload_contract::LogicalId;
use memcordon_core::workload_registry_v3::{ImageEntryV1, RuntimeImageDefinitionV1};
use memcordon_readiness_verifier::ProductKey;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::linux_mixed_installed::{
    ActivatedMixedPolicy, ExclusiveAccount, InstalledMixedLaunch, MixedImages,
};
use crate::command::CommandSpec;
use crate::consumer_readiness_ledger::SourceIdentity;
use crate::{CiError, Result};

#[derive(Clone, Copy)]
pub struct ImageCaseContext<'a> {
    pub identity: &'a SourceIdentity,
    pub cell: &'a ProductKey,
    pub lease_id: &'a str,
    pub activated: &'a ActivatedMixedPolicy,
    pub provider: &'a memcordon_core::PublicProviderBindingV1,
    pub images: &'a MixedImages,
    pub account: &'a ExclusiveAccount,
    pub expected_agent_sha256: &'a str,
    pub output: &'a Path,
    pub artifact_root: &'a Path,
    pub admin_root: &'a Path,
    pub deadline: Instant,
    pub cleanup_deadline: Instant,
    /// Original persisted cell cutoffs, transferred unchanged to the external
    /// helper. These are not renewed when a case or cleanup is retried.
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

#[derive(Serialize)]
pub struct ImageCaseObservation {
    pub family: String,
    pub scenario: String,
    pub definition: PathBuf,
    pub definition_capture: PathBuf,
    pub cleanup_definition_capture: PathBuf,
    pub source_root: PathBuf,
    pub selected_member: Option<String>,
    pub invocation: PathBuf,
    pub native_process: PathBuf,
    pub native_creation: PathBuf,
    pub source_inventory: PathBuf,
    pub baseline_entrypoint: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub exit: PathBuf,
    pub native_exit: Option<i32>,
    pub error: Option<String>,
    pub preparation_probe: Option<PathBuf>,
}

pub struct RetainedImage {
    pub definition: PathBuf,
    pub image: RuntimeImageDefinitionV1,
    pub installation: Option<PathBuf>,
    pub retirement: Option<PathBuf>,
}

#[derive(Serialize)]
pub struct ExportCaseObservation {
    pub family: String,
    pub scenario: String,
    pub fixture_mode: String,
    pub challenge: PathBuf,
    pub contract: PathBuf,
    pub activation: Option<PathBuf>,
    pub prepared: Option<PathBuf>,
    pub prepared_native: Option<PathBuf>,
    pub ready: Option<PathBuf>,
    pub controller_setup: Option<PathBuf>,
    pub native_source: Option<PathBuf>,
    pub native_invocation: Option<PathBuf>,
    pub native_wait: Option<PathBuf>,
    pub native_family: Option<PathBuf>,
    pub provider_request: Option<PathBuf>,
    pub recovery: Option<PathBuf>,
    pub stdout: Option<PathBuf>,
    pub stderr: Option<PathBuf>,
    pub result: Option<PathBuf>,
    pub native_exit: Option<i32>,
    pub error: Option<String>,
}

pub struct ImageCaseReport {
    pub observations: Vec<ImageCaseObservation>,
    pub export_observations: Vec<ExportCaseObservation>,
    pub retained_images: Vec<RetainedImage>,
    pub launches: Vec<InstalledMixedLaunch>,
    pub prepared_owners: Vec<crate::linux_consumer_readiness::PreparedLinuxObserver>,
    pub descendant_owners: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub importer_owners: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub export_worker_owners: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub directory_custody: Vec<File>,
    pub file_custody: Vec<File>,
    pub administrative_export_handles: Vec<File>,
    export_helpers: Vec<ExportPermissionOwner>,
    pub failures: Vec<String>,
    pub output: PathBuf,
    pub cleanup_deadline: Instant,
    pub cleanup_attempts: u64,
}

struct ExportPermissionOwner {
    child: std::process::Child,
    held: Option<crate::linux_consumer_readiness::HeldLinuxProcess>,
    peer: Option<std::os::fd::OwnedFd>,
    stdout: File,
    stderr: File,
    directory: PathBuf,
    setup: serde_json::Value,
    administrative_start: usize,
    administrative_end: usize,
    cgroup_index: usize,
    cgroup_parent_index: usize,
    source_index: usize,
    cgroup_ancestry_start: usize,
    cgroup_ancestry_end: usize,
    capture_ancestry_start: usize,
    capture_ancestry_end: usize,
}

/// Exercise import integrity against fresh copies, retaining an actual neighboring
/// successful import and every native mutation intent before calling the installer.
pub fn run_import_cases(context: ImageCaseContext<'_>) -> Result<ImageCaseReport> {
    if !context.output.is_absolute()
        || !context.output.starts_with(context.artifact_root)
        || !context.admin_root.is_absolute()
        || context.cleanup_deadline < context.deadline
        || context.work_deadline_unix_millis == 0
        || context.cleanup_deadline_unix_millis <= context.work_deadline_unix_millis
        || context.lease_id.is_empty()
        || !context
            .lease_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CiError::Message("invalid owned image-case context".into()));
    }
    std::fs::create_dir(context.output)?;
    std::fs::set_permissions(context.output, std::fs::Permissions::from_mode(0o711))?;
    let admin = context
        .admin_root
        .join("image-cases")
        .join(context.lease_id);
    std::fs::create_dir_all(&admin)?;
    std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700))?;
    let mut report = ImageCaseReport {
        observations: Vec::new(),
        export_observations: Vec::new(),
        retained_images: Vec::new(),
        launches: Vec::new(),
        prepared_owners: Vec::new(),
        descendant_owners: Vec::new(),
        importer_owners: Vec::new(),
        directory_custody: hold_ancestry(&admin)?,
        file_custody: Vec::new(),
        administrative_export_handles: Vec::new(),
        export_helpers: Vec::new(),
        export_worker_owners: Vec::new(),
        failures: Vec::new(),
        output: context.output.to_path_buf(),
        cleanup_deadline: context.cleanup_deadline,
        cleanup_attempts: 0,
    };
    let admin_metadata = std::fs::symlink_metadata(context.admin_root)?;
    retain(
        &context.output.join("owner.json"),
        &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-image-case-owner","revision":1,"identity":context.identity,"cell":context.cell,
            "lease_id":context.lease_id,"provider":context.provider,"account":context.account,
            "expected_agent_sha256":context.expected_agent_sha256,"output":context.output,"admin_root":context.admin_root,"image_admin_root":admin,
            "admin_root_device":admin_metadata.dev(),"admin_root_inode":admin_metadata.ino(),
            "work_deadline_unix_millis":context.work_deadline_unix_millis,"cleanup_deadline_unix_millis":context.cleanup_deadline_unix_millis
        }))?,
        &mut report.file_custody,
    )?;
    let selected = match select_startup_members(context.images) {
        Ok(selected) => selected,
        Err(error) => {
            report.failures.push(error.to_string());
            return Ok(report);
        }
    };
    for (scenario, member) in [
        ("neighbor-import", None),
        ("first-image", Some(selected.0.as_str())),
        ("interpreter", Some(selected.1.as_str())),
        ("shared-library", Some(selected.2.as_str())),
        ("writable-alias", Some(selected.0.as_str())),
    ] {
        if let Err(error) = import_case(&context, &admin, &mut report, scenario, member) {
            report.failures.push(format!("{scenario}: {error}"));
            break;
        }
    }
    if report.failures.is_empty() {
        for (scenario, member) in [
            ("ld-injection", None),
            ("loader-config", None),
            ("rpath-injection", Some(selected.0.as_str())),
        ] {
            if let Err(error) = import_case(&context, &admin, &mut report, scenario, member) {
                report.failures.push(format!("{scenario}: {error}"));
                break;
            }
        }
    }
    if report.failures.is_empty() {
        for scenario in [
            "symlink",
            "fifo",
            "device",
            "socket",
            "traversal",
            "concurrent-writer",
        ] {
            if let Err(error) = export_case(&context, &admin, &mut report, scenario) {
                if let Some(observation) = report.export_observations.last_mut() {
                    observation.error = Some(error.to_string());
                }
                report.failures.push(format!("export {scenario}: {error}"));
                break;
            }
        }
    }
    Ok(report)
}

/// Settle every frontend/capture/native family independently. Image retirement
/// is deliberately separate: the outer owner must first restore its registry.
pub fn finalize_attempts(report: &mut ImageCaseReport, deadline: Instant) -> Result<()> {
    let deadline = deadline.min(report.cleanup_deadline);
    // Partial device setup may retain controller mount references; close
    // those explicit obligations before asking the provider to retire roots.
    let mut failures = Vec::new();
    for helper in &mut report.export_helpers {
        if let Some(peer) = helper.peer.take()
            && let Err(error) = memcordon_platform::linux_checked_close(peer)
        {
            failures.push(format!(
                "external export peer close remains uncertain: {error}"
            ));
        }
        match helper.child.try_wait() {
            Ok(None) => {
                if let Err(error) = helper.child.kill() {
                    failures.push(format!("external export helper stop: {error}"));
                }
            }
            Ok(Some(_)) => {}
            Err(error) => {
                failures.push(format!("external export helper wait observation: {error}"))
            }
        }
    }
    for helper in &mut report.export_helpers {
        loop {
            match helper.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Ok(None) => {
                    failures.push(
                        "external export helper remains owned at original cleanup cutoff".into(),
                    );
                    break;
                }
                Err(error) => {
                    failures.push(format!("external export helper reap: {error}"));
                    break;
                }
            }
        }
        if let Some(held) = &helper.held {
            match held.exited() {
                Ok(true) => {}
                Ok(false) => {
                    failures.push("external export helper PIDFD retirement unavailable".into())
                }
                Err(error) => failures.push(error),
            }
        }
        for file in [&helper.stdout, &helper.stderr] {
            if let Err(error) = file.sync_all() {
                failures.push(format!("external export capture sync: {error}"));
            }
        }
    }
    for file in report.administrative_export_handles.drain(..) {
        if let Err(error) =
            memcordon_platform::linux_checked_close(std::os::fd::OwnedFd::from(file))
        {
            failures.push(format!(
                "administrative export native close remains uncertain: {error}"
            ));
        }
    }
    for launch in &mut report.launches {
        match launch.frontend.try_wait() {
            Ok(None) => {
                if let Err(error) = launch.frontend.kill() {
                    failures.push(error.to_string());
                }
            }
            Ok(Some(_)) => {}
            Err(error) => failures.push(error.to_string()),
        }
        launch.frontend.stdin.take();
    }
    for launch in &mut report.launches {
        if let Err(error) =
            launch.wait_and_capture(deadline.saturating_duration_since(Instant::now()))
        {
            failures.push(error.to_string());
        }
    }
    loop {
        let mut pending = false;
        for observer in &report.prepared_owners {
            match observer.native_family_retired(&report.descendant_owners) {
                Ok(true) => {}
                Ok(false) => pending = true,
                Err(error) => {
                    pending = true;
                    failures.push(error.to_string());
                }
            }
        }
        for child in report
            .descendant_owners
            .iter()
            .chain(&report.export_worker_owners)
        {
            match child.exited() {
                Ok(true) => {}
                Ok(false) => pending = true,
                Err(error) => {
                    pending = true;
                    failures.push(error.to_string());
                }
            }
        }
        if !pending {
            break;
        }
        if Instant::now() >= deadline {
            failures
                .push("image-case native family remains owned at original cleanup cutoff".into());
            break;
        }
        failures.sort();
        failures.dedup();
        std::thread::sleep(Duration::from_millis(10));
    }
    failures.sort();
    failures.dedup();
    report.failures.extend(failures.iter().cloned());
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CiError::Message(failures.join("; ")))
    }
}

/// Invoke the supported native retirement path after the outer owner has
/// restored/read back the original registry. Every failed intent remains owned.
pub fn finalize_retained_images(report: &mut ImageCaseReport, deadline: Instant) -> Result<()> {
    let deadline = deadline.min(report.cleanup_deadline);
    report.cleanup_attempts = report
        .cleanup_attempts
        .checked_add(1)
        .ok_or_else(|| CiError::Message("image cleanup retry counter overflow".into()))?;
    let mut failures = Vec::new();
    for ordinal in 0..report.retained_images.len() {
        if report.retained_images[ordinal].retirement.is_some() {
            continue;
        }
        let result = (|| -> Result<PathBuf> {
            let definition = &report.retained_images[ordinal].definition;
            let expected = serde_json::to_vec(&report.retained_images[ordinal].image)?;
            let mut held = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(definition)?;
            let metadata = held.metadata()?;
            let mut actual = Vec::new();
            std::io::Read::by_ref(&mut held)
                .take(expected.len() as u64 + 1)
                .read_to_end(&mut actual)?;
            if metadata.nlink() != 1 || actual != expected {
                return Err(CiError::Message(
                    "retained image definition changed before retirement".into(),
                ));
            }
            let output = CommandSpec::new(
                "/usr/libexec/memcordon-sealed-agent",
                &report.output,
                remaining(deadline)?,
            )
            .bounded_until(deadline)
            .args([
                OsString::from("package"),
                OsString::from("policy"),
                OsString::from("image"),
                OsString::from("retire"),
                OsString::from("--definition"),
                definition.clone().into_os_string(),
                OsString::from("--json"),
            ])
            .output_quiet()?;
            let base = report
                .output
                .join(format!("retirement-{}-{ordinal}", report.cleanup_attempts));
            retain(
                &base.with_extension("stdout.json"),
                &output.stdout,
                &mut report.file_custody,
            )?;
            retain(
                &base.with_extension("stderr.bin"),
                &output.stderr,
                &mut report.file_custody,
            )?;
            retain(
                &base.with_extension("exit.json"),
                &serde_json::to_vec(
                    &serde_json::json!({"native_exit":output.status.code(),"success":output.status.success()}),
                )?,
                &mut report.file_custody,
            )?;
            if !output.status.success() {
                return Err(CiError::Message(
                    "native image retirement failed; intent retained".into(),
                ));
            }
            memcordon_core::canonical_json::reject_duplicate_json_keys(&output.stdout)
                .map_err(CiError::Message)?;
            let receipt: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            let reference = report.retained_images[ordinal]
                .image
                .reference()
                .map_err(CiError::Message)?;
            if receipt["format"] != "memcordon.runtime-image-retirement"
                || receipt["revision"] != 1
                || receipt["storage_absent"] != true
                || receipt["reference"] != serde_json::to_value(reference)?
            {
                return Err(CiError::Message(
                    "native retirement receipt differs from exact owned image".into(),
                ));
            }
            let named = std::fs::symlink_metadata(definition)?;
            if (named.dev(), named.ino()) != (metadata.dev(), metadata.ino()) {
                return Err(CiError::Message(
                    "retirement definition named identity changed".into(),
                ));
            }
            Ok(base.with_extension("stdout.json"))
        })();
        match result {
            Ok(path) => report.retained_images[ordinal].retirement = Some(path),
            Err(error) => failures.push(format!("image {ordinal}: {error}")),
        }
    }
    report.failures.extend(failures.iter().cloned());
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CiError::Message(failures.join("; ")))
    }
}

fn import_case(
    context: &ImageCaseContext<'_>,
    admin: &Path,
    report: &mut ImageCaseReport,
    scenario: &str,
    member: Option<&str>,
) -> Result<()> {
    remaining(context.deadline)?;
    let output = context.output.join(scenario);
    let staged = admin.join(scenario);
    std::fs::create_dir(&output)?;
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o711))?;
    std::fs::create_dir(&staged)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700))?;
    report.directory_custody.extend(hold_ancestry(&staged)?);
    let root = staged.join("source");
    std::fs::create_dir(&root)?;
    let mut definition = context.images.runtime.clone();
    let discriminator = hex(&Sha256::digest(serde_json::to_vec(&(
        context.identity,
        context.cell,
        context.lease_id,
        scenario,
    ))?));
    definition.image_id = LogicalId::new(discriminator).map_err(CiError::Message)?;
    let valid_baseline_definition = definition.clone();
    let baseline_entrypoint = output.join("baseline-entrypoint.bin");
    let entrypoint = definition
        .entrypoints
        .as_slice()
        .iter()
        .find(|entry| entry.id.as_str() == "owned-readiness")
        .ok_or_else(|| CiError::Message("actual baseline entrypoint absent".into()))?;
    let entrypoint_member = resolve_member(&definition, entrypoint.path.as_str())?;
    let mut entrypoint_owner = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(context.images.runtime_source.join(&entrypoint_member))?;
    let entrypoint_bytes =
        read_image_bytes_until(&mut entrypoint_owner, 64 * 1024 * 1024, context.deadline)?;
    retain(
        &baseline_entrypoint,
        &entrypoint_bytes,
        &mut report.file_custody,
    )?;
    report.file_custody.push(entrypoint_owner);
    copy_inventory(
        &context.images.runtime_source,
        &root,
        &definition,
        report,
        context.deadline,
    )?;
    if scenario == "ld-injection" {
        let mut raw = serde_json::to_value(&definition)?;
        raw["startup_environment"]
            .as_array_mut()
            .ok_or_else(|| CiError::Message("startup environment is not an array".into()))?
            .push(serde_json::json!({"name":"LD_PRELOAD","value":"/work/owned-injected.so"}));
        definition = serde_json::from_value(raw)?;
    } else if scenario == "loader-config" {
        let bytes = b"/work/owned-injected.so\n";
        match std::fs::create_dir(root.join("etc")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        report
            .directory_custody
            .extend(hold_ancestry(&root.join("etc"))?);
        retain(
            &root.join("etc/ld.so.preload"),
            bytes,
            &mut report.file_custody,
        )?;
        let mut raw = serde_json::to_value(&definition)?;
        raw["entries"].as_array_mut().ok_or_else(|| CiError::Message("image inventory is not an array".into()))?
            .push(serde_json::json!({"kind":"regular","path":"etc/ld.so.preload","sha256":hex(&Sha256::digest(bytes)),"size":bytes.len(),"executable":false}));
        definition = serde_json::from_value(raw)?;
    }
    if let Some(member) = member {
        let path = root.join(member);
        if scenario == "writable-alias" {
            std::fs::hard_link(&path, staged.join("writable-startup-alias"))?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        } else if scenario == "rpath-injection" {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut file)
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 64 * 1024 * 1024 {
                return Err(CiError::Message("owned ELF mutation exceeds bound".into()));
            }
            add_writable_rpath(&mut bytes)?;
            file.write_all_at(&bytes, 0)?;
            file.sync_all()?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555))?;
            let mut raw = serde_json::to_value(&definition)?;
            let entry = raw["entries"]
                .as_array_mut()
                .ok_or_else(|| CiError::Message("image inventory is not an array".into()))?
                .iter_mut()
                .find(|entry| entry["path"] == member)
                .ok_or_else(|| CiError::Message("mutated ELF inventory member absent".into()))?;
            entry["sha256"] = hex(&Sha256::digest(&bytes)).into();
            definition = serde_json::from_value(raw)?;
        } else {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let mut byte = [0u8; 1];
            file.read_exact_at(&mut byte, 0)?;
            byte[0] ^= 1;
            file.write_all_at(&byte, 0)?;
            file.sync_all()?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555))?;
        }
    }
    let definition_path = staged.join("definition.json");
    let source_inventory = output.join("native-source-inventory.json");
    let mut native_members = Vec::new();
    for entry in definition.entries.as_slice() {
        remaining(context.deadline)?;
        let ImageEntryV1::Regular { path, .. } = entry else {
            continue;
        };
        let source = root.join(path.as_str());
        let mut held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&source)?;
        let before = held.metadata()?;
        let bytes = read_image_bytes_until(&mut held, 64 * 1024 * 1024, context.deadline)?;
        if bytes.len() > 64 * 1024 * 1024 || !before.is_file() {
            return Err(CiError::Message(
                "native source inventory member exceeds bound/type".into(),
            ));
        }
        let selected = member == Some(path.as_str()) || path.as_str() == "etc/ld.so.preload";
        let retained_bytes = if selected {
            let destination = output.join(format!("source-member-{}.bin", native_members.len()));
            retain(&destination, &bytes, &mut report.file_custody)?;
            Some(destination)
        } else {
            None
        };
        let baseline_bytes = if member == Some(path.as_str()) {
            let original = context.images.runtime_source.join(path.as_str());
            let mut held = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(original)?;
            let bytes = read_image_bytes_until(&mut held, 64 * 1024 * 1024, context.deadline)?;
            if bytes.len() > 64 * 1024 * 1024 {
                return Err(CiError::Message(
                    "baseline source member exceeds bound".into(),
                ));
            }
            let destination = output.join(format!("baseline-member-{}.bin", native_members.len()));
            retain(&destination, &bytes, &mut report.file_custody)?;
            Some(destination)
        } else {
            None
        };
        let after = held.metadata()?;
        if (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(CiError::Message(
                "native source inventory member changed during capture".into(),
            ));
        }
        native_members.push(serde_json::json!({"path":path.as_str(),"device":before.dev(),"inode":before.ino(),"uid":before.uid(),"mode":before.mode(),
            "nlink":before.nlink(),"size":before.len(),"ctime_seconds":before.ctime(),"ctime_nanoseconds":before.ctime_nsec(),
            "sha256":hex(&Sha256::digest(&bytes)),"bytes":retained_bytes,"baseline_bytes":baseline_bytes}));
        report.file_custody.push(held);
    }
    let alias = if scenario == "writable-alias" {
        let path = staged.join("writable-startup-alias");
        let metadata = std::fs::symlink_metadata(&path)?;
        Some(
            serde_json::json!({"path":path,"device":metadata.dev(),"inode":metadata.ino(),"nlink":metadata.nlink(),"mode":metadata.mode()}),
        )
    } else {
        None
    };
    retain(
        &source_inventory,
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.linux-image-source-inventory","revision":1,
        "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"scenario":scenario,"source_root":root,
        "baseline_definition":valid_baseline_definition,"members":native_members,"alias":alias}),
        )?,
        &mut report.file_custody,
    )?;
    retain(
        &definition_path,
        &serde_json::to_vec(&definition)?,
        &mut report.file_custody,
    )?;
    // This immutable intent precedes native import, including a lost command
    // return. Recovery reads the finite owned slot and exact definition bytes;
    // a missing installation capture does not imply absence of native storage.
    let definition_bytes = serde_json::to_vec(&definition)?;
    // A malformed loader environment is rejected before the installer can
    // derive or allocate a storage reference. Keep the valid same-id baseline
    // as an explicit absence/cleanup command; never parse the malformed request
    // as if it were a successful native image definition.
    let submitted_reference = definition.reference();
    let cleanup_image = if submitted_reference.is_ok() {
        definition.clone()
    } else {
        valid_baseline_definition
    };
    let cleanup_definition = staged.join("cleanup-definition.json");
    let cleanup_bytes = serde_json::to_vec(&cleanup_image)?;
    let definition_capture = output.join("submitted-definition.json");
    let cleanup_definition_capture = output.join("cleanup-definition.json");
    retain(
        &definition_capture,
        &definition_bytes,
        &mut report.file_custody,
    )?;
    retain(
        &cleanup_definition_capture,
        &cleanup_bytes,
        &mut report.file_custody,
    )?;
    retain(
        &cleanup_definition,
        &cleanup_bytes,
        &mut report.file_custody,
    )?;
    retain(
        &output.join("import-intent.json"),
        &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-readiness-image-import-intent","revision":1,
            "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,
            "scenario":scenario,"definition":definition_path,
            "definition_sha256":hex(&Sha256::digest(&definition_bytes)),
            "reference":cleanup_image.reference().map_err(CiError::Message)?,
            "cleanup_definition":cleanup_definition,"cleanup_definition_sha256":hex(&Sha256::digest(&cleanup_bytes)),
            "submitted_definition_valid":submitted_reference.is_ok(),
            "source_root":root,"work_deadline_unix_millis":context.work_deadline_unix_millis,
            "cleanup_deadline_unix_millis":context.cleanup_deadline_unix_millis,
        }))?,
        &mut report.file_custody,
    )?;
    // Intent is owned before the native command: even a lost return can mean an import exists.
    let retained = report.retained_images.len();
    report.retained_images.push(RetainedImage {
        definition: cleanup_definition,
        image: cleanup_image,
        installation: None,
        retirement: None,
    });
    let argv = [
        OsString::from("package"),
        OsString::from("policy"),
        OsString::from("image"),
        OsString::from("install"),
        OsString::from("--definition"),
        definition_path.clone().into_os_string(),
        OsString::from("--source-root"),
        root.clone().into_os_string(),
        OsString::from("--json"),
    ];
    let invocation = output.join("invocation.json");
    retain(
        &invocation,
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.linux-image-import-command","revision":1,
            "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"scenario":scenario,
            "program":"/usr/libexec/memcordon-sealed-agent","executable_sha256":context.expected_agent_sha256,
            "argv":argv.iter().map(|v|v.to_string_lossy()).collect::<Vec<_>>(),"cwd":output,"environment_cleared":true,
            "definition_sha256":hex(&Sha256::digest(&definition_bytes)),
            "work_deadline_unix_millis":context.work_deadline_unix_millis,
            "cleanup_deadline_unix_millis":context.cleanup_deadline_unix_millis}),
        )?,
        &mut report.file_custody,
    )?;
    let native_process = output.join("native-process.json");
    let native_creation = output.join("native-creation.json");
    let stdout = output.join("stdout.json");
    let stderr = output.join("stderr.bin");
    let exit = output.join("exit.json");
    report.observations.push(ImageCaseObservation {
        family: if matches!(
            scenario,
            "ld-injection" | "loader-config" | "rpath-injection"
        ) {
            "L-IMG-02"
        } else {
            "L-IMG-01"
        }
        .into(),
        scenario: scenario.into(),
        definition: definition_path,
        definition_capture,
        cleanup_definition_capture,
        source_root: root,
        selected_member: member.map(str::to_owned),
        invocation,
        native_process: native_process.clone(),
        native_creation: native_creation.clone(),
        source_inventory,
        baseline_entrypoint,
        stdout: stdout.clone(),
        stderr: stderr.clone(),
        exit: exit.clone(),
        native_exit: None,
        error: None,
        preparation_probe: None,
    });
    let captured = capture_import_command(
        context,
        &output,
        argv,
        &native_creation,
        &native_process,
        &mut report.file_custody,
        &mut report.importer_owners,
    )?;
    retain(&stdout, &captured.stdout, &mut report.file_custody)?;
    retain(&stderr, &captured.stderr, &mut report.file_custody)?;
    retain(
        &exit,
        &serde_json::to_vec(
            &serde_json::json!({"native_exit":captured.status.code(),"success":captured.status.success()}),
        )?,
        &mut report.file_custody,
    )?;
    report
        .observations
        .last_mut()
        .expect("owned invocation")
        .native_exit = captured.status.code();
    if captured.status.success() {
        report.retained_images[retained].installation = Some(stdout);
        if matches!(scenario, "loader-config" | "rpath-injection") {
            probe_loader_closure(context, report, retained, scenario, &output)?;
        } else if scenario != "neighbor-import" {
            return Err(CiError::Message(
                "altered startup source was unexpectedly imported; native intent retained".into(),
            ));
        }
    } else if scenario == "neighbor-import" {
        return Err(CiError::Message(
            "neighboring valid image import failed; negatives cannot establish setup".into(),
        ));
    }
    Ok(())
}

/// Capture the actual selected native importer while retaining its creation,
/// kernel image and original PIDFD loans through wait and source readback.
pub fn capture_import_command(
    context: &ImageCaseContext<'_>,
    output: &Path,
    argv: impl IntoIterator<Item = OsString>,
    native_creation: &Path,
    native_process: &Path,
    file_custody: &mut Vec<File>,
    kernel_custody: &mut Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
) -> Result<memcordon_testkit::ObservedOutput> {
    let mut agent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/libexec/memcordon-sealed-agent")?;
    let agent_before = agent.metadata()?;
    let agent_bytes = read_image_bytes_until(&mut agent, 512 * 1024 * 1024, context.deadline)?;
    if agent_before.uid() != 0
        || agent_before.mode() & 0o022 != 0
        || agent_before.nlink() != 1
        || !agent_before.is_file()
        || agent_bytes.len() > 512 * 1024 * 1024
        || hex(&Sha256::digest(&agent_bytes)) != context.expected_agent_sha256
    {
        return Err(CiError::Message(
            "image importer actual installed executable custody differs".into(),
        ));
    }
    let mut child_identity = None;
    let mut child_pidfd = None;
    let mut child_kernel_owner = None;
    let captured = CommandSpec::new(
        "/usr/libexec/memcordon-sealed-agent",
        output,
        remaining(context.deadline)?,
    )
    .bounded_until(context.deadline)
    .args(argv)
    .cleared_environment()
    .output_quiet_with_creation(|child|{
        let pid=child.id();let birth=crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?;
        let native_pid=rustix::process::Pid::from_raw(i32::try_from(pid).map_err(|error|CiError::Message(error.to_string()))?)
            .ok_or_else(||CiError::Message("importer native process absent".into()))?;
        let pidfd=rustix::process::pidfd_open(native_pid,rustix::process::PidfdFlags::empty()).map_err(|error|CiError::Message(error.to_string()))?;
        let stat=rustix::fs::fstat(&pidfd).map_err(|error|CiError::Message(error.to_string()))?;
        let mut owner=crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid,birth).map_err(CiError::Message)?;
        let image=owner.hold_executable_image(context.deadline).map_err(CiError::Message)?;
        if image["sha256"]!=context.expected_agent_sha256||image["device"]!=agent_before.dev()||image["inode"]!=agent_before.ino()||image["length"]!=agent_before.len(){return Err(CiError::Message("actual kernel importer image differs from held selected agent".into()));}
        retain(native_creation,&serde_json::to_vec(&serde_json::json!({"format":"memcordon.linux-image-import-creation","revision":1,
            "process_id":pid,"birth":birth,"pidfd_device":stat.st_dev,"pidfd_inode":stat.st_ino,
            "invocation_sha256":hex(&Sha256::digest(std::fs::read(output.join("invocation.json"))?)),"kernel_image":image}))?,file_custody)?;
        child_kernel_owner=Some(owner);
        child_pidfd=Some(pidfd);
        child_identity=Some((pid,birth));Ok(())
    })?;
    let (pid, birth) = child_identity
        .ok_or_else(|| CiError::Message("actual importer creation identity absent".into()))?;
    let pidfd = child_pidfd
        .take()
        .ok_or_else(|| CiError::Message("actual importer pidfd absent".into()))?;
    let mut wait = [rustix::event::PollFd::new(
        &pidfd,
        rustix::event::PollFlags::IN,
    )];
    if rustix::event::poll(
        &mut wait,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|error| CiError::Message(error.to_string()))?
        == 0
        || !wait[0]
            .revents()
            .intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP)
    {
        return Err(CiError::Message(
            "actual importer native pidfd has not retired after wait".into(),
        ));
    }
    let pidfd_revents = wait[0].revents().bits();
    let pidfd_stat =
        rustix::fs::fstat(&pidfd).map_err(|error| CiError::Message(error.to_string()))?;
    drop(pidfd);
    if !child_kernel_owner
        .as_ref()
        .ok_or_else(|| CiError::Message("original importer kernel owner absent".into()))?
        .exited()
        .map_err(CiError::Message)?
    {
        return Err(CiError::Message(
            "original kernel importer owner remains live after wait".into(),
        ));
    }
    let agent_after = agent.metadata()?;
    let agent_named = std::fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")?;
    if (
        agent_after.dev(),
        agent_after.ino(),
        agent_after.len(),
        agent_after.ctime(),
        agent_after.ctime_nsec(),
    ) != (
        agent_before.dev(),
        agent_before.ino(),
        agent_before.len(),
        agent_before.ctime(),
        agent_before.ctime_nsec(),
    ) || (agent_named.dev(), agent_named.ino()) != (agent_before.dev(), agent_before.ino())
    {
        return Err(CiError::Message(
            "actual importer executable changed during native command".into(),
        ));
    }
    use std::os::unix::process::ExitStatusExt;
    retain(
        native_process,
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.linux-image-import-process","revision":1,
        "process_id":pid,"birth":birth,"raw_wait_status":captured.status.into_raw(),"native_exit":captured.status.code(),"signal":captured.status.signal(),
        "invocation_sha256":hex(&Sha256::digest(std::fs::read(output.join("invocation.json"))?)),
        "stdout_sha256":hex(&Sha256::digest(&captured.stdout)),"stderr_sha256":hex(&Sha256::digest(&captured.stderr)),
        "executable_device":agent_before.dev(),"executable_inode":agent_before.ino(),
        "creation_sha256":hex(&Sha256::digest(std::fs::read(native_creation)?)),
        "pidfd_device":pidfd_stat.st_dev,"pidfd_inode":pidfd_stat.st_ino,"pidfd_revents":pidfd_revents}),
        )?,
        file_custody,
    )?;
    file_custody.push(agent);
    kernel_custody.push(
        child_kernel_owner
            .take()
            .ok_or_else(|| CiError::Message("original importer kernel owner absent".into()))?,
    );
    Ok(captured)
}

fn read_image_bytes_until(file: &mut File, limit: usize, deadline: Instant) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        remaining(deadline)?;
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if count > limit.saturating_sub(bytes.len()) {
            return Err(CiError::Message(
                "held image capture exceeds finite bound".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

fn probe_loader_closure(
    context: &ImageCaseContext<'_>,
    report: &mut ImageCaseReport,
    retained: usize,
    scenario: &str,
    output: &Path,
) -> Result<()> {
    use super::linux_mixed_installed::{
        InstalledMixedLaunchInput, activate_owned_policy_staged_until,
        persist_policy_refusal_census,
    };
    let directory = output.join("preparation-probe");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o711))?;
    let protected = report.retained_images[retained]
        .definition
        .parent()
        .ok_or_else(|| CiError::Message("held image definition parent absent".into()))?
        .join("preparation-probe");
    std::fs::create_dir(&protected)?;
    std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o700))?;
    report.directory_custody.extend(hold_ancestry(&protected)?);
    let mut images = context.images.clone();
    images.runtime = report.retained_images[retained].image.clone();
    images.runtime_definition = report.retained_images[retained].definition.clone();
    images.runtime_source = report
        .observations
        .last()
        .expect("owned import observation")
        .source_root
        .clone();
    let activated = activate_owned_policy_staged_until(
        context.activated.registry.legacy.clone(),
        &images,
        context.account,
        context.identity,
        context.cell,
        Vec::new(),
        Vec::new(),
        &directory,
        &protected,
        context.deadline,
    )?;
    let protected_contract = protected.join("contract.json");
    let contract = directory.join("contract.json");
    let contract_bytes = serde_json::to_vec(&activated.contract)?;
    retain(
        &protected_contract,
        &contract_bytes,
        &mut report.file_custody,
    )?;
    retain(&contract, &contract_bytes, &mut report.file_custody)?;
    std::fs::set_permissions(&contract, std::fs::Permissions::from_mode(0o444))?;
    let arguments = vec![
        OsString::from("bytes-argv-status"),
        OsString::from("0"),
        OsString::from("loader-closure-probe"),
    ];
    let budget = format!(
        "+{}ms",
        remaining(context.deadline)?.as_millis().min(60_000)
    );
    let launch = InstalledMixedLaunch::start(InstalledMixedLaunchInput {
        directory: &directory.join("launch"),
        contract: &contract,
        caller_uid: 65534,
        caller_gid: 65534,
        target_arguments: &arguments,
        deadline: std::ffi::OsStr::new(&budget),
        memory: std::ffi::OsStr::new("+512M"),
    })?;
    let index = report.launches.len();
    report.launches.push(launch);
    report.launches[index].frontend.stdin.take();
    report.launches[index].wait_and_capture(remaining(context.deadline)?)?;
    let result = std::fs::read(&report.launches[index].result)?;
    let decoded: serde_json::Value = serde_json::from_slice(&result)?;
    let requests = std::fs::read_dir(&report.launches[index].observation_directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".provider-request.bin"))
        })
        .collect::<Vec<_>>();
    if requests.len() != 1 {
        return Err(CiError::Message(
            "image preparation did not retain one exact native request".into(),
        ));
    }
    let request_path = requests[0].clone();
    let request = std::fs::read(&request_path)?;
    let attempt = request_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".provider-request.bin"))
        .ok_or_else(|| CiError::Message("loader probe native request attempt absent".into()))?;
    let census = directory.join("native-census.json");
    persist_policy_refusal_census(
        context.account,
        context.provider,
        context.identity,
        context.cell,
        context.lease_id,
        scenario,
        attempt,
        &result,
        &request,
        &census,
        context.deadline,
    )?;
    let receipt = directory.join("preparation-probe.json");
    retain(
        &receipt,
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.linux-image-loader-preparation-probe","revision":1,
                "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"scenario":scenario,
                "activation":activated.activation_path,"contract":contract,"protected_contract":protected_contract,
                "contract_sha256":hex(&Sha256::digest(&contract_bytes)),"provider_request":request_path,
                "result":report.launches[index].result,"native_census":census,
                "frontend_invocation":serde_json::from_slice::<serde_json::Value>(&report.launches[index].retained_frontend_invocation()?)?,
                "frontend_wait":report.launches[index].retained_frontend_wait()?,"raw_result":decoded
            }),
        )?,
        &mut report.file_custody,
    )?;
    report
        .observations
        .last_mut()
        .expect("owned import observation")
        .preparation_probe = Some(receipt);
    Ok(())
}

/// Mutates a real owned ELF64 dynamic entry into an actual writable RPATH.
/// The updated inventory hashes these exact bytes so loader validation, rather
/// than a stale member checksum, must reject the native startup definition.
fn add_writable_rpath(bytes: &mut [u8]) -> Result<()> {
    let failure = || {
        CiError::Message(
            "owned ELF lacks a bounded dynamic string suitable for RPATH mutation".into(),
        )
    };
    let u16_at = |offset: usize| -> Result<u16> {
        Ok(u16::from_le_bytes(
            bytes
                .get(offset..offset + 2)
                .ok_or_else(failure)?
                .try_into()
                .map_err(|_| failure())?,
        ))
    };
    let u64_at = |offset: usize| -> Result<u64> {
        Ok(u64::from_le_bytes(
            bytes
                .get(offset..offset + 8)
                .ok_or_else(failure)?
                .try_into()
                .map_err(|_| failure())?,
        ))
    };
    if bytes.get(..6) != Some(&b"\x7fELF\x02\x01"[..]) {
        return Err(failure());
    }
    let headers = usize::try_from(u64_at(32)?).map_err(|_| failure())?;
    let stride = usize::from(u16_at(54)?);
    let count = usize::from(u16_at(56)?);
    if stride < 56 || count == 0 || count > 256 {
        return Err(failure());
    }
    let mut loads = Vec::new();
    let mut dynamic = None;
    for ordinal in 0..count {
        let offset = headers
            .checked_add(ordinal.checked_mul(stride).ok_or_else(failure)?)
            .ok_or_else(failure)?;
        let kind = u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or_else(failure)?
                .try_into()
                .map_err(|_| failure())?,
        );
        let file = u64_at(offset + 8)?;
        let address = u64_at(offset + 16)?;
        let size = u64_at(offset + 32)?;
        if kind == 1 {
            loads.push((file, address, size));
        }
        if kind == 2 {
            dynamic = Some((file, size));
        }
    }
    let (start, size) = dynamic.ok_or_else(failure)?;
    if size > 1024 * 1024 || size % 16 != 0 {
        return Err(failure());
    }
    let start = usize::try_from(start).map_err(|_| failure())?;
    let mut string_address = None;
    let mut needed = None;
    for ordinal in 0..usize::try_from(size / 16).map_err(|_| failure())? {
        let offset = start
            .checked_add(ordinal.checked_mul(16).ok_or_else(failure)?)
            .ok_or_else(failure)?;
        let tag = u64_at(offset)?;
        let value = u64_at(offset + 8)?;
        if tag == 0 {
            break;
        }
        if tag == 5 {
            string_address = Some(value);
        }
        if tag == 1 && needed.is_none() {
            needed = Some((offset, value));
        }
    }
    let address = string_address.ok_or_else(failure)?;
    let string_base = loads
        .iter()
        .find_map(|(file, base, size)| {
            address
                .checked_sub(*base)
                .filter(|delta| *delta < *size)
                .and_then(|delta| file.checked_add(delta))
        })
        .ok_or_else(failure)?;
    let (tag_offset, string_offset) = needed.ok_or_else(failure)?;
    let position = usize::try_from(string_base.checked_add(string_offset).ok_or_else(failure)?)
        .map_err(|_| failure())?;
    let original = bytes.get(position..).ok_or_else(failure)?;
    let length = original
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(failure)?;
    if !(5..=4096).contains(&length) {
        return Err(failure());
    }
    bytes
        .get_mut(tag_offset..tag_offset + 8)
        .ok_or_else(failure)?
        .copy_from_slice(&15u64.to_le_bytes());
    bytes
        .get_mut(position..position + 6)
        .ok_or_else(failure)?
        .copy_from_slice(b"/work\0");
    Ok(())
}

fn export_case(
    context: &ImageCaseContext<'_>,
    admin: &Path,
    report: &mut ImageCaseReport,
    scenario: &str,
) -> Result<()> {
    use super::linux_mixed_installed::{
        InstalledMixedLaunchInput, activate_owned_policy_staged_until,
    };
    use memcordon_core::workload_contract_v3::{RequirementV3, RootRelativePath};
    remaining(context.deadline)?;
    let directory = context.output.join(format!("export-{scenario}"));
    let privileged = admin.join(format!("export-{scenario}"));
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o711))?;
    std::fs::create_dir(&privileged)?;
    std::fs::set_permissions(&privileged, std::fs::Permissions::from_mode(0o700))?;
    report.directory_custody.extend(hold_ancestry(&privileged)?);
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(|error| CiError::Message(error.to_string()))?;
    if challenge == [0; 32] {
        return Err(CiError::Message(
            "fresh export challenge unavailable".into(),
        ));
    }
    let challenge_path = directory.join("challenge.bin");
    retain(&challenge_path, &challenge, &mut report.file_custody)?;
    let contract_path = directory.join("request.json");
    let index = report.export_observations.len();
    let own_worker_index = report.export_worker_owners.len();
    report.export_observations.push(ExportCaseObservation {
        family: "L-IMG-04".into(),
        scenario: format!("export-{scenario}"),
        fixture_mode: scenario.into(),
        challenge: challenge_path,
        contract: contract_path.clone(),
        activation: None,
        prepared: None,
        prepared_native: None,
        ready: None,
        controller_setup: None,
        native_source: None,
        native_invocation: None,
        native_wait: None,
        native_family: None,
        provider_request: None,
        recovery: None,
        stdout: None,
        stderr: None,
        result: None,
        native_exit: None,
        error: None,
    });
    let requirements = if scenario == "socket" {
        vec![RequirementV3::UnixPathStream {
            id: LogicalId::new("pathname".into()).map_err(CiError::Message)?,
            writable_root: LogicalId::new("work".into()).map_err(CiError::Message)?,
        }]
    } else {
        Vec::new()
    };
    let export = RootRelativePath::new(
        if scenario == "traversal" {
            "work/parent/exported.bin"
        } else {
            "work/exported.bin"
        }
        .into(),
    )
    .map_err(CiError::Message)?;
    let activated = activate_owned_policy_staged_until(
        context.activated.registry.legacy.clone(),
        context.images,
        context.account,
        context.identity,
        context.cell,
        requirements,
        vec![export],
        &directory,
        &privileged.join("activation-policy"),
        context.deadline,
    )?;
    report.export_observations[index].activation = Some(activated.activation_path.clone());
    retain(
        &contract_path,
        &serde_json::to_vec(&activated.contract)?,
        &mut report.file_custody,
    )?;
    std::fs::set_permissions(&contract_path, std::fs::Permissions::from_mode(0o444))?;
    let arguments = vec![
        OsString::from("export-object"),
        OsString::from(hex(&challenge)),
        OsString::from(scenario),
    ];
    let product_budget = format!(
        "+{}ms",
        remaining(context.deadline)?.as_millis().min(60_000)
    );
    let launch = InstalledMixedLaunch::start(InstalledMixedLaunchInput {
        directory: &directory.join("launch"),
        contract: &contract_path,
        caller_uid: 65534,
        caller_gid: 65534,
        target_arguments: &arguments,
        deadline: std::ffi::OsStr::new(&product_budget),
        memory: std::ffi::OsStr::new("+512M"),
    })?;
    let launch_index = report.launches.len();
    report.launches.push(launch);
    report.export_observations[index].stdout = Some(report.launches[launch_index].stdout.clone());
    report.export_observations[index].stderr = Some(report.launches[launch_index].stderr.clone());
    report.export_observations[index].result = Some(report.launches[launch_index].result.clone());
    let prepared_relative = directory
        .strip_prefix(context.artifact_root)
        .map_err(|error| CiError::Message(error.to_string()))?
        .join("prepared.json")
        .to_str()
        .ok_or_else(|| CiError::Message("export prepared path not UTF8".into()))?
        .to_owned();
    let observer = report.launches[launch_index].acquire_prepared(
        context.provider,
        &activated.contract,
        context.artifact_root,
        &prepared_relative,
        remaining(context.deadline)?,
    )?;
    let observer_index = report.prepared_owners.len();
    report.prepared_owners.push(observer);
    report.export_observations[index].prepared =
        Some(context.artifact_root.join(&prepared_relative));
    let native_relative = directory
        .strip_prefix(context.artifact_root)
        .map_err(|error| CiError::Message(error.to_string()))?
        .join("prepared-native.json")
        .to_str()
        .ok_or_else(|| CiError::Message("export native path not UTF8".into()))?
        .to_owned();
    report.prepared_owners[observer_index]
        .persist_native_receipt(
            &context.identity.run_id,
            context.artifact_root,
            &native_relative,
        )
        .map_err(CiError::Message)?;
    report.export_observations[index].prepared_native =
        Some(context.artifact_root.join(native_relative));
    report.prepared_owners[observer_index]
        .acknowledge(&report.launches[launch_index].observation_directory)
        .map_err(CiError::Message)?;
    let ready = wait_export_ready(
        &report.launches[launch_index].stdout,
        &hex(&challenge),
        scenario,
        context.deadline,
        &report.prepared_owners[observer_index].target,
    )?;
    let ready_path = directory.join("ready.json");
    retain(
        &ready_path,
        &serde_json::to_vec(&ready)?,
        &mut report.file_custody,
    )?;
    report.export_observations[index].ready = Some(ready_path);
    let mut export_helper = None;
    if scenario == "concurrent-writer" {
        let writer_start = report.descendant_owners.len();
        let tree = wait_export_stage(
            &report.launches[launch_index].stdout,
            &hex(&challenge),
            "export-writer-held",
            context.deadline,
            &report.prepared_owners[observer_index].target,
        )?;
        report.launches[launch_index].hold_fixture_tree_into(
            &report.prepared_owners[observer_index],
            &tree.observation,
            &mut report.descendant_owners,
        )?;
        let held_path = directory.join("writer-held.json");
        retain(
            &held_path,
            &serde_json::to_vec(&tree)?,
            &mut report.file_custody,
        )?;
        report.export_observations[index].controller_setup = Some(held_path);
        let worker_index = report.export_worker_owners.len();
        retain_export_worker(context, report, observer_index, &directory)?;
        let writers = &report.descendant_owners[writer_start..];
        if writers.len() != 1 {
            return Err(CiError::Message(
                "pre-empty export writer cohort is not exactly one held child".into(),
            ));
        }
        let writer_namespace_pid = *writers[0]
            .live_snapshot()
            .map_err(CiError::Message)?
            .namespace_pids
            .last()
            .filter(|pid| **pid != 0)
            .ok_or_else(|| {
                CiError::Message("pre-empty export writer native namespace PID absent".into())
            })?;
        retain(
            &directory.join("writer-native-held.json"),
            &serde_json::to_vec(&writers[0].live_snapshot().map_err(CiError::Message)?)?,
            &mut report.file_custody,
        )?;
        // Stop the fixture's pre-empty writer while its native identity is
        // retained. The required post-empty write is a separate external event.
        report.launches[launch_index]
            .frontend
            .stdin
            .as_mut()
            .ok_or_else(|| {
                CiError::Message("export fixture input owner absent before writer stop".into())
            })?
            .write_all(b"S")?;
        let stopped = wait_export_stage(
            &report.launches[launch_index].stdout,
            &hex(&challenge),
            "export-writer-retired",
            context.deadline,
            &report.prepared_owners[observer_index].target,
        )?;
        let mut retired = Vec::new();
        for writer in &report.descendant_owners[writer_start..] {
            if !writer.exited().map_err(CiError::Message)? {
                return Err(CiError::Message(
                    "pre-empty export writer remains natively live after stop".into(),
                ));
            }
            retired.push(writer.retirement_identity().map_err(CiError::Message)?);
        }
        if retired.is_empty()
            || stopped.observation["before_root_release"] != true
            || stopped.observation["pid"] != writer_namespace_pid
            || stopped.observation["native_wait_completed"] != true
            || stopped.observation["raw_wait_status"] != 0
            || stopped.observation["native_exit_code"] != 0
            || !stopped.observation["native_signal"].is_null()
        {
            return Err(CiError::Message(
                "export writer stop lacks actual held identity or pre-release phase".into(),
            ));
        }
        retain(
            &directory.join("writer-retired.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.linux-export-preempty-writer-retirement","revision":1,
                "fixture":stopped,"held_retirement":retired
            }))?,
            &mut report.file_custody,
        )?;
        export_helper = Some(start_export_permission_helper(
            context,
            report,
            observer_index,
            worker_index,
            &directory,
            &challenge,
        )?);
    } else if scenario == "device" {
        let handles_start = report.administrative_export_handles.len();
        let setup = create_owned_export_device(
            &report.prepared_owners[observer_index],
            &mut report.administrative_export_handles,
        )?;
        let handles_end = report.administrative_export_handles.len();
        let path = directory.join("device-created.json");
        retain(
            &path,
            &serde_json::to_vec(&setup)?,
            &mut report.file_custody,
        )?;
        report.export_observations[index].controller_setup = Some(path);
        let root = report.administrative_export_handles[handles_start].metadata()?;
        let work = report.administrative_export_handles[handles_start + 1].metadata()?;
        let device = report.administrative_export_handles[handles_start + 2].metadata()?;
        let named_root = std::fs::metadata(
            Path::new("/proc")
                .join(
                    report.prepared_owners[observer_index]
                        .target
                        .process_id
                        .to_string(),
                )
                .join("root"),
        )?;
        if setup["root_device"] != root.dev()
            || setup["root_inode"] != root.ino()
            || setup["work_device"] != work.dev()
            || setup["work_inode"] != work.ino()
            || setup["device"] != device.dev()
            || setup["inode"] != device.ino()
            || setup["rdev"] != device.rdev()
            || setup["mode"] != device.mode()
            || (named_root.dev(), named_root.ino()) != (root.dev(), root.ino())
            || report.prepared_owners[observer_index]
                .target
                .exited()
                .map_err(CiError::Message)?
        {
            return Err(CiError::Message(
                "owned export device changed before administrative handle retirement".into(),
            ));
        }
        // These controller mount/file holds are separate from the target's
        // PIDFD custody and must close before provider root retirement.
        let mut closures = Vec::new();
        let mut closure_errors = Vec::new();
        for (role, file) in ["root", "work", "device"].into_iter().zip(
            report
                .administrative_export_handles
                .drain(handles_start..handles_end),
        ) {
            let closed = memcordon_platform::linux_checked_close(std::os::fd::OwnedFd::from(file));
            let error = closed.err();
            if let Some(error) = &error {
                closure_errors.push(format!(
                    "owned export device {role} native close failed: {error}"
                ));
            }
            closures.push(
                serde_json::json!({"role":role,"native_close_succeeded":error.is_none(),
                "native_close_errno":error.as_ref().and_then(std::io::Error::raw_os_error)}),
            );
        }
        report.failures.extend(closure_errors.iter().cloned());
        let publication = retain(
            &directory.join("device-admin-handles-retired.json"),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.linux-export-administrative-handle-retirement","revision":1,
                "attempt_id":report.prepared_owners[observer_index].observation.admission.attempt_id,
                "before_root_release":true,"closures":closures
            }))?,
            &mut report.file_custody,
        );
        if let Err(error) = publication {
            let failure = format!("owned export native closure receipt publication: {error}");
            report.failures.push(failure.clone());
            closure_errors.push(failure);
        }
        if !closure_errors.is_empty() {
            return Err(CiError::Message(closure_errors.join("; ")));
        }
    }
    let source_path = directory.join("native-export-source.json");
    if scenario != "concurrent-writer" {
        retain_export_worker(context, report, observer_index, &directory)?;
    }
    let source = capture_export_source(
        &report.prepared_owners[observer_index],
        scenario,
        context.account,
    )?;
    retain(
        &source_path,
        &serde_json::to_vec(&source)?,
        &mut report.file_custody,
    )?;
    report.export_observations[index].native_source = Some(source_path);
    report.launches[launch_index].release_fixture_barrier()?;
    if let Some(helper_index) = export_helper {
        finish_export_permission_helper(context, report, helper_index, observer_index)?;
    }
    report.launches[launch_index].wait_and_capture(remaining(context.deadline)?)?;
    report.export_observations[index].native_exit = report.launches[launch_index]
        .frontend_status
        .as_ref()
        .and_then(|status| status.code());
    finalize_attempts(report, context.cleanup_deadline)?;
    let invocation = directory.join("frontend-invocation.json");
    let wait = directory.join("frontend-native-wait.json");
    retain(
        &invocation,
        &report.launches[launch_index].retained_frontend_invocation()?,
        &mut report.file_custody,
    )?;
    retain(
        &wait,
        &serde_json::to_vec(&report.launches[launch_index].retained_frontend_wait()?)?,
        &mut report.file_custody,
    )?;
    let observer = &report.prepared_owners[observer_index];
    let family = directory.join("native-family-retirement.json");
    retain(
        &family,
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.linux-export-held-retirement","revision":1,
        "attempt_id":observer.observation.admission.attempt_id,"target":observer.target.retirement_identity().map_err(CiError::Message)?,
        "namespace_init":observer.namespace_init.retirement_identity().map_err(CiError::Message)?,"guardian":observer.guardian.retirement_identity().map_err(CiError::Message)?,
        "caller":observer.caller.retirement_identity().map_err(CiError::Message)?,
        "workers":report.export_worker_owners[own_worker_index..].iter().map(|owner|owner.retirement_identity()).collect::<std::result::Result<Vec<_>,_>>().map_err(CiError::Message)?}),
        )?,
        &mut report.file_custody,
    )?;
    report.export_observations[index].native_invocation = Some(invocation);
    report.export_observations[index].native_wait = Some(wait);
    report.export_observations[index].native_family = Some(family);
    let requests = std::fs::read_dir(&report.launches[launch_index].observation_directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".provider-request.bin"))
        })
        .collect::<Vec<_>>();
    if requests.len() != 1 {
        return Err(CiError::Message(
            "export attempt did not retain exactly one actual typed provider request".into(),
        ));
    }
    report.export_observations[index].provider_request = Some(requests[0].clone());
    // The independent decoder joins the actual exporter result and native
    // family emptiness; frontend completion alone never certifies rejection.
    Ok(())
}

fn capture_export_source(
    observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
    scenario: &str,
    account: &ExclusiveAccount,
) -> Result<serde_json::Value> {
    if observer.target.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "export root retired before native source capture".into(),
        ));
    }
    let root = Path::new("/proc")
        .join(observer.target.process_id.to_string())
        .join("root");
    let root_file = File::open(&root)?;
    let root_stamp = root_file.metadata()?;
    if (root_stamp.dev(), root_stamp.ino())
        != (
            observer.observation.root_device,
            observer.observation.root_inode,
        )
    {
        return Err(CiError::Message(
            "native export source root differs from prepared held root".into(),
        ));
    }
    let work: File = rustix::fs::openat(
        &root_file,
        "work",
        rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?
    .into();
    let name = if scenario == "traversal" {
        "parent"
    } else {
        "exported.bin"
    };
    let member: File = rustix::fs::openat(
        &work,
        name,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?
    .into();
    let before = member.metadata()?;
    let target = if before.file_type().is_symlink() {
        Some(std::fs::read_link(root.join("work").join(name))?)
    } else {
        None
    };
    let after = member.metadata()?;
    let named = std::fs::symlink_metadata(root.join("work").join(name))?;
    let stamp = |value: &std::fs::Metadata| {
        (
            value.dev(),
            value.ino(),
            value.mode(),
            value.uid(),
            value.gid(),
            value.nlink(),
            value.len(),
            value.ctime(),
            value.ctime_nsec(),
        )
    };
    if stamp(&before) != stamp(&after)
        || stamp(&before) != stamp(&named)
        || observer.target.exited().map_err(CiError::Message)?
    {
        return Err(CiError::Message(
            "native export source changed while fixture held".into(),
        ));
    }
    Ok(
        serde_json::json!({"format":"memcordon.linux-export-native-source","revision":1,"scenario":scenario,
        "attempt_id":observer.observation.admission.attempt_id,"target":observer.target.live_snapshot().map_err(CiError::Message)?,
        "root_device":root_stamp.dev(),"root_inode":root_stamp.ino(),"member":name,"device":before.dev(),"inode":before.ino(),
        "mode":before.mode(),"uid":before.uid(),"gid":before.gid(),"nlink":before.nlink(),"length":before.len(),
        "ctime_seconds":before.ctime(),"ctime_nanoseconds":before.ctime_nsec(),"symlink_target":target,
        "exclusive_uid":account.uid,"exclusive_gid":account.gid}),
    )
}

/// Read only the selected owned attempt journal and retain its exact native
/// worker before any fallible image measurement. This is observation, not
/// workload or cleanup authority.
pub fn retain_prepared_worker(
    observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
    expected_agent_sha256: &str,
    deadline: Instant,
    directories: &mut Vec<File>,
    files: &mut Vec<File>,
    workers: &mut Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
) -> Result<serde_json::Value> {
    remaining(deadline)?;
    let attempt = observer.observation.admission.attempt_id.as_str();
    if attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || expected_agent_sha256.len() != 64
        || !expected_agent_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CiError::Message(
            "prepared worker attempt/selected image differs".into(),
        ));
    }
    let parent = Path::new("/var/lib/memcordon/sealed");
    let ancestry_start = directories.len();
    directories.extend(hold_ancestry(parent)?);
    let path = parent.join(attempt);
    let mut journal = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let before = journal.metadata()?;
    files.push(journal.try_clone()?);
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o077 != 0
        || before.len() > 1024 * 1024
    {
        return Err(CiError::Message(
            "prepared worker journal is not protected owned data".into(),
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut journal)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let text = std::str::from_utf8(&bytes).map_err(|error| CiError::Message(error.to_string()))?;
    let (body, digest_line) = text
        .rsplit_once("digest=")
        .ok_or_else(|| CiError::Message("prepared worker journal digest absent".into()))?;
    if digest_line != format!("{}\n", hex(&Sha256::digest(body.as_bytes()))) {
        return Err(CiError::Message(
            "prepared worker journal checksum differs".into(),
        ));
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
        || lines.next() != Some(format!("cgroup={attempt}").as_str())
    {
        return Err(CiError::Message(
            "prepared worker journal envelope differs".into(),
        ));
    }
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or_else(|| CiError::Message("prepared worker journal payload absent".into()))?;
    if lines.next().is_some() {
        return Err(CiError::Message(
            "prepared worker journal envelope has extra fields".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(payload.as_bytes())
        .map_err(CiError::Message)?;
    let record: serde_json::Value = serde_json::from_str(payload)?;
    if record["attempt_id"] != attempt
        || record["mixed_admission_metadata"]
            != serde_json::to_value(&observer.observation.admission)?
    {
        return Err(CiError::Message(
            "prepared worker journal crosses authenticated request".into(),
        ));
    }
    for (field, process) in [
        ("target", &observer.target),
        ("namespace_init", &observer.namespace_init),
        ("guardian", &observer.guardian),
    ] {
        if record[field] != serde_json::json!({"pid":process.process_id,"start_time":process.birth})
            || process.exited().map_err(CiError::Message)?
        {
            return Err(CiError::Message(
                "prepared worker journal crosses live held family".into(),
            ));
        }
    }
    let worker = &record["mixed_worker"];
    let object = worker
        .as_object()
        .ok_or_else(|| CiError::Message("prepared journal worker absent".into()))?;
    let pid = worker["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| CiError::Message("prepared journal worker PID invalid".into()))?;
    let birth = worker["start_time"]
        .as_u64()
        .filter(|birth| *birth > 0)
        .ok_or_else(|| CiError::Message("prepared journal worker birth invalid".into()))?;
    if object.len() != 2
        || pid == observer.target.process_id
        || pid == observer.namespace_init.process_id
        || pid == observer.guardian.process_id
        || pid == observer.caller.process_id
    {
        return Err(CiError::Message(
            "prepared journal worker identity aliases family".into(),
        ));
    }
    workers.push(
        crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth)
            .map_err(CiError::Message)?,
    );
    let image = workers
        .last_mut()
        .expect("retained worker owner")
        .hold_executable_image(deadline)
        .map_err(CiError::Message)?;
    if image["sha256"] != expected_agent_sha256 {
        return Err(CiError::Message(
            "prepared worker image differs from selected agent".into(),
        ));
    }
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let after = named.metadata()?;
    let mut readback = vec![0; bytes.len()];
    named.read_exact_at(&mut readback, 0)?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
        before.mode(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
        after.mode(),
    ) || after.uid() != 0
        || after.nlink() != 1
        || readback != bytes
    {
        return Err(CiError::Message(
            "prepared worker journal named identity changed".into(),
        ));
    }
    for (ancestor, held) in parent
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .zip(&directories[ancestry_start..])
    {
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(ancestor)?;
        let expected = held.metadata()?;
        let actual = named.metadata()?;
        if (
            expected.dev(),
            expected.ino(),
            expected.uid(),
            expected.mode(),
        ) != (actual.dev(), actual.ino(), actual.uid(), actual.mode())
            || actual.uid() != 0
            || !actual.is_dir()
            || (actual.mode() & 0o022 != 0 && actual.mode() & libc::S_ISVTX == 0)
        {
            return Err(CiError::Message(
                "prepared worker journal ancestry changed".into(),
            ));
        }
    }
    for process in [
        &observer.target,
        &observer.namespace_init,
        &observer.guardian,
        workers.last().expect("retained worker owner"),
    ] {
        if process.exited().map_err(CiError::Message)? {
            return Err(CiError::Message(
                "prepared worker/family exited through association readback".into(),
            ));
        }
    }
    remaining(deadline)?;
    Ok(
        serde_json::json!({"format":"memcordon.linux-prepared-worker-observation","revision":1,
        "attempt_id":attempt,"provider":observer.observation.provider,"admission":observer.observation.admission,
        "journal_path":path,"journal_device":before.dev(),"journal_inode":before.ino(),"journal_sha256":hex(&Sha256::digest(&bytes)),
        "journal_bytes":bytes,"worker":{"pid":pid,"birth":birth,"image_sha256":expected_agent_sha256},"native_image":image}),
    )
}

fn retain_export_worker(
    context: &ImageCaseContext<'_>,
    report: &mut ImageCaseReport,
    observer_index: usize,
    directory: &Path,
) -> Result<()> {
    let receipt = retain_prepared_worker(
        &report.prepared_owners[observer_index],
        context.expected_agent_sha256,
        context.deadline,
        &mut report.directory_custody,
        &mut report.file_custody,
        &mut report.export_worker_owners,
    )?;
    retain(
        &directory.join("export-worker.json"),
        &serde_json::to_vec(&receipt)?,
        &mut report.file_custody,
    )
}

/// Retain the actual prepared root, exact source and cgroup while the gated
/// fixture remains live. Every acquired file stays owned on later errors.
fn retain_export_source(
    observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
    account: &ExclusiveAccount,
    owners: &mut Vec<File>,
    deadline: Instant,
) -> Result<(usize, usize, serde_json::Value)> {
    use rustix::fs::{Mode, OFlags, openat};
    remaining(deadline)?;
    if observer.target.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "external export source target is not held live".into(),
        ));
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(
            Path::new("/proc")
                .join(observer.target.process_id.to_string())
                .join("root"),
        )?;
    let root_metadata = root.metadata()?;
    let root_index = owners.len();
    owners.push(root);
    if (root_metadata.dev(), root_metadata.ino())
        != (
            observer.observation.root_device,
            observer.observation.root_inode,
        )
    {
        return Err(CiError::Message(
            "external export source root differs from authenticated native root".into(),
        ));
    }
    let work: File = openat(
        &owners[root_index],
        "work",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let work_index = owners.len();
    owners.push(work);
    let source: File = openat(
        &owners[work_index],
        "exported.bin",
        OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let source_index = owners.len();
    owners.push(source);
    let source = owners[source_index].metadata()?;
    if !source.is_file()
        || source.nlink() != 1
        || source.uid() != account.uid
        || source.gid() != account.gid
    {
        return Err(CiError::Message(
            "external export source is not the exact owned regular account file".into(),
        ));
    }
    let cgroup = observer
        .retain_cgroup_descriptor()
        .map_err(CiError::Message)?;
    let cgroup_index = owners.len();
    owners.push(cgroup);
    let group = owners[cgroup_index].metadata()?;
    let named_root = std::fs::metadata(
        Path::new("/proc")
            .join(observer.target.process_id.to_string())
            .join("root"),
    )?;
    let named_work: File = openat(
        &owners[root_index],
        "work",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let named_source: File = openat(
        &named_work,
        "exported.bin",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let named = named_source.metadata()?;
    let after = owners[source_index].metadata()?;
    let work = owners[work_index].metadata()?;
    let reopened_work = named_work.metadata()?;
    if (named_root.dev(), named_root.ino()) != (root_metadata.dev(), root_metadata.ino())
        || (work.dev(), work.ino()) != (reopened_work.dev(), reopened_work.ino())
        || [named, after].iter().any(|actual| {
            !actual.is_file()
                || actual.nlink() != 1
                || (
                    actual.dev(),
                    actual.ino(),
                    actual.uid(),
                    actual.gid(),
                    actual.len(),
                    actual.ctime(),
                    actual.ctime_nsec(),
                ) != (
                    source.dev(),
                    source.ino(),
                    source.uid(),
                    source.gid(),
                    source.len(),
                    source.ctime(),
                    source.ctime_nsec(),
                )
        })
    {
        return Err(CiError::Message(
            "external export source named identity or stable metadata changed during acquisition"
                .into(),
        ));
    }
    if observer.target.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "external export target retired during source acquisition".into(),
        ));
    }
    Ok((
        source_index,
        cgroup_index,
        serde_json::json!({
            "source":{"device":source.dev(),"inode":source.ino(),"uid":source.uid(),"gid":source.gid(),
                "length":source.len(),"ctime_seconds":source.ctime(),"ctime_nanoseconds":source.ctime_nsec()},
            "cgroup":{"device":group.dev(),"inode":group.ino()},
            "root":{"device":root_metadata.dev(),"inode":root_metadata.ino()},
            "work":{"device":work.dev(),"inode":work.ino()}
        }),
    ))
}

/// Transfer only the two already-owned descriptors. No pathname is opened by
/// this transport and a short send never becomes an acknowledged setup.
fn send_export_setup(
    peer: &std::os::fd::OwnedFd,
    source: &File,
    cgroup: &File,
    setup: &[u8],
    deadline: Instant,
) -> Result<()> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    use std::io::IoSlice;
    use std::mem::MaybeUninit;
    use std::os::fd::AsFd;
    if setup.is_empty() || setup.len() > 64 * 1024 {
        return Err(CiError::Message(
            "external export setup packet exceeds finite bound".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(setup).map_err(CiError::Message)?;
    let descriptors = [source.as_fd(), cgroup.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(CiError::Message(
            "external export descriptor buffer cannot hold exact two owners".into(),
        ));
    }
    loop {
        remaining(deadline)?;
        match sendmsg(
            peer,
            &[IoSlice::new(setup)],
            &mut control,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Ok(count) if count == setup.len() => return Ok(()),
            Ok(_) => {
                return Err(CiError::Message(
                    "external export setup native send was short".into(),
                ));
            }
            Err(error) if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
    }
}

fn receive_export_packet(
    peer: &std::os::fd::OwnedFd,
    deadline: Instant,
) -> Result<serde_json::Value> {
    let mut socket = File::from(peer.try_clone()?);
    let received = (|| -> Result<serde_json::Value> {
        let mut bytes = vec![0u8; 64 * 1024 + 1];
        loop {
            remaining(deadline)?;
            match socket.read(&mut bytes) {
                Ok(0) => {
                    return Err(CiError::Message(
                        "external export peer closed before typed observation".into(),
                    ));
                }
                Ok(count) if count <= 64 * 1024 => {
                    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes[..count])
                        .map_err(CiError::Message)?;
                    return Ok(serde_json::from_slice(&bytes[..count])?);
                }
                Ok(_) => {
                    return Err(CiError::Message(
                        "external export observation exceeds finite packet bound".into(),
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        }
    })();
    let closed = memcordon_platform::linux_checked_close(socket.into());
    match (received, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(CiError::Message(format!(
            "external export receive owner close: {error}"
        ))),
        (Err(error), Err(close)) => Err(CiError::Message(format!(
            "{error}; external export receive owner close: {close}"
        ))),
    }
}

fn start_export_permission_helper(
    context: &ImageCaseContext<'_>,
    report: &mut ImageCaseReport,
    observer_index: usize,
    worker_index: usize,
    directory: &Path,
    challenge: &[u8; 32],
) -> Result<usize> {
    use std::os::unix::ffi::OsStrExt;
    use std::process::{Command, Stdio};
    remaining(context.deadline)?;
    let administrative_start = report.administrative_export_handles.len();
    let (source_index, cgroup_index, metadata) = retain_export_source(
        &report.prepared_owners[observer_index],
        context.account,
        &mut report.administrative_export_handles,
        context.deadline,
    )?;
    let cgroup_parent_path = Path::new("/sys/fs/cgroup/memcordon-sealed");
    let cgroup_ancestry_start = report.directory_custody.len();
    report
        .directory_custody
        .extend(hold_ancestry(cgroup_parent_path)?);
    let cgroup_ancestry_end = report.directory_custody.len();
    let cgroup_parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(cgroup_parent_path)?;
    let cgroup_parent_index = report.administrative_export_handles.len();
    report.administrative_export_handles.push(cgroup_parent);
    let parent = &report.administrative_export_handles[cgroup_parent_index];
    let parent_stamp = parent.metadata()?;
    let attempt = report.prepared_owners[observer_index]
        .observation
        .admission
        .attempt_id
        .as_str();
    let named = rustix::fs::statat(parent, attempt, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;
    if !parent_stamp.is_dir()
        || parent_stamp.uid() != 0
        || parent_stamp.mode() & 0o022 != 0
        || rustix::fs::fstatfs(parent)
            .map_err(std::io::Error::from)?
            .f_type as u64
            != 0x63677270
        || named.st_dev as u64 != metadata["cgroup"]["device"].as_u64().unwrap_or(u64::MAX)
        || named.st_ino as u64 != metadata["cgroup"]["inode"].as_u64().unwrap_or(u64::MAX)
    {
        return Err(CiError::Message(
            "external export cgroup name differs from actual held prepared cgroup".into(),
        ));
    }
    let administrative_end = report.administrative_export_handles.len();
    let worker = &report.export_worker_owners[worker_index];
    if worker.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "selected external export worker retired before setup".into(),
        ));
    }
    let setup = serde_json::json!({"format":"memcordon.native-export-permission-setup","revision":1,
        "challenge_hex":hex(challenge),"work_unix_ms":context.work_deadline_unix_millis,
        "cleanup_unix_ms":context.cleanup_deadline_unix_millis,"source":metadata["source"],"cgroup":metadata["cgroup"],
        "worker":{"pid":worker.process_id,"birth":worker.birth,"image_sha256":context.expected_agent_sha256}});
    let setup_bytes = serde_json::to_vec(&setup)?;
    retain(
        &directory.join("external-helper-setup.json"),
        &setup_bytes,
        &mut report.file_custody,
    )?;
    let program = context.images.runtime_source.join("bin/owned-readiness");
    report.directory_custody.extend(hold_ancestry(
        program
            .parent()
            .ok_or_else(|| CiError::Message("helper source parent absent".into()))?,
    )?);
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&program)?;
    let stamp = executable.metadata()?;
    let mut bytes = Vec::new();
    loop {
        remaining(context.deadline)?;
        let mut chunk = [0u8; 64 * 1024];
        let count = executable.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|length| length > 512 * 1024 * 1024)
        {
            return Err(CiError::Message(
                "external helper measured source exceeds native artifact bound".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    report.file_custody.push(executable);
    if !stamp.is_file()
        || stamp.nlink() != 1
        || bytes.len() > 512 * 1024 * 1024
        || hex(&Sha256::digest(&bytes)) != context.images.fixture_sha256
    {
        return Err(CiError::Message(
            "external helper differs from acquired native fixture artifact".into(),
        ));
    }
    let capture_ancestry_start = report.directory_custody.len();
    report
        .directory_custody
        .extend(hold_evidence_ancestry(directory, context.deadline)?);
    let capture_ancestry_end = report.directory_custody.len();
    let capture = |name| -> Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(name))?)
    };
    let stdout = capture("external-helper-stdout.bin")?;
    let stderr = capture("external-helper-stderr.bin")?;
    let (peer, child_peer) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(std::io::Error::from)?;
    let arguments = vec![
        OsString::from("native-export-permission"),
        OsString::from("--work-unix-ms"),
        OsString::from(context.work_deadline_unix_millis.to_string()),
        OsString::from("--cleanup-unix-ms"),
        OsString::from(context.cleanup_deadline_unix_millis.to_string()),
    ];
    retain(
        &directory.join("external-helper-invocation.json"),
        &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-external-export-helper-invocation","revision":1,
            "program":program.as_os_str().as_bytes(),"arguments":arguments.iter().map(|value|value.as_os_str().as_bytes()).collect::<Vec<_>>(),
            "cwd":directory.as_os_str().as_bytes(),"env_clear":true,"executable_sha256":context.images.fixture_sha256,
            "setup_sha256":hex(&Sha256::digest(&setup_bytes))
        }))?,
        &mut report.file_custody,
    )?;
    let child = Command::new(&program)
        .args(&arguments)
        .current_dir(directory)
        .env_clear()
        .stdin(Stdio::from(child_peer))
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()?;
    let index = report.export_helpers.len();
    report.export_helpers.push(ExportPermissionOwner {
        child,
        held: None,
        peer: Some(peer),
        stdout,
        stderr,
        directory: directory.to_owned(),
        setup,
        administrative_start,
        administrative_end,
        cgroup_index,
        cgroup_parent_index,
        source_index,
        cgroup_ancestry_start,
        cgroup_ancestry_end,
        capture_ancestry_start,
        capture_ancestry_end,
    });
    let pid = report.export_helpers[index].child.id();
    let birth = crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?;
    report.export_helpers[index].held = Some(
        crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth)
            .map_err(CiError::Message)?,
    );
    let image = report.export_helpers[index]
        .held
        .as_mut()
        .expect("retained helper process")
        .hold_executable_image(context.deadline)
        .map_err(CiError::Message)?;
    if image.get("sha256").and_then(serde_json::Value::as_str)
        != Some(context.images.fixture_sha256.as_str())
    {
        return Err(CiError::Message(
            "external helper kernel executable differs from measured artifact".into(),
        ));
    }
    retain(
        &directory.join("external-helper-held.json"),
        &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-external-export-helper-held","revision":1,
            "process_id":pid,"birth":birth,"native_image":image,"held_before_setup_delivery":true,
            "setup_sha256":hex(&Sha256::digest(&setup_bytes)),"challenge_hex":hex(challenge)
        }))?,
        &mut report.file_custody,
    )?;
    let peer = report.export_helpers[index]
        .peer
        .as_ref()
        .expect("retained helper peer");
    send_export_setup(
        peer,
        &report.administrative_export_handles[source_index],
        &report.administrative_export_handles[cgroup_index],
        &setup_bytes,
        context.deadline,
    )?;
    let armed = receive_export_packet(peer, context.deadline)?;
    if armed["format"] != "memcordon.native-export-permission-armed"
        || armed["revision"] != 1
        || armed["challenge_hex"] != hex(challenge)
        || armed["source"] != metadata["source"]
        || armed["worker"] != report.export_helpers[index].setup["worker"]
    {
        return Err(CiError::Message(
            "external helper armed observation differs from exact setup owners".into(),
        ));
    }
    retain(
        &directory.join("external-helper-armed.json"),
        &serde_json::to_vec(&armed)?,
        &mut report.file_custody,
    )?;
    Ok(index)
}

fn finish_export_permission_helper(
    context: &ImageCaseContext<'_>,
    report: &mut ImageCaseReport,
    helper_index: usize,
    observer_index: usize,
) -> Result<()> {
    let mut peer_close_errors = Vec::new();
    let helper = &report.export_helpers[helper_index];
    let peer = helper
        .peer
        .as_ref()
        .ok_or_else(|| CiError::Message("external helper peer owner absent".into()))?;
    let event = receive_export_packet(peer, context.deadline)?;
    let fields = [
        "format",
        "revision",
        "event_id",
        "challenge_hex",
        "source",
        "worker",
        "cgroup_retirement",
    ];
    if event.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || event["format"] != "memcordon.native-export-permission-event"
        || event["revision"] != 1
        || event["challenge_hex"] != helper.setup["challenge_hex"]
        || event["source"] != helper.setup["source"]
        || event["worker"] != helper.setup["worker"]
        || event["event_id"].as_str().is_none_or(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(CiError::Message(
            "external permission event differs from actual selected source and worker".into(),
        ));
    }
    let directory = helper.directory.clone();
    retain(
        &directory.join("external-helper-event.json"),
        &serde_json::to_vec(&event)?,
        &mut report.file_custody,
    )?;
    let observer = &report.prepared_owners[observer_index];
    loop {
        remaining(context.deadline)?;
        if observer.target.exited().map_err(CiError::Message)?
            && observer.namespace_init.exited().map_err(CiError::Message)?
            && observer.guardian.exited().map_err(CiError::Message)?
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let family = serde_json::json!({"format":"memcordon.linux-export-native-family-retirement","revision":1,
        "prepared":observer.observation,"challenge_hex":event["challenge_hex"],
        "target":observer.target.retirement_identity().map_err(CiError::Message)?,
        "namespace_init":observer.namespace_init.retirement_identity().map_err(CiError::Message)?,
        "guardian":observer.guardian.retirement_identity().map_err(CiError::Message)?});
    let family_bytes = serde_json::to_vec(&family)?;
    retain(
        &directory.join("external-family-retirement.json"),
        &family_bytes,
        &mut report.file_custody,
    )?;
    let helper = &report.export_helpers[helper_index];
    let workers = report
        .export_worker_owners
        .iter()
        .filter(|worker| {
            Some(worker.process_id as u64) == event["worker"]["pid"].as_u64()
                && Some(worker.birth) == event["worker"]["birth"].as_u64()
        })
        .collect::<Vec<_>>();
    if workers.len() != 1 || workers[0].exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "external event worker does not join one retained live selected native owner".into(),
        ));
    }
    let source = report.administrative_export_handles[helper.source_index].metadata()?;
    let source_observation = serde_json::json!({"device":source.dev(),"inode":source.ino(),"uid":source.uid(),"gid":source.gid(),
        "length":source.len(),"ctime_seconds":source.ctime(),"ctime_nanoseconds":source.ctime_nsec()});
    if !source.is_file() || source.nlink() != 1 || source_observation != event["source"] {
        return Err(CiError::Message(
            "external event source changed before controlled mutation acknowledgment".into(),
        ));
    }
    let group = &report.administrative_export_handles[helper.cgroup_index];
    let stamp = group.metadata()?;
    let group_observation = serde_json::json!({"device":stamp.dev(),"inode":stamp.ino(),"native_links":stamp.nlink(),
        "filesystem":"cgroup2","kind":"removed-held-inode"});
    if stamp.nlink() != 0
        || rustix::fs::fstatfs(group)
            .map_err(std::io::Error::from)?
            .f_type as u64
            != 0x63677270
        || group_observation != event["cgroup_retirement"]
        || group_observation["device"] != helper.setup["cgroup"]["device"]
        || group_observation["inode"] != helper.setup["cgroup"]["inode"]
    {
        return Err(CiError::Message(
            "external event does not join actual removed native cgroup inode".into(),
        ));
    }
    let parent = &report.administrative_export_handles[helper.cgroup_parent_index];
    verify_export_cgroup_ancestry(
        &report.directory_custody[helper.cgroup_ancestry_start..helper.cgroup_ancestry_end],
        context.deadline,
    )?;
    let parent_stamp = parent.metadata()?;
    let named_parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/sys/fs/cgroup/memcordon-sealed")?;
    let named_stamp = named_parent.metadata()?;
    if (
        parent_stamp.dev(),
        parent_stamp.ino(),
        parent_stamp.uid(),
        parent_stamp.mode(),
    ) != (
        named_stamp.dev(),
        named_stamp.ino(),
        named_stamp.uid(),
        named_stamp.mode(),
    ) || parent_stamp.uid() != 0
        || parent_stamp.mode() & 0o022 != 0
    {
        return Err(CiError::Message(
            "external cgroup native parent association changed".into(),
        ));
    }
    let named_close = memcordon_platform::linux_checked_close(named_parent.into());
    if let Err(error) = named_close {
        return Err(CiError::Message(format!(
            "external cgroup named parent close remains uncertain: {error}"
        )));
    }
    let attempt = observer.observation.admission.attempt_id.as_str();
    match rustix::fs::statat(parent, attempt, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(error) => return Err(std::io::Error::from(error).into()),
        Ok(_) => {
            return Err(CiError::Message(
                "external attempt cgroup name remains allocated".into(),
            ));
        }
    }
    verify_export_cgroup_ancestry(
        &report.directory_custody[helper.cgroup_ancestry_start..helper.cgroup_ancestry_end],
        context.deadline,
    )?;
    let cgroup_bytes = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-export-native-cgroup-retirement","revision":1,
        "attempt_id":attempt,"prepared":observer.observation,"held":group_observation,
        "parent":{"path":"/sys/fs/cgroup/memcordon-sealed","device":parent_stamp.dev(),"inode":parent_stamp.ino(),
            "uid":parent_stamp.uid(),"mode":parent_stamp.mode()},"named_attempt_errno":2
    }))?;
    retain(
        &directory.join("external-cgroup-retirement.json"),
        &cgroup_bytes,
        &mut report.file_custody,
    )?;
    let ack = serde_json::json!({"format":"memcordon.native-export-permission-ack","revision":1,
        "event_id":event["event_id"],"challenge_hex":event["challenge_hex"],
        "source_device":event["source"]["device"],"source_inode":event["source"]["inode"],
        "worker_pid":event["worker"]["pid"],"worker_birth":event["worker"]["birth"],
        "family_retirement_sha256":hex(&Sha256::digest(&family_bytes)),
        "cgroup_retirement_sha256":hex(&Sha256::digest(&cgroup_bytes)),"retirement_kind":"removed-held-inode"});
    let ack_bytes = serde_json::to_vec(&ack)?;
    retain(
        &directory.join("external-helper-ack.json"),
        &ack_bytes,
        &mut report.file_custody,
    )?;
    let start = helper.administrative_start;
    let end = helper.administrative_end;
    if end != report.administrative_export_handles.len() {
        return Err(CiError::Message(
            "external administrative hold range is not the exact active owner suffix".into(),
        ));
    }
    let mut closures = Vec::new();
    let mut close_errors = Vec::new();
    for owner in report.administrative_export_handles.drain(start..end) {
        match memcordon_platform::linux_checked_close(owner.into()) {
            Ok(()) => closures.push(serde_json::json!({"completed":true,"errno":null})),
            Err(error) => {
                closures.push(serde_json::json!({"completed":false,"errno":error.raw_os_error()}));
                close_errors.push(error.to_string());
            }
        }
    }
    report.failures.extend(
        close_errors
            .iter()
            .map(|error| format!("external administrative closure: {error}")),
    );
    retain(
        &directory.join("external-administrative-closure.json"),
        &serde_json::to_vec(&closures)?,
        &mut report.file_custody,
    )?;
    if !close_errors.is_empty() {
        return Err(CiError::Message(close_errors.join("; ")));
    }
    let helper = &report.export_helpers[helper_index];
    let sender = helper
        .peer
        .as_ref()
        .expect("retained external peer")
        .try_clone()?;
    let send = (|| -> Result<()> {
        loop {
            remaining(context.deadline)?;
            match rustix::net::send(
                &sender,
                &ack_bytes,
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            ) {
                Ok(count) if count == ack_bytes.len() => return Ok(()),
                Ok(_) => {
                    return Err(CiError::Message(
                        "external acknowledgment native send was short".into(),
                    ));
                }
                Err(error)
                    if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
    })();
    let close = memcordon_platform::linux_checked_close(sender);
    if let Err(error) = close {
        let failure = format!("external acknowledgment socket close: {error}");
        report.failures.push(failure.clone());
        peer_close_errors.push(failure);
    }
    send?;
    let settled = receive_export_packet(
        helper.peer.as_ref().expect("retained external peer"),
        context.cleanup_deadline,
    )?;
    retain(
        &directory.join("external-helper-settled.json"),
        &serde_json::to_vec(&settled)?,
        &mut report.file_custody,
    )?;
    let settled_fields = [
        "format",
        "revision",
        "challenge_hex",
        "work_unix_ms",
        "cleanup_unix_ms",
        "permission_answer",
        "mark_installed",
        "unmark",
        "closures",
        "operation",
        "operation_error",
        "settlement_errors",
    ];
    let roles = [
        "event",
        "event-pidfd",
        "worker-pidfd",
        "group",
        "source",
        "cgroup",
    ];
    let operation_fields = [
        "event_id",
        "before_length",
        "after_length",
        "before_ctime_seconds",
        "before_ctime_nanoseconds",
        "after_ctime_seconds",
        "after_ctime_nanoseconds",
        "family_retirement_sha256",
        "cgroup_retirement_sha256",
        "cgroup_retirement",
    ];
    if settled.as_object().is_none_or(|object| {
        object.len() != settled_fields.len()
            || object
                .keys()
                .any(|field| !settled_fields.contains(&field.as_str()))
    }) || settled["permission_answer"]
        .as_object()
        .is_none_or(|object| {
            object.len() != 2
                || !object.contains_key("attempted")
                || !object.contains_key("fan_allow_written")
        })
        || settled["unmark"].as_object().is_none_or(|object| {
            object.len() != 3
                || object
                    .keys()
                    .any(|field| !["attempted", "completed", "errno"].contains(&field.as_str()))
        })
        || settled["operation"].as_object().is_none_or(|object| {
            object.len() != operation_fields.len()
                || object
                    .keys()
                    .any(|field| !operation_fields.contains(&field.as_str()))
        })
        || settled["operation"]["after_ctime_seconds"]
            .as_i64()
            .is_none()
        || settled["operation"]["after_ctime_nanoseconds"]
            .as_u64()
            .is_none_or(|value| value >= 1_000_000_000)
        || settled["unmark"]["attempted"] != true
        || !settled["unmark"]["errno"].is_null()
        || settled["mark_installed"] != true
        || settled["closures"].as_array().is_none_or(|values| {
            values.len() != roles.len()
                || values.iter().zip(roles).any(|(value, role)| {
                    value.as_object().is_none_or(|object| {
                        object.len() != 4
                            || object.keys().any(|field| {
                                !["role", "attempted", "completed", "errno"]
                                    .contains(&field.as_str())
                            })
                    }) || value["role"] != role
                        || value["attempted"] != true
                        || value["completed"] != true
                        || !value["errno"].is_null()
                })
        })
        || settled["format"] != "memcordon.native-export-permission-settled"
        || settled["revision"] != 1
        || settled["challenge_hex"] != event["challenge_hex"]
        || settled["work_unix_ms"] != helper.setup["work_unix_ms"]
        || settled["cleanup_unix_ms"] != helper.setup["cleanup_unix_ms"]
        || settled["permission_answer"]["attempted"] != true
        || settled["permission_answer"]["fan_allow_written"] != true
        || settled["operation"]["event_id"] != event["event_id"]
        || settled["operation"]["before_length"] != event["source"]["length"]
        || settled["operation"]["after_length"].as_u64()
            != event["source"]["length"]
                .as_u64()
                .and_then(|length| length.checked_add(32))
        || settled["operation"]["before_ctime_seconds"] != event["source"]["ctime_seconds"]
        || settled["operation"]["before_ctime_nanoseconds"] != event["source"]["ctime_nanoseconds"]
        || settled["operation"]["family_retirement_sha256"] != ack["family_retirement_sha256"]
        || settled["operation"]["cgroup_retirement_sha256"] != ack["cgroup_retirement_sha256"]
        || settled["operation"]["cgroup_retirement"] != event["cgroup_retirement"]
        || settled["unmark"]["completed"] != true
        || !settled["operation_error"].is_null()
        || settled["settlement_errors"]
            .as_array()
            .is_none_or(|errors| !errors.is_empty())
        || settled["closures"].as_array().is_none_or(|values| {
            values.is_empty() || values.iter().any(|value| value["completed"] != true)
        })
    {
        return Err(CiError::Message(
            "external helper did not settle actual permission and native owners".into(),
        ));
    }
    let helper = &mut report.export_helpers[helper_index];
    if let Some(Err(error)) = helper
        .peer
        .take()
        .map(memcordon_platform::linux_checked_close)
    {
        let failure = format!("external settled peer native close: {error}");
        report.failures.push(failure.clone());
        peer_close_errors.push(failure);
    }
    let status = loop {
        remaining(context.cleanup_deadline)?;
        match helper.child.try_wait()? {
            Some(status) => break status,
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    let held = helper
        .held
        .as_ref()
        .ok_or_else(|| CiError::Message("external helper native process owner absent".into()))?;
    if !held.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "external helper native PIDFD remains live after actual wait".into(),
        ));
    }
    let mut captures = Vec::new();
    for (role, file) in [("stdout", &helper.stdout), ("stderr", &helper.stderr)] {
        verify_evidence_ancestry(
            &directory,
            &report.directory_custody[helper.capture_ancestry_start..helper.capture_ancestry_end],
            context.cleanup_deadline,
        )?;
        remaining(context.cleanup_deadline)?;
        file.sync_all()?;
        let stamp = file.metadata()?;
        if !stamp.is_file()
            || stamp.nlink() != 1
            || stamp.uid() != 0
            || stamp.mode() & 0o077 != 0
            || stamp.len() > 64 * 1024 * 1024
        {
            return Err(CiError::Message(
                "external helper capture exceeds native bound".into(),
            ));
        }
        let bytes = read_export_capture(file, stamp.len(), context.cleanup_deadline)?;
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(format!("external-helper-{role}.bin")))?;
        let named_stamp = named.metadata()?;
        let after = file.metadata()?;
        let native_stamp = |value: &std::fs::Metadata| {
            (
                value.dev(),
                value.ino(),
                value.len(),
                value.ctime(),
                value.ctime_nsec(),
                value.nlink(),
                value.uid(),
                value.gid(),
                value.mode(),
            )
        };
        if !named_stamp.is_file()
            || native_stamp(&stamp) != native_stamp(&named_stamp)
            || native_stamp(&stamp) != native_stamp(&after)
        {
            return Err(CiError::Message(
                "external helper capture held/named native identity changed".into(),
            ));
        }
        let named_bytes = read_export_capture(&named, stamp.len(), context.cleanup_deadline)?;
        if named_bytes != bytes
            || native_stamp(&named.metadata()?) != native_stamp(&stamp)
            || native_stamp(&file.metadata()?) != native_stamp(&stamp)
        {
            return Err(CiError::Message(
                "external helper capture exact named readback changed".into(),
            ));
        }
        let named_close = memcordon_platform::linux_checked_close(named.into());
        if let Err(error) = named_close {
            return Err(CiError::Message(format!(
                "external helper named capture close: {error}"
            )));
        }
        remaining(context.cleanup_deadline)?;
        verify_evidence_ancestry(
            &directory,
            &report.directory_custody[helper.capture_ancestry_start..helper.capture_ancestry_end],
            context.cleanup_deadline,
        )?;
        captures.push(
            serde_json::json!({"role":role,"device":stamp.dev(),"inode":stamp.ino(),
            "length":stamp.len(),"sha256":hex(&Sha256::digest(&bytes))}),
        );
    }
    verify_evidence_ancestry(
        &directory,
        &report.directory_custody[helper.capture_ancestry_start..helper.capture_ancestry_end],
        context.cleanup_deadline,
    )?;
    let capture_ancestry = report.directory_custody
        [helper.capture_ancestry_start..helper.capture_ancestry_end]
        .iter()
        .enumerate()
        .map(|(ordinal, file)| {
            file.metadata().map(|stamp| {
                serde_json::json!({"ordinal":ordinal,"device":stamp.dev(),"inode":stamp.ino(),
            "uid":stamp.uid(),"gid":stamp.gid(),"mode":stamp.mode()})
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    retain(
        &directory.join("external-helper-retirement.json"),
        &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-external-export-helper-retirement","revision":1,
            "challenge_hex":event["challenge_hex"],"process":held.retirement_identity().map_err(CiError::Message)?,
            "native_exit":status.code(),"native_success":status.success(),"captures":captures,
            "capture_directory":directory.to_str().ok_or_else(||CiError::Message("external capture directory is not UTF8".into()))?,
            "capture_directory_ancestry":capture_ancestry
        }))?,
        &mut report.file_custody,
    )?;
    if !status.success() {
        return Err(CiError::Message(
            "external helper actual native exit failed".into(),
        ));
    }
    if !peer_close_errors.is_empty() {
        return Err(CiError::Message(peer_close_errors.join("; ")));
    }
    Ok(())
}

fn verify_export_cgroup_ancestry(held: &[File], deadline: Instant) -> Result<()> {
    let names = ["sys", "fs", "cgroup", "memcordon-sealed"];
    if held.len() != names.len() + 1 {
        return Err(CiError::Message(
            "external cgroup retained ancestry cardinality differs".into(),
        ));
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for ordinal in 0..held.len() {
        remaining(deadline)?;
        if ordinal > 0 {
            current = rustix::fs::openat(
                &current,
                names[ordinal - 1],
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)?
            .into();
        }
        let expected = held[ordinal].metadata()?;
        let actual = current.metadata()?;
        if !actual.is_dir()
            || actual.uid() != 0
            || actual.mode() & 0o022 != 0
            || (
                expected.dev(),
                expected.ino(),
                expected.uid(),
                expected.mode(),
            ) != (actual.dev(), actual.ino(), actual.uid(), actual.mode())
        {
            return Err(CiError::Message(
                "external cgroup nofollow named ancestry changed".into(),
            ));
        }
    }
    Ok(())
}

fn read_export_capture(file: &File, length: u64, deadline: Instant) -> Result<Vec<u8>> {
    if length > 64 * 1024 * 1024 {
        return Err(CiError::Message(
            "external capture read exceeds bounded original length".into(),
        ));
    }
    let mut bytes = vec![0u8; length as usize];
    let mut offset = 0usize;
    while offset < bytes.len() {
        remaining(deadline)?;
        let end = bytes.len().min(offset + 64 * 1024);
        match file.read_at(&mut bytes[offset..end], offset as u64) {
            Ok(0) => {
                return Err(CiError::Message(
                    "external capture native read reached premature EOF".into(),
                ));
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    loop {
        remaining(deadline)?;
        let mut extra = [0u8; 1];
        match file.read_at(&mut extra, length) {
            Ok(0) => return Ok(bytes),
            Ok(_) => {
                return Err(CiError::Message(
                    "external capture grew beyond held native length".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn hold_evidence_ancestry(path: &Path, deadline: Instant) -> Result<Vec<File>> {
    use std::path::Component;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(CiError::Message(
            "external capture directory is not an absolute normalized path".into(),
        ));
    }
    let mut held = Vec::new();
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut named = PathBuf::from("/");
    let root = current.metadata()?;
    if !root.is_dir() || root.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "external capture root is not protected".into(),
        ));
    }
    held.push(current.try_clone()?);
    for part in path.components().filter_map(|part| {
        if let Component::Normal(name) = part {
            Some(name)
        } else {
            None
        }
    }) {
        remaining(deadline)?;
        current = rustix::fs::openat(
            &current,
            part,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?
        .into();
        named.push(part);
        let stamp = current.metadata()?;
        let expected_sticky_root = named == Path::new("/tmp")
            && stamp.uid() == 0
            && stamp.mode() & libc::S_ISVTX != 0
            && named != path;
        if !stamp.is_dir() || (stamp.mode() & 0o022 != 0 && !expected_sticky_root) {
            return Err(CiError::Message(
                "external capture ancestry is writable outside its original trusted owner".into(),
            ));
        }
        held.push(current.try_clone()?);
    }
    Ok(held)
}

fn verify_evidence_ancestry(path: &Path, held: &[File], deadline: Instant) -> Result<()> {
    remaining(deadline)?;
    let fresh = hold_evidence_ancestry(path, deadline)?;
    if fresh.len() != held.len() {
        return Err(CiError::Message(
            "external capture original ancestry cardinality changed".into(),
        ));
    }
    for (original, named) in held.iter().zip(&fresh) {
        remaining(deadline)?;
        let original = original.metadata()?;
        let named = named.metadata()?;
        if (
            original.dev(),
            original.ino(),
            original.uid(),
            original.gid(),
            original.mode(),
        ) != (
            named.dev(),
            named.ino(),
            named.uid(),
            named.gid(),
            named.mode(),
        ) {
            return Err(CiError::Message(
                "external capture nofollow ancestry differs from original native owner".into(),
            ));
        }
    }
    Ok(())
}

fn wait_export_ready(
    path: &Path,
    challenge: &str,
    scenario: &str,
    deadline: Instant,
    target: &crate::linux_consumer_readiness::HeldLinuxProcess,
) -> Result<crate::linux_consumer_readiness::LinuxTranscriptRow> {
    let row = wait_export_stage(path, challenge, "export-object-ready", deadline, target)?;
    let expected = if scenario == "traversal" {
        "/work/parent/exported.bin"
    } else {
        "/work/exported.bin"
    };
    let kind = match scenario {
        "symlink" => "symlink",
        "fifo" => "fifo",
        "socket" => "socket",
        "device" => "admin-device-required",
        "traversal" => "parent-symlink",
        "concurrent-writer" => "regular-with-held-writer",
        _ => return Err(CiError::Message("unfrozen export scenario".into())),
    };
    if row.observation["scenario"] != scenario
        || row.observation["path"] != expected
        || row.observation["kind"] != kind
        || (scenario == "traversal" && row.observation["source_path"] != "/work/other/exported.bin")
        || (scenario != "traversal" && !row.observation["source_path"].is_null())
    {
        return Err(CiError::Message(
            "actual export fixture readiness differs from declared scenario/path".into(),
        ));
    }
    Ok(row)
}

fn wait_export_stage(
    path: &Path,
    challenge: &str,
    stage: &str,
    deadline: Instant,
    target: &crate::linux_consumer_readiness::HeldLinuxProcess,
) -> Result<crate::linux_consumer_readiness::LinuxTranscriptRow> {
    loop {
        remaining(deadline)?;
        if target.exited().map_err(CiError::Message)? {
            return Err(CiError::Message(
                "held export target retired before readiness".into(),
            ));
        }
        if path.try_exists()? {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let before = file.metadata()?;
            if !before.is_file() || before.nlink() != 1 || before.len() > 1024 * 1024 {
                return Err(CiError::Message(
                    "live export transcript exceeds native bound".into(),
                ));
            }
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut file)
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            let named = std::fs::symlink_metadata(path)?;
            if bytes.len() > 1024 * 1024
                || !named.is_file()
                || (before.dev(), before.ino()) != (named.dev(), named.ino())
            {
                return Err(CiError::Message(
                    "live export transcript named custody differs".into(),
                ));
            }
            // Only an unfinished final line from the proven live capture
            // writer is ignored; complete records remain strictly decoded.
            for line in bytes
                .split_inclusive(|byte| *byte == b'\n')
                .filter(|line| line.last() == Some(&b'\n'))
            {
                memcordon_core::canonical_json::reject_duplicate_json_keys(line)
                    .map_err(CiError::Message)?;
                let row: crate::linux_consumer_readiness::LinuxTranscriptRow =
                    serde_json::from_slice(line)?;
                let native = target.live_snapshot().map_err(CiError::Message)?;
                if row.format != "memcordon.linux-readiness-transcript"
                    || row.revision != 1
                    || row.challenge != challenge
                    || row.root_birth != target.birth
                    || native.namespace_pids.last() != Some(&row.root_pid)
                {
                    return Err(CiError::Message(
                        "export transcript challenge/schema differs".into(),
                    ));
                }
                if row.operation == stage {
                    return Ok(row);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn create_owned_export_device(
    observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
    owners: &mut Vec<File>,
) -> Result<serde_json::Value> {
    use rustix::fs::{FileType, Mode, OFlags, makedev, mknodat, openat};
    if observer.target.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "native export device target is not held live".into(),
        ));
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(
            Path::new("/proc")
                .join(observer.target.process_id.to_string())
                .join("root"),
        )?;
    let metadata = root.metadata()?;
    if (metadata.dev(), metadata.ino())
        != (
            observer.observation.root_device,
            observer.observation.root_inode,
        )
    {
        return Err(CiError::Message(
            "native export device root differs from authenticated prepared root".into(),
        ));
    }
    let root_index = owners.len();
    owners.push(root);
    let work: File = openat(
        &owners[root_index],
        "work",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let work_meta = work.metadata()?;
    let work_index = owners.len();
    owners.push(work);
    mknodat(
        &owners[work_index],
        "exported.bin",
        FileType::CharacterDevice,
        Mode::RUSR | Mode::WUSR,
        makedev(1, 3),
    )
    .map_err(std::io::Error::from)?;
    let device: File = openat(
        &owners[work_index],
        "exported.bin",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let actual = device.metadata()?;
    owners.push(device);
    if actual.mode() & libc::S_IFMT != libc::S_IFCHR
        || actual.rdev() != makedev(1, 3)
        || actual.nlink() != 1
        || observer.target.exited().map_err(CiError::Message)?
    {
        return Err(CiError::Message(
            "native private export device type/identity/liveness differs".into(),
        ));
    }
    let named = std::fs::metadata(
        Path::new("/proc")
            .join(observer.target.process_id.to_string())
            .join("root"),
    )?;
    if (named.dev(), named.ino()) != (metadata.dev(), metadata.ino()) {
        return Err(CiError::Message(
            "native prepared root changed during private device setup".into(),
        ));
    }
    Ok(
        serde_json::json!({"format":"memcordon.linux-native-export-device","revision":1,"target_pid":observer.target.process_id,"target_birth":observer.target.birth,"root_device":metadata.dev(),"root_inode":metadata.ino(),"work_device":work_meta.dev(),"work_inode":work_meta.ino(),"path":"/work/exported.bin","device":actual.dev(),"inode":actual.ino(),"rdev":actual.rdev(),"mode":actual.mode(),"links":actual.nlink(),"held_live_before_and_after":true}),
    )
}

fn select_startup_members(images: &MixedImages) -> Result<(String, String, String)> {
    let first = images
        .runtime
        .entrypoints
        .as_slice()
        .first()
        .ok_or_else(|| CiError::Message("runtime has no native first image".into()))?
        .path
        .as_str()
        .to_owned();
    let path = images.runtime_source.join(&first);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let dependencies = memcordon_core::elf_closure::inspect(
        |offset, bytes| file.read_exact_at(bytes, offset).map_err(|e| e.to_string()),
        file.metadata()?.len(),
        &images.runtime.target,
    )
    .map_err(CiError::Message)?
    .ok_or_else(|| CiError::Message("first image is not native ELF".into()))?;
    let interpreter = dependencies.interpreter.ok_or_else(|| {
        CiError::Message("native dynamically linked interpreter unavailable".into())
    })?;
    let interpreter = interpreter
        .strip_prefix('/')
        .ok_or_else(|| CiError::Message("interpreter is not absolute-in-root".into()))?;
    let interpreter = resolve_member(&images.runtime, interpreter)?;
    let needed = dependencies
        .needed
        .first()
        .ok_or_else(|| CiError::Message("native shared-library dependency unavailable".into()))?;
    let library = images
        .runtime
        .library_directories
        .as_slice()
        .iter()
        .find_map(|directory| {
            let member = Path::new(directory.as_str()).join(needed);
            resolve_member(&images.runtime, member.to_str()?).ok()
        })
        .ok_or_else(|| CiError::Message("declared native shared library unavailable".into()))?;
    Ok((first, interpreter, library))
}

fn resolve_member(definition: &RuntimeImageDefinitionV1, path: &str) -> Result<String> {
    let mut member = path.to_owned();
    for _ in 0..64 {
        match definition
            .entries
            .as_slice()
            .iter()
            .find(|entry| entry.path().as_str() == member)
        {
            Some(ImageEntryV1::Regular { .. }) => return Ok(member),
            Some(ImageEntryV1::Symlink { target, .. }) => member = target.as_str().to_owned(),
            None => {
                return Err(CiError::Message(
                    "startup dependency absent from declared runtime".into(),
                ));
            }
        }
    }
    Err(CiError::Message("startup alias depth exceeds bound".into()))
}

fn copy_inventory(
    source: &Path,
    destination: &Path,
    definition: &RuntimeImageDefinitionV1,
    report: &mut ImageCaseReport,
    deadline: Instant,
) -> Result<()> {
    report.directory_custody.extend(hold_ancestry(source)?);
    for entry in definition.entries.as_slice() {
        remaining(deadline)?;
        let ImageEntryV1::Regular {
            path,
            sha256,
            size,
            executable,
        } = entry
        else {
            continue;
        };
        let input_path = source.join(path.as_str());
        let output_path = destination.join(path.as_str());
        let parent = output_path
            .parent()
            .ok_or_else(|| CiError::Message("image member parent absent".into()))?;
        std::fs::create_dir_all(parent)?;
        report
            .directory_custody
            .extend(hold_ancestry(input_path.parent().expect("member parent"))?);
        report.directory_custody.extend(hold_ancestry(parent)?);
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&input_path)?;
        let before = input.metadata()?;
        if !before.is_file() || before.nlink() != 1 || before.len() != *size {
            return Err(CiError::Message(
                "selected image source native type/size differs".into(),
            ));
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&output_path)?;
        let mut hash = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            remaining(deadline)?;
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied
                .checked_add(count as u64)
                .ok_or_else(|| CiError::Message("image copy byte overflow".into()))?;
            if copied > *size {
                return Err(CiError::Message("image source grew".into()));
            }
            hash.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
        }
        if copied != *size || hex(&hash.finalize()) != String::from(sha256.clone()) {
            return Err(CiError::Message(
                "selected image bytes differ from approved manifest".into(),
            ));
        }
        output.sync_all()?;
        std::fs::set_permissions(
            &output_path,
            std::fs::Permissions::from_mode(if *executable { 0o555 } else { 0o444 }),
        )?;
        let named = std::fs::symlink_metadata(&input_path)?;
        let after = input.metadata()?;
        if (
            named.dev(),
            named.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
        ) != (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
        ) {
            return Err(CiError::Message(
                "selected image source changed during owned copy".into(),
            ));
        }
        let written = output.metadata()?;
        let mut copied_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&output_path)?;
        let copied_metadata = copied_file.metadata()?;
        let mut copied_hash = Sha256::new();
        loop {
            remaining(deadline)?;
            let count = copied_file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied_hash.update(&buffer[..count]);
        }
        if copied_metadata.nlink() != 1
            || copied_metadata.len() != *size
            || (written.dev(), written.ino()) != (copied_metadata.dev(), copied_metadata.ino())
            || hex(&copied_hash.finalize()) != String::from(sha256.clone())
        {
            return Err(CiError::Message(
                "copied image named identity/readback differs from approved bytes".into(),
            ));
        }
        report.file_custody.push(input);
        report.file_custody.push(copied_file);
    }
    Ok(())
}

fn hold_ancestry(path: &Path) -> Result<Vec<File>> {
    if !path.is_absolute() {
        return Err(CiError::Message(
            "image custody root must be absolute".into(),
        ));
    }
    let mut result = Vec::new();
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(ancestor)?;
        let held = file.metadata()?;
        let named = std::fs::symlink_metadata(ancestor)?;
        if !held.is_dir()
            || !named.is_dir()
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
            || held.uid() != 0
            || (held.mode() & 0o022 != 0 && held.mode() & libc::S_ISVTX == 0)
        {
            return Err(CiError::Message(
                "image source/staging ancestry is not protected native root custody".into(),
            ));
        }
        result.push(file);
    }
    Ok(result)
}

fn retain(path: &Path, bytes: &[u8], owners: &mut Vec<File>) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let held = file.metadata()?;
    let mut named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let actual = named.metadata()?;
    let mut readback = Vec::new();
    std::io::Read::by_ref(&mut named)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut readback)?;
    if held.nlink() != 1
        || actual.nlink() != 1
        || (held.dev(), held.ino()) != (actual.dev(), actual.ino())
        || readback != bytes
    {
        return Err(CiError::Message(
            "image artifact named custody differs".into(),
        ));
    }
    File::open(path.parent().expect("artifact parent"))?.sync_all()?;
    owners.push(named);
    Ok(())
}
fn remaining(deadline: Instant) -> Result<Duration> {
    let value = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(60));
    if value.is_zero() {
        Err(CiError::Message(
            "original image-case cutoff exhausted; owners retained".into(),
        ))
    } else {
        Ok(value)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
