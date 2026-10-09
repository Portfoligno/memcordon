//! Descriptive selected-product bytes joined to the actual outer lease records.
use super::{
    artifacts,
    installed_consumer::{MaterializedPayload, binary_path},
    source,
};
use crate::{CiError, Result, command::CommandSpec, consumer_readiness_ledger::SourceIdentity};
use memcordon_readiness_verifier::{
    Artifact, Component, HostObservation, InstalledLifecycleJournal, InstalledLifecycleReceipt,
    LifecycleObservation, ProductKey, ProductObservation, RegistryGraph,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn relative(root: &Path, path: &Path) -> Result<String> {
    path.strip_prefix(root)
        .map_err(|_| CiError::Message("selected product artifact escapes cell custody".into()))?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| CiError::Message("selected artifact path encoding differs".into()))
}
fn retain(source: &Path, destination: &Path) -> Result<()> {
    use std::io::Write;
    let bytes = artifacts::read_file(source)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
pub fn collect(
    identity: &SourceIdentity,
    key: &ProductKey,
    payload: &MaterializedPayload,
    predecessor: &MaterializedPayload,
    root: &Path,
    cell_root: &Path,
    artifact_root: &Path,
    target: &Path,
    packages: &Path,
    deadline: Instant,
) -> Result<(ProductObservation, Vec<Artifact>)> {
    let journal_path = cell_root.join("lifetime/installed-journal.json");
    let receipt_path = cell_root.join("lifetime/installed-retirement.json");
    let journal: InstalledLifecycleJournal = source::read_json(&journal_path)?;
    let receipt: InstalledLifecycleReceipt = source::read_json(&receipt_path)?;
    if journal.run_id != identity.run_id
        || journal.key != *key
        || receipt.run_id != identity.run_id
        || receipt.key != *key
        || receipt.lease_id != journal.lease_id
        || receipt.journal_sha256 != artifacts::checksum(&artifacts::read_file(&journal_path)?)
    {
        return Err(CiError::Message(
            "actual outer installed receipt association differs".into(),
        ));
    }
    let destination = cell_root.join("selected-product");
    fs::create_dir(&destination)?;
    let mut components = Vec::new();
    for binary in &payload.distribution.binaries {
        let role = match binary.as_str() {
            "memcordon" => "public-cli",
            "memcordon-sealed-agent" => "sealed-agent",
            "memcordon-target-desktop-bootstrap" => "desktop-bootstrap",
            "memcordon-session-broker" => "session-broker",
            _ => {
                return Err(CiError::Message(
                    "unknown selected operational component".into(),
                ));
            }
        };
        let selected = binary_path(&payload.directory, binary, &key.target);
        let copy = destination.join(super::target::binary_name(binary, &key.target));
        retain(&selected, &copy)?;
        let hash = artifacts::checksum(&artifacts::read_file(&copy)?);
        // The outer verify/upgrade phase retained its actual installed-byte
        // readback. Preserve that raw receipt rather than taking another sample
        // after the one uninstall has already completed.
        let readback = journal
            .events
            .iter()
            .filter(|event| {
                event.operation == "actual-installed-package-readback"
                    && event.phase == "upgrade"
                    && event.succeeded
            })
            .last()
            .ok_or_else(|| CiError::Message("selected upgrade native readback absent".into()))?;
        let raw: serde_json::Value =
            source::read_json(&artifact_root.join(&readback.native_receipt))?;
        if !raw["binaries"].as_array().is_some_and(|records| {
            records.iter().any(|record| {
                record["binary"].as_str() == Some(binary)
                    && record["sha256"].as_str() == Some(hash.as_str())
            })
        }) {
            return Err(CiError::Message(
                "selected component differs from actual installed upgrade readback".into(),
            ));
        }
        components.push(Component {
            role: role.into(),
            artifact: relative(artifact_root, &copy)?,
            installed_sha256: hash,
        });
    }
    let runtime = destination.join("runtime-manifest.json");
    retain(&payload.directory.join("runtime-manifest.json"), &runtime)?;
    let (bundle, _) = super::target::TargetBundle::load(target)?;
    let package = if key.channel.ends_with("native") {
        target.join(&bundle.archive.name)
    } else {
        let (bundle, _) = super::packages::PackageBundle::load(packages)?;
        let selected = bundle
            .files
            .iter()
            .find(|file| file.package.as_deref() == Some("memcordon"))
            .ok_or_else(|| CiError::Message("selected final CLI crate absent".into()))?;
        packages.join(&selected.name)
    };
    let materialization = destination.join(
        package
            .file_name()
            .ok_or_else(|| CiError::Message("selected materialization filename absent".into()))?,
    );
    retain(&package, &materialization)?;
    let graph = if key.channel.ends_with("cargo") {
        let graph_path = cell_root.join(if key.channel.starts_with("public-") {
            "public-cargo/registry-graph.json"
        } else {
            "candidate-cargo-lineage/registry-graph.json"
        });
        let mut graph: RegistryGraph = source::read_json(&graph_path)?;
        if key.channel.starts_with("public-") {
            let parent = graph_path.parent().expect("graph parent");
            graph.raw_metadata = relative(artifact_root, &parent.join(&graph.raw_metadata))?;
            graph.raw_lock = relative(artifact_root, &parent.join(&graph.raw_lock))?;
            for package in &mut graph.packages {
                package.crate_artifact =
                    relative(artifact_root, &parent.join(&package.crate_artifact))?;
            }
            source::write_json(&graph_path, &graph)?;
        }
        Some((
            relative(artifact_root, &graph_path)?,
            artifacts::checksum(&artifacts::read_file(&graph_path)?),
        ))
    } else {
        None
    };
    let host = native_host(root, &key.target, deadline)?;
    let predecessor_name = format!("memcordon-{}.crate", predecessor.source.version());
    let predecessor_archive = predecessor
        .artifacts
        .iter()
        .find(|artifact| artifact.path.file_name() == Some(std::ffi::OsStr::new(&predecessor_name)))
        .ok_or_else(|| {
            CiError::Message("actual predecessor CLI archive measurement absent".into())
        })?;
    if artifacts::checksum(&artifacts::read_file(&predecessor_archive.path)?)
        != predecessor_archive.sha256
    {
        return Err(CiError::Message(
            "actual predecessor CLI archive changed".into(),
        ));
    }
    let lifecycle = LifecycleObservation {
        lease_id: journal.lease_id.clone(),
        journal: relative(artifact_root, &journal_path)?,
        receipt: relative(artifact_root, &receipt_path)?,
        journal_before_mutation: journal
            .events
            .first()
            .is_some_and(|event| event.phase == "owned-before-mutation" && event.succeeded),
        installed_verified: journal
            .events
            .iter()
            .any(|event| event.phase == "verify" && event.succeeded),
        all_cases_inside_lease: journal
            .events
            .iter()
            .any(|event| event.phase == "cases" && event.succeeded),
        explicit_finalization: receipt.explicit_finalization_count == 1,
        finalization_records: receipt.explicit_finalization_count,
        package_absent: receipt.package_absent,
        policy_retired: receipt.policy_retired,
        native_resources_retired: receipt.native_resources_retired,
        cleanup_failures: receipt.cleanup_failures,
        outstanding: receipt.outstanding,
        predecessor_version: predecessor.source.version().to_string(),
        predecessor_package_sha256: predecessor_archive.sha256.clone(),
    };
    let (request_revision, result_revision, runtime_profile) =
        if key.target.ends_with("-pc-windows-msvc") {
            (1, 1, "windows-host-network-external-v1")
        } else {
            (3, 2, "linux-tcp4-unix-private-v1")
        };
    let product = ProductObservation {
        key: key.clone(),
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        version: identity.version.clone(),
        host,
        features: payload.distribution.features.clone(),
        components,
        materialization: relative(artifact_root, &materialization)?,
        runtime_manifest: relative(artifact_root, &runtime)?,
        package_sha256: artifacts::checksum(&artifacts::read_file(&materialization)?),
        registry_graph: graph.as_ref().map(|graph| graph.0.clone()),
        registry_graph_sha256: graph.map(|graph| graph.1),
        request_revision,
        result_revision,
        runtime_profile: runtime_profile.into(),
        lifecycle,
    };
    let mut retained = Vec::new();
    let mut pending = vec![cell_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.path() == cell_root.join("cell-owner.json") {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(CiError::Message(
                    "cell artifact tree contains symlink".into(),
                ));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                let bytes = artifacts::read_file(&entry.path())?;
                retained.push(Artifact {
                    path: relative(artifact_root, &entry.path())?,
                    length: bytes.len() as u64,
                    sha256: artifacts::checksum(&bytes),
                });
            } else {
                return Err(CiError::Message(
                    "cell artifact tree contains special file".into(),
                ));
            }
            if retained.len() + pending.len() > 65536 {
                return Err(CiError::Message(
                    "cell artifact inventory exceeds finite bound".into(),
                ));
            }
        }
    }
    Ok((product, retained))
}

pub(crate) fn native_host(root: &Path, target: &str, deadline: Instant) -> Result<HostObservation> {
    if target != super::distribution::native_target()? {
        return Err(CiError::Message(
            "native observation target differs from running controller".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    let kernel = {
        let kernel = CommandSpec::new("uname", root, Duration::from_secs(10))
            .arg("-srv")
            .bounded_until(deadline)
            .output_quiet()?;
        let machine = CommandSpec::new("uname", root, Duration::from_secs(10))
            .arg("-m")
            .bounded_until(deadline)
            .output_quiet()?;
        let expected = if target.starts_with("aarch64-") {
            "aarch64"
        } else {
            "x86_64"
        };
        if !kernel.status.success()
            || !machine.status.success()
            || std::str::from_utf8(&machine.stdout).ok().map(str::trim) != Some(expected)
        {
            return Err(CiError::Message(
                "actual native kernel observation differs from selected target".into(),
            ));
        }
        String::from_utf8(kernel.stdout)
            .map_err(|_| CiError::Message("kernel observation encoding differs".into()))?
            .trim()
            .to_owned()
    };
    #[cfg(windows)]
    let kernel = windows_native_kernel(target)?;
    let toolchain = crate::config::toolchains(root)?.stable;
    let located = CommandSpec::new("rustup", root, Duration::from_secs(30))
        .args(["which", "--toolchain", &toolchain, "rustc"])
        .bounded_until(deadline)
        .output_quiet()?;
    if !located.status.success() {
        return Err(CiError::Message(
            "selected native compiler path unavailable".into(),
        ));
    }
    let compiler = PathBuf::from(
        String::from_utf8(located.stdout)
            .map_err(|_| CiError::Message("compiler path encoding differs".into()))?
            .trim(),
    );
    let compiler_bytes = artifacts::read_file(&compiler)?;
    super::target::validate_executable(&compiler_bytes, target)?;
    let version = CommandSpec::new(&compiler, root, Duration::from_secs(30))
        .args(["--version", "--verbose"])
        .bounded_until(deadline)
        .output_quiet()?;
    let identity = String::from_utf8(version.stdout)
        .map_err(|_| CiError::Message("compiler identity encoding differs".into()))?;
    if !version.status.success()
        || !identity
            .lines()
            .any(|line| line.strip_prefix("host: ") == Some(target))
    {
        return Err(CiError::Message(
            "actual selected compiler host differs from native target".into(),
        ));
    }
    Ok(HostObservation {
        kernel,
        native_target: target.into(),
        executable_target: target.into(),
        emulated: false,
        toolchain_identity: identity.trim().into(),
        toolchain_sha256: artifacts::checksum(&compiler_bytes),
        lockfile_sha256: artifacts::checksum(&artifacts::read_file(&root.join("Cargo.lock"))?),
    })
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_native_kernel(target: &str) -> Result<String> {
    use windows_sys::Win32::System::SystemInformation::{
        GetNativeSystemInfo, OSVERSIONINFOW, SYSTEM_INFO,
    };
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(version: *mut OSVERSIONINFOW) -> i32;
    }
    // SAFETY: both APIs receive initialized writable structures of their exact
    // native sizes; neither call mutates installation or process authority.
    let mut system: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetNativeSystemInfo(&mut system) };
    let architecture = unsafe { system.Anonymous.Anonymous.wProcessorArchitecture };
    let expected = if target.starts_with("aarch64-") {
        12
    } else {
        9
    };
    if architecture != expected {
        return Err(CiError::Message("actual Windows native architecture differs from selected product (emulation is not readiness)".into()));
    }
    let mut version: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    version.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    let status = unsafe { RtlGetVersion(&mut version) };
    if status != 0 {
        return Err(CiError::Message(format!(
            "actual Windows kernel version query failed: {status}"
        )));
    }
    Ok(format!(
        "Windows NT {}.{}.{} native-architecture={architecture}",
        version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber
    ))
}
