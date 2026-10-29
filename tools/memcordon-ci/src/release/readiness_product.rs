//! Descriptive selected-product bytes joined to the actual outer lease records.
use super::{
    artifacts,
    installed_consumer::{MaterializedPayload, binary_path},
    source,
};
use crate::{CiError, Result, command::CommandSpec, readiness_identity::SourceIdentity};
use memcordon_readiness_verifier::{
    Artifact, Component, HostObservation, InstalledLifecycleJournal, ProductKey, RegistryGraph,
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

#[expect(
    clippy::too_many_arguments,
    reason = "Actual selected bytes and native lease evidence have independent custody roots"
)]
pub fn collect_current(
    identity: &SourceIdentity,
    key: &ProductKey,
    payload: &MaterializedPayload,
    root: &Path,
    cell_root: &Path,
    artifact_root: &Path,
    target: &Path,
    packages: &Path,
    deadline: Instant,
) -> Result<(
    memcordon_readiness_verifier::current::ProductObservationV2,
    Vec<Artifact>,
)> {
    use memcordon_readiness_verifier::current::{
        InstalledLifecycleReceiptV2, LifecycleObservationV2, ProductObservationV2, WireVersion,
    };
    let journal_path = cell_root.join("lifetime/installed-journal.json");
    let receipt_path = cell_root.join("lifetime/installed-retirement.json");
    let journal: InstalledLifecycleJournal = source::read_json(&journal_path)?;
    let receipt: InstalledLifecycleReceiptV2 = source::read_json(&receipt_path)?;
    memcordon_readiness_verifier::current::validate_native_inventory(&key.target, &receipt.native)
        .map_err(CiError::Message)?;
    if receipt.format != "memcordon.installed-lifecycle.receipt"
        || receipt.revision != 2
        || journal.run_id != identity.run_id
        || journal.key != *key
        || receipt.run_id != identity.run_id
        || receipt.key != *key
        || receipt.lease_id != journal.lease_id
        || receipt.journal_sha256 != artifacts::checksum(&artifacts::read_file(&journal_path)?)
    {
        return Err(CiError::Message(
            "current native lifecycle receipt binding differs".into(),
        ));
    }
    let destination = cell_root.join("selected-product");
    fs::create_dir(&destination)?;
    let readback = journal
        .events
        .iter()
        .rfind(|event| {
            event.operation == "actual-installed-package-readback"
                && event.phase == "upgrade"
                && event.succeeded
        })
        .ok_or_else(|| CiError::Message("current installed upgrade byte readback absent".into()))?;
    let raw: serde_json::Value = source::read_json(&artifact_root.join(&readback.native_receipt))?;
    let mut components = Vec::new();
    for binary in &payload.distribution.binaries {
        let role = match binary.as_str() {
            "memcordon" => "public-cli",
            "memcordon-sealed-agent" => "sealed-agent",
            "memcordon-target-desktop-bootstrap" => "desktop-bootstrap",
            "memcordon-session-broker" => "session-broker",
            _ => return Err(CiError::Message("unknown current product component".into())),
        };
        let copy = destination.join(super::target::binary_name(binary, &key.target));
        retain(&binary_path(&payload.directory, binary, &key.target), &copy)?;
        let hash = artifacts::checksum(&artifacts::read_file(&copy)?);
        if !raw["binaries"].as_array().is_some_and(|records| {
            records.iter().any(|record| {
                record["binary"].as_str() == Some(binary)
                    && record["sha256"].as_str() == Some(hash.as_str())
            })
        }) {
            return Err(CiError::Message(
                "current installed component byte association differs".into(),
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
    let manifest = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(
        &artifacts::read_file(&runtime)?,
    )
    .map_err(CiError::Message)?;
    let package = if key.channel.ends_with("native") {
        let (bundle, _) = super::target::TargetBundle::load(target)?;
        target.join(bundle.archive.name)
    } else {
        let (bundle, _) = super::packages::PackageBundle::load(packages)?;
        packages.join(
            &bundle
                .files
                .iter()
                .find(|file| file.package.as_deref() == Some("memcordon"))
                .ok_or_else(|| CiError::Message("current selected CLI crate absent".into()))?
                .name,
        )
    };
    let materialization = destination.join(
        package
            .file_name()
            .ok_or_else(|| CiError::Message("selected package filename absent".into()))?,
    );
    retain(&package, &materialization)?;
    let graph = if key.channel.ends_with("cargo") {
        let path = cell_root.join(if key.channel.starts_with("public-") {
            "public-cargo/registry-graph.json"
        } else {
            "candidate-cargo-lineage/registry-graph.json"
        });
        let mut graph: RegistryGraph = source::read_json(&path)?;
        let path = if key.channel.starts_with("public-") {
            let parent = path
                .parent()
                .ok_or_else(|| CiError::Message("current registry graph parent absent".into()))?;
            graph.raw_metadata = relative(artifact_root, &parent.join(&graph.raw_metadata))?;
            graph.raw_lock = relative(artifact_root, &parent.join(&graph.raw_lock))?;
            for package in &mut graph.packages {
                package.crate_artifact =
                    relative(artifact_root, &parent.join(&package.crate_artifact))?;
            }
            let projected = destination.join("registry-graph.json");
            source::write_json(&projected, &graph)?;
            projected
        } else {
            path
        };
        Some((
            relative(artifact_root, &path)?,
            artifacts::checksum(&artifacts::read_file(&path)?),
        ))
    } else {
        None
    };
    let lifecycle = LifecycleObservationV2 {
        lease_id: journal.lease_id.clone(),
        journal: relative(artifact_root, &journal_path)?,
        receipt: relative(artifact_root, &receipt_path)?,
        journal_before_mutation: journal
            .events
            .first()
            .is_some_and(|e| e.phase == "owned-before-mutation" && e.succeeded),
        installed_verified: journal
            .events
            .iter()
            .any(|e| e.phase == "verify" && e.succeeded),
        all_cases_inside_lease: journal
            .events
            .iter()
            .any(|e| e.phase == "cases" && e.succeeded),
        explicit_finalization: receipt.explicit_finalization_count == 1,
        finalization_records: receipt.explicit_finalization_count,
        package_absent: receipt.package_absent,
        native: receipt.native,
        cleanup_failures: receipt.cleanup_failures,
        outstanding: receipt.outstanding,
    };
    let product = ProductObservationV2 {
        key: key.clone(),
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        version: identity.version.clone(),
        host: native_host(root, &key.target, deadline)?,
        features: payload.distribution.features.clone(),
        components,
        materialization: relative(artifact_root, &materialization)?,
        runtime_manifest: relative(artifact_root, &runtime)?,
        package_sha256: artifacts::checksum(&artifacts::read_file(&materialization)?),
        registry_graph: graph.as_ref().map(|g| g.0.clone()),
        registry_graph_sha256: graph.map(|g| g.1),
        request: WireVersion {
            format: "memcordon.workload-request".into(),
            revision: 1,
        },
        result: WireVersion {
            format: "memcordon.result".into(),
            revision: 3,
        },
        native_protocols: match &manifest.sealed {
            memcordon_core::runtime_manifest_v2::SealedRuntimeV2::Included {
                native_protocols,
                ..
            } => serde_json::from_value(serde_json::to_value(native_protocols)?)?,
            _ => {
                return Err(CiError::Message(
                    "current readiness native protocol table absent".into(),
                ));
            }
        },
        runtime_profile: match manifest.sealed {
            memcordon_core::runtime_manifest_v2::SealedRuntimeV2::Included { profile, .. } => {
                profile
            }
            _ => {
                return Err(CiError::Message(
                    "current readiness requires an included request runtime".into(),
                ));
            }
        },
        lifecycle,
    };
    let mut retained = Vec::new();
    let mut pending = vec![cell_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path == cell_root.join("cell-owner.json") {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let bytes = artifacts::read_file(&path)?;
                retained.push(Artifact {
                    path: relative(artifact_root, &path)?,
                    length: bytes.len() as u64,
                    sha256: artifacts::checksum(&bytes),
                });
            } else {
                return Err(CiError::Message(
                    "current cell artifact is not a regular file or directory".into(),
                ));
            }
            if retained.len() + pending.len() > 65536 {
                return Err(CiError::Message(
                    "current cell artifact inventory exceeds bound".into(),
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
