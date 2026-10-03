//! Native production builds and finite distributable archives.
use super::{
    artifacts::{self, FileRecord},
    distribution::{Distribution, TargetDistribution},
    source::{self, BuildSourceIdentity, SelectedSource},
};
use crate::{CiError, Result, command::rustup_cargo};
use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifest,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Read, Write},
    path::Path,
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBundle {
    pub format: String,
    pub revision: u32,
    pub source: BuildSourceIdentity,
    pub distribution: TargetDistribution,
    pub archive: FileRecord,
    pub members: Vec<FileRecord>,
    pub fixture: FileRecord,
}

pub fn binary_name(binary: &str, target: &str) -> String {
    if target.contains("windows") {
        format!("{binary}.exe")
    } else {
        binary.into()
    }
}

/// Fresh directory for the native unit producer's held-directory contract.
/// Set private permissions at creation rather than relying on runner umask or
/// modifying a preexisting directory containing another operation's evidence.
pub fn unit_export_directory(parent: &Path) -> Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("unit-export-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    Ok(builder.tempdir_in(parent)?)
}

pub fn validate_executable(bytes: &[u8], target: &str) -> Result<()> {
    let arm = target.starts_with("aarch64-");
    let valid = if target.contains("linux") {
        bytes.starts_with(b"\x7fELF")
            && bytes.get(4) == Some(&2)
            && bytes.get(5) == Some(&1)
            && bytes.get(18..20) == Some(if arm { &[183, 0][..] } else { &[62, 0][..] })
    } else if target.contains("apple") {
        bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
            && bytes.get(4..8)
                == Some(if arm {
                    &[12, 0, 0, 1][..]
                } else {
                    &[7, 0, 0, 1][..]
                })
    } else if target.contains("windows") {
        bytes.starts_with(b"MZ")
            && bytes
                .get(60..64)
                .and_then(|offset| <[u8; 4]>::try_from(offset).ok())
                .map(u32::from_le_bytes)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| bytes.get(offset..offset.checked_add(6)?))
                .is_some_and(|header| {
                    header.starts_with(b"PE\0\0")
                        && header.get(4..6)
                            == Some(if arm {
                                &[0x64, 0xaa][..]
                            } else {
                                &[0x64, 0x86][..]
                            })
                })
    } else {
        false
    };
    if !valid {
        return Err(CiError::Message(
            "executable format/architecture differs from native target".into(),
        ));
    }
    Ok(())
}

pub fn encode_archive(
    target: &str,
    members: &BTreeMap<String, Vec<u8>>,
    executable_names: &BTreeSet<String>,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    if target.contains("windows") {
        let mut archive = zip::ZipWriter::new(Cursor::new(&mut output));
        for (name, bytes) in members {
            artifacts::safe_basename(name)?;
            archive.start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(if executable_names.contains(name) {
                        0o755
                    } else {
                        0o644
                    }),
            )?;
            archive.write_all(bytes)?;
        }
        archive.finish()?;
    } else {
        let encoder = flate2::write::GzEncoder::new(&mut output, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (name, bytes) in members {
            artifacts::safe_basename(name)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(if executable_names.contains(name) {
                0o755
            } else {
                0o644
            });
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            archive.append_data(&mut header, name, Cursor::new(bytes))?;
        }
        archive.into_inner()?.finish()?;
    }
    if output.len() as u64 > artifacts::MAX_FILE_BYTES {
        return Err(CiError::Message("target archive exceeds byte bound".into()));
    }
    Ok(output)
}

pub fn decode_archive(bytes: &[u8], target: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    if bytes.len() as u64 > artifacts::MAX_FILE_BYTES {
        return Err(CiError::Message("target compressed bound exceeded".into()));
    }
    let mut members = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut expanded = 0_u64;
    let mut insert = |name: String, size: u64, reader: &mut dyn Read| -> Result<()> {
        artifacts::safe_basename(&name)?;
        expanded = expanded
            .checked_add(size)
            .ok_or_else(|| CiError::Message("target expanded overflow".into()))?;
        if expanded > artifacts::MAX_FILE_BYTES
            || members.len() >= 128
            || !folded.insert(name.to_ascii_lowercase())
        {
            return Err(CiError::Message(
                "target member/duplicate/expanded bound exceeded".into(),
            ));
        }
        let mut data = Vec::new();
        reader.take(size + 1).read_to_end(&mut data)?;
        if data.len() as u64 != size {
            return Err(CiError::Message("truncated target archive".into()));
        }
        members.insert(name, data);
        Ok(())
    };
    if target.contains("windows") {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index)?;
            if file.is_dir() || file.is_symlink() {
                return Err(CiError::Message("forbidden target ZIP member".into()));
            }
            let name = file.name().to_owned();
            let size = file.size();
            insert(name, size, &mut file)?;
        }
    } else {
        let mut archive = tar::Archive::new(flate2::bufread::GzDecoder::new(Cursor::new(bytes)));
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                return Err(CiError::Message("forbidden target tar member".into()));
            }
            let name = entry
                .path()?
                .to_str()
                .ok_or_else(|| CiError::Message("non-UTF8 target member".into()))?
                .to_owned();
            let size = entry.size();
            insert(name, size, &mut entry)?;
        }
        let mut decoder = archive.into_inner();
        let mut padding = Vec::new();
        decoder
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut padding)?;
        if padding.len() > 1024 * 1024
            || padding.iter().any(|byte| *byte != 0)
            || decoder.into_inner().position() != bytes.len() as u64
        {
            return Err(CiError::Message(
                "target archive has trailing stream".into(),
            ));
        }
    }
    Ok(members)
}

impl TargetBundle {
    pub fn load(directory: &Path) -> Result<(Self, Vec<u8>)> {
        let bundle: Self = source::read_json(&directory.join("target.json"))?;
        bundle.source.validate()?;
        bundle.distribution.validate()?;
        if bundle.fixture.kind != "fixture"
            || bundle.fixture.target.as_deref() != Some(bundle.distribution.target.as_str())
            || bundle.fixture.package.is_some()
        {
            return Err(CiError::Message(
                "native fixture association differs".into(),
            ));
        }
        let fixture = artifacts::read_file(&directory.join(&bundle.fixture.name))?;
        artifacts::check_bytes(&bundle.fixture, &fixture)?;
        validate_executable(&fixture, &bundle.distribution.target)?;
        if bundle.format != "memcordon.target"
            || bundle.revision != 1
            || bundle.archive.kind != "archive"
            || bundle.archive.target.as_deref() != Some(bundle.distribution.target.as_str())
            || bundle.archive.package.is_some()
        {
            return Err(CiError::Message(
                "target envelope association differs".into(),
            ));
        }
        let bytes = artifacts::read_file(&directory.join(&bundle.archive.name))?;
        artifacts::check_bytes(&bundle.archive, &bytes)?;
        let members = decode_archive(&bytes, &bundle.distribution.target)?;
        let expected: BTreeSet<_> = bundle
            .distribution
            .binaries
            .iter()
            .map(|name| binary_name(name, &bundle.distribution.target))
            .chain(bundle.distribution.units.iter().cloned())
            .chain(["runtime-manifest.json".into(), "package.json".into()])
            .collect();
        if members.keys().cloned().collect::<BTreeSet<_>>() != expected
            || bundle.members.len() != members.len()
        {
            return Err(CiError::Message(
                "target runtime inventory incomplete/unexpected".into(),
            ));
        }
        let mut recorded = BTreeSet::new();
        for file in &bundle.members {
            if !recorded.insert(&file.name)
                || file.target.as_deref() != Some(bundle.distribution.target.as_str())
            {
                return Err(CiError::Message("duplicate or wrong-target member".into()));
            }
            let bytes = members
                .get(&file.name)
                .ok_or_else(|| CiError::Message("target member absent".into()))?;
            artifacts::check_bytes(file, bytes)?;
        }
        for name in &bundle.distribution.binaries {
            validate_executable(
                &members[&binary_name(name, &bundle.distribution.target)],
                &bundle.distribution.target,
            )?;
        }
        let manifest =
            RuntimeManifest::parse(&members["runtime-manifest.json"]).map_err(CiError::Message)?;
        super::compatibility::NativePackage::verify(
            &members["package.json"],
            &bundle.source,
            &bundle.distribution,
            &members,
        )?;
        if manifest.target != bundle.distribution.target
            || manifest.source_commit != bundle.source.commit()
            || manifest.version != bundle.source.version().to_string()
        {
            return Err(CiError::Message("runtime manifest source differs".into()));
        }
        for component in &manifest.components {
            let bytes = members
                .get(&component.path)
                .ok_or_else(|| CiError::Message("manifest component absent".into()))?;
            if component.size != bytes.len() as u64
                || component.sha256 != artifacts::checksum(bytes)
            {
                return Err(CiError::Message(
                    "runtime manifest byte identity differs".into(),
                ));
            }
        }
        Ok((bundle, bytes))
    }
}

pub fn build(root: &Path, source_path: &Path, destination: &Path) -> Result<()> {
    let selected: SelectedSource = source::read_json(source_path)?;
    let distribution = Distribution::read(root)?.native()?.clone();
    build_selected(root, &selected.into(), &distribution, destination)
}

/// Build an actual native payload from tagged or ordinary working-tree source.
/// Working source remains ineligible for release assembly and publication.
pub fn build_selected(
    root: &Path,
    selected: &BuildSourceIdentity,
    distribution: &TargetDistribution,
    destination: &Path,
) -> Result<()> {
    selected.recheck(root)?;
    distribution.validate()?;
    if distribution.target != super::distribution::native_target()? {
        return Err(CiError::Message(
            "selected payload target is not native".into(),
        ));
    }
    let toolchain = crate::config::toolchains(root)?.stable;
    let rustc = crate::command::CommandSpec::toolchain_program(
        "rustup",
        root,
        &toolchain,
        "rustc",
        Duration::from_secs(60),
    )
    .arg("-vV")
    .output_quiet()?;
    if !rustc.status.success()
        || !std::str::from_utf8(&rustc.stdout).ok().is_some_and(|text| {
            text.lines()
                .any(|line| line.strip_prefix("host: ") == Some(distribution.target.as_str()))
        })
    {
        return Err(CiError::Message(
            "selected compiler host differs from native release target".into(),
        ));
    }
    let product = root.join("target/ci-build/product");
    let mut command = rustup_cargo(
        root,
        &toolchain,
        [
            "build",
            "--release",
            "--locked",
            "-p",
            "memcordon",
            "--target-dir",
        ],
        Duration::from_secs(1800),
    )
    .arg(&product)
    .arg("--target")
    .arg(&distribution.target);
    for feature in &distribution.features {
        command = command.arg("--features").arg(feature);
    }
    for binary in &distribution.binaries {
        command = command.arg("--bin").arg(binary);
    }
    command.run()?;
    for phase in crate::native_test_plan::commands(true) {
        rustup_cargo(root, &toolchain, ["test"], phase.deadline)
            .args(phase.arguments)
            .run()?;
    }
    let backend = if distribution.target.contains("linux") {
        "backend-linux-cgroup"
    } else if distribution.target.contains("windows") {
        "backend-windows-job"
    } else {
        "backend-macos-watchdog"
    };
    crate::command::CommandSpec::new(std::env::current_exe()?, root, Duration::from_secs(3600))
        .args(["suite", backend])
        .run()?;
    selected.recheck(root)?;
    if destination.exists() {
        return Err(CiError::Message(
            "target output requires fresh destination".into(),
        ));
    }
    let mut members = BTreeMap::new();
    let mut executable_names = BTreeSet::new();
    let mut components = Vec::new();
    for binary in &distribution.binaries {
        let filename = binary_name(binary, &distribution.target);
        let bytes = artifacts::read_file(
            &product
                .join(&distribution.target)
                .join("release")
                .join(&filename),
        )?;
        validate_executable(&bytes, &distribution.target)?;
        let role = match binary.as_str() {
            "memcordon" => RuntimeComponentRole::PublicCli,
            "memcordon-sealed-agent" => RuntimeComponentRole::SealedAgent,
            "memcordon-target-desktop-bootstrap" => RuntimeComponentRole::DesktopBootstrap,
            "memcordon-session-broker" => RuntimeComponentRole::SessionBroker,
            _ => return Err(CiError::Message("unexpected production binary".into())),
        };
        components.push(RuntimeComponentRecord {
            id: if role == RuntimeComponentRole::SealedAgent {
                "sealed-agent".into()
            } else {
                binary.clone()
            },
            path: filename.clone(),
            role,
            size: bytes.len() as u64,
            mode: 0o755,
            sha256: artifacts::checksum(&bytes),
        });
        executable_names.insert(filename.clone());
        members.insert(filename, bytes);
    }
    let manifest = if distribution.features.is_empty() {
        RuntimeManifest::cli_only(
            selected.version().to_string(),
            selected.commit().to_owned(),
            distribution.target.clone(),
            components,
        )
    } else if distribution.target.contains("windows") {
        RuntimeManifest::windows(
            selected.version().to_string(),
            selected.commit().to_owned(),
            distribution.target.clone(),
            components,
        )
    } else {
        RuntimeManifest::linux_selected(
            selected.version().to_string(),
            selected.commit().to_owned(),
            distribution.target.clone(),
            components,
            distribution
                .features
                .iter()
                .any(|feature| feature == "private-tcp"),
        )
    }
    .map_err(CiError::Message)?;
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    members.insert("runtime-manifest.json".into(), manifest_bytes);
    if !distribution.units.is_empty() {
        let directory = unit_export_directory(Path::new("/tmp"))?;
        crate::command::CommandSpec::new(
            product
                .join(&distribution.target)
                .join("release")
                .join("memcordon-sealed-agent"),
            root,
            Duration::from_secs(30),
        )
        .args(["__export-unit-files"])
        .arg(directory.path())
        .run()?;
        for unit in &distribution.units {
            members.insert(
                unit.clone(),
                artifacts::read_file(&directory.path().join(unit))?,
            );
        }
    }
    let package = super::compatibility::NativePackage::measured(selected, distribution, &members)?;
    let mut package_bytes = serde_json::to_vec_pretty(&package)?;
    package_bytes.push(b'\n');
    members.insert("package.json".into(), package_bytes);
    let archive_bytes = encode_archive(&distribution.target, &members, &executable_names)?;
    let name = format!(
        "memcordon-{}-{}.{}",
        selected.version(),
        distribution.target,
        if distribution.target.contains("windows") {
            "zip"
        } else {
            "tar.gz"
        }
    );
    let records = members
        .iter()
        .map(|(name, bytes)| FileRecord {
            name: name.clone(),
            kind: if executable_names.contains(name) {
                "executable"
            } else {
                "runtime-data"
            }
            .into(),
            target: Some(distribution.target.clone()),
            package: None,
            byte_len: bytes.len() as u64,
            sha256: artifacts::checksum(bytes),
        })
        .collect();
    let archive = FileRecord {
        name,
        kind: "archive".into(),
        target: Some(distribution.target.clone()),
        package: None,
        byte_len: archive_bytes.len() as u64,
        sha256: artifacts::checksum(&archive_bytes),
    };
    fs::create_dir_all(destination)?;
    fs::write(destination.join(&archive.name), archive_bytes)?;
    let fixture_name = binary_name("memcordon-test-fixture", &distribution.target);
    let fixture_bytes =
        artifacts::read_file(&root.join("target/ci/native/release").join(&fixture_name))?;
    validate_executable(&fixture_bytes, &distribution.target)?;
    fs::write(destination.join(&fixture_name), &fixture_bytes)?;
    let fixture = FileRecord {
        name: fixture_name,
        kind: "fixture".into(),
        target: Some(distribution.target.clone()),
        package: None,
        byte_len: fixture_bytes.len() as u64,
        sha256: artifacts::checksum(&fixture_bytes),
    };
    source::write_json(
        &destination.join("target.json"),
        &TargetBundle {
            format: "memcordon.target".into(),
            revision: 1,
            source: selected.clone(),
            distribution: distribution.clone(),
            archive,
            members: records,
            fixture,
        },
    )?;
    TargetBundle::load(destination)?;
    Ok(())
}
