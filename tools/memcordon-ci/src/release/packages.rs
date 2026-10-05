//! Package once, then consume the exact extracted public sources.
use super::{
    artifacts::{self, FileRecord},
    source::{self, BuildSourceIdentity, PUBLIC_PACKAGES, SelectedSource},
};
use crate::{
    CiError, Result,
    command::{PackageOutput, rustup_cargo},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageBundle {
    pub format: String,
    pub revision: u32,
    pub source: BuildSourceIdentity,
    pub files: Vec<FileRecord>,
}

pub fn prepare(root: &Path, source_path: &Path, target: &Path, destination: &Path) -> Result<()> {
    let source: SelectedSource = source::read_json(source_path)?;
    prepare_build(
        root,
        &BuildSourceIdentity::from(source),
        target,
        destination,
    )
}

pub fn prepare_build(
    root: &Path,
    source: &BuildSourceIdentity,
    target: &Path,
    destination: &Path,
) -> Result<()> {
    source.recheck(root)?;
    let distribution = super::distribution::Distribution::read(root)?;
    let metadata = source::metadata(root)?;
    let order = source::public_order(&metadata, source.version())?;
    if order.len() != distribution.packages.len() {
        return Err(CiError::Message(
            "selected package inventory differs".into(),
        ));
    }
    if destination.exists() {
        return Err(CiError::Message("package destination must be fresh".into()));
    }
    let output = PackageOutput::new(root, Some(target))?;
    output
        .command(root, &crate::config::toolchains(root)?.stable, &order)
        .phase(crate::command::CiPhase::Package)
        .selection(source, None)
        .run()?;
    source.recheck(root)?;
    fs::create_dir_all(destination)?;
    let mut records = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for entry in fs::read_dir(output.archive_directory())? {
        let entry = entry?;
        if entry
            .path()
            .extension()
            .is_none_or(|extension| extension != "crate")
        {
            continue;
        }
        let bytes = artifacts::read_file(&entry.path())?;
        let members = artifacts::crate_members(&bytes)?;
        let (name, version) = artifacts::crate_identity(&members)?;
        if !PUBLIC_PACKAGES.contains(&name.as_str())
            || &version != source.version()
            || !names.insert(name.clone())
        {
            return Err(CiError::Message(
                "unexpected/duplicate/stale Cargo package output".into(),
            ));
        }
        let filename = entry
            .file_name()
            .into_string()
            .map_err(|_| CiError::Message("Cargo package filename is not UTF-8".into()))?;
        artifacts::safe_basename(&filename)?;
        let digest = artifacts::checksum(&bytes);
        super::registry::render_upload(&name, &version.to_string(), &bytes, &digest)?;
        fs::write(destination.join(&filename), &bytes)?;
        records.push(FileRecord {
            name: filename,
            kind: "crate".into(),
            target: None,
            package: Some(name),
            byte_len: bytes.len() as u64,
            sha256: digest,
        });
    }
    if names.len() != PUBLIC_PACKAGES.len() {
        return Err(CiError::Message(
            "required Cargo package output absent".into(),
        ));
    }
    records.sort_by_key(|record| {
        order
            .iter()
            .position(|name| Some(name) == record.package.as_ref())
            .expect("validated package order")
    });
    source::write_json(
        &destination.join("packages.json"),
        &PackageBundle {
            format: "memcordon.packages".into(),
            revision: 1,
            source: source.clone(),
            files: records,
        },
    )
}

impl PackageBundle {
    pub fn load(directory: &Path) -> Result<(Self, Vec<Vec<u8>>)> {
        let bundle: Self = source::read_json(&directory.join("packages.json"))?;
        bundle.source.validate()?;
        if bundle.format != "memcordon.packages"
            || bundle.revision != 1
            || bundle.files.len() != PUBLIC_PACKAGES.len()
        {
            return Err(CiError::Message(
                "unsupported/incomplete package bundle".into(),
            ));
        }
        let mut package_names = std::collections::BTreeSet::new();
        let mut filenames = std::collections::BTreeSet::new();
        let mut payloads = Vec::new();
        for record in &bundle.files {
            artifacts::safe_basename(&record.name)?;
            let bytes = artifacts::read_file(&directory.join(&record.name))?;
            artifacts::check_bytes(record, &bytes)?;
            let (name, version) = artifacts::crate_identity(&artifacts::crate_members(&bytes)?)?;
            if record.kind != "crate"
                || record.target.is_some()
                || record.package.as_deref() != Some(name.as_str())
                || &version != bundle.source.version()
                || !PUBLIC_PACKAGES.contains(&name.as_str())
                || !package_names.insert(name)
                || !filenames.insert(&record.name)
            {
                return Err(CiError::Message(
                    "package member/source/version association differs".into(),
                ));
            }
            super::registry::render_upload(
                record.package.as_deref().expect("checked package"),
                &version.to_string(),
                &bytes,
                &record.sha256,
            )?;
            payloads.push(bytes);
        }
        let observed = archive_order(&bundle, &payloads)?;
        if bundle
            .files
            .iter()
            .filter_map(|file| file.package.as_ref())
            .ne(observed.iter())
        {
            return Err(CiError::Message(
                "package bundle is not in actual archive dependency order".into(),
            ));
        }
        Ok((bundle, payloads))
    }
}

/// Derive upload order again from normalized payloads, independently of checkout metadata.
pub fn archive_order(bundle: &PackageBundle, payloads: &[Vec<u8>]) -> Result<Vec<String>> {
    use std::collections::BTreeSet;
    if bundle.files.len() != PUBLIC_PACKAGES.len() || payloads.len() != bundle.files.len() {
        return Err(CiError::Message(
            "incomplete normalized package inventory".into(),
        ));
    }
    let mut edges = BTreeMap::<String, BTreeSet<String>>::new();
    for (record, bytes) in bundle.files.iter().zip(payloads) {
        let members = artifacts::crate_members(bytes)?;
        let (name, version) = artifacts::crate_identity(&members)?;
        if record.package.as_deref() != Some(name.as_str()) || &version != bundle.source.version() {
            return Err(CiError::Message(
                "normalized package identity differs".into(),
            ));
        }
        let manifest: toml::Value = toml::from_str(
            std::str::from_utf8(&members["Cargo.toml"])
                .map_err(|_| CiError::Message("normalized manifest is not UTF-8".into()))?,
        )?;
        let mut dependencies = BTreeSet::new();
        let mut tables = vec![
            manifest
                .as_table()
                .ok_or_else(|| CiError::Message("manifest table absent".into()))?,
        ];
        if let Some(targets) = manifest.get("target") {
            for target in targets
                .as_table()
                .ok_or_else(|| CiError::Message("invalid target dependencies".into()))?
                .values()
            {
                tables.push(
                    target.as_table().ok_or_else(|| {
                        CiError::Message("invalid target dependency table".into())
                    })?,
                );
            }
        }
        for table in tables {
            for kind in ["dependencies", "build-dependencies", "dev-dependencies"] {
                let Some(values) = table.get(kind) else {
                    continue;
                };
                for (alias, value) in values
                    .as_table()
                    .ok_or_else(|| CiError::Message("invalid normalized dependencies".into()))?
                {
                    let (dependency, requirement) = if let Some(version) = value.as_str() {
                        (alias.as_str(), version)
                    } else {
                        let value = value.as_table().ok_or_else(|| {
                            CiError::Message("invalid dependency declaration".into())
                        })?;
                        if value.contains_key("path")
                            || value.contains_key("git")
                            || value.contains_key("registry")
                        {
                            return Err(CiError::Message(
                                "normalized payload has a source-only dependency".into(),
                            ));
                        }
                        (
                            value
                                .get("package")
                                .and_then(toml::Value::as_str)
                                .unwrap_or(alias),
                            value
                                .get("version")
                                .and_then(toml::Value::as_str)
                                .ok_or_else(|| {
                                    CiError::Message("normalized dependency version absent".into())
                                })?,
                        )
                    };
                    if dependency.starts_with("memcordon") {
                        if !PUBLIC_PACKAGES.contains(&dependency)
                            || !semver::VersionReq::parse(requirement)?
                                .matches(bundle.source.version())
                        {
                            return Err(CiError::Message(
                                "unpublished or mismatched packaged dependency".into(),
                            ));
                        }
                        if kind != "dev-dependencies" {
                            dependencies.insert(dependency.to_owned());
                        }
                    }
                }
            }
        }
        if edges.insert(name, dependencies).is_some() {
            return Err(CiError::Message("duplicate normalized package".into()));
        }
    }
    if edges.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != PUBLIC_PACKAGES.into_iter().collect()
    {
        return Err(CiError::Message("normalized package set differs".into()));
    }
    let mut ordered = Vec::new();
    while !edges.is_empty() {
        let next = edges
            .iter()
            .find(|(_, dependencies)| dependencies.iter().all(|name| ordered.contains(name)))
            .map(|(name, _)| name.clone())
            .ok_or_else(|| CiError::Message("normalized dependency cycle".into()))?;
        edges.remove(&next);
        ordered.push(next);
    }
    Ok(ordered)
}

pub struct PackageConsumer {
    _directory: tempfile::TempDir,
    pub manifest: PathBuf,
    pub config: PathBuf,
    pub cli_source: PathBuf,
    pub install_root: PathBuf,
    pub bundle: PackageBundle,
}

impl PackageConsumer {
    pub fn prepare(root: &Path, packages: &Path) -> Result<Self> {
        let (bundle, bytes) = PackageBundle::load(packages)?;
        let directory = tempfile::tempdir()?;
        let mut patches = toml::Table::new();
        let mut dependencies = toml::Table::new();
        let mut cli_source = None;
        for (record, bytes) in bundle.files.iter().zip(bytes) {
            let name = record.package.as_deref().expect("validated package");
            let extracted = directory.path().join(name);
            artifacts::extract_members(&artifacts::crate_members(&bytes)?, &extracted)?;
            if name == "memcordon" {
                cli_source = Some(extracted.clone());
            }
            let path = extracted.to_str().ok_or_else(|| {
                CiError::Message("Cargo patch TOML path is not representable as UTF-8".into())
            })?;
            patches.insert(
                name.into(),
                toml::Value::Table(toml::Table::from_iter([(
                    "path".into(),
                    toml::Value::String(path.into()),
                )])),
            );
            dependencies.insert(
                name.into(),
                toml::Value::Table(toml::Table::from_iter([(
                    "version".into(),
                    toml::Value::String(bundle.source.version().to_string()),
                )])),
            );
        }
        let config = directory.path().join("package-overrides.toml");
        fs::write(
            &config,
            toml::to_string(&toml::Table::from_iter([(
                "patch".into(),
                toml::Value::Table(toml::Table::from_iter([(
                    "crates-io".into(),
                    toml::Value::Table(patches),
                )])),
            )]))
            .map_err(|error| CiError::Message(error.to_string()))?,
        )?;
        let consumer = directory.path().join("consumer");
        fs::create_dir(&consumer)?;
        fs::create_dir(consumer.join("src"))?;
        let manifest = consumer.join("Cargo.toml");
        fs::write(
            &manifest,
            toml::to_string(&toml::Table::from_iter([
                (
                    "package".into(),
                    toml::Value::Table(toml::Table::from_iter([
                        (
                            "name".into(),
                            toml::Value::String("memcordon-external-consumer".into()),
                        ),
                        ("version".into(), toml::Value::String("0.0.0".into())),
                        ("edition".into(), toml::Value::String("2024".into())),
                    ])),
                ),
                ("dependencies".into(), toml::Value::Table(dependencies)),
                ("workspace".into(), toml::Value::Table(toml::Table::new())),
            ]))
            .map_err(|error| CiError::Message(error.to_string()))?,
        )?;
        fs::write(
            consumer.join("src").join("main.rs"),
            "fn main() { let bytes: memcordon_core::ByteSize = \"4MiB\".parse().expect(\"public byte-size parser\"); assert_eq!(bytes.bytes(), 4 * 1024 * 1024); }\n",
        )?;
        let install_root = directory.path().join("install");
        let value = Self {
            _directory: directory,
            manifest,
            config,
            cli_source: cli_source.expect("required CLI package"),
            install_root,
            bundle,
        };
        let toolchain = crate::config::toolchains(root)?.stable;
        prepare_consumer_lock(root, &toolchain, &value.manifest, &value.config)?;
        let output = rustup_cargo(
            root,
            &toolchain,
            [
                std::ffi::OsStr::new("metadata"),
                std::ffi::OsStr::new("--locked"),
                std::ffi::OsStr::new("--format-version"),
                std::ffi::OsStr::new("1"),
                std::ffi::OsStr::new("--manifest-path"),
                value.manifest.as_os_str(),
                std::ffi::OsStr::new("--config"),
                value.config.as_os_str(),
            ],
            Duration::from_secs(300),
        )
        .output_quiet()?;
        if !output.status.success() {
            return Err(CiError::Message("package consumer metadata failed".into()));
        }
        let metadata: cargo_metadata::Metadata = serde_json::from_slice(&output.stdout)?;
        for name in PUBLIC_PACKAGES {
            let packages: Vec<_> = metadata
                .packages
                .iter()
                .filter(|package| package.name.as_str() == name)
                .collect();
            if packages.len() != 1
                || packages[0].source.is_some()
                || &packages[0].version != value.bundle.source.version()
                || packages[0]
                    .manifest_path
                    .as_std_path()
                    .parent()
                    .map(fs::canonicalize)
                    .transpose()?
                    != Some(fs::canonicalize(value._directory.path().join(name))?)
            {
                return Err(CiError::Message("consumer resolved source checkout or a registry predecessor instead of exact payload".into()));
            }
        }
        Ok(value)
    }

    pub fn build(&self, root: &Path, target: &Path) -> Result<()> {
        let stable = crate::config::toolchains(root)?.stable;
        rustup_cargo(
            root,
            &stable,
            [
                std::ffi::OsStr::new("test"),
                std::ffi::OsStr::new("--locked"),
                std::ffi::OsStr::new("--manifest-path"),
                self.manifest.as_os_str(),
                std::ffi::OsStr::new("--config"),
                self.config.as_os_str(),
                std::ffi::OsStr::new("--target-dir"),
                target.as_os_str(),
            ],
            Duration::from_secs(900),
        )
        .run()?;
        rustup_cargo(
            root,
            &stable,
            [
                std::ffi::OsStr::new("run"),
                std::ffi::OsStr::new("--locked"),
                std::ffi::OsStr::new("--manifest-path"),
                self.manifest.as_os_str(),
                std::ffi::OsStr::new("--config"),
                self.config.as_os_str(),
                std::ffi::OsStr::new("--target-dir"),
                target.as_os_str(),
            ],
            Duration::from_secs(900),
        )
        .run()?;
        Ok(())
    }

    pub fn install_cli(
        &self,
        root: &Path,
        target: &Path,
        distribution: &super::distribution::TargetDistribution,
    ) -> Result<()> {
        let stable = crate::config::toolchains(root)?.stable;
        let mut spec = rustup_cargo(
            root,
            &stable,
            ["install", "--locked", "--path"],
            Duration::from_secs(1800),
        )
        .arg(&self.cli_source)
        .arg("--config")
        .arg(&self.config)
        .arg("--root")
        .arg(&self.install_root)
        .arg("--target-dir")
        .arg(target);
        for feature in &distribution.features {
            spec = spec.arg("--features").arg(feature);
        }
        for binary in &distribution.binaries {
            spec = spec.arg("--bin").arg(binary);
        }
        spec.run()?;
        Ok(())
    }
}

/// Reconcile the generated local workspace while retaining selected external pins.
pub fn prepare_consumer_lock(
    root: &Path,
    toolchain: &str,
    manifest: &Path,
    config: &Path,
) -> Result<()> {
    let selected = root.join("Cargo.lock");
    let consumer = manifest.with_file_name("Cargo.lock");
    fs::copy(&selected, &consumer)?;
    rustup_cargo(
        root,
        toolchain,
        [
            std::ffi::OsStr::new("update"),
            std::ffi::OsStr::new("--workspace"),
            std::ffi::OsStr::new("--manifest-path"),
            manifest.as_os_str(),
            std::ffi::OsStr::new("--config"),
            config.as_os_str(),
        ],
        Duration::from_secs(300),
    )
    .run()?;
    verify_external_lock(&selected, &consumer)
}

pub fn verify_external_lock(selected: &Path, consumer: &Path) -> Result<()> {
    let parse = |path: &Path| -> Result<BTreeMap<(String, String, String), Option<String>>> {
        let text = fs::read_to_string(path)?;
        let lock: toml::Value = toml::from_str(&text)?;
        let mut entries = BTreeMap::new();
        for package in lock
            .get("package")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| CiError::Message("lockfile package list absent".into()))?
        {
            let Some(source) = package.get("source").and_then(toml::Value::as_str) else {
                continue;
            };
            let name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| CiError::Message("lockfile name absent".into()))?;
            let version = package
                .get("version")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| CiError::Message("lockfile version absent".into()))?;
            if entries
                .insert(
                    (name.into(), version.into(), source.into()),
                    package
                        .get("checksum")
                        .and_then(toml::Value::as_str)
                        .map(str::to_owned),
                )
                .is_some()
            {
                return Err(CiError::Message(
                    "duplicate lockfile external package".into(),
                ));
            }
        }
        Ok(entries)
    };
    let selected = parse(selected)?;
    for (identity, checksum) in parse(consumer)? {
        if selected.get(&identity) != Some(&checksum) {
            return Err(CiError::Message(
                "package consumer changed selected external dependency/version/checksum".into(),
            ));
        }
    }
    Ok(())
}
