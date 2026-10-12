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
use sha2::{Digest, Sha256};
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
    cargo_home: PathBuf,
    selected_target: Option<String>,
    source_members: BTreeMap<PathBuf, [u8; 32]>,
    consumer_graph: Option<serde_json::Value>,
    install_graph: Option<serde_json::Value>,
    selected_features: Vec<String>,
}

impl PackageConsumer {
    pub fn prepare(root: &Path, packages: &Path) -> Result<Self> {
        Self::prepare_selection(root, packages, None)
    }

    pub fn prepare_selected(
        root: &Path,
        packages: &Path,
        distribution: &super::distribution::TargetDistribution,
    ) -> Result<Self> {
        distribution.validate()?;
        Self::prepare_selection(root, packages, Some(distribution))
    }

    fn prepare_selection(
        root: &Path,
        packages: &Path,
        distribution: Option<&super::distribution::TargetDistribution>,
    ) -> Result<Self> {
        let (bundle, bytes) = PackageBundle::load(packages)?;
        let directory = tempfile::tempdir()?;
        let mut patches = toml::Table::new();
        let mut dependencies = toml::Table::new();
        let mut cli_source = None;
        let mut source_members = BTreeMap::new();
        for (record, bytes) in bundle.files.iter().zip(bytes) {
            let name = record.package.as_deref().expect("validated package");
            let extracted = directory.path().join(name);
            artifacts::extract_members(&artifacts::crate_members(&bytes)?, &extracted)?;
            for (member, bytes) in artifacts::crate_members(&bytes)? {
                source_members.insert(extracted.join(member), Sha256::digest(bytes).into());
            }
            if name == "memcordon" {
                let install_source = directory.path().join("install-source");
                artifacts::extract_members(&artifacts::crate_members(&bytes)?, &install_source)?;
                for (member, bytes) in artifacts::crate_members(&bytes)? {
                    if member != "Cargo.lock" {
                        source_members
                            .insert(install_source.join(member), Sha256::digest(bytes).into());
                    }
                }
                cli_source = Some(install_source);
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
                    toml::Value::String(format!("={}", bundle.source.version())),
                )])),
            );
            if let ("memcordon", Some(distribution)) = (name, distribution) {
                dependencies
                    .get_mut(name)
                    .expect("inserted CLI dependency")
                    .as_table_mut()
                    .expect("dependency table")
                    .insert(
                        "features".into(),
                        toml::Value::Array(
                            distribution
                                .features
                                .iter()
                                .cloned()
                                .map(toml::Value::String)
                                .collect(),
                        ),
                    );
            }
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
        let cargo_home = directory.path().join("cargo-home");
        fs::create_dir(&cargo_home)?;
        let mut value = Self {
            _directory: directory,
            manifest,
            config,
            cli_source: cli_source.expect("required CLI package"),
            install_root,
            bundle,
            cargo_home,
            selected_target: distribution.map(|distribution| distribution.target.clone()),
            source_members,
            consumer_graph: None,
            install_graph: None,
            selected_features: distribution
                .map(|distribution| distribution.features.clone())
                .unwrap_or_default(),
        };
        let toolchain = crate::config::toolchains(root)?.stable;
        let packaged_lock = value._directory.path().join("memcordon").join("Cargo.lock");
        let consumer_metadata = prepare_packaged_consumer_lock(
            &toolchain,
            &packaged_lock,
            &value.manifest,
            &value.config,
            Some(&value.cargo_home),
            distribution,
            false,
        )?;
        let install_metadata = prepare_packaged_consumer_lock(
            &toolchain,
            &packaged_lock,
            &value.cli_source.join("Cargo.toml"),
            &value.config,
            Some(&value.cargo_home),
            distribution,
            true,
        )?;
        value.consumer_graph = Some(resolved_graph(&consumer_metadata)?);
        value.install_graph = Some(resolved_graph(&install_metadata)?);
        let mut metadata_command = rustup_cargo(
            value.manifest.parent().expect("consumer manifest parent"),
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
        .isolated_cargo(&value.cargo_home);
        if let Some(distribution) = distribution {
            metadata_command = metadata_command
                .arg("--filter-platform")
                .arg(&distribution.target);
        }
        let output = metadata_command.output_quiet()?;
        if !output.status.success() {
            return Err(CiError::Message("package consumer metadata failed".into()));
        }
        let metadata: cargo_metadata::Metadata = serde_json::from_slice(&output.stdout)?;
        if Some(resolved_graph(&metadata)?) != value.consumer_graph {
            return Err(CiError::Message(
                "locked candidate feature/dependency graph differs from selected adaptation".into(),
            ));
        }
        verify_resolved_external_lock(
            &packaged_lock,
            &value.manifest.with_file_name("Cargo.lock"),
            &metadata,
        )?;
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
        value.verify_packaged_sources()?;
        Ok(value)
    }

    fn verify_packaged_sources(&self) -> Result<()> {
        for (path, expected) in &self.source_members {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file() || <[u8; 32]>::from(Sha256::digest(fs::read(path)?)) != *expected
            {
                return Err(CiError::Message(
                    "candidate Cargo modified a canonical packaged source or installation resource"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    fn verify_selected_graph(&self, root: &Path, cli: bool) -> Result<()> {
        let manifest = if cli {
            self.cli_source.join("Cargo.toml")
        } else {
            self.manifest.clone()
        };
        let toolchain = crate::config::toolchains(root)?.stable;
        let mut command = rustup_cargo(
            manifest.parent().expect("candidate manifest parent"),
            &toolchain,
            ["metadata", "--locked", "--format-version", "1"],
            Duration::from_secs(300),
        )
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--config")
        .arg(&self.config)
        .isolated_cargo(&self.cargo_home);
        if let Some(target) = &self.selected_target {
            command = command.arg("--filter-platform").arg(target);
        }
        if cli {
            for feature in &self.selected_features {
                command = command.arg("--features").arg(feature);
            }
        }
        let output = command.output_quiet()?;
        if !output.status.success() {
            return Err(CiError::Message(
                "locked candidate dependency readback failed".into(),
            ));
        }
        let metadata: cargo_metadata::Metadata = serde_json::from_slice(&output.stdout)?;
        let expected = if cli {
            &self.install_graph
        } else {
            &self.consumer_graph
        };
        if &Some(resolved_graph(&metadata)?) != expected {
            return Err(CiError::Message(
                "candidate target/features/dependency kinds or edge graph changed".into(),
            ));
        }
        Ok(())
    }

    /// Retains the actual locked candidate install graph and the exact final
    /// archives it consumed. Canonical packaged sources remain unchanged.
    pub fn retain_install_graph(
        &self,
        root: &Path,
        packages: &Path,
        destination: &Path,
        artifact_root: &Path,
        deadline: std::time::Instant,
    ) -> Result<PathBuf> {
        use std::io::Write;
        self.verify_packaged_sources()?;
        let manifest = self.cli_source.join("Cargo.toml");
        let toolchain = crate::config::toolchains(root)?.stable;
        let mut command = rustup_cargo(
            &self.cli_source,
            &toolchain,
            ["metadata", "--locked", "--format-version", "1"],
            Duration::from_secs(300),
        )
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--config")
        .arg(&self.config)
        .isolated_cargo(&self.cargo_home)
        .bounded_until(deadline);
        if let Some(target) = &self.selected_target {
            command = command.arg("--filter-platform").arg(target);
        }
        for feature in &self.selected_features {
            command = command.arg("--features").arg(feature);
        }
        let output = command.output_quiet()?;
        if !output.status.success() {
            return Err(CiError::Message(
                "candidate consumed graph metadata failed".into(),
            ));
        }
        let metadata: cargo_metadata::Metadata = serde_json::from_slice(&output.stdout)?;
        if Some(resolved_graph(&metadata)?) != self.install_graph {
            return Err(CiError::Message(
                "candidate consumed graph changed after install".into(),
            ));
        }
        fs::create_dir(destination)?;
        let persist = |name: &str, bytes: &[u8]| -> Result<PathBuf> {
            let path = destination.join(name);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(path)
        };
        let relative = |path: &Path| -> Result<String> {
            Ok(path
                .strip_prefix(artifact_root)
                .map_err(|_| {
                    CiError::Message("candidate lineage escapes cell artifact root".into())
                })?
                .to_str()
                .ok_or_else(|| CiError::Message("candidate lineage path encoding differs".into()))?
                .to_owned())
        };
        let raw_metadata = persist("metadata.json", &output.stdout)?;
        persist("metadata-stderr", &output.stderr)?;
        let raw_lock = persist(
            "Cargo.lock",
            &super::artifacts::read_file(&self.cli_source.join("Cargo.lock"))?,
        )?;
        let resolve = metadata
            .resolve
            .as_ref()
            .ok_or_else(|| CiError::Message("candidate consumed resolve graph absent".into()))?;
        let mut reachable = std::collections::BTreeSet::new();
        let mut pending = vec![
            resolve
                .root
                .clone()
                .ok_or_else(|| CiError::Message("candidate install graph root absent".into()))?,
        ];
        while let Some(id) = pending.pop() {
            if reachable.insert(id.clone()) {
                let node = resolve
                    .nodes
                    .iter()
                    .find(|node| node.id == id)
                    .ok_or_else(|| CiError::Message("candidate consumed node absent".into()))?;
                pending.extend(node.deps.iter().map(|edge| edge.pkg.clone()));
            }
        }
        fs::create_dir(destination.join("crates"))?;
        let mut graph = Vec::new();
        for node in resolve
            .nodes
            .iter()
            .filter(|node| reachable.contains(&node.id))
        {
            let package = metadata
                .packages
                .iter()
                .find(|package| package.id == node.id)
                .ok_or_else(|| CiError::Message("candidate consumed package absent".into()))?;
            let filename = format!("{}-{}.crate", package.name, package.version);
            let bytes = if let Some(record) = self
                .bundle
                .files
                .iter()
                .find(|record| record.package.as_deref() == Some(package.name.as_str()))
            {
                let bytes = super::artifacts::read_file(&packages.join(&record.name))?;
                super::artifacts::check_bytes(record, &bytes)?;
                bytes
            } else {
                let cache = self.cargo_home.join("registry/cache");
                let mut matches = Vec::new();
                for entry in fs::read_dir(&cache)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        let candidate = entry.path().join(&filename);
                        if candidate.is_file() {
                            matches.push(candidate);
                        }
                    }
                }
                if matches.len() != 1 {
                    return Err(CiError::Message(
                        "candidate consumed external cache archive absent or ambiguous".into(),
                    ));
                }
                super::artifacts::read_file(&matches[0])?
            };
            let archive = destination.join("crates").join(&filename);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&archive)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            let mut edges = Vec::new();
            for edge in &node.deps {
                let dependency = metadata
                    .packages
                    .iter()
                    .find(|package| package.id == edge.pkg)
                    .ok_or_else(|| {
                        CiError::Message("candidate consumed edge package absent".into())
                    })?;
                for kind in &edge.dep_kinds {
                    let domain = if kind.kind == cargo_metadata::DependencyKind::Normal {
                        serde_json::Value::Null
                    } else {
                        serde_json::to_value(kind.kind)?
                    };
                    edges.push(serde_json::json!({"name":dependency.name,"version":dependency.version,"kind":domain,"target":kind.target}));
                }
            }
            graph.push(serde_json::json!({"name":package.name,"version":package.version,"crate_sha256":super::artifacts::checksum(&bytes),"crate_artifact":relative(&archive)?,"features":node.features,"dependencies":edges}));
        }
        let graph_path = destination.join("registry-graph.json");
        super::source::write_json(
            &graph_path,
            &serde_json::json!({"format":"memcordon.consumer-readiness.registry-graph","revision":1,"packages":graph,"raw_metadata":relative(&raw_metadata)?,"raw_lock":relative(&raw_lock)?}),
        )?;
        fs::File::open(destination.join("crates"))?.sync_all()?;
        fs::File::open(destination)?.sync_all()?;
        self.verify_packaged_sources()?;
        Ok(graph_path)
    }

    pub fn build(&self, root: &Path, target: &Path) -> Result<()> {
        self.verify_packaged_sources()?;
        self.verify_selected_graph(root, false)?;
        let stable = crate::config::toolchains(root)?.stable;
        let mut test = rustup_cargo(
            self.manifest.parent().expect("consumer manifest parent"),
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
        .isolated_cargo(&self.cargo_home);
        if let Some(selected) = &self.selected_target {
            test = test.arg("--target").arg(selected);
        }
        test.run()?;
        let mut run = rustup_cargo(
            self.manifest.parent().expect("consumer manifest parent"),
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
        .isolated_cargo(&self.cargo_home);
        if let Some(selected) = &self.selected_target {
            run = run.arg("--target").arg(selected);
        }
        run.run()?;
        self.verify_packaged_sources()?;
        self.verify_selected_graph(root, false)
    }

    pub fn install_cli(
        &self,
        root: &Path,
        target: &Path,
        distribution: &super::distribution::TargetDistribution,
    ) -> Result<()> {
        if self
            .selected_target
            .as_ref()
            .is_some_and(|target| target != &distribution.target)
            || self.selected_features != distribution.features
        {
            return Err(CiError::Message(
                "candidate installation selection differs from adapted target/features".into(),
            ));
        }
        self.verify_packaged_sources()?;
        self.verify_selected_graph(root, true)?;
        let stable = crate::config::toolchains(root)?.stable;
        let mut spec = rustup_cargo(
            &self.cli_source,
            &stable,
            ["install", "--locked", "--path"],
            Duration::from_secs(1800),
        )
        .isolated_cargo(&self.cargo_home)
        .arg(&self.cli_source)
        .arg("--config")
        .arg(&self.config)
        .arg("--root")
        .arg(&self.install_root)
        .arg("--target-dir")
        .arg(target);
        spec = spec.arg("--target").arg(&distribution.target);
        for feature in &distribution.features {
            spec = spec.arg("--features").arg(feature);
        }
        for binary in &distribution.binaries {
            spec = spec.arg("--bin").arg(binary);
        }
        spec.run()?;
        self.verify_packaged_sources()?;
        self.verify_selected_graph(root, true)
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
    prepare_packaged_consumer_lock(toolchain, &selected, manifest, config, None, None, false)
        .map(|_| ())
}

fn prepare_packaged_consumer_lock(
    toolchain: &str,
    selected: &Path,
    manifest: &Path,
    config: &Path,
    cargo_home: Option<&Path>,
    distribution: Option<&super::distribution::TargetDistribution>,
    cli: bool,
) -> Result<cargo_metadata::Metadata> {
    let consumer = manifest.with_file_name("Cargo.lock");
    fs::copy(selected, &consumer)?;
    let mut command = rustup_cargo(
        manifest.parent().expect("consumer manifest parent"),
        toolchain,
        [
            std::ffi::OsStr::new("metadata"),
            std::ffi::OsStr::new("--format-version"),
            std::ffi::OsStr::new("1"),
            std::ffi::OsStr::new("--manifest-path"),
            manifest.as_os_str(),
            std::ffi::OsStr::new("--config"),
            config.as_os_str(),
        ],
        Duration::from_secs(300),
    );
    if let Some(home) = cargo_home {
        command = command.isolated_cargo(home);
    }
    if let Some(distribution) = distribution {
        command = command.arg("--filter-platform").arg(&distribution.target);
        if cli {
            for feature in &distribution.features {
                command = command.arg("--features").arg(feature);
            }
        }
    }
    let output = command.output_quiet()?;
    if !output.status.success() {
        return Err(CiError::Message(
            "candidate test lock metadata adaptation failed".into(),
        ));
    }
    let metadata: cargo_metadata::Metadata = serde_json::from_slice(&output.stdout)?;
    verify_external_lock(selected, &consumer)?;
    verify_resolved_external_lock(selected, &consumer, &metadata)?;
    Ok(metadata)
}

fn resolved_graph(metadata: &cargo_metadata::Metadata) -> Result<serde_json::Value> {
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| CiError::Message("candidate resolve graph absent".into()))?;
    let mut nodes = std::collections::BTreeMap::new();
    for node in &resolve.nodes {
        let mut features = node
            .features
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        features.sort();
        let mut edges = node
            .deps
            .iter()
            .map(|dependency| {
                let mut kinds = dependency
                    .dep_kinds
                    .iter()
                    .map(serde_json::to_string)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                kinds.sort();
                serde_json::to_string(&(&dependency.name, &dependency.pkg, kinds))
            })
            .collect::<std::result::Result<Vec<_>, serde_json::Error>>()?;
        edges.sort();
        if nodes
            .insert(
                node.id.to_string(),
                serde_json::json!({"features":features,"edges":edges}),
            )
            .is_some()
        {
            return Err(CiError::Message(
                "candidate graph has duplicate package identity".into(),
            ));
        }
    }
    Ok(serde_json::json!({"root":resolve.root,"nodes":nodes}))
}

pub fn verify_same_resolved_graph(
    selected: &cargo_metadata::Metadata,
    observed: &cargo_metadata::Metadata,
) -> Result<()> {
    if resolved_graph(selected)? != resolved_graph(observed)? {
        return Err(CiError::Message(
            "candidate target/features/dependency kinds or edge graph changed".into(),
        ));
    }
    Ok(())
}

pub fn verify_resolved_external_lock(
    selected: &Path,
    adapted: &Path,
    metadata: &cargo_metadata::Metadata,
) -> Result<()> {
    verify_external_lock(selected, adapted)?;
    let text = fs::read_to_string(adapted)?;
    let lock: toml::Value = toml::from_str(&text)?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| CiError::Message("adapted lock packages absent".into()))?;
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| CiError::Message("candidate resolved dependency graph absent".into()))?;
    let reachable = resolve
        .nodes
        .iter()
        .map(|node| &node.id)
        .collect::<std::collections::BTreeSet<_>>();
    for package in metadata
        .packages
        .iter()
        .filter(|package| reachable.contains(&package.id))
    {
        let Some(source) = package.source.as_ref() else {
            continue;
        };
        if packages
            .iter()
            .filter(|entry| {
                entry.get("name").and_then(toml::Value::as_str) == Some(package.name.as_str())
                    && entry.get("version").and_then(toml::Value::as_str)
                        == Some(package.version.to_string().as_str())
                    && entry.get("source").and_then(toml::Value::as_str)
                        == Some(source.to_string().as_str())
            })
            .count()
            != 1
        {
            return Err(CiError::Message(
                "reachable external resolution differs from the adapted packaged lock".into(),
            ));
        }
    }
    for package in metadata
        .packages
        .iter()
        .filter(|package| package.source.is_none())
    {
        if package.name.as_str().starts_with("memcordon")
            && package.name.as_str() != "memcordon-external-consumer"
            && !PUBLIC_PACKAGES.contains(&package.name.as_str())
        {
            return Err(CiError::Message(
                "candidate resolved an undeclared MemCordon checkout peer".into(),
            ));
        }
    }
    Ok(())
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
