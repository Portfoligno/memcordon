//! Offline admission and shared consumer qualification of an assembled release.
use super::*;

#[derive(Debug, Serialize)]
pub(super) struct ConsumerEvidence {
    name: String,
    version: String,
    archive_sha256: String,
    pub phase: &'static str,
    pub dependency_resolution: Option<&'static str>,
    pub lock_generated: bool,
    pub check_passed: bool,
    pub install_passed: Option<bool>,
    pub source_unchanged: bool,
    pub provider: Option<NativeSmokeReport>,
    pub passed: bool,
}

impl ConsumerEvidence {
    pub fn new(record: &CrateRecord) -> Self {
        Self {
            name: record.name.clone(),
            version: record.version.clone(),
            archive_sha256: record.archive_sha256.clone(),
            phase: "staging",
            dependency_resolution: None,
            lock_generated: false,
            check_passed: false,
            install_passed: None,
            source_unchanged: false,
            provider: None,
            passed: false,
        }
    }
}

#[derive(Serialize)]
struct RehearsalReport {
    schema_version: u32,
    kind: &'static str,
    origin: &'static str,
    source_commit: Option<String>,
    tag: Option<String>,
    version: Option<String>,
    release_manifest_sha256: Option<String>,
    host_os: &'static str,
    host_architecture: &'static str,
    host_target: Option<String>,
    phase: &'static str,
    native_asset: Option<AssetRecord>,
    native_smoke: NativeSmokeReport,
    native_qualified: bool,
    crates: Vec<ConsumerEvidence>,
    passed: bool,
}

/// Reject lexical escapes and filesystem aliases escaping the admitted bundle.
pub(super) fn bundle_file(bundle: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(failure(
            "release bundle reference is not a local relative path",
        ));
    }
    let root = bundle.canonicalize()?;
    let path = root.join(relative).canonicalize()?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err(failure(
            "release bundle reference escapes its root or is not a file",
        ));
    }
    Ok(path)
}

pub(super) struct CandidatePackages {
    archives: BTreeMap<String, (CrateRecord, PathBuf)>,
}

pub(super) struct CandidateSources {
    packages: BTreeMap<String, (String, PathBuf)>,
    root: PathBuf,
}

impl CandidatePackages {
    pub fn stage(&self, consumer: &Path) -> Result<CandidateSources> {
        let candidate = consumer.join("candidate");
        fs::create_dir(&candidate)?;
        let mut packages = BTreeMap::new();
        let mut patches = toml::Table::new();
        for (name, (record, archive)) in &self.archives {
            // Bind every extraction to the admitted archive, even on later consumers.
            validate_archive_identity(archive, record)?;
            let destination = candidate.join(name);
            extract_crate_source(archive, &destination)?;
            let destination = destination.canonicalize()?;
            let encoded_path = destination
                .to_str()
                .ok_or_else(|| failure("candidate package path is not UTF-8"))?;
            let mut patch = toml::Table::new();
            patch.insert("path".into(), toml::Value::String(encoded_path.to_owned()));
            patches.insert(name.clone(), toml::Value::Table(patch));
            packages.insert(name.clone(), (record.version.clone(), destination));
        }
        let mut patch = toml::Table::new();
        patch.insert("crates-io".into(), toml::Value::Table(patches));
        let mut config = toml::Table::new();
        config.insert("patch".into(), toml::Value::Table(patch));
        fs::create_dir(consumer.join(".cargo"))?;
        fs::write(
            consumer.join(".cargo").join("config.toml"),
            toml::to_string(&config).map_err(|error| failure(error.to_string()))?,
        )?;
        Ok(CandidateSources {
            packages,
            root: candidate.canonicalize()?,
        })
    }
}

impl CandidateSources {
    pub fn package_root(&self, name: &str) -> Result<PathBuf> {
        self.packages
            .get(name)
            .map(|(_, path)| path.clone())
            .ok_or_else(|| failure("candidate install package was not admitted"))
    }

    pub fn validate_resolution(&self, bytes: &[u8], consumer_package: &str) -> Result<()> {
        let metadata: serde_json::Value = serde_json::from_slice(bytes)?;
        let packages = metadata
            .get("packages")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| failure("candidate metadata has no package inventory"))?;
        let mut resolved = BTreeSet::new();
        for package in packages {
            let name = package
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| failure("candidate metadata package has no name"))?;
            let Some((version, path)) = self.packages.get(name) else {
                if package.get("source") == Some(&serde_json::Value::Null)
                    && name != "memcordon-release-consumer"
                {
                    return Err(failure(
                        "candidate resolution contains an unadmitted local package",
                    ));
                }
                continue;
            };
            let manifest = package
                .get("manifest_path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| failure("candidate metadata package has no manifest"))?;
            let actual = Path::new(manifest).canonicalize()?;
            if package.get("source") != Some(&serde_json::Value::Null)
                || package.get("version").and_then(serde_json::Value::as_str)
                    != Some(version.as_str())
                || actual.parent() != Some(path.as_path())
                || !actual.starts_with(&self.root)
                || !resolved.insert(name)
            {
                return Err(failure(
                    "candidate resolution escaped an admitted package identity",
                ));
            }
        }
        if !resolved.contains(consumer_package) {
            return Err(failure(
                "candidate resolution omits the requested release package",
            ));
        }
        Ok(())
    }
}

pub(super) fn consumer_install_arguments(
    record: &CrateRecord,
    candidate: Option<&Path>,
    install: &Path,
) -> Vec<OsString> {
    let mut arguments = vec![OsString::from("install")];
    if let Some(package) = candidate {
        arguments.extend([OsString::from("--path"), package.as_os_str().to_os_string()]);
    } else {
        arguments.extend([
            OsString::from(&record.name),
            OsString::from("--version"),
            OsString::from(&record.version),
        ]);
    }
    arguments.extend([
        OsString::from("--locked"),
        OsString::from("--root"),
        install.as_os_str().to_os_string(),
    ]);
    arguments
}

fn validate_archive_identity(archive: &Path, record: &CrateRecord) -> Result<()> {
    if sha256_file(archive)? != record.archive_sha256
        || canonical_crate_tree(archive)? != record.canonical_tree_sha256
    {
        return Err(failure(
            "candidate archive digest or canonical tree differs",
        ));
    }
    let identity = canonical_crate_identity(archive)?;
    if identity.sha256 != record.canonical_identity_sha256
        || identity.package_name != record.name
        || identity.package_version != record.version
        || identity.vcs_commit != record.vcs_commit
        || identity.vcs_dirty
    {
        return Err(failure(
            "candidate archive normalized identity or provenance differs",
        ));
    }
    Ok(())
}

fn copy_bounded(source: &Path, destination: &Path, maximum: u64) -> Result<()> {
    let mut input = File::open(source)?.take(maximum.saturating_add(1));
    let mut output = File::create(destination)?;
    if std::io::copy(&mut input, &mut output)? > maximum {
        return Err(failure("candidate archive exceeds configured size policy"));
    }
    output.sync_all()?;
    Ok(())
}

fn validate_candidate_manifest(
    root: &Path,
    release: &config::Release,
    manifest: &ReleaseManifest,
) -> Result<ReleaseIdentity> {
    validate_manifest_crates(release, manifest)?;
    let workspace: toml::Value = toml::from_str(&fs::read_to_string(root.join("Cargo.toml"))?)?;
    let workspace_version = workspace
        .get("workspace")
        .and_then(|value| value.get("package"))
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| failure("workspace package version is absent"))?;
    let version = validate_dynamic_release_identity(
        &manifest.tag,
        &manifest.version,
        &Version::parse(workspace_version)?,
    )?;
    let commit = git_text(root, &["rev-parse", "HEAD"])?;
    let tags = git_text(root, &["tag", "--points-at", "HEAD"])?;
    if manifest.schema_version != config::RELEASE_SCHEMA_VERSION
        || manifest.project != "memcordon"
        || manifest.source_commit != commit
        || !tags.lines().any(|tag| tag == manifest.tag)
        || manifest.prerelease != !version.pre.is_empty()
        || manifest.rust_toolchain != config::toolchains(root)?.stable
    {
        return Err(failure(
            "candidate release manifest differs from checked-out tag identity",
        ));
    }
    Ok(ReleaseIdentity {
        tag: manifest.tag.clone(),
        version,
        commit,
        changelog_section: String::new(),
        source_date: manifest.source_date.clone(),
    })
}

fn checked_out_blob(root: &Path, path: &str) -> Result<Vec<u8>> {
    let listing = git(root, ["ls-tree", "-z", "--full-name", "HEAD", "--", path])?;
    let listing =
        std::str::from_utf8(&listing).map_err(|_| failure("workflow tree entry is not UTF-8"))?;
    let entry = listing
        .strip_suffix('\0')
        .ok_or_else(|| failure("workflow file is absent from checked-out commit"))?;
    if entry.contains('\0') {
        return Err(failure("workflow file has ambiguous tree identity"));
    }
    let (metadata, name) = entry
        .split_once('\t')
        .ok_or_else(|| failure("workflow tree identity is malformed"))?;
    let fields: Vec<_> = metadata.split_whitespace().collect();
    if fields.len() != 3 || fields[0] != "100644" || fields[1] != "blob" || name != path {
        return Err(failure("workflow file is not an ordinary tracked document"));
    }
    let size = git_text(root, &["cat-file", "-s", fields[2]])?
        .parse::<usize>()
        .map_err(|_| failure("workflow blob size is invalid"))?;
    if size > memcordon_ci::policy::MAXIMUM_YAML_BYTES {
        return Err(failure("workflow blob exceeds YAML size policy"));
    }
    git(root, ["cat-file", "blob", fields[2]])
}

fn validate_candidate_workflow(
    root: &Path,
    release: &config::Release,
    manifest: &ReleaseManifest,
) -> Result<()> {
    let expected_ref = format!(
        "{}/.github/workflows/{}@refs/tags/{}",
        release.repository, release.workflow, manifest.tag
    );
    if manifest.workflow_commit != manifest.source_commit || manifest.workflow_ref != expected_ref {
        return Err(failure("candidate workflow is not bound to its source tag"));
    }
    let entry = [".github", "workflows", release.workflow.as_str()].join("/");
    let graph = workflow_graph_from(entry, |path| checked_out_blob(root, path))?;
    let pins: BTreeMap<_, _> = config::action_pins(root)?
        .action
        .into_iter()
        .map(|pin| (pin.name, pin.uses))
        .collect();
    if manifest.workflow_sha256 != sha256_bytes(graph.entry()?)
        || manifest.workflow_resources != graph.resource_digests()
        || manifest.action_revisions != pins
    {
        return Err(failure(
            "candidate workflow provenance differs from checked-out commit",
        ));
    }
    crate::policy::validate_workflow_bytes_with_local_actions(
        root,
        Path::new(&graph.entry_path),
        graph.entry()?,
        &config::policy(root)?,
        &graph.documents,
    )
}

fn qualify(root: &Path, bundle: &Path, report: &mut RehearsalReport) -> Result<()> {
    let (release, manifest, _) = bundle_manifest_at(root, bundle)?;
    let identity = validate_candidate_manifest(root, &release, &manifest)?;
    validate_candidate_workflow(root, &release, &manifest)?;
    report.source_commit = Some(manifest.source_commit.clone());
    report.tag = Some(manifest.tag.clone());
    report.version = Some(manifest.version.clone());
    report.release_manifest_sha256 = Some(sha256_file(&bundle_file(
        bundle,
        Path::new(&release.assets.manifest),
    )?)?);
    let host = config::release_target_id_for_host(std::env::consts::OS, std::env::consts::ARCH)?;
    report.host_target = Some(host.to_owned());
    let target = release
        .assets
        .target
        .iter()
        .find(|target| target.id == host)
        .ok_or_else(|| failure("candidate host target is unconfigured"))?;
    // Copy once into a private admission directory. No candidate code executes until
    // every package and native inventory has passed all identity checks.
    let admitted = TempDir::new()?;
    let mut archives = BTreeMap::new();
    let mut filenames = BTreeSet::new();
    let defaults = configured_default_cargo_binaries(&release)?;
    for record in &manifest.crates {
        let filename = format!("{}-{}.crate", record.name, record.version);
        filenames.insert(OsString::from(&filename));
        let archive = admitted.path().join(&filename);
        copy_bounded(
            &bundle_file(bundle, &Path::new("packages").join(&filename))?,
            &archive,
            release.maximum_package_bytes,
        )?;
        validate_archive_identity(&archive, record)?;
        validate_crate_readme(&archive, &record.name)?;
        if record.name == "memcordon" {
            validate_reviewed_memcordon_distribution(&archive, &defaults)?;
        }
        if archives
            .insert(record.name.clone(), (record.clone(), archive))
            .is_some()
        {
            return Err(failure("duplicate candidate package"));
        }
    }
    let actual = fs::read_dir(bundle.join("packages"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    if actual != filenames {
        return Err(failure("candidate package directory inventory differs"));
    }
    let mut targets = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut native = None;
    for asset in &manifest.assets {
        let configured = release
            .assets
            .target
            .iter()
            .find(|target| target.rust_target == asset.target)
            .ok_or_else(|| failure("candidate native target is unconfigured"))?;
        if !targets.insert(&asset.target)
            || !names.insert(&asset.name)
            || asset.name != archive_name(&identity.version, configured)
        {
            return Err(failure(
                "candidate native inventory contains duplicate or unexpected identities",
            ));
        }
        let source = bundle_file(bundle, Path::new(&asset.name))?;
        if fs::metadata(&source)?.len() != asset.size
            || asset.size > release.maximum_asset_bytes
            || sha256_file(&source)? != asset.sha256
        {
            return Err(failure("candidate native archive size or digest differs"));
        }
        if configured.id == host {
            let path = admitted.path().join(&asset.name);
            copy_bounded(&source, &path, release.maximum_asset_bytes)?;
            if sha256_file(&path)? != asset.sha256 {
                return Err(failure("candidate native archive changed during admission"));
            }
            let inspection = inspect_extract_and_smoke(root, &path, target, &identity, false)?;
            if inspection.runtime_manifest_sha256 != asset.runtime_manifest_sha256
                || inspection.components != asset.components
            {
                return Err(failure("candidate runtime inventory differs"));
            }
            native = Some((asset.clone(), path));
        }
    }
    if targets.len() != release.assets.target.len() {
        return Err(failure("candidate native target inventory is incomplete"));
    }
    let (asset, native_path) =
        native.ok_or_else(|| failure("candidate host native asset is absent"))?;
    report.native_asset = Some(asset);
    report.phase = "native-qualification";
    inspect_extract_and_smoke_report(
        root,
        &native_path,
        target,
        &identity,
        true,
        &mut report.native_smoke,
    )?;
    report.native_qualified = true;
    let packages = CandidatePackages { archives };
    report.phase = "crate-qualification";
    for record in &manifest.crates {
        report.crates.push(ConsumerEvidence::new(record));
        qualify_crate_consumer(
            root,
            record,
            Some(&packages),
            report
                .crates
                .last_mut()
                .expect("inserted consumer evidence"),
        )?;
    }
    report.phase = "complete";
    report.passed = true;
    Ok(())
}

fn finish_report(primary: Result<()>, write: Result<()>) -> Result<()> {
    match (primary, write) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(write)) => Err(write),
        (Err(primary), Err(write)) => Err(failure(format!(
            "rehearsal failed: primary={primary}; report={write}"
        ))),
    }
}

pub(super) fn run(root: &Path, bundle: &Path, report_path: &Path) -> Result<()> {
    let bundle = root.join(bundle);
    let report_path = root.join(report_path);
    let mut report = RehearsalReport {
        schema_version: 1,
        kind: "post-publish-rehearsal",
        origin: "candidate-release-bundle",
        source_commit: None,
        tag: None,
        version: None,
        release_manifest_sha256: None,
        host_os: std::env::consts::OS,
        host_architecture: std::env::consts::ARCH,
        host_target: None,
        phase: "bundle-admission",
        native_asset: None,
        native_smoke: NativeSmokeReport::default(),
        native_qualified: false,
        crates: Vec::new(),
        passed: false,
    };
    let primary = qualify(root, &bundle, &mut report);
    let write = (|| {
        fs::create_dir_all(
            report_path
                .parent()
                .ok_or_else(|| failure("rehearsal report has no parent"))?,
        )?;
        let parent = report_path
            .parent()
            .ok_or_else(|| failure("rehearsal report has no parent"))?;
        let mut output = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(&mut output, &report)?;
        output.write_all(b"\n")?;
        output.as_file().sync_all()?;
        output
            .persist(&report_path)
            .map_err(|error| failure(format!("persist rehearsal report: {}", error.error)))?;
        Ok(())
    })();
    finish_report(primary, write)
}

#[cfg(test)]
#[path = "../tests/release/rehearsal.rs"]
mod tests;
