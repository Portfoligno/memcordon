//! Prepared payloads contain actual bytes and ordinary source identities.
use super::{
    artifacts::{self, FileRecord},
    distribution::Distribution,
    packages::PackageBundle,
    source::{self, BuildSourceIdentity, SelectedSource},
};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicManifest {
    pub schema: u32,
    pub version: semver::Version,
    pub tag: String,
    pub commit: String,
    pub files: Vec<FileRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateManifest {
    pub format: String,
    pub revision: u32,
    pub version: semver::Version,
    pub commit: String,
    pub files: Vec<FileRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateBundle {
    pub format: String,
    pub revision: u32,
    pub source: BuildSourceIdentity,
    pub distribution: Distribution,
    pub files: Vec<FileRecord>,
    pub notes_selection: NotesSelection,
    pub notes: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotesSelection {
    ExactVersion,
    Unreleased,
    Unavailable,
}

impl CandidateBundle {
    pub fn load(directory: &Path) -> Result<(Self, Vec<Vec<u8>>)> {
        let metadata: Self = source::read_json(&directory.join("candidate.json"))?;
        metadata.source.validate()?;
        if metadata.format != "memcordon.prepared-candidate"
            || metadata.revision != 1
            || !matches!(metadata.source, BuildSourceIdentity::Working { .. })
            || directory.join("prepared.json").exists()
        {
            return Err(CiError::Message("candidate envelope/source differs".into()));
        }
        match (&metadata.notes_selection, &metadata.notes) {
            (NotesSelection::Unavailable, None) => {}
            (NotesSelection::ExactVersion | NotesSelection::Unreleased, Some(notes))
                if !notes.trim().is_empty() && notes.len() <= 1024 * 1024 => {}
            _ => {
                return Err(CiError::Message(
                    "candidate notes disposition differs".into(),
                ));
            }
        }
        validate_inventory(&metadata.distribution, &metadata.files)?;
        let payloads = load_payloads(
            directory,
            &metadata.source,
            &metadata.distribution,
            &metadata.files,
        )?;
        let expected: BTreeSet<_> = metadata
            .files
            .iter()
            .map(|file| file.name.clone())
            .chain(["candidate.json".into()])
            .collect();
        let actual = fs::read_dir(directory)?
            .map(|entry| {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    return Err(CiError::Message(
                        "candidate inventory contains nonfile".into(),
                    ));
                }
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| CiError::Message("candidate filename is not UTF-8".into()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if expected != actual {
            return Err(CiError::Message(
                "candidate directory inventory differs".into(),
            ));
        }
        Ok((metadata, payloads))
    }
}

pub fn candidate_notes(
    root: &Path,
    version: &semver::Version,
) -> Result<(NotesSelection, Option<String>)> {
    let text = String::from_utf8(artifacts::read_file(&root.join("CHANGELOG.md"))?)
        .map_err(|_| CiError::Message("changelog is not UTF-8".into()))?;
    let exact = version.to_string();
    for (token, selection) in [
        (exact.as_str(), NotesSelection::ExactVersion),
        ("Unreleased", NotesSelection::Unreleased),
    ] {
        let Some(notes) = section_notes(&text, token) else {
            continue;
        };
        if notes.trim().is_empty() {
            if selection == NotesSelection::ExactVersion {
                return Err(CiError::Message(
                    "selected candidate changelog section is empty".into(),
                ));
            }
            // A new development cycle may have no Unreleased notes yet.
            continue;
        }
        return Ok((selection, Some(notes)));
    }
    Ok((NotesSelection::Unavailable, None))
}

fn section_notes(text: &str, token: &str) -> Option<String> {
    let mut selected = false;
    let mut present = false;
    let mut notes = String::new();
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            if selected {
                break;
            }
            selected = heading
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_matches(['[', ']'])
                == token;
            present |= selected;
        } else if selected {
            notes.push_str(line);
            notes.push('\n');
        }
    }
    present.then_some(notes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedBundle {
    pub format: String,
    pub revision: u32,
    pub source: SelectedSource,
    pub distribution: Distribution,
    pub files: Vec<FileRecord>,
    pub notes: String,
}

pub struct LoadedBundle {
    pub metadata: PreparedBundle,
    pub payloads: Vec<Vec<u8>>,
}

impl PreparedBundle {
    pub fn load(directory: &Path) -> Result<LoadedBundle> {
        let metadata: Self = source::read_json(&directory.join("prepared.json"))?;
        metadata.validate()?;
        let payloads = load_payloads(
            directory,
            &metadata.source.clone().into(),
            &metadata.distribution,
            &metadata.files,
        )?;
        Ok(LoadedBundle { metadata, payloads })
    }

    pub fn validate(&self) -> Result<()> {
        self.source.validate()?;
        self.distribution.validate()?;
        if self.format != "memcordon.prepared-release"
            || self.revision != 1
            || self.files.len() > 128
            || self.notes.is_empty()
            || self.notes.len() > 1024 * 1024
        {
            return Err(CiError::Message(
                "prepared release format/size differs".into(),
            ));
        }
        validate_inventory(&self.distribution, &self.files)?;
        Ok(())
    }
}

fn checksum_file<'a>(files: impl Iterator<Item = &'a FileRecord>) -> Vec<u8> {
    let mut records: Vec<_> = files.collect();
    records.sort_by(|left, right| left.name.cmp(&right.name));
    let mut output = Vec::new();
    for file in records {
        writeln!(&mut output, "{}  {}", file.sha256, file.name).expect("Vec write");
    }
    output
}

pub fn changelog_notes(root: &Path, version: &semver::Version) -> Result<String> {
    let text = String::from_utf8(artifacts::read_file(&root.join("CHANGELOG.md"))?)
        .map_err(|_| CiError::Message("changelog is not UTF-8".into()))?;
    let mut selected = false;
    let mut notes = String::new();
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            if selected {
                break;
            }
            let token = heading
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_matches(['[', ']']);
            selected = token == version.to_string();
            continue;
        }
        if selected {
            notes.push_str(line);
            notes.push('\n');
        }
    }
    if notes.trim().is_empty() {
        return Err(CiError::Message(
            "exact selected changelog section absent".into(),
        ));
    }
    Ok(notes)
}

pub fn assemble(
    root: &Path,
    source_path: &Path,
    packages: &Path,
    targets: &[PathBuf],
    destination: &Path,
) -> Result<()> {
    let source: SelectedSource = source::read_json(source_path)?;
    assemble_build(root, &source.into(), packages, targets, destination)
}

pub fn assemble_build(
    root: &Path,
    source: &BuildSourceIdentity,
    packages: &Path,
    target_directories: &[PathBuf],
    destination: &Path,
) -> Result<()> {
    let started = std::time::Instant::now();
    let record = |state: &str, error: Option<&CiError>| {
        let directory = root.join("target/ci/reports/execution");
        let write = || -> Result<()> {
            fs::create_dir_all(&directory)?;
            let temporary = directory.join("assembly.tmp");
            let value = serde_json::json!({"phase":"assembly", "expected-operation":"validate selected package/native bytes and finalize nonpublication or tagged envelope", "source":source, "state":state, "elapsed-ms":started.elapsed().as_millis(), "error":error.map(|error| crate::command::bounded_excerpt(error.to_string().as_bytes()))});
            source::write_json(&temporary, &value)?;
            fs::rename(temporary, directory.join("assembly.json"))?;
            Ok(())
        };
        if let Err(error) = write() {
            eprintln!("diagnostic retention incomplete: {error}");
        }
    };
    record("in-progress", None);
    let result = assemble_build_inner(root, source, packages, target_directories, destination);
    record(
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
        result.as_ref().err(),
    );
    result
}

fn assemble_build_inner(
    root: &Path,
    source: &BuildSourceIdentity,
    packages: &Path,
    target_directories: &[PathBuf],
    destination: &Path,
) -> Result<()> {
    source.recheck(root)?;
    let distribution = Distribution::read(root)?;
    let (packages, package_bytes) = PackageBundle::load(packages)?;
    if &packages.source != source || destination.exists() {
        return Err(CiError::Message(
            "assembly source/destination differs".into(),
        ));
    }
    let mut files = packages.files;
    let mut bytes = package_bytes;
    let mut manifests = std::collections::BTreeMap::new();
    for directory in target_directories {
        let (target, archive) = super::target::TargetBundle::load(directory)?;
        if &target.source != source || !distribution.targets.contains(&target.distribution) {
            return Err(CiError::Message(
                "target artifact source/selection differs".into(),
            ));
        }
        files.push(target.archive);
        let members = super::target::decode_archive(&archive, &target.distribution.target)?;
        manifests.insert(
            target.distribution.target.clone(),
            memcordon_core::runtime_manifest::RuntimeManifest::parse(
                &members["runtime-manifest.json"],
            )
            .map_err(CiError::Message)?,
        );
        bytes.push(archive);
    }
    let compatibility =
        super::compatibility::Compatibility::selected(source, &distribution, &manifests)?;
    let mut compatibility_bytes = serde_json::to_vec_pretty(&compatibility)?;
    compatibility_bytes.push(b'\n');
    files.push(FileRecord {
        name: "compatibility.json".into(),
        kind: "compatibility".into(),
        target: None,
        package: None,
        byte_len: compatibility_bytes.len() as u64,
        sha256: artifacts::checksum(&compatibility_bytes),
    });
    bytes.push(compatibility_bytes);
    let (manifest_name, mut manifest_bytes) = match source {
        BuildSourceIdentity::Tagged { source } => (
            "release-manifest.json",
            serde_json::to_vec_pretty(&PublicManifest {
                schema: 1,
                version: source.version.clone(),
                tag: source.version.to_string(),
                commit: source.commit.clone(),
                files: files.clone(),
            })?,
        ),
        BuildSourceIdentity::Working { version, commit } => (
            "candidate-manifest.json",
            serde_json::to_vec_pretty(&CandidateManifest {
                format: "memcordon.candidate-manifest".into(),
                revision: 1,
                version: version.clone(),
                commit: commit.clone(),
                files: files.clone(),
            })?,
        ),
    };
    manifest_bytes.push(b'\n');
    files.push(FileRecord {
        name: manifest_name.into(),
        kind: "manifest".into(),
        package: None,
        target: None,
        byte_len: manifest_bytes.len() as u64,
        sha256: artifacts::checksum(&manifest_bytes),
    });
    bytes.push(manifest_bytes);
    let sums = checksum_file(files.iter());
    files.push(FileRecord {
        name: "SHA256SUMS".into(),
        kind: "checksums".into(),
        package: None,
        target: None,
        byte_len: sums.len() as u64,
        sha256: artifacts::checksum(&sums),
    });
    bytes.push(sums);
    validate_inventory(&distribution, &files)?;
    fs::create_dir_all(destination)?;
    for (file, bytes) in files.iter().zip(bytes) {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination.join(&file.name))?
            .write_all(&bytes)?;
    }
    match source {
        BuildSourceIdentity::Tagged { source } => {
            let prepared = PreparedBundle {
                format: "memcordon.prepared-release".into(),
                revision: 1,
                source: source.clone(),
                distribution,
                files,
                notes: changelog_notes(root, &source.version)?,
            };
            prepared.validate()?;
            source::write_json(&destination.join("prepared.json"), &prepared)?;
            PreparedBundle::load(destination)?;
        }
        BuildSourceIdentity::Working { .. } => {
            let (notes_selection, notes) = candidate_notes(root, source.version())?;
            let candidate = CandidateBundle {
                format: "memcordon.prepared-candidate".into(),
                revision: 1,
                source: source.clone(),
                distribution,
                files,
                notes_selection,
                notes,
            };
            source::write_json(&destination.join("candidate.json"), &candidate)?;
            CandidateBundle::load(destination)?;
            let notes = match candidate.notes_selection {
                NotesSelection::ExactVersion => "exact-version",
                NotesSelection::Unreleased => "unreleased",
                NotesSelection::Unavailable => "unavailable",
            };
            crate::workflow_output::write(&[("release-notes", notes.into())])?;
            if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
                let mut summary = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                writeln!(
                    summary,
                    "Candidate preparation of `{}` (`{}`) completed payload validation. Release notes: **{notes}**. Candidate artifacts cannot be published.",
                    candidate.source.commit(),
                    candidate.source.version()
                )?;
            }
        }
    }
    Ok(())
}

fn load_payloads(
    directory: &Path,
    build: &BuildSourceIdentity,
    distribution: &Distribution,
    files: &[FileRecord],
) -> Result<Vec<Vec<u8>>> {
    let mut payloads = Vec::new();
    let mut manifests = std::collections::BTreeMap::new();
    for file in files {
        let bytes = artifacts::read_file(&directory.join(&file.name))?;
        artifacts::check_bytes(file, &bytes)?;
        if file.kind == "archive" {
            let target = distribution
                .targets
                .iter()
                .find(|target| Some(target.target.as_str()) == file.target.as_deref())
                .ok_or_else(|| {
                    CiError::Message("prepared archive target is not selected".into())
                })?;
            let members = super::target::decode_archive(&bytes, &target.target)?;
            let expected: BTreeSet<_> = target
                .binaries
                .iter()
                .map(|name| super::target::binary_name(name, &target.target))
                .chain(target.units.iter().cloned())
                .chain(["runtime-manifest.json".into(), "package.json".into()])
                .collect();
            if members.keys().cloned().collect::<BTreeSet<_>>() != expected {
                return Err(CiError::Message(
                    "prepared archive native inventory differs".into(),
                ));
            }
            let manifest = memcordon_core::runtime_manifest::RuntimeManifest::parse(
                &members["runtime-manifest.json"],
            )
            .map_err(CiError::Message)?;
            super::compatibility::NativePackage::verify(
                &members["package.json"],
                build,
                target,
                &members,
            )?;
            if manifest.version != build.version().to_string()
                || manifest.source_commit != build.commit()
                || manifest.target != target.target
                || manifest.components.len() != target.binaries.len()
            {
                return Err(CiError::Message(
                    "prepared archive runtime source/selection differs".into(),
                ));
            }
            for component in &manifest.components {
                let bytes = members
                    .get(&component.path)
                    .ok_or_else(|| CiError::Message("prepared component absent".into()))?;
                super::target::validate_executable(bytes, &target.target)?;
                if component.size != bytes.len() as u64
                    || component.sha256 != artifacts::checksum(bytes)
                {
                    return Err(CiError::Message(
                        "prepared component byte identity differs".into(),
                    ));
                }
            }
            manifests.insert(target.target.clone(), manifest);
        }
        payloads.push(bytes);
    }
    let manifest = files
        .iter()
        .position(|file| file.kind == "manifest")
        .expect("validated manifest");
    let expected_files = files
        .iter()
        .filter(|file| matches!(file.kind.as_str(), "crate" | "archive" | "compatibility"))
        .cloned()
        .collect::<Vec<_>>();
    memcordon_core::canonical_json::reject_duplicate_json_keys(&payloads[manifest])
        .map_err(CiError::Message)?;
    match build {
        BuildSourceIdentity::Tagged { source } => {
            let public: PublicManifest = serde_json::from_slice(&payloads[manifest])?;
            if public.schema != 1
                || public.version != source.version
                || public.tag != source.version.to_string()
                || public.commit != source.commit
                || public.files != expected_files
            {
                return Err(CiError::Message(
                    "public manifest differs from prepared bytes".into(),
                ));
            }
        }
        BuildSourceIdentity::Working { version, commit } => {
            let candidate: CandidateManifest = serde_json::from_slice(&payloads[manifest])?;
            if candidate.format != "memcordon.candidate-manifest"
                || candidate.revision != 1
                || &candidate.version != version
                || &candidate.commit != commit
                || candidate.files != expected_files
            {
                return Err(CiError::Message(
                    "candidate manifest differs from prepared bytes".into(),
                ));
            }
        }
    }
    let compatibility = files
        .iter()
        .position(|file| file.kind == "compatibility")
        .expect("validated compatibility inventory");
    memcordon_core::canonical_json::reject_duplicate_json_keys(&payloads[compatibility])
        .map_err(CiError::Message)?;
    let supplied: super::compatibility::Compatibility =
        serde_json::from_slice(&payloads[compatibility])?;
    if supplied != super::compatibility::Compatibility::selected(build, distribution, &manifests)? {
        return Err(CiError::Message(
            "public compatibility metadata differs from measured selected runtimes".into(),
        ));
    }
    let checksums = files
        .iter()
        .position(|file| file.kind == "checksums")
        .expect("validated checksums");
    if payloads[checksums] != checksum_file(files.iter().filter(|file| file.kind != "checksums")) {
        return Err(CiError::Message("prepared checksum listing differs".into()));
    }
    let package_files: Vec<_> = files
        .iter()
        .filter(|file| file.kind == "crate")
        .cloned()
        .collect();
    let package_bytes: Vec<_> = files
        .iter()
        .zip(&payloads)
        .filter(|(file, _)| file.kind == "crate")
        .map(|(_, bytes)| bytes.clone())
        .collect();
    let packages = PackageBundle {
        format: "memcordon.packages".into(),
        revision: 1,
        source: build.clone(),
        files: package_files,
    };
    let order = super::packages::archive_order(&packages, &package_bytes)?;
    if packages
        .files
        .iter()
        .filter_map(|file| file.package.as_ref())
        .ne(order.iter())
    {
        return Err(CiError::Message(
            "prepared registry order differs from normalized archives".into(),
        ));
    }
    Ok(payloads)
}

fn validate_inventory(distribution: &Distribution, files: &[FileRecord]) -> Result<()> {
    distribution.validate()?;
    if files.len() > 128 {
        return Err(CiError::Message("prepared file count exceeds bound".into()));
    }
    let mut names = BTreeSet::new();
    let mut packages = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    let mut aggregate = 0_u64;
    for file in files {
        aggregate = aggregate
            .checked_add(file.byte_len)
            .ok_or_else(|| CiError::Message("prepared byte total overflow".into()))?;
        if aggregate > 1024 * 1024 * 1024 {
            return Err(CiError::Message(
                "prepared aggregate byte bound exceeded".into(),
            ));
        }
        artifacts::safe_basename(&file.name)?;
        if !names.insert(file.name.to_ascii_lowercase())
            || file.byte_len == 0
            || file.byte_len > artifacts::MAX_FILE_BYTES
            || file.sha256.len() != hex::encode([0_u8; 32]).len()
            || !file
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(CiError::Message(
                "prepared file name/length/digest differs".into(),
            ));
        }
        match file.kind.as_str() {
            "crate" if file.target.is_none() => {
                let package = file
                    .package
                    .as_ref()
                    .ok_or_else(|| CiError::Message("crate package absent".into()))?;
                if !packages.insert(package.clone()) {
                    return Err(CiError::Message("duplicate prepared package".into()));
                }
            }
            "archive" if file.package.is_none() => {
                let target = file
                    .target
                    .as_ref()
                    .ok_or_else(|| CiError::Message("archive target absent".into()))?;
                if !targets.insert(target.clone()) {
                    return Err(CiError::Message("duplicate prepared target".into()));
                }
            }
            "manifest" | "checksums" | "compatibility"
                if file.package.is_none() && file.target.is_none() =>
            {
                if !kinds.insert(file.kind.clone()) {
                    return Err(CiError::Message("duplicate prepared metadata".into()));
                }
            }
            _ => return Err(CiError::Message("unsupported prepared file kind".into())),
        }
    }
    if packages != distribution.packages.iter().cloned().collect()
        || targets
            != distribution
                .targets
                .iter()
                .map(|target| target.target.clone())
                .collect()
        || kinds
            != BTreeSet::from([
                "manifest".into(),
                "checksums".into(),
                "compatibility".into(),
            ])
    {
        return Err(CiError::Message(
            "incomplete selected release inventory".into(),
        ));
    }
    Ok(())
}
