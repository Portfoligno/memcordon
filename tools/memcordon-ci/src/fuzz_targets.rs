use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FuzzShard {
    First,
    Second,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CharterRegistry {
    pub schema: u32,
    pub targets: Vec<Charter>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Charter {
    pub id: String,
    pub bin: String,
    pub production_unit: String,
    pub class: String,
    pub invariants: Vec<String>,
    pub max_input_bytes: usize,
    pub timeout_class: String,
    pub corpus_owner: String,
    pub seed_directory: String,
    pub artifact_retention_days: u16,
    pub aliases: Vec<String>,
    pub shard: FuzzShard,
    pub hosts: Vec<String>,
    pub import_mode: String,
    pub parity_required: bool,
}

fn invalid(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}

fn component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

impl Charter {
    /// Stable ordinal IDs preserve shard placement when a binary is renamed or added.
    pub fn derived_shard(&self) -> Result<FuzzShard> {
        // PROV-05 reserves this public triage identity for the canonical survivor.
        // Keep its original first-shard slot through binary renames and migration.
        if self.id == "agent-package-inspection" {
            return Ok(FuzzShard::First);
        }
        let number = self
            .id
            .strip_prefix("fuzz-")
            .and_then(|id| id.parse::<u32>().ok())
            .filter(|number| *number > 0)
            .ok_or_else(|| {
                invalid("fuzz charter ID must be fuzz- followed by a positive ordinal")
            })?;
        if self.id.strip_prefix("fuzz-") != Some(number.to_string().as_str()) {
            return Err(invalid(
                "fuzz charter ordinal must use canonical decimal spelling",
            ));
        }
        Ok(if number % 2 == 1 {
            FuzzShard::First
        } else {
            FuzzShard::Second
        })
    }

    /// Closed argument vocabulary keeps dynamic values out of concatenated flags.
    pub fn max_length_argument(&self) -> Result<&'static str> {
        match self.max_input_bytes {
            4096 => Ok("-max_len=4096"),
            65_536 => Ok("-max_len=65536"),
            1_048_576 => Ok("-max_len=1048576"),
            _ => Err(invalid("unsupported fuzz input bound")),
        }
    }

    pub fn corpus_directory(&self, root: &Path) -> PathBuf {
        root.join("target/ci/fuzz-corpus").join(&self.id)
    }

    pub fn artifact_directory(&self, root: &Path) -> PathBuf {
        root.join("target/ci/reports/fuzz").join(&self.id)
    }
}

impl CharterRegistry {
    pub fn parse(manifest: &str, charters: &str) -> Result<Self> {
        let registry: Self = toml::from_str(charters)?;
        if registry.schema != 1 || registry.targets.is_empty() {
            return Err(invalid("unsupported or empty fuzz charter registry"));
        }
        let bins: BTreeSet<_> = targets(manifest, None)?.into_iter().collect();
        let mut ids = BTreeSet::new();
        let mut declared = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        for charter in &registry.targets {
            if !component(&charter.id)
                || !component(&charter.bin)
                || !ids.insert(&charter.id)
                || !declared.insert(charter.bin.clone())
            {
                return Err(invalid("duplicate or invalid fuzz charter ID/bin"));
            }
            if charter.shard != charter.derived_shard()? {
                return Err(invalid(
                    "declared fuzz shard differs from stable charter ID",
                ));
            }
            charter.max_length_argument()?;
            if charter.timeout_class != "smoke-30-seconds" || charter.artifact_retention_days != 90
            {
                return Err(invalid(
                    "fuzz timeout or artifact retention differs from managed lane",
                ));
            }
            if !["parser", "state", "roundtrip", "cross-field", "policy"]
                .contains(&charter.class.as_str())
                || !["direct", "shared-source"].contains(&charter.import_mode.as_str())
                || (charter.import_mode == "shared-source") != charter.parity_required
            {
                return Err(invalid(
                    "invalid fuzz class or compilation-parity declaration",
                ));
            }
            if charter.production_unit.trim().is_empty()
                || charter.corpus_owner.trim().is_empty()
                || charter.invariants.is_empty()
                || charter
                    .invariants
                    .iter()
                    .any(|value| value.trim().is_empty() || value == "no-panic")
                || charter.invariants.iter().collect::<BTreeSet<_>>().len()
                    != charter.invariants.len()
            {
                return Err(invalid("fuzz charter lacks owned production invariants"));
            }
            if !relative_path(&charter.seed_directory)
                || !Path::new(&charter.seed_directory).starts_with("fuzz/seeds")
            {
                return Err(invalid(
                    "fuzz seed directory must be beneath checked-in fuzz/seeds",
                ));
            }
            if charter.hosts.is_empty()
                || charter.hosts.iter().collect::<BTreeSet<_>>().len() != charter.hosts.len()
                || charter.hosts.iter().any(|host| {
                    !["linux-x64", "linux-arm64", "macos-x64", "macos-arm64"]
                        .contains(&host.as_str())
                })
            {
                return Err(invalid("invalid or empty supported fuzz hosts"));
            }
            for alias in &charter.aliases {
                if !component(alias) || bins.contains(alias) || !aliases.insert(alias) {
                    return Err(invalid(
                        "fuzz alias is invalid, ambiguous, or still an active binary",
                    ));
                }
            }
        }
        if declared != bins {
            return Err(invalid(
                "fuzz charters must cover every Cargo binary exactly once",
            ));
        }
        Ok(registry)
    }

    pub fn load(root: &Path) -> Result<Self> {
        Self::parse(
            &fs::read_to_string(root.join("fuzz/Cargo.toml"))?,
            &fs::read_to_string(root.join("fuzz/targets.toml"))?,
        )
    }

    pub fn selected(&self, shard: Option<FuzzShard>, host: &str) -> Result<Vec<&Charter>> {
        let mut selected: Vec<_> = self
            .targets
            .iter()
            .filter(|target| shard.is_none() || shard == Some(target.shard))
            .collect();
        selected.sort_by(|left, right| left.id.cmp(&right.id));
        if selected.is_empty()
            || selected
                .iter()
                .any(|target| !target.hosts.iter().any(|allowed| allowed == host))
        {
            return Err(invalid(
                "empty fuzz shard or unsupported host; coverage cannot be silently skipped",
            ));
        }
        Ok(selected)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CorpusEntry {
    pub sha256: String,
    pub bytes: usize,
}

/// Merge immutable seed/alias inputs by content identity, preserving source files.
/// Symlinks and nonregular entries cannot redirect corpus reads or writes.
pub fn merge_corpora(
    sources: &[PathBuf],
    destination: &Path,
    max_bytes: usize,
) -> Result<Vec<CorpusEntry>> {
    for ancestor in destination.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid("corpus destination ancestor cannot be a symlink"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::create_dir_all(destination)?;
    if fs::symlink_metadata(destination)?.file_type().is_symlink() {
        return Err(invalid("corpus destination cannot be a symlink"));
    }
    let mut entries = std::collections::BTreeMap::new();
    for source in sources {
        // Snapshot names before writing so restored corpus directories may also
        // be an input without walking files created by this merge itself.
        let inventory = walkdir::WalkDir::new(source)
            .follow_links(false)
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| invalid(error.to_string()))?;
        for entry in inventory {
            if entry.file_type().is_dir() {
                continue;
            }
            if !entry.file_type().is_file() {
                return Err(invalid("corpus input is not a regular file"));
            }
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let file = options.open(entry.path())?;
            if !file.metadata()?.is_file() {
                return Err(invalid("opened corpus input is not a regular file"));
            }
            let mut bytes = Vec::new();
            use std::io::Read;
            file.take(
                u64::try_from(max_bytes)
                    .map_err(|_| invalid("unsupported corpus bound"))?
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)?;
            if bytes.len() > max_bytes {
                return Err(invalid("corpus input exceeds declared target maximum"));
            }
            let sha256 = hex::encode(Sha256::digest(&bytes));
            let path = destination.join(&sha256);
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    file.write_all(&bytes)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(&path)?;
                    if !metadata.file_type().is_file()
                        || metadata.len() != bytes.len() as u64
                        || fs::read(&path)? != bytes
                    {
                        return Err(invalid(
                            "existing corpus digest path has different contents or object type",
                        ));
                    }
                }
                Err(error) => return Err(error.into()),
            }
            entries.insert(
                sha256.clone(),
                CorpusEntry {
                    sha256,
                    bytes: bytes.len(),
                },
            );
        }
    }
    Ok(entries.into_values().collect())
}

pub fn prepare_corpus(root: &Path, charter: &Charter) -> Result<Vec<CorpusEntry>> {
    let mut sources = vec![root.join(&charter.seed_directory)];
    let destination = charter.corpus_directory(root);
    if destination.try_exists()? {
        sources.push(destination.clone());
    }
    for name in std::iter::once(&charter.bin).chain(&charter.aliases) {
        let path = root.join("fuzz/corpus").join(name);
        if path.try_exists()? {
            sources.push(path);
        }
    }
    let entries = merge_corpora(&sources, &destination, charter.max_input_bytes)?;
    if entries.is_empty() {
        return Err(invalid("fuzz target has no declared seed corpus"));
    }
    Ok(entries)
}

/// Preserve historical crash names at their original paths and copy their bytes
/// into the stable charter namespace. This does not retire an alias or certify replay.
pub fn preserve_artifacts(root: &Path, charter: &Charter) -> Result<Vec<CorpusEntry>> {
    let mut sources = Vec::new();
    for name in std::iter::once(&charter.bin).chain(&charter.aliases) {
        let path = root.join("fuzz/artifacts").join(name);
        if path.try_exists()? {
            sources.push(path);
        }
    }
    merge_corpora(
        &sources,
        &charter.artifact_directory(root),
        charter.max_input_bytes,
    )
}

#[derive(Debug, Serialize)]
pub struct TargetEvidence<'a> {
    pub schema: u32,
    pub charter: &'a Charter,
    pub phase: &'a str,
    pub corpus: &'a [CorpusEntry],
    pub artifacts: &'a [CorpusEntry],
    pub failure: Option<String>,
}

pub fn write_evidence(root: &Path, evidence: &TargetEvidence<'_>) -> Result<()> {
    let directory = evidence.charter.artifact_directory(root);
    fs::create_dir_all(&directory)?;
    let mut bytes = serde_json::to_vec_pretty(evidence)?;
    bytes.push(b'\n');
    fs::write(directory.join("evidence.json"), bytes)?;
    Ok(())
}

pub fn finish_target(
    root: &Path,
    charter: &Charter,
    corpus: &[CorpusEntry],
    command: Result<()>,
) -> Result<()> {
    let artifacts = preserve_artifacts(root, charter);
    let failure = match (command.as_ref().err(), artifacts.as_ref().err()) {
        (Some(command), Some(artifacts)) => Some(format!(
            "command: {command}; artifact preservation: {artifacts}"
        )),
        (Some(command), None) => Some(command.to_string()),
        (None, Some(artifacts)) => Some(format!("artifact preservation: {artifacts}")),
        (None, None) => None,
    };
    write_evidence(
        root,
        &TargetEvidence {
            schema: 1,
            charter,
            phase: if artifacts.is_err() {
                "artifact-preservation-failed"
            } else if command.is_err() {
                "failed"
            } else {
                "passed"
            },
            corpus,
            artifacts: artifacts.as_deref().unwrap_or_default(),
            failure,
        },
    )?;
    artifacts?;
    command
}

pub fn validate(root: &Path) -> Result<()> {
    let registry = CharterRegistry::load(root)?;
    let manifest: toml::Value = toml::from_str(&fs::read_to_string(root.join("fuzz/Cargo.toml"))?)?;
    struct SharedSource(bool);
    fn shared_source_meta(meta: &syn::Meta) -> bool {
        if meta.path().is_ident("path") {
            return true;
        }
        if let syn::Meta::List(list) = meta
            && list.path.is_ident("cfg_attr")
        {
            let parse = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
            return syn::parse::Parser::parse2(parse, list.tokens.clone())
                .map(|arguments| arguments.iter().skip(1).any(shared_source_meta))
                .unwrap_or(true);
        }
        false
    }
    impl<'ast> syn::visit::Visit<'ast> for SharedSource {
        fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
            self.0 |= shared_source_meta(&attribute.meta);
            syn::visit::visit_attribute(self, attribute);
        }
        fn visit_macro(&mut self, value: &'ast syn::Macro) {
            self.0 |= value.path.is_ident("include");
            syn::visit::visit_macro(self, value);
        }
    }
    for charter in &registry.targets {
        let seed = root.join(&charter.seed_directory);
        if !fs::symlink_metadata(&seed)?.file_type().is_dir() {
            return Err(invalid("fuzz seed directory is not a real directory"));
        }
        let mut count = 0;
        for entry in fs::read_dir(&seed)? {
            let metadata = fs::symlink_metadata(entry?.path())?;
            if !metadata.file_type().is_file() || metadata.len() > charter.max_input_bytes as u64 {
                return Err(invalid(
                    "fuzz seed is nonregular or exceeds declared input class",
                ));
            }
            count += 1;
        }
        if count == 0 {
            return Err(invalid(
                "fuzz charter checked-in seed directory is absent or empty",
            ));
        }
        let bin = manifest["bin"]
            .as_array()
            .expect("validated explicit bin inventory")
            .iter()
            .find(|bin| bin["name"].as_str() == Some(&charter.bin))
            .expect("exact charter coverage");
        let path = bin["path"]
            .as_str()
            .filter(|value| relative_path(value))
            .ok_or_else(|| invalid("fuzz binary source path must be relative"))?;
        let syntax = syn::parse_file(&fs::read_to_string(root.join("fuzz").join(path))?)
            .map_err(|error| invalid(error.to_string()))?;
        let mut shared = SharedSource(false);
        syn::visit::Visit::visit_file(&mut shared, &syntax);
        if shared.0 != charter.parity_required {
            return Err(invalid(
                "fuzz harness source inclusion differs from its compilation-parity declaration",
            ));
        }
    }
    Ok(())
}

/// Cargo's explicit bin inventory is the single source of fuzz coverage.
pub fn targets(manifest: &str, shard: Option<FuzzShard>) -> Result<Vec<String>> {
    let document: toml::Value = toml::from_str(manifest)?;
    let bins = document
        .get("bin")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| CiError::Message("fuzz manifest has no explicit bin inventory".into()))?;
    let mut names = BTreeSet::new();
    for bin in bins {
        let name = bin
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
            .ok_or_else(|| CiError::Message("fuzz bin has an invalid name".into()))?;
        if !names.insert(name.to_owned()) {
            return Err(CiError::Message(
                "fuzz bin inventory contains duplicate names".into(),
            ));
        }
    }
    let selected: Vec<_> = names
        .into_iter()
        .enumerate()
        .filter_map(|(index, name)| {
            // Sorted alternating targets distribute the observed expensive harnesses.
            let first = index % 2 == 0;
            (shard.is_none() || first == (shard == Some(FuzzShard::First))).then_some(name)
        })
        .collect();
    if selected.is_empty() {
        return Err(CiError::Message("fuzz selection is empty".into()));
    }
    Ok(selected)
}
