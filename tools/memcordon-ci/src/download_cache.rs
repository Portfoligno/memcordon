//! Source archives are identified by the acquisition recipe, never a binary hit.
use crate::{
    CiError, Result,
    cache::{CacheEntry, OptionalCache},
    cache_inputs::{KeyInputs, keys},
    command::rustup_cargo,
    release::artifacts,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum DownloadFamily {
    Workspace,
    Fuzz,
    ToolCargoAudit,
    ToolCargoDeny,
    ToolCargoFuzz,
}

impl DownloadFamily {
    pub fn name(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Fuzz => "fuzz",
            Self::ToolCargoAudit => "cargo-audit",
            Self::ToolCargoDeny => "cargo-deny",
            Self::ToolCargoFuzz => "cargo-fuzz",
        }
    }
    pub fn for_purpose(purpose: &str) -> Self {
        match purpose {
            "cargo-audit" => Self::ToolCargoAudit,
            "cargo-deny" => Self::ToolCargoDeny,
            "cargo-fuzz" => Self::ToolCargoFuzz,
            "fuzz" => Self::Fuzz,
            _ => Self::Workspace,
        }
    }
    fn output_keys(self) -> (&'static str, &'static str) {
        match self {
            Self::Workspace => ("workspace-downloads-populated", "workspace-downloads-key"),
            Self::Fuzz => ("fuzz-downloads-populated", "fuzz-downloads-key"),
            Self::ToolCargoAudit => ("download-cargo-audit-populated", "download-cargo-audit-key"),
            Self::ToolCargoDeny => ("download-cargo-deny-populated", "download-cargo-deny-key"),
            Self::ToolCargoFuzz => ("download-cargo-fuzz-populated", "download-cargo-fuzz-key"),
        }
    }
}

// One process owns one top-level CLI invocation. Lanes only append successful
// current-command facts; a later warm binary observation cannot erase them.
static POPULATED: Mutex<BTreeMap<DownloadFamily, String>> = Mutex::new(BTreeMap::new());

pub fn cargo_home(cwd: &Path) -> Result<PathBuf> {
    let home = if let Some(home) = std::env::var_os("CARGO_HOME").filter(|value| !value.is_empty())
    {
        let home = PathBuf::from(home);
        if home.is_absolute() {
            home
        } else {
            cwd.join(home)
        }
    } else {
        default_home()?.join(".cargo")
    };
    if home.to_str().is_none() {
        return Err(CiError::Message("Cargo home not lossless Unicode".into()));
    }
    Ok(home)
}

fn default_home() -> Result<PathBuf> {
    // std uses native Windows profile discovery, unlike a POSIX HOME fallback.
    #[allow(deprecated)]
    std::env::home_dir().ok_or_else(|| CiError::Message("Cargo home unidentified".into()))
}

pub fn bootstrap_home_matches(root: &Path) -> bool {
    let paths = cargo_home(root).and_then(|actual| Ok((actual, default_home()?.join(".cargo"))));
    paths.is_ok_and(|(actual, expected)| {
        actual
            .canonicalize()
            .ok()
            .zip(expected.canonicalize().ok())
            .is_some_and(|(actual, expected)| actual == expected)
    })
}

fn selected(root: &Path, family: DownloadFamily) -> Result<(PathBuf, String)> {
    let pins = crate::config::toolchains(root)?;
    Ok(if family == DownloadFamily::Fuzz {
        (root.join("fuzz"), pins.miri)
    } else {
        (root.to_path_buf(), pins.stable)
    })
}

fn build_context(root: &Path, family: DownloadFamily, deadline: Instant) -> Result<CacheEntry> {
    let (cwd, toolchain) = selected(root, family)?;
    let home = cargo_home(&cwd)?;
    let tool = !matches!(family, DownloadFamily::Workspace | DownloadFamily::Fuzz);
    // Registry installs read configuration beginning at Cargo home, not checkout.
    let configuration = crate::cache_inputs::download_configs(&cwd, tool)?;
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().to_ascii_uppercase();
        if name == "CARGO_BUILD_TARGET"
            || name.starts_with("CARGO_SOURCE_")
            || name.starts_with("CARGO_REGISTRIES_")
            || name.starts_with("CARGO_REGISTRY_")
        {
            return Err(CiError::Message(
                "unmodeled download acquisition override".into(),
            ));
        }
    }
    let reader = rustup_cargo(&cwd, &toolchain, ["-V"], Duration::from_secs(30))
        .bootstrap_environment()
        .bounded_until(deadline)
        .defer_group_failure()
        .output_quiet()?;
    crate::command::require_successful_output("download Cargo reader", &reader)?;
    let reader = String::from_utf8(reader.stdout)
        .map_err(|_| CiError::Message("Cargo reader identity not UTF-8".into()))?;
    let mut compatibility = configuration;
    compatibility.insert("download-family".into(), family.name().into());
    compatibility.insert("archive-os".into(), std::env::consts::OS.into());
    compatibility.insert("cargo-reader".into(), reader);
    compatibility.insert("toolchain".into(), toolchain);
    compatibility.insert(
        "recipe".into(),
        if tool {
            "registry-install-locked-default-features-native"
        } else {
            "fetch-locked-all-targets"
        }
        .into(),
    );
    let mut content = BTreeMap::new();
    if tool {
        compatibility.insert(
            "native-target".into(),
            crate::release::distribution::native_target()?.into(),
        );
        let pins = crate::config::tools(root)?;
        let pin = match family {
            DownloadFamily::ToolCargoAudit => pins.cargo_audit,
            DownloadFamily::ToolCargoDeny => pins.cargo_deny,
            DownloadFamily::ToolCargoFuzz => pins.cargo_fuzz,
            _ => unreachable!(),
        };
        content.insert("version".into(), pin);
        content.insert("package".into(), family.name().into());
    } else {
        // Manifest bytes define the locked fetch; unrelated local source does not.
        let manifest: toml::Value =
            toml::from_str(&std::fs::read_to_string(root.join("Cargo.toml"))?)?;
        let members = manifest["workspace"]["members"]
            .as_array()
            .ok_or_else(|| CiError::Message("workspace members absent".into()))?;
        let mut manifests = vec![root.join("Cargo.toml"), cwd.join("Cargo.lock")];
        if family == DownloadFamily::Fuzz {
            manifests.push(cwd.join("Cargo.toml"));
        }
        for member in members {
            let member = member
                .as_str()
                .ok_or_else(|| CiError::Message("invalid workspace member".into()))?;
            manifests.push(root.join(member).join("Cargo.toml"));
        }
        for path in manifests {
            content.insert(
                path.strip_prefix(root)
                    .map_err(|_| CiError::Message("manifest outside workspace".into()))?
                    .display()
                    .to_string(),
                artifacts::checksum(&artifacts::read_file(&path)?),
            );
        }
    }
    let (exact_key, prefix) = keys(&KeyInputs {
        family: "downloads".into(),
        layout_revision: 5,
        compatibility,
        content,
    })?;
    Ok(CacheEntry {
        exact_key,
        restore_prefix: Some(prefix),
        paths: vec![home.join("registry/cache"), home.join("git/db")],
    })
}

pub fn context(root: &Path, family: DownloadFamily) -> Result<OptionalCache> {
    context_until(root, family, Instant::now() + Duration::from_secs(30))
}

pub fn context_until(
    root: &Path,
    family: DownloadFamily,
    deadline: Instant,
) -> Result<OptionalCache> {
    optional_context_result(family, build_context(root, family, deadline))
}

pub(crate) fn optional_context_result(
    family: DownloadFamily,
    result: Result<CacheEntry>,
) -> Result<OptionalCache> {
    match result {
        Ok(entry) => Ok(OptionalCache::Available { entry }),
        Err(error) if crate::work_outcome::has_unresolved_owner(&error) => Err(error),
        Err(error) => {
            eprintln!("download family {} unavailable: {error}", family.name());
            Ok(OptionalCache::Unavailable {
                reason: "unmodeled acquisition inputs or Cargo home".into(),
            })
        }
    }
}

pub fn emit(root: &Path, family: DownloadFamily) -> Result<()> {
    let entry = context(root, family)?;
    let available = match &entry {
        OptionalCache::Available { entry } => Some(entry),
        _ => None,
    };
    crate::workflow_output::write(&[
        (
            "source-key",
            available.map_or_else(String::new, |entry| entry.exact_key.clone()),
        ),
        (
            "source-restore-prefix",
            available
                .and_then(|entry| entry.restore_prefix.clone())
                .unwrap_or_default(),
        ),
        (
            "source-paths",
            available
                .map(|entry| crate::workflow_output::action_paths(&entry.paths))
                .transpose()?
                .unwrap_or_default(),
        ),
        (
            "bootstrap-home-matches",
            bootstrap_home_matches(root).to_string(),
        ),
    ])?;
    println!("{}", serde_json::to_string_pretty(&entry)?);
    Ok(())
}

pub fn record(family: DownloadFamily, before: &OptionalCache, after: &OptionalCache) {
    if let (OptionalCache::Available { entry: before }, OptionalCache::Available { entry: after }) =
        (before, after)
        && before.exact_key == after.exact_key
        && before.paths == after.paths
    {
        POPULATED
            .lock()
            .expect("population mutex poisoned")
            .insert(family, before.exact_key.clone());
    }
}

/// Successful `--locked` installation alone may warn and proceed without a
/// packaged lockfile. Inspect the actual acquired registry archive before
/// publishing this recipe's completeness claim.
pub fn packaged_lock_present(root: &Path, package: &str, version: &str) -> Result<bool> {
    let cache = cargo_home(root)?.join("registry/cache");
    if !cache.is_dir() {
        return Ok(false);
    }
    let filename = format!("{package}-{version}.crate");
    let expected = PathBuf::from(format!("{package}-{version}")).join("Cargo.lock");
    for (index, directory) in std::fs::read_dir(cache)?.enumerate() {
        if index >= 64 {
            return Err(CiError::Message("registry directory bound exceeded".into()));
        }
        let directory = directory?;
        // Cargo's two standard crates.io archive namespaces for the modeled
        // reader/layout. A same-name package in an unrelated registry cannot
        // establish that this default-registry installation had a lockfile.
        if !matches!(
            directory.file_name().to_str(),
            Some("index.crates.io-1949cf8c6b5b557f" | "github.com-1ecc6299db9ec823")
        ) {
            continue;
        }
        if !directory.file_type()?.is_dir() {
            continue;
        }
        let path = directory.path().join(&filename);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 32 * 1024 * 1024
        {
            return Ok(false);
        }
        let bytes = artifacts::read_file(&path)?;
        let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
        let mut archive = tar::Archive::new(std::io::Read::take(decoder, 64 * 1024 * 1024));
        for (index, entry) in archive.entries()?.enumerate() {
            if index >= 10_000 {
                return Ok(false);
            }
            let entry = entry?;
            if entry.path()?.as_ref() == expected
                && entry.header().entry_type().is_file()
                && entry.size() > 0
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn flush() -> Result<()> {
    let facts = POPULATED.lock().expect("population mutex poisoned");
    let mut outputs = Vec::new();
    for (family, key) in facts.iter() {
        let (populated, key_output) = family.output_keys();
        outputs.push((populated, "true".into()));
        outputs.push((key_output, key.clone()));
    }
    crate::workflow_output::write(&outputs)
}

pub fn populated_key(family: DownloadFamily) -> Option<String> {
    POPULATED
        .lock()
        .expect("population mutex poisoned")
        .get(&family)
        .cloned()
}

pub fn fetch_until(
    root: &Path,
    family: DownloadFamily,
    deadline: Instant,
    report: Option<&Path>,
) -> Result<()> {
    if !matches!(family, DownloadFamily::Workspace | DownloadFamily::Fuzz) {
        return Err(CiError::Message(
            "tool downloads require actual installation".into(),
        ));
    }
    let before = context_until(root, family, deadline)?;
    let (cwd, toolchain) = selected(root, family)?;
    let command = rustup_cargo(
        &cwd,
        &toolchain,
        ["fetch", "--locked"],
        crate::preparation::remaining(deadline, Duration::from_secs(900))?,
    )
    .bounded_until(deadline);
    if let Some(report) = report {
        crate::preparation::observed(
            command,
            report,
            match family {
                DownloadFamily::Workspace => "workspace-fetch",
                DownloadFamily::Fuzz => "fuzz-fetch",
                _ => unreachable!(),
            },
        )?;
    } else {
        command.run()?;
    }
    record(family, &before, &context_until(root, family, deadline)?);
    Ok(())
}
