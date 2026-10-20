//! Job-local ordinary Cargo sources. Only `build/` is ever a transport member.
//!
//! Rollout: on each native target run `cargo test -p memcordon-ci --test
//! ordinary_consumer_cache actual_packaged_ordinary_consumer_round_trip_reuses_only_registry_dependencies
//! -- --ignored --exact`. Review its real registry freshness, local rebuilding,
//! immutable package and fresh binary-install assertions before adding that exact
//! native target and pinned toolchain tuple to `VALIDATED_NATIVE_TARGETS`. Never activate through environment
//! variables or persisted success files. Rerun after compiler/layout changes.
use super::{artifacts, distribution, packages::PackageConsumer, source, target::TargetBundle};
use crate::{CiError, Result, cache_inputs::KeyInputs, cache_restore::RestoreMode};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const SLOT_MARKER: &str = "memcordon ordinary consumer slot 6\n";
const BUILD_MARKER: &str = "memcordon ordinary consumer build 6\n";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ConsumerBuildLayout {
    #[default]
    Ephemeral,
    StableOrdinary,
}

/// Closed selection at the dispatcher, before any slot or cache mutation.
pub fn validate_selection(
    layout: ConsumerBuildLayout,
    cargo: bool,
    ordinary: bool,
    external: bool,
) -> Result<()> {
    if layout == ConsumerBuildLayout::StableOrdinary && (!cargo || !ordinary || external) {
        return Err(CiError::Message("stable-ordinary requires the ordinary prepublication Cargo channel without external input".into()));
    }
    Ok(())
}

pub struct OrdinarySlot {
    directory: PathBuf,
    source: PathBuf,
    build: PathBuf,
    _lock: fs::File,
    _build_lock: fs::File,
}

impl OrdinarySlot {
    pub fn source(&self) -> &Path {
        &self.source
    }
    pub fn cargo_home(&self) -> PathBuf {
        self.directory.join("cargo-home")
    }
    pub fn install(&self) -> PathBuf {
        self.directory.join("install")
    }
    pub fn build(&self) -> &Path {
        &self.build
    }
    /// Record this family's layout after real Cargo produced its genuine marker.
    pub fn mark_build_layout(&self) -> Result<()> {
        if !fs::read(self.build.join("CACHEDIR.TAG"))?
            .starts_with(b"Signature: 8a477f597d28d172789f06886806bc55")
        {
            return Err(CiError::Message(
                "ordinary build lacks genuine Cargo marker".into(),
            ));
        }
        fs::write(self.build.join("ordinary-layout"), BUILD_MARKER)?;
        Ok(())
    }
    fn context(&self) -> PathBuf {
        self.directory.join("coordination").join("context.json")
    }

    pub fn open(root: &Path, target: &str) -> Result<Self> {
        let temporary = std::env::var_os("RUNNER_TEMP").ok_or_else(|| {
            CiError::Message("stable ordinary consumer requires RUNNER_TEMP".into())
        })?;
        Self::open_at(root, Path::new(&temporary), target)
    }

    /// Explicit path seam for ownership tests; production always uses RUNNER_TEMP.
    pub fn open_at(root: &Path, temporary: &Path, target: &str) -> Result<Self> {
        if target != distribution::native_target()? {
            return Err(CiError::Message(
                "ordinary consumer requires actual native target".into(),
            ));
        }
        validate_ancestry(temporary)?;
        let temporary = temporary.canonicalize()?;
        let directory = crate::cache_restore::safe_root(
            &temporary,
            &PathBuf::from("memcordon-ordinary-consumer").join(target),
        )?;
        fs::create_dir_all(&directory)?;
        let lock_path = directory.join("owner.lock");
        if lock_path.try_exists()? && !fs::symlink_metadata(&lock_path)?.is_file() {
            return Err(CiError::Message("unsafe ordinary slot lock".into()));
        }
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let lock = options.open(&lock_path)?;
        #[cfg(unix)]
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| CiError::Message("ordinary consumer slot Busy".into()))?;
        let marker = directory.join("slot-layout");
        if marker.try_exists()? {
            if fs::read_to_string(&marker)? != SLOT_MARKER {
                return Err(CiError::Message("ordinary slot layout differs".into()));
            }
        } else {
            if fs::read_dir(&directory)?.count() != 1 {
                return Err(CiError::Message(
                    "unowned ordinary consumer leftovers".into(),
                ));
            }
            fs::write(&marker, SLOT_MARKER)?;
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if !matches!(
                entry.file_name().to_str(),
                Some(
                    "owner.lock"
                        | "slot-layout"
                        | "source"
                        | "cargo-home"
                        | "install"
                        | "coordination"
                )
            ) {
                return Err(CiError::Message("unexpected ordinary slot content".into()));
            }
        }
        fs::create_dir_all(directory.join("coordination"))?;
        let build = crate::cache_restore::safe_root(
            root,
            &PathBuf::from("target/ci-consumer-build/ordinary")
                .join(target)
                .join("build"),
        )?;
        let build_parent = build.parent().expect("fixed build parent");
        fs::create_dir_all(build_parent)?;
        let build_lock_path = build_parent.join("owner.lock");
        if build_lock_path.try_exists()?
            && (fs::symlink_metadata(&build_lock_path)?
                .file_type()
                .is_symlink()
                || !fs::symlink_metadata(&build_lock_path)?.is_file())
        {
            return Err(CiError::Message(
                "unsafe ordinary build ownership lock".into(),
            ));
        }
        let build_lock = options.open(build_lock_path)?;
        #[cfg(unix)]
        rustix::fs::flock(
            &build_lock,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| CiError::Message("ordinary consumer build Busy".into()))?;
        Ok(Self {
            source: directory.join("source"),
            directory,
            build,
            _lock: lock,
            _build_lock: build_lock,
        })
    }

    fn reset_sources(&self) -> Result<()> {
        let _settled = crate::cache_restore::settled_locks(std::slice::from_ref(&self.build))?;
        // Installations are never recursively erased as cache sanitation.
        if self.install().try_exists()? {
            return Err(CiError::Message(
                "ordinary install state remains; recover the failed invocation before reuse".into(),
            ));
        }
        let prior = if self.context().try_exists()? {
            Some(read_state(&self.context())?)
        } else {
            None
        };
        for path in [&self.source, &self.cargo_home()] {
            if path.try_exists()? {
                if prior.is_none() {
                    return Err(CiError::Message(
                        "abandoned ordinary source/home without context".into(),
                    ));
                }
                let relative = path.strip_prefix(&self.directory).expect("owned child");
                crate::cache_restore::safe_root(&self.directory, relative)?;
            }
        }
        if let Some(prior) = prior {
            verify_files(&self.source, &prior.files)?;
        }
        for path in [&self.source, &self.cargo_home()] {
            if path.try_exists()? {
                fs::remove_dir_all(path)?;
            }
        }
        fs::create_dir(&self.source)?;
        Ok(())
    }
}

fn validate_ancestry(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(CiError::Message("RUNNER_TEMP must be absolute".into()));
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CiError::Message("unsafe RUNNER_TEMP ancestry".into()));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(CiError::Message("RUNNER_TEMP reparse ancestry".into()));
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotContext {
    revision: u32,
    key: String,
    prefix: String,
    files: BTreeMap<PathBuf, String>,
    inputs: BTreeMap<String, String>,
    completed: bool,
    compatibility: BTreeMap<String, String>,
}

fn read_state(path: &Path) -> Result<SlotContext> {
    let bytes = artifacts::read_file(path)?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(CiError::Message("ordinary context exceeds bounds".into()));
    }
    let state: SlotContext = serde_json::from_slice(&bytes)?;
    if state.revision != 6 {
        return Err(CiError::Message("ordinary context layout differs".into()));
    }
    Ok(state)
}

fn files(root: &Path) -> Result<BTreeMap<PathBuf, String>> {
    crate::cache_restore::safe_root(
        root.parent()
            .ok_or_else(|| CiError::Message("source parent absent".into()))?,
        Path::new("source"),
    )?;
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
        if entry.file_type().is_file() {
            let bytes = artifacts::read_file(entry.path())?;
            total += bytes.len() as u64;
            if files.len() >= 50_000 || total > 512 * 1024 * 1024 {
                return Err(CiError::Message("ordinary source exceeds bounds".into()));
            }
            files.insert(
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("source child")
                    .to_owned(),
                artifacts::checksum(&bytes),
            );
        }
    }
    Ok(files)
}

fn verify_files(root: &Path, expected: &BTreeMap<PathBuf, String>) -> Result<()> {
    if files(root)? != *expected {
        return Err(CiError::Message("ordinary source/context changed".into()));
    }
    Ok(())
}

fn compatibility(root: &Path, slot: &OrdinarySlot) -> Result<BTreeMap<String, String>> {
    let context = crate::cache::context_partition(
        root,
        "native-release",
        "ordinary-consumer",
        &[],
        Some(crate::cache_restore::CompiledPartition::NativeTests),
    )?;
    let available = context.usable;
    let mut compatibility = context.inputs;
    compatibility.insert("native-available".into(), available.to_string());
    // Packaged source bytes, not the unrelated checkout source, select exact content.
    for key in ["lock", "distribution", "purpose", "shard"] {
        compatibility.remove(key);
    }
    compatibility.extend(crate::cache_inputs::cargo_configs_with_home(
        slot.source(),
        &slot.cargo_home(),
        Some(distribution::native_target()?),
    )?);
    for (name, path) in [
        ("checkout", root.canonicalize()?),
        ("source", slot.source.canonicalize()?),
        ("cargo-home", slot.cargo_home().canonicalize()?),
        (
            "registry-source",
            slot.cargo_home().join("registry").join("src"),
        ),
        ("build", slot.build.clone()),
    ] {
        compatibility.insert(name.into(), path.display().to_string());
    }
    compatibility.insert(
        "recipe".into(),
        "ordinary:test+run:dev;install:release;explicit-native;isolated-home;source-seed-v1".into(),
    );
    for relative in [
        "tools/memcordon-ci/src/release/packages.rs",
        "tools/memcordon-ci/src/release/ordinary_consumer_cache.rs",
        "tools/memcordon-ci/src/command.rs",
    ] {
        compatibility.insert(
            format!("harness:{relative}"),
            artifacts::checksum(&artifacts::read_file(&root.join(relative))?),
        );
    }
    Ok(compatibility)
}

fn identity(root: &Path, consumer: &PackageConsumer, slot: &OrdinarySlot) -> Result<SlotContext> {
    let compatibility = compatibility(root, slot)?;
    let inputs = consumer.ordinary_input_identity()?;
    let files = files(slot.source())?;
    make_state(compatibility, inputs, files)
}

fn make_state(
    compatibility: BTreeMap<String, String>,
    inputs: BTreeMap<String, String>,
    files: BTreeMap<PathBuf, String>,
) -> Result<SlotContext> {
    let mut content = inputs.clone();
    for (path, digest) in &files {
        content.insert(format!("source:{}", path.display()), digest.clone());
    }
    let (key, prefix) = crate::cache_inputs::keys(&KeyInputs {
        family: "consumer".into(),
        layout_revision: 6,
        compatibility: compatibility.clone(),
        content,
    })?;
    Ok(SlotContext {
        revision: 6,
        key,
        prefix,
        files,
        inputs,
        completed: false,
        compatibility,
    })
}

/// Recompute the graph and input bytes without recreating any tested source/home/install.
fn current_inputs(
    root: &Path,
    slot: &OrdinarySlot,
    bundle: &super::packages::PackageBundle,
    distribution: &super::distribution::TargetDistribution,
) -> Result<BTreeMap<String, String>> {
    let manifest = slot.source.join("consumer").join("Cargo.toml");
    let config = slot.source.join("package-overrides.toml");
    let cli = slot.source.join("install-source").join("Cargo.toml");
    let mut inputs = BTreeMap::new();
    for file in [
        &manifest,
        &config,
        &manifest.with_file_name("Cargo.lock"),
        &cli.with_file_name("Cargo.lock"),
    ] {
        inputs.insert(
            file.display().to_string(),
            artifacts::checksum(&artifacts::read_file(file)?),
        );
    }
    let stable = crate::config::toolchains(root)?.stable;
    for (name, manifest, install) in [
        ("consumer-graph", &manifest, false),
        ("install-graph", &cli, true),
    ] {
        let mut command = crate::command::rustup_cargo(
            manifest.parent().expect("manifest parent"),
            &stable,
            ["metadata", "--locked", "--format-version", "1"],
            std::time::Duration::from_secs(300),
        )
        .isolated_cargo(&slot.cargo_home())
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--config")
        .arg(&config)
        .arg("--filter-platform")
        .arg(&distribution.target);
        if install {
            for feature in &distribution.features {
                command = command.arg("--features").arg(feature);
            }
        }
        let output = command.output_quiet()?;
        if !output.status.success() {
            return Err(CiError::Message(
                "ordinary save graph verification failed".into(),
            ));
        }
        let metadata: cargo_metadata::Metadata = serde_json::from_slice(&output.stdout)?;
        inputs.insert(
            name.into(),
            serde_json::to_string(&Some(super::packages::resolved_graph(&metadata)?))?,
        );
    }
    for record in &bundle.files {
        inputs.insert(record.name.clone(), record.sha256.clone());
    }
    Ok(inputs)
}

fn selected(
    root: &Path,
    target: &Path,
    packages: &Path,
) -> Result<super::distribution::TargetDistribution> {
    let (native, _) = TargetBundle::load(target)?;
    let (crates, _) = super::packages::PackageBundle::load(packages)?;
    if native.source != crates.source {
        return Err(CiError::Message(
            "ordinary consumer artifact sources differ".into(),
        ));
    }
    native.source.recheck(root)?;
    if native.distribution.target != distribution::native_target()? {
        return Err(CiError::Message(
            "ordinary consumer artifact target differs".into(),
        ));
    }
    let ordinary = distribution::Distribution::read(root)?.native()?.clone();
    if serde_json::to_value(&native.distribution)? != serde_json::to_value(&ordinary)? {
        return Err(CiError::Message(
            "ordinary consumer distribution differs (readiness/capture is ephemeral)".into(),
        ));
    }
    Ok(native.distribution)
}

/// Until a target's real four-package round trip is run, it remains cold.
// Actual four-package archive/build/install round trip: c4bda6e1, 124.47s.
// rustc 1.97.1 (8bab26f4f), Cargo 1.97.1 (c980f4866), native Apple ARM64.
const VALIDATED_NATIVE_TARGETS: &[(&str, &str, &str, &str)] = &[(
    "aarch64-apple-darwin",
    "1.97.1",
    "8bab26f4f68e0e26f0bb7960be334d5b520ea452",
    "cargo 1.97.1 (c980f4866 2026-06-30)",
)];

pub fn native_reuse_validated(target: &str) -> bool {
    VALIDATED_NATIVE_TARGETS
        .iter()
        .any(|(selected, _, _, _)| *selected == target)
}

fn available(state: &SlotContext, target: &str) -> bool {
    VALIDATED_NATIVE_TARGETS
        .iter()
        .any(|(selected, toolchain, compiler_commit, cargo)| {
            *selected == target
                && state.compatibility.get("toolchain").map(String::as_str) == Some(*toolchain)
                && state.compatibility.get("rustc").is_some_and(|identity| {
                    identity
                        .lines()
                        .any(|line| line.strip_prefix("commit-hash: ") == Some(*compiler_commit))
                })
                && state
                    .compatibility
                    .get("cargo")
                    .is_some_and(|identity| identity.trim() == *cargo)
        })
        && state
            .compatibility
            .get("native-available")
            .map(String::as_str)
            == Some("true")
}

pub fn emit(root: &Path, target: &Path, packages: &Path, for_save: bool) -> Result<()> {
    let distribution = selected(root, target, packages)?;
    let slot = OrdinarySlot::open(root, &distribution.target)?;
    let state = if for_save {
        let state = read_state(&slot.context())?;
        verify_files(slot.source(), &state.files)?;
        let (bundle, _) = super::packages::PackageBundle::load(packages)?;
        let current = make_state(
            compatibility(root, &slot)?,
            current_inputs(root, &slot, &bundle, &distribution)?,
            files(slot.source())?,
        )?;
        if current.key != state.key
            || current.prefix != state.prefix
            || current.inputs != state.inputs
            || current.compatibility != state.compatibility
        {
            return Err(CiError::Message(
                "ordinary compiler/source/path/graph/configuration changed before save".into(),
            ));
        }
        state
    } else {
        slot.reset_sources()?;
        let consumer =
            PackageConsumer::prepare_cached_ordinary(root, packages, &distribution, slot)?;
        let slot = consumer.ordinary_slot().expect("stable constructor");
        let state = identity(root, &consumer, slot)?;
        source::write_json(&slot.context(), &state)?;
        return emit_state(&state, slot, false, &distribution.target);
    };
    let _settled = crate::cache_restore::settled_locks(std::slice::from_ref(&slot.build))?;
    emit_state(&state, &slot, for_save, &distribution.target)
}

fn emit_state(
    state: &SlotContext,
    slot: &OrdinarySlot,
    for_save: bool,
    target: &str,
) -> Result<()> {
    let usable = available(state, target);
    crate::workflow_output::write(&[
        ("compiled-cache-usable", usable.to_string()),
        (
            "consumer-key",
            if usable {
                state.key.clone()
            } else {
                String::new()
            },
        ),
        (
            "consumer-restore-prefix",
            if usable {
                state.prefix.clone()
            } else {
                String::new()
            },
        ),
        (
            "consumer-paths",
            if usable {
                crate::workflow_output::action_path(&slot.build)?
            } else {
                String::new()
            },
        ),
        (
            "consumer-save-ready",
            (usable && for_save && state.completed && build_ready(slot.build())?).to_string(),
        ),
    ])?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"layout":"stable-ordinary", "compiled-cache-usable":usable, "reason":if usable { "validated ordinary consumer" } else { "native/compiler acceptance or current compatibility unavailable; cold compilation" }, "target":target})
        )?
    );
    Ok(())
}

fn prepare_current(root: &Path, target: &Path, packages: &Path) -> Result<PackageConsumer> {
    let distribution = selected(root, target, packages)?;
    let slot = OrdinarySlot::open(root, &distribution.target)?;
    let prior = read_state(&slot.context())?;
    slot.reset_sources()?;
    let consumer = PackageConsumer::prepare_cached_ordinary(root, packages, &distribution, slot)?;
    let slot = consumer.ordinary_slot().expect("stable constructor");
    let state = identity(root, &consumer, slot)?;
    if state.key != prior.key || state.files != prior.files {
        return Err(CiError::Message(
            "ordinary context changed before execution".into(),
        ));
    }
    source::write_json(&slot.context(), &state)?;
    Ok(consumer)
}

pub fn prepare_execution(root: &Path, target: &Path, packages: &Path) -> Result<PackageConsumer> {
    let consumer = prepare_current(root, target, packages)?;
    sanitize(root, &consumer, RestoreMode::Exact)?;
    Ok(consumer)
}

pub fn prepare_restore(
    root: &Path,
    target: &Path,
    packages: &Path,
    mode: RestoreMode,
) -> Result<()> {
    let consumer = prepare_current(root, target, packages)?;
    sanitize(root, &consumer, mode)
}

pub(crate) fn build_ready(target: &Path) -> Result<bool> {
    Ok(target.join("ordinary-layout").try_exists()?
        && fs::read_to_string(target.join("ordinary-layout"))? == BUILD_MARKER
        && target.join("CACHEDIR.TAG").try_exists()?
        && fs::read(target.join("CACHEDIR.TAG"))?
            .starts_with(b"Signature: 8a477f597d28d172789f06886806bc55"))
}

fn sanitize(root: &Path, consumer: &PackageConsumer, mode: RestoreMode) -> Result<()> {
    let slot = consumer.ordinary_slot().expect("stable constructor");
    let target = crate::cache_restore::safe_root(
        root,
        slot.build
            .strip_prefix(root.canonicalize()?)
            .map_err(|_| CiError::Message("ordinary build escaped checkout".into()))?,
    )?;
    let locks = crate::cache_restore::settled_locks(std::slice::from_ref(&target))?;
    let valid = build_ready(&target)?;
    let state = read_state(&slot.context())?;
    drop(locks);
    if matches!(mode, RestoreMode::Discard)
        || !valid
        || !available(&state, distribution::native_target()?)
    {
        if target.try_exists()? {
            fs::remove_dir_all(&target)?;
        }
    } else {
        consumer.clean_ordinary_locals(root, &target)?;
    }
    Ok(())
}

pub fn complete(
    consumer: &PackageConsumer,
    distribution: &super::distribution::TargetDistribution,
) -> Result<()> {
    let slot = consumer
        .ordinary_slot()
        .ok_or_else(|| CiError::Message("ordinary completion requires stable owner".into()))?;
    let mut state = read_state(&slot.context())?;
    verify_files(slot.source(), &state.files)?;
    // This is only called after measured materialization and all installed teardown.
    crate::cache_restore::safe_root(&slot.directory, Path::new("install"))?;
    if slot.install().try_exists()? {
        for entry in walkdir::WalkDir::new(slot.install())
            .follow_links(false)
            .min_depth(1)
        {
            let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
            let install = slot.install();
            let relative = entry.path().strip_prefix(&install).expect("install child");
            let allowed = if entry.file_type().is_dir() {
                relative == Path::new("bin")
            } else {
                relative == Path::new(".crates.toml")
                    || relative == Path::new(".crates2.json")
                    || distribution.binaries.iter().any(|binary| {
                        relative
                            == super::installed_consumer::binary_path(
                                Path::new("bin"),
                                binary,
                                &distribution.target,
                            )
                    })
            };
            if !allowed {
                return Err(CiError::Message(
                    "unexpected ordinary installation content; recovery required".into(),
                ));
            }
        }
        fs::remove_dir_all(slot.install())?;
    }
    let _settled = crate::cache_restore::settled_locks(std::slice::from_ref(&slot.build))?;
    if slot.build.try_exists()? {
        slot.mark_build_layout()?;
    }
    state.completed = true;
    source::write_json(&slot.context(), &state)
}
