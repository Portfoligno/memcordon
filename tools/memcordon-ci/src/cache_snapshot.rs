//! Bounded immutable copies of settled cache data. An index is never a work result.
use crate::{
    CiError, Result,
    cache_inputs::{KeyInputs, keys},
    cache_restore::{self, CompiledPartition},
    release::artifacts,
};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

fn snapshot_deadline() -> Instant {
    let original = Instant::now() + Duration::from_secs(300);
    crate::preparation::active_group().map_or(original, |group| original.min(group.deadline()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotKind {
    Compiled,
    ToolBuild,
    RegistryArchives,
    RegistryIndex,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    path: PathBuf,
    size: u64,
    hash: String,
    mode: u32,
    modified: SystemTime,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    revision: u32,
    kind: SnapshotKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transfer: Option<TransferIdentity>,
    compatibility: String,
    roots: Vec<PathBuf>,
    files: Vec<Item>,
}

struct Selection {
    revision: u32,
    stage: PathBuf,
    roots: Vec<PathBuf>,
    compatibility: String,
    input: String,
    family: &'static str,
    count: usize,
    bytes: u64,
    metadata: usize,
    transfer: Option<TransferIdentity>,
}

/// Content metadata only. Import never creates invocation-local completion facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferIdentity {
    complete: bool,
    input: String,
}

#[derive(Clone, Debug)]
pub struct Transfer {
    pub key: String,
    pub path: PathBuf,
}

/// A finite compiled selection; paths are derived exclusively from the existing layout.
#[derive(Clone, Copy, Debug)]
pub struct TransferSelection<'a> {
    pub kind: SnapshotKind,
    pub purpose: &'a str,
    pub shard: &'a str,
    pub partition: Option<CompiledPartition>,
}

pub struct TransferRequest {
    pub key: String,
    pub prefix: String,
    pub path: PathBuf,
}

fn transfer_selection(
    root: &Path,
    request: TransferSelection<'_>,
    complete: bool,
    incoming: bool,
) -> Result<Selection> {
    if !matches!(
        request.kind,
        SnapshotKind::Compiled | SnapshotKind::ToolBuild
    ) {
        return Err(CiError::Message(
            "only compiler transfers use this envelope".into(),
        ));
    }
    let mut selected = selection(
        root,
        request.kind,
        request.purpose,
        request.shard,
        request.partition,
    )?;
    selected.stage = transfer_stage(root, request, complete, incoming)?;
    selected.revision = 8;
    selected.family = match (request.kind, complete) {
        (SnapshotKind::Compiled, true) => "compiled-transfer",
        (SnapshotKind::Compiled, false) => "compiled-transfer-seed",
        (SnapshotKind::ToolBuild, true) => "tool-build-transfer",
        (SnapshotKind::ToolBuild, false) => "tool-build-transfer-seed",
        _ => unreachable!(),
    };
    selected.transfer = Some(TransferIdentity {
        complete,
        input: selected.input.clone(),
    });
    Ok(selected)
}

fn transfer_stage(
    root: &Path,
    request: TransferSelection<'_>,
    complete: bool,
    incoming: bool,
) -> Result<PathBuf> {
    if request.kind == SnapshotKind::ToolBuild {
        cache_restore::tool_build_layout(request.purpose, request.shard)?;
    } else if request.kind == SnapshotKind::Compiled {
        cache_restore::partition_layout(request.purpose, request.shard, request.partition)?;
    } else {
        return Err(CiError::Message("invalid compiled transfer class".into()));
    }
    let slot = match request.partition {
        None => "compiled",
        Some(CompiledPartition::NativeTests) => "native",
        Some(CompiledPartition::Product) => "product",
        Some(CompiledPartition::PrivateNativeTests) => "private-native",
        Some(CompiledPartition::AuxiliaryProfiles) => "auxiliary",
        Some(CompiledPartition::FuzzTargets) => "fuzz",
        Some(CompiledPartition::MiriTargets) => "miri",
    };
    let class = if complete { "complete" } else { "partial" };
    cache_restore::safe_root(
        root,
        &Path::new("target/ci-transfer")
            .join(if incoming { "in" } else { "out" })
            .join(request.purpose)
            .join(request.shard)
            .join(slot)
            .join(class),
    )
    .map_err(|error| CiError::CacheSafety(Box::new(error)))
}

pub fn transfer_request(
    root: &Path,
    request: TransferSelection<'_>,
    complete: bool,
) -> Result<TransferRequest> {
    let selected = transfer_selection(root, request, complete, true)?;
    let (_, compatible) = identity(&selected, BTreeMap::new())?;
    let exact = [
        compatible.as_str(),
        artifacts::checksum(selected.input.as_bytes()).as_str(),
        "-",
    ]
    .concat();
    Ok(TransferRequest {
        key: [exact.as_str(), "lookup"].concat(),
        prefix: [exact, compatible].join("\n"),
        path: selected.stage,
    })
}

/// Caller supplies actual invocation-local completion/settlement, never cached facts.
pub fn stage_transfer(
    root: &Path,
    request: TransferSelection<'_>,
    complete: bool,
) -> Result<Transfer> {
    let selected = transfer_selection(root, request, complete, false)?;
    let transfer = copy_transfer(root, request, &selected)?;
    validate_transfer_inputs(root, request, complete, &selected)?;
    Ok(transfer)
}

fn copy_transfer(
    root: &Path,
    request: TransferSelection<'_>,
    selected: &Selection,
) -> Result<Transfer> {
    for path in &selected.roots {
        ordinary(path)?;
    }
    let locks = source_locks(selected, request.kind)?;
    let layout = if request.kind == SnapshotKind::ToolBuild {
        cache_restore::tool_build_layout(request.purpose, request.shard)?
    } else {
        cache_restore::partition_layout(request.purpose, request.shard, request.partition)?
    };
    for target in layout.cargo_targets {
        let target = root.join(target);
        if target.try_exists()? && !cache_restore::cargo_marker_present(&target)? {
            return Err(CiError::Message("transfer missing Cargo marker".into()));
        }
    }
    let key = create(selected, request.kind)?;
    drop(locks);
    Ok(Transfer {
        key,
        path: selected.stage.clone(),
    })
}

fn validate_transfer_inputs(
    root: &Path,
    request: TransferSelection<'_>,
    complete: bool,
    selected: &Selection,
) -> Result<()> {
    let current = transfer_selection(root, request, complete, false)?;
    if current.input != selected.input
        || current.compatibility != selected.compatibility
        || current.roots != selected.roots
    {
        return Err(CiError::Message(
            "transfer inputs changed during copy".into(),
        ));
    }
    Ok(())
}

thread_local! {
    static COPY_RESERVATION: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn reservation(selected: &Selection, kind: SnapshotKind) -> Result<u64> {
    let deadline = snapshot_deadline();
    let mut bytes = 0_u64;
    let mut count = 0_usize;
    for root in &selected.roots {
        if !root.try_exists()? {
            continue;
        }
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .follow_root_links(false)
        {
            let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
            ordinary(entry.path())?;
            count += 1;
            if count > selected.count || Instant::now() >= deadline {
                return Err(CiError::Message(
                    "snapshot reservation exceeds bounds".into(),
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.is_file()
                && allowed(
                    kind,
                    entry.path().strip_prefix(root).unwrap_or(entry.path()),
                )
            {
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| CiError::Message("snapshot reservation overflow".into()))?;
            }
            if bytes > selected.bytes {
                return Err(CiError::Message(
                    "snapshot reservation exceeds byte limit".into(),
                ));
            }
        }
    }
    bytes
        .checked_add(selected.metadata as u64)
        .and_then(|value| value.checked_add(64 * 1024 * 1024))
        .ok_or_else(|| CiError::Message("snapshot reservation overflow".into()))
}

/// Only immutable disjoint compiler roots can use this bounded copy pair.
/// Context queries and output emission stay on the controller thread.
pub fn stage_transfer_pair(
    root: &Path,
    first: Option<(TransferSelection<'_>, bool)>,
    second: Option<(TransferSelection<'_>, bool)>,
) -> [Result<Option<Transfer>>; 2] {
    let serial = || {
        [
            first
                .map(|(selection, complete)| stage_transfer(root, selection, complete))
                .transpose(),
            second
                .map(|(selection, complete)| stage_transfer(root, selection, complete))
                .transpose(),
        ]
    };
    let (Some((a, ac)), Some((b, bc))) = (first, second) else {
        return serial();
    };
    if !matches!(a.kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild)
        || !matches!(b.kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild)
    {
        return serial();
    }
    let a_selected = match transfer_selection(root, a, ac, false) {
        Ok(selected) => selected,
        Err(error) => return [Err(error), stage_transfer(root, b, bc).map(Some)],
    };
    let b_selected = match transfer_selection(root, b, bc, false) {
        Ok(selected) => selected,
        Err(error) => return [stage_transfer(root, a, ac).map(Some), Err(error)],
    };
    let ar = match reservation(&a_selected, a.kind) {
        Ok(value) => value,
        Err(error) => return [Err(error), stage_transfer(root, b, bc).map(Some)],
    };
    let br = match reservation(&b_selected, b.kind) {
        Ok(value) => value,
        Err(error) => return [stage_transfer(root, a, ac).map(Some), Err(error)],
    };
    let prepared = (|| -> Result<(u64, u64)> {
        let a = &a_selected;
        let b = &b_selected;
        if a.stage.starts_with(&b.stage)
            || b.stage.starts_with(&a.stage)
            || a.roots
                .iter()
                .any(|a| b.roots.iter().any(|b| a.starts_with(b) || b.starts_with(a)))
        {
            return Err(CiError::Message(
                "snapshot roots require serial ownership".into(),
            ));
        }
        let aggregate = ar
            .checked_add(br)
            .ok_or_else(|| CiError::Message("aggregate snapshot reservation overflow".into()))?;
        if free_bytes(&a.stage)?.min(free_bytes(&b.stage)?) < aggregate {
            return Err(CiError::Message(
                "aggregate snapshot disk reservation unavailable".into(),
            ));
        }
        Ok((ar, br))
    })();
    let (ar, br) = match prepared {
        Ok(reservation) => reservation,
        Err(error)
            if crate::segment_cache::cache_safety_error(&error)
                || crate::work_outcome::has_unresolved_owner(&error) =>
        {
            return [Err(error), Ok(None)];
        }
        Err(_) => return serial(),
    };
    let deadline = snapshot_deadline();
    let mut copies = finalize_copies(
        deadline,
        || {
            COPY_RESERVATION.with(|slot| slot.set(Some(ar)));
            let result = copy_transfer(root, a, &a_selected);
            COPY_RESERVATION.with(|slot| slot.set(None));
            result.map(Some)
        },
        || {
            COPY_RESERVATION.with(|slot| slot.set(Some(br)));
            let result = copy_transfer(root, b, &b_selected);
            COPY_RESERVATION.with(|slot| slot.set(None));
            result.map(Some)
        },
    );
    // Git/toolchain input probes can have their own process/resource effects.
    // Keep every such query serial on the controller, outside the copy workers.
    for (result, (request, complete, selected)) in copies
        .iter_mut()
        .zip([(a, ac, &a_selected), (b, bc, &b_selected)])
    {
        if result.as_ref().is_ok_and(Option::is_some)
            && let Err(error) = validate_transfer_inputs(root, request, complete, selected)
        {
            *result = Err(error);
        }
    }
    copies
}

fn finalize_copies<T: Send>(
    deadline: Instant,
    first: impl FnOnce() -> Result<T> + Send,
    second: impl FnOnce() -> Result<T> + Send,
) -> [Result<T>; 2] {
    std::thread::scope(|scope| {
        let first = std::thread::Builder::new()
            .name("ci-first-snapshot".into())
            .spawn_scoped(scope, || {
                crate::preparation::with_finalization(deadline, first)
            });
        let second = std::thread::Builder::new()
            .name("ci-second-snapshot".into())
            .spawn_scoped(scope, || {
                crate::preparation::with_finalization(deadline, second)
            });
        [
            first.map_err(CiError::Io).and_then(|owner| {
                owner.join().unwrap_or_else(|_| {
                    Err(CiError::Message("first snapshot owner panicked".into()))
                })
            }),
            second.map_err(CiError::Io).and_then(|owner| {
                owner.join().unwrap_or_else(|_| {
                    Err(CiError::Message("second snapshot owner panicked".into()))
                })
            }),
        ]
    })
}

/// Prefer complete bytes; neither class imports a current compilation fact.
pub fn import_transfer(root: &Path, request: TransferSelection<'_>) -> Result<()> {
    for complete in [true, false] {
        let stage = transfer_stage(root, request, complete, true)?;
        ordinary(&stage)?;
        if !stage.try_exists()? {
            continue;
        }
        let selected = transfer_selection(root, request, complete, true)?;
        ordinary(&selected.stage)?;
        if !selected.stage.try_exists()? {
            continue;
        }
        for path in &selected.roots {
            ordinary(path)?;
        }
        let locks = source_locks(&selected, request.kind)?;
        // An existing live tree belongs to this checkout, never merge cache data into it.
        for path in &selected.roots {
            if path.try_exists()? && !marker_root(path) && fs::read_dir(path)?.next().is_some() {
                return Err(CiError::CacheSafety(Box::new(CiError::Message(
                    "transfer conflicts with a live compiler root".into(),
                ))));
            }
        }
        let imported = import_selected(&selected, request.kind);
        let restore_mode = imported
            .as_ref()
            .copied()
            .unwrap_or(cache_restore::RestoreMode::Compatible);
        drop(locks);
        if let Err(error) = imported {
            if matches!(&error, CiError::CacheSafety(_)) {
                return Err(error);
            }
            eprintln!("optional compiler transfer rejected: {error}");
            if request.kind == SnapshotKind::ToolBuild {
                cache_restore::prepare_tool_build(
                    root,
                    request.purpose,
                    request.shard,
                    cache_restore::RestoreMode::Discard,
                )?;
            } else {
                cache_restore::prepare_partition(
                    root,
                    request.purpose,
                    request.shard,
                    request.partition,
                    cache_restore::RestoreMode::Discard,
                )?;
            }
            cleanup_selected(root, &selected)?;
            continue;
        }
        let sanitation = if request.kind == SnapshotKind::ToolBuild {
            cache_restore::prepare_tool_build(root, request.purpose, request.shard, restore_mode)
        } else {
            cache_restore::prepare_partition(
                root,
                request.purpose,
                request.shard,
                request.partition,
                restore_mode,
            )
        };
        if let Err(error) = sanitation {
            if crate::segment_cache::cache_safety_error(&error)
                || crate::work_outcome::has_unresolved_owner(&error)
            {
                return Err(error);
            }
            eprintln!("optional imported compiler data could not be sanitized: {error}");
            if request.kind == SnapshotKind::ToolBuild {
                cache_restore::prepare_tool_build(
                    root,
                    request.purpose,
                    request.shard,
                    cache_restore::RestoreMode::Discard,
                )?;
            } else {
                cache_restore::prepare_partition(
                    root,
                    request.purpose,
                    request.shard,
                    request.partition,
                    cache_restore::RestoreMode::Discard,
                )?;
            }
            cleanup_selected(root, &selected)?;
            continue;
        }
        cleanup_selected(root, &selected)?;
        return Ok(());
    }
    Ok(())
}

pub fn cleanup_transfers(root: &Path, request: TransferSelection<'_>) -> Result<()> {
    for incoming in [true, false] {
        for complete in [true, false] {
            let stage = transfer_stage(root, request, complete, incoming)?;
            cleanup_stage(root, &stage)?;
        }
    }
    Ok(())
}

fn source_selection(root: &Path, kind: SnapshotKind, incoming: bool) -> Result<Selection> {
    if !matches!(
        kind,
        SnapshotKind::RegistryArchives | SnapshotKind::RegistryIndex
    ) {
        return Err(CiError::Message(
            "source transfer requires public source kind".into(),
        ));
    }
    let mut selected = selection(root, kind, "native-debug", "complete", None)?;
    selected.stage = cache_restore::safe_root(
        root,
        &Path::new("target/ci-transfer")
            .join(if incoming { "in" } else { "out" })
            .join(if kind == SnapshotKind::RegistryArchives {
                "archives"
            } else {
                "index"
            }),
    )
    .map_err(|error| CiError::CacheSafety(Box::new(error)))?;
    Ok(selected)
}

pub fn source_request(root: &Path, kind: SnapshotKind) -> Result<TransferRequest> {
    let selected = source_selection(root, kind, true)?;
    let (_, prefix) = identity(&selected, BTreeMap::new())?;
    Ok(TransferRequest {
        key: [prefix.as_str(), "lookup"].concat(),
        prefix,
        path: selected.stage,
    })
}

pub fn stage_source(root: &Path, kind: SnapshotKind) -> Result<Transfer> {
    let selected = source_selection(root, kind, false)?;
    for path in &selected.roots {
        ordinary(path)?;
    }
    let locks = source_locks(&selected, kind)?;
    let key = create(&selected, kind)?;
    let current = source_selection(root, kind, false)?;
    if current.input != selected.input || current.compatibility != selected.compatibility {
        return Err(CiError::Message("source transfer inputs changed".into()));
    }
    drop(locks);
    Ok(Transfer {
        key,
        path: selected.stage,
    })
}

pub fn source_read_locks(root: &Path) -> Result<Vec<File>> {
    let selected = source_selection(root, SnapshotKind::RegistryArchives, false)?;
    source_locks(&selected, SnapshotKind::RegistryArchives)
}

pub fn import_source(root: &Path, kind: SnapshotKind) -> Result<()> {
    let slot = match kind {
        SnapshotKind::RegistryArchives => "archives",
        SnapshotKind::RegistryIndex => "index",
        _ => return Err(CiError::Message("unsupported source import".into())),
    };
    let stage = cache_restore::safe_root(root, &Path::new("target/ci-transfer/in").join(slot))?;
    ordinary(&stage)?;
    if !stage.try_exists()? {
        return Ok(());
    }
    let selected = source_selection(root, kind, true)?;
    ordinary(&selected.stage)?;
    for path in &selected.roots {
        ordinary(path)?;
    }
    if !selected.stage.try_exists()? {
        return Ok(());
    }
    let locks = source_locks(&selected, kind)?;
    if let Err(error) = import_selected(&selected, kind) {
        if matches!(&error, CiError::CacheSafety(_)) {
            return Err(error);
        }
        eprintln!("optional source transfer rejected: {error}");
    }
    drop(locks);
    cleanup_selected(root, &selected)
}

pub fn cleanup_source(root: &Path) -> Result<()> {
    for direction in ["in", "out"] {
        for slot in ["archives", "index"] {
            let stage = cache_restore::safe_root(
                root,
                &Path::new("target/ci-transfer").join(direction).join(slot),
            )?;
            cleanup_stage(root, &stage)?;
        }
    }
    Ok(())
}

pub fn ordinary(path: &Path) -> Result<()> {
    ordinary_checked(path).map_err(|error| CiError::CacheSafety(Box::new(error)))
}

fn ordinary_checked(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(CiError::Message("unsafe snapshot path kind".into()));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(CiError::Message("snapshot reparse point".into()));
            }
        }
    }
    Ok(())
}

fn selection(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<Selection> {
    let (_slot, roots, compatibility, input, family, count, bytes, metadata) = match kind {
        SnapshotKind::Compiled | SnapshotKind::ToolBuild => {
            if kind == SnapshotKind::ToolBuild {
                if partition.is_some() {
                    return Err(CiError::Message(
                        "tool-build does not accept partition".into(),
                    ));
                }
                cache_restore::tool_build_layout(purpose, shard)?;
            } else {
                cache_restore::partition_layout(purpose, shard, partition)?;
            }
            let slot = match partition {
                Some(CompiledPartition::NativeTests) => "native-tests",
                Some(CompiledPartition::Product) => "product",
                Some(CompiledPartition::PrivateNativeTests) => "private-native-tests",
                Some(CompiledPartition::AuxiliaryProfiles) => "auxiliary-profiles",
                Some(CompiledPartition::FuzzTargets) => "fuzz-targets",
                Some(CompiledPartition::MiriTargets) => "miri-targets",
                None => "recipe",
            };
            let context = crate::cache::context_partition(root, purpose, shard, &[], partition)?;
            let entry_name = if kind == SnapshotKind::ToolBuild {
                "tool-build"
            } else {
                "product"
            };
            let Some(crate::cache::OptionalCache::Available { entry }) =
                context.entries.get(entry_name)
            else {
                return Err(CiError::Message(
                    "compiled snapshot inputs unavailable".into(),
                ));
            };
            (
                slot,
                entry.paths.iter().map(|path| root.join(path)).collect(),
                entry.restore_prefix.clone().expect("compiled prefix"),
                entry.exact_key.clone(),
                if kind == SnapshotKind::ToolBuild {
                    "tool-build-seed"
                } else {
                    "compiled-seed"
                },
                500_000,
                6 * 1024 * 1024 * 1024,
                32 * 1024 * 1024,
            )
        }
        SnapshotKind::RegistryArchives | SnapshotKind::RegistryIndex => {
            for (name, value) in std::env::vars_os() {
                let name = name.to_string_lossy().to_ascii_uppercase();
                if name.starts_with("CARGO_SOURCE_")
                    || name.starts_with("CARGO_REGISTRY_")
                    || (name.starts_with("CARGO_REGISTRIES_")
                        && !(name == "CARGO_REGISTRIES_CRATES_IO_PROTOCOL" && value == "sparse"))
                {
                    return Err(CiError::Message(
                        "unmodeled snapshot registry override".into(),
                    ));
                }
            }
            let home = crate::download_cache::cargo_home(root)?;
            ordinary(&home)?;
            let configuration = crate::cache_inputs::registry_seed_configs(root)?;
            let mut facts = configuration;
            facts.insert("scope".into(), "public-crates-io-sparse".into());
            facts.insert("transport-os".into(), std::env::consts::OS.into());
            if kind == SnapshotKind::RegistryIndex {
                if facts
                    .get("registries.crates-io.protocol")
                    .is_some_and(|protocol| protocol != "\"sparse\"")
                    || std::env::var_os("CARGO_REGISTRIES_CRATES_IO_PROTOCOL")
                        .is_some_and(|protocol| protocol != "sparse")
                {
                    return Err(CiError::Message(
                        "index snapshot requires sparse protocol".into(),
                    ));
                }
                let pins = crate::config::toolchains(root)?;
                let reader = crate::command::rustup_cargo(
                    root,
                    &pins.stable,
                    ["-V"],
                    Duration::from_secs(30),
                )
                .output_quiet()?;
                if !reader.status.success() {
                    return Err(CiError::Message("Cargo snapshot reader unavailable".into()));
                }
                facts.insert(
                    "reader".into(),
                    String::from_utf8(reader.stdout)
                        .map_err(|_| CiError::Message("Cargo reader not UTF-8".into()))?,
                );
            }
            let compatibility = artifacts::checksum(&serde_json::to_vec(&facts)?);
            if kind == SnapshotKind::RegistryArchives {
                (
                    "registry-archives",
                    vec![home.join("registry/cache")],
                    compatibility.clone(),
                    compatibility,
                    "registry-archive-seed",
                    50_000,
                    4 * 1024 * 1024 * 1024,
                    16 * 1024 * 1024,
                )
            } else {
                (
                    "registry-index",
                    vec![home.join("registry/index")],
                    compatibility.clone(),
                    compatibility,
                    "registry-index-snapshot",
                    50_000,
                    4 * 1024 * 1024 * 1024,
                    16 * 1024 * 1024,
                )
            }
        }
    };
    let stage = cache_restore::safe_root(root, &stage_relative(kind, purpose, shard, partition)?)?;
    Ok(Selection {
        transfer: None,
        revision: if kind == SnapshotKind::ToolBuild
            || (kind == SnapshotKind::Compiled
                && (partition.is_none() || partition == Some(CompiledPartition::MiriTargets)))
        {
            7
        } else {
            6
        },
        stage,
        roots,
        compatibility,
        input,
        family,
        count,
        bytes,
        metadata,
    })
}

fn identity(selected: &Selection, content: BTreeMap<String, String>) -> Result<(String, String)> {
    keys(&KeyInputs {
        family: selected.family.into(),
        layout_revision: selected.revision,
        compatibility: BTreeMap::from([("inputs".into(), selected.compatibility.clone())]),
        content,
    })
}

fn index_roots(selected: &Selection, kind: SnapshotKind) -> Vec<PathBuf> {
    match kind {
        SnapshotKind::Compiled | SnapshotKind::ToolBuild => selected.roots.clone(),
        SnapshotKind::RegistryArchives => vec![PathBuf::from("registry/cache")],
        SnapshotKind::RegistryIndex => vec![PathBuf::from("registry/index")],
    }
}

fn stage_relative(
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<PathBuf> {
    let base = Path::new("target/ci-cache-export");
    if kind == SnapshotKind::ToolBuild {
        if partition.is_some() {
            return Err(CiError::Message(
                "tool-build does not accept partition".into(),
            ));
        }
        cache_restore::tool_build_layout(purpose, shard)?;
        return Ok(base.join("tool-build").join(purpose));
    }
    if kind == SnapshotKind::Compiled
        && (partition.is_none() || partition == Some(CompiledPartition::MiriTargets))
    {
        cache_restore::partition_layout(purpose, shard, partition)?;
        return Ok(base.join("recipe").join(purpose).join(shard));
    }
    let slot = match kind {
        SnapshotKind::RegistryArchives => "registry-archives",
        SnapshotKind::RegistryIndex => "registry-index",
        SnapshotKind::ToolBuild => unreachable!("tool slot handled above"),
        SnapshotKind::Compiled => match partition
            .ok_or_else(|| CiError::Message("compiled snapshot requires partition".into()))?
        {
            CompiledPartition::NativeTests => "native-tests",
            CompiledPartition::Product => "product",
            CompiledPartition::PrivateNativeTests => "private-native-tests",
            CompiledPartition::AuxiliaryProfiles => "auxiliary-profiles",
            CompiledPartition::FuzzTargets => "fuzz-targets",
            CompiledPartition::MiriTargets => {
                unreachable!("Miri recipe slot handled above")
            }
        },
    };
    Ok(Path::new("target/ci-cache-export").join(slot))
}

fn preflight(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    cache_restore::safe_root(root, &stage_relative(kind, purpose, shard, partition)?)?;
    if kind == SnapshotKind::Compiled {
        let layout = cache_restore::partition_layout(purpose, shard, partition)?;
        for path in layout.directories {
            cache_restore::safe_root(root, &path)?;
        }
        for path in layout.required_files {
            ordinary(&root.join(path))?;
        }
    } else if kind == SnapshotKind::ToolBuild {
        for path in cache_restore::tool_build_layout(purpose, shard)?.directories {
            cache_restore::safe_root(root, &path)?;
        }
    } else {
        ordinary(&crate::download_cache::cargo_home(root)?)?;
    }
    Ok(())
}

pub fn seed_context(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    preflight(root, kind, purpose, shard, partition)?;
    let selected = match selection(root, kind, purpose, shard, partition) {
        Ok(selected) => selected,
        Err(error) if crate::work_outcome::has_unresolved_owner(&error) => return Err(error),
        Err(error) => {
            eprintln!("optional seed context unavailable: {error}");
            return crate::workflow_output::write(&[
                ("seed-lookup-key", String::new()),
                ("seed-restore-prefix", String::new()),
                ("seed-import-path", String::new()),
                ("input-key", String::new()),
                ("seed-compatibility", String::new()),
            ]);
        }
    };
    let (_, prefix) = identity(&selected, BTreeMap::new())?;
    let exact_prefix = [
        prefix.as_str(),
        artifacts::checksum(selected.input.as_bytes()).as_str(),
        "-",
    ]
    .concat();
    let lookup = [exact_prefix.as_str(), "lookup"].concat();
    crate::workflow_output::write(&[
        ("seed-lookup-key", lookup),
        (
            "seed-restore-prefix",
            if matches!(kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild) {
                [exact_prefix, prefix].join("\n")
            } else {
                prefix
            },
        ),
        ("seed-import-path", selected.stage.display().to_string()),
        ("input-key", selected.input),
        ("seed-compatibility", selected.compatibility),
    ])
}

fn source_locks(selected: &Selection, kind: SnapshotKind) -> Result<Vec<File>> {
    source_locks_checked(selected, kind).map_err(|error| CiError::CacheSafety(Box::new(error)))
}

fn source_locks_checked(selected: &Selection, kind: SnapshotKind) -> Result<Vec<File>> {
    if matches!(kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild) {
        let targets: Vec<_> = selected
            .roots
            .iter()
            .map(|path| {
                if marker_root(path) {
                    path.parent().expect("marker parent").to_path_buf()
                } else {
                    path.clone()
                }
            })
            .collect();
        return cache_restore::settled_locks(&targets);
    }
    let home = selected.roots[0]
        .parent()
        .and_then(Path::parent)
        .expect("registry home");
    let mut locks = Vec::new();
    for name in [".package-cache", ".package-cache-mutate"] {
        let path = home.join(name);
        ordinary(&path)?;
        if !path.try_exists()? {
            continue;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| CiError::Message("source cache has active writer".into()))?;
        locks.push(file);
    }
    Ok(locks)
}

fn allowed(kind: SnapshotKind, relative: &Path) -> bool {
    let parts = relative.components().collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return false;
    }
    for part in &parts {
        let Some(name) = part.as_os_str().to_str() else {
            return false;
        };
        if name == ".cargo-lock" {
            return false;
        }
        if name.contains(':') || name.contains('\\') || name.ends_with('.') || name.ends_with(' ') {
            return false;
        }
        let stem = name
            .split('.')
            .next()
            .expect("path component stem")
            .to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|suffix| {
                    matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                })
            })
        {
            return false;
        }
    }
    if matches!(kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild) {
        return true;
    }
    let Some(source) = parts.first().and_then(|part| part.as_os_str().to_str()) else {
        return false;
    };
    if kind == SnapshotKind::RegistryArchives {
        parts.len() == 2
            && matches!(
                source,
                "index.crates.io-1949cf8c6b5b557f" | "index.crates.io-6f17d22bba15001f"
            )
            && relative
                .extension()
                .is_some_and(|extension| extension == "crate")
    } else {
        source == "index.crates.io-1949cf8c6b5b557f"
            && (parts
                .get(1)
                .is_some_and(|part| part.as_os_str() == ".cache")
                || (parts.len() == 2 && parts[1].as_os_str() == "config.json"))
    }
}

fn mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        if metadata.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

fn public_index_config(path: &Path) -> Result<()> {
    if path.file_name().is_none_or(|name| name != "config.json") {
        return Ok(());
    }
    if fs::metadata(path)?.len() > 64 * 1024 {
        return Err(CiError::Message(
            "sparse source configuration oversized".into(),
        ));
    }
    let config: serde_json::Value = serde_json::from_slice(&artifacts::read_file(path)?)?;
    let table = config
        .as_object()
        .ok_or_else(|| CiError::Message("sparse source configuration malformed".into()))?;
    if table
        .keys()
        .any(|key| !matches!(key.as_str(), "dl" | "api" | "auth-required"))
        || config.get("dl").and_then(serde_json::Value::as_str)
            != Some("https://static.crates.io/crates")
        || config.get("api").and_then(serde_json::Value::as_str) != Some("https://crates.io")
        || config
            .get("auth-required")
            .is_some_and(|value| value != &serde_json::Value::Bool(false))
    {
        return Err(CiError::Message(
            "unmodeled/private sparse source configuration".into(),
        ));
    }
    Ok(())
}

fn copy_file(
    source: &Path,
    destination: &Path,
    deadline: Instant,
    transport: Option<&Item>,
) -> Result<Item> {
    ordinary(destination)?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    copy_open_file(source, destination, deadline, transport, output)
}

fn copy_open_file(
    source: &Path,
    destination: &Path,
    deadline: Instant,
    transport: Option<&Item>,
    mut output: File,
) -> Result<Item> {
    ordinary(source)?;
    ordinary(destination)?;
    let before = fs::symlink_metadata(source)?;
    if !before.is_file() {
        return Err(CiError::Message(
            "snapshot payload is not a regular file".into(),
        ));
    }
    let modified = before.modified()?;
    let mut input = File::open(source)?;
    let opened = input.metadata()?;
    if opened.len() != before.len()
        || opened.modified()? != modified
        || mode(&opened) != mode(&before)
    {
        return Err(CiError::Message(
            "snapshot source changed before copy".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(CiError::Message("snapshot source identity changed".into()));
        }
    }
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(CiError::Message("snapshot copy deadline".into()));
        }
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
        size += count as u64;
        if size > before.len() {
            return Err(CiError::Message("snapshot source grew during copy".into()));
        }
    }
    let after = fs::symlink_metadata(source)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(CiError::Message("snapshot source identity changed".into()));
        }
    }
    if size != before.len()
        || after.len() != size
        || after.modified()? != modified
        || mode(&before) != mode(&after)
    {
        return Err(CiError::Message(
            "snapshot source changed during copy".into(),
        ));
    }
    output.set_times(
        fs::FileTimes::new().set_modified(transport.map_or(modified, |item| item.modified)),
    )?;
    if let Some(item) = transport {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            output.set_permissions(fs::Permissions::from_mode(item.mode))?;
        }
        #[cfg(not(unix))]
        {
            let mut permissions = output.metadata()?.permissions();
            permissions.set_readonly(item.mode & 0o222 == 0);
            output.set_permissions(permissions)?;
        }
    } else {
        output.set_permissions(before.permissions())?;
    }
    Ok(Item {
        path: PathBuf::new(),
        size,
        hash: hex::encode(hash.finalize()),
        mode: mode(&before),
        modified,
    })
}

fn marker_root(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "CACHEDIR.TAG")
}

fn destination(selected: &Selection, item: &Item, kind: SnapshotKind) -> Result<PathBuf> {
    let mut parts = item.path.components();
    let Some(Component::Normal(slot)) = parts.next() else {
        return Err(CiError::Message("unsafe snapshot member".into()));
    };
    let slot: usize = slot
        .to_str()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| CiError::Message("invalid snapshot root slot".into()))?;
    let root = selected
        .roots
        .get(slot)
        .ok_or_else(|| CiError::Message("invalid snapshot root slot".into()))?;
    let relative = parts.as_path();
    if relative.as_os_str().is_empty() || !allowed(kind, relative) {
        return Err(CiError::Message("unsafe snapshot member".into()));
    }
    if marker_root(root) {
        if relative != Path::new("CACHEDIR.TAG") {
            return Err(CiError::Message("invalid marker snapshot member".into()));
        }
        Ok(root.clone())
    } else {
        Ok(root.join(relative))
    }
}

fn content_hash(path: &Path, expected: u64, deadline: Instant) -> Result<String> {
    ordinary(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() != expected {
        return Err(CiError::Message("snapshot file size/kind mismatch".into()));
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(CiError::Message("snapshot validation deadline".into()));
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > expected {
            return Err(CiError::Message("snapshot file grew".into()));
        }
        hash.update(&buffer[..count]);
    }
    if total != expected {
        return Err(CiError::Message("snapshot file shortened".into()));
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg_attr(windows, allow(unsafe_code))]
fn free_bytes(path: &Path) -> Result<u64> {
    let existing = path
        .ancestors()
        .find(|path| path.exists())
        .ok_or_else(|| CiError::Message("snapshot filesystem absent".into()))?;
    #[cfg(unix)]
    {
        let status =
            rustix::fs::statvfs(existing).map_err(|error| CiError::Message(error.to_string()))?;
        status
            .f_bavail
            .checked_mul(status.f_frsize)
            .ok_or_else(|| CiError::Message("snapshot free-space overflow".into()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let path: Vec<_> = existing.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut available = 0;
        let result = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(available)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = existing;
        Err(CiError::Message(
            "snapshot free-space query unsupported".into(),
        ))
    }
}

pub fn snapshot(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    preflight(root, kind, purpose, shard, partition)?;
    let selected = match selection(root, kind, purpose, shard, partition) {
        Ok(value) => value,
        Err(error) if crate::work_outcome::has_unresolved_owner(&error) => return Err(error),
        Err(error) => {
            eprintln!("optional snapshot unavailable: {error}");
            return crate::workflow_output::write(&[("snapshot-ready", "false".into())]);
        }
    };
    // Ownership failures are blocking, unlike optional copy/resource failures.
    for path in &selected.roots {
        ordinary(path)?;
    }
    let locks = source_locks(&selected, kind)?;
    if selected.revision >= 7 && matches!(kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild) {
        let layout = if kind == SnapshotKind::ToolBuild {
            cache_restore::tool_build_layout(purpose, shard)?
        } else {
            cache_restore::partition_layout(purpose, shard, partition)?
        };
        for target in layout.cargo_targets {
            let target = root.join(target);
            if target.try_exists()? && !cache_restore::cargo_marker_present(&target)? {
                return crate::workflow_output::write(&[("snapshot-ready", "false".into())]);
            }
        }
    }
    if partition == Some(CompiledPartition::AuxiliaryProfiles)
        && !cache_restore::cargo_marker_present(&root.join("target"))?
    {
        return crate::workflow_output::write(&[("snapshot-ready", "false".into())]);
    }
    let result = create(&selected, kind);
    drop(locks);
    match result {
        Ok(key) => {
            let current = selection(root, kind, purpose, shard, partition);
            if let Err(error) = &current
                && crate::work_outcome::has_unresolved_owner(error)
            {
                return current.map(|_| ());
            }
            if !current.is_ok_and(|current| {
                current.input == selected.input
                    && current.compatibility == selected.compatibility
                    && current.roots == selected.roots
            }) {
                eprintln!("optional snapshot inputs changed during copy");
                return crate::workflow_output::write(&[("snapshot-ready", "false".into())]);
            }
            crate::workflow_output::write(&[
                ("snapshot-ready", "true".into()),
                ("snapshot-key", key),
                ("snapshot-path", selected.stage.display().to_string()),
                ("input-key", selected.input),
                ("seed-compatibility", selected.compatibility),
            ])
        }
        Err(error) => {
            eprintln!("optional snapshot copy unavailable: {error}");
            crate::workflow_output::write(&[("snapshot-ready", "false".into())])
        }
    }
}

fn create(selected: &Selection, kind: SnapshotKind) -> Result<String> {
    let deadline = snapshot_deadline();
    // One immutable staging copy per operation. No live-output hardlinks.
    if selected.stage.try_exists()? {
        return Err(CiError::Message("snapshot staging already exists".into()));
    }
    let payload = selected.stage.join("payload");
    let mut inventory = Vec::new();
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for (slot, source) in selected.roots.iter().enumerate() {
        if !source.try_exists()? {
            continue;
        }
        for entry in walkdir::WalkDir::new(source)
            .follow_links(false)
            .follow_root_links(false)
        {
            let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
            entries += 1;
            if entries > selected.count.saturating_sub(16) || Instant::now() >= deadline {
                return Err(CiError::Message("snapshot inventory exceeds bounds".into()));
            }
            ordinary(entry.path())?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.is_dir() {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(source)
                .map_err(|error| CiError::Message(error.to_string()))?;
            // A required marker is itself a root, represented by a fixed name.
            let relative = if relative.as_os_str().is_empty() {
                Path::new("CACHEDIR.TAG")
            } else {
                relative
            };
            if !allowed(kind, relative) || entry.file_name() == ".cargo-lock" {
                continue;
            }
            if kind == SnapshotKind::RegistryIndex {
                public_index_config(entry.path())?;
            }
            total = total
                .checked_add(metadata.len())
                .ok_or_else(|| CiError::Message("snapshot size overflow".into()))?;
            if inventory.len() >= selected.count || total > selected.bytes {
                return Err(CiError::Message("snapshot payload exceeds bounds".into()));
            }
            let path = PathBuf::from(slot.to_string()).join(relative);
            inventory.push((
                entry.path().to_path_buf(),
                path,
                metadata.len(),
                metadata.modified()?,
                mode(&metadata),
            ));
        }
    }
    if !inventory
        .iter()
        .any(|(_, path, ..)| path.file_name().is_some_and(|name| name != "CACHEDIR.TAG"))
    {
        return Err(CiError::Message("snapshot has no reusable payload".into()));
    }
    let required = total
        .checked_add(selected.metadata as u64)
        .and_then(|value| value.checked_add(64 * 1024 * 1024))
        .ok_or_else(|| CiError::Message("snapshot disk requirement overflow".into()))?;
    if COPY_RESERVATION.with(|reserved| reserved.get().is_some_and(|reserved| required > reserved))
    {
        return Err(CiError::Message(
            "snapshot grew beyond its aggregate reservation".into(),
        ));
    }
    if free_bytes(&selected.stage)? < required {
        return Err(CiError::Message(
            "snapshot free-space margin insufficient".into(),
        ));
    }
    fs::create_dir_all(&selected.stage)?;
    fs::create_dir(&payload)?;
    let mut files = Vec::new();
    let mut copied_sources = Vec::new();
    for (source, path, size, modified, permissions) in inventory {
        let destination = payload.join(&path);
        fs::create_dir_all(destination.parent().expect("snapshot parent"))?;
        let mut item = copy_file(&source, &destination, deadline, None)?;
        if item.size != size || item.modified != modified || item.mode != permissions {
            return Err(CiError::Message("snapshot inventory changed".into()));
        }
        item.path = path;
        copied_sources.push(source);
        files.push(item);
    }
    for (source, item) in copied_sources.iter().zip(&files) {
        let metadata = fs::symlink_metadata(source)?;
        if metadata.modified()? != item.modified
            || mode(&metadata) != item.mode
            || content_hash(source, item.size, deadline)? != item.hash
        {
            return Err(CiError::Message(
                "snapshot source changed before closure".into(),
            ));
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let content = files
        .iter()
        .map(|item| {
            (
                item.path.display().to_string(),
                serde_json::to_string(&(item.size, &item.hash, item.mode))
                    .expect("file tuple serialization"),
            )
        })
        .collect();
    let (key, prefix) = identity(selected, content)?;
    let suffix = key.strip_prefix(&prefix).expect("snapshot key prefix");
    let key = if matches!(kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild) {
        [
            prefix.as_str(),
            artifacts::checksum(selected.input.as_bytes()).as_str(),
            "-",
            suffix,
        ]
        .concat()
    } else {
        key
    };
    let index = Index {
        revision: selected.revision,
        kind,
        transfer: selected.transfer.clone(),
        compatibility: selected.compatibility.clone(),
        roots: index_roots(selected, kind),
        files,
    };
    let mut bytes = serde_json::to_vec(&index)?;
    bytes.push(b'\n');
    if bytes.len() > selected.metadata {
        return Err(CiError::Message("snapshot index exceeds bounds".into()));
    }
    fs::write(selected.stage.join("index.json"), bytes)?;
    Ok(key)
}

pub fn import(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    let selected = selection(root, kind, purpose, shard, partition)?;
    for path in &selected.roots {
        ordinary(path)?;
    }
    let locks = source_locks(&selected, kind)?;
    if matches!(kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild) {
        for path in &selected.roots {
            if !marker_root(path) && path.try_exists()? && fs::read_dir(path)?.next().is_some() {
                return Err(CiError::Message(
                    "compiled seed requires empty destination".into(),
                ));
            }
        }
    }
    // Path safety is blocking even when the optional payload is malformed.
    let index_path = selected.stage.join("index.json");
    ordinary(&index_path)?;
    let index = if index_path.try_exists()?
        && fs::metadata(&index_path)?.len() <= selected.metadata as u64
    {
        artifacts::read_file(&index_path)
            .and_then(|bytes| Ok(serde_json::from_slice::<Index>(&bytes)?))
            .ok()
    } else {
        None
    };
    if let Some(index) = index {
        for item in &index.files {
            if let Ok(path) = destination(&selected, item, kind) {
                ordinary(&path)?;
            }
        }
    }
    let result = import_selected(&selected, kind);
    drop(locks);
    if let Err(error) = result {
        eprintln!("optional cache snapshot rejected: {error}");
        if kind == SnapshotKind::ToolBuild {
            cache_restore::prepare_tool_build(
                root,
                purpose,
                shard,
                cache_restore::RestoreMode::Discard,
            )?;
        } else if kind == SnapshotKind::Compiled {
            cache_restore::prepare_partition(
                root,
                purpose,
                shard,
                partition,
                cache_restore::RestoreMode::Discard,
            )?;
        }
        return cleanup_selected(root, &selected);
    }
    if kind == SnapshotKind::ToolBuild {
        cache_restore::prepare_tool_build(
            root,
            purpose,
            shard,
            cache_restore::RestoreMode::Compatible,
        )?;
    } else if kind == SnapshotKind::Compiled {
        cache_restore::prepare_partition(
            root,
            purpose,
            shard,
            partition,
            cache_restore::RestoreMode::Compatible,
        )?;
    }
    cleanup_selected(root, &selected)
}

fn cleanup_stage(root: &Path, stage: &Path) -> Result<()> {
    let relative = stage
        .strip_prefix(root.canonicalize()?)
        .map_err(|_| CiError::Message("snapshot staging escaped checkout".into()))?;
    let checked = cache_restore::safe_root(root, relative)?;
    let removal = if checked.try_exists()? {
        fs::remove_dir_all(checked)
    } else {
        Ok(())
    };
    if let Err(error) = removal {
        eprintln!("optional owned snapshot staging cleanup incomplete: {error}");
    }
    Ok(())
}

fn cleanup_selected(root: &Path, selected: &Selection) -> Result<()> {
    cleanup_stage(root, &selected.stage)
}

/// Remove only the finite owned staging layout after its cache action finishes.
pub fn cleanup(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    if kind == SnapshotKind::Compiled {
        cache_restore::partition_layout(purpose, shard, partition)?;
    } else if kind == SnapshotKind::ToolBuild {
        cache_restore::tool_build_layout(purpose, shard)?;
    }
    let stage = cache_restore::safe_root(root, &stage_relative(kind, purpose, shard, partition)?)?;
    cleanup_stage(root, &stage)
}

fn import_selected(selected: &Selection, kind: SnapshotKind) -> Result<cache_restore::RestoreMode> {
    ordinary(&selected.stage)?;
    for root in &selected.roots {
        ordinary(root)?;
    }
    if matches!(kind, SnapshotKind::Compiled | SnapshotKind::ToolBuild) {
        for root in &selected.roots {
            if !marker_root(root) && root.try_exists()? && fs::read_dir(root)?.next().is_some() {
                return Err(CiError::CacheSafety(Box::new(CiError::Message(
                    "compiled seed requires empty destination".into(),
                ))));
            }
        }
    }
    let deadline = snapshot_deadline();
    let index_path = selected.stage.join("index.json");
    ordinary(&index_path)?;
    if fs::metadata(&index_path)?.len() > selected.metadata as u64 {
        return Err(CiError::Message("snapshot index oversized".into()));
    }
    let index: Index = serde_json::from_slice(&artifacts::read_file(&index_path)?)?;
    if index.revision != selected.revision
        || index.kind != kind
        || index.transfer.as_ref().map(|value| value.complete)
            != selected.transfer.as_ref().map(|value| value.complete)
        || index.compatibility != selected.compatibility
        || index.roots != index_roots(selected, kind)
        || index.files.is_empty()
        || index.files.len() > selected.count
    {
        return Err(CiError::Message("snapshot input/layout mismatch".into()));
    }
    if index
        .transfer
        .as_ref()
        .is_some_and(|identity| identity.input.is_empty() || identity.input.len() > 4096)
    {
        return Err(CiError::Message("transfer origin input is invalid".into()));
    }
    let payload = selected.stage.join("payload");
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    // Validate every member and live collision before the first import mutation.
    let restore_mode = if index
        .transfer
        .as_ref()
        .is_some_and(|origin| origin.complete && origin.input == selected.input)
    {
        cache_restore::RestoreMode::Exact
    } else {
        cache_restore::RestoreMode::Compatible
    };
    for item in &index.files {
        let destination = destination(selected, item, kind)
            .map_err(|error| CiError::CacheSafety(Box::new(error)))?;
        let name = item
            .path
            .to_str()
            .ok_or_else(|| CiError::Message("snapshot member not UTF-8".into()))?;
        if !seen.insert(name.to_lowercase()) || item.mode & !0o777 != 0 {
            return Err(CiError::Message("unsafe/duplicate snapshot member".into()));
        }
        total = total
            .checked_add(item.size)
            .ok_or_else(|| CiError::Message("snapshot size overflow".into()))?;
        if total > selected.bytes {
            return Err(CiError::Message("snapshot payload oversized".into()));
        }
        let source = payload.join(&item.path);
        ordinary(&source)?;
        if kind == SnapshotKind::RegistryIndex {
            public_index_config(&source)?;
        }
        if content_hash(&source, item.size, deadline)? != item.hash {
            return Err(CiError::Message("snapshot payload digest mismatch".into()));
        }
        ordinary(&destination)?;
        if destination.try_exists()?
            && content_hash(&destination, item.size, deadline)? != item.hash
        {
            return Err(CiError::CacheSafety(Box::new(CiError::Message(
                "snapshot conflicts with current file".into(),
            ))));
        }
    }
    for item in &index.files {
        let destination = destination(selected, item, kind)?;
        if destination.try_exists()? {
            continue;
        }
        fs::create_dir_all(destination.parent().expect("snapshot destination parent"))?;
        // A failed/short copy must never become a live registry archive or
        // sparse-index file. Keep it private until all bytes are validated.
        let temporary = tempfile::NamedTempFile::new_in(
            destination.parent().expect("snapshot destination parent"),
        )?;
        let copied = copy_open_file(
            &payload.join(&item.path),
            temporary.path(),
            deadline,
            Some(item),
            temporary.reopen()?,
        )?;
        if copied.hash != item.hash || copied.size != item.size {
            return Err(CiError::Message("snapshot changed during import".into()));
        }
        temporary
            .persist_noclobber(&destination)
            .map_err(|error| CiError::Io(error.error))?;
    }
    Ok(restore_mode)
}

#[cfg(test)]
#[path = "../tests/private/cache_snapshot_selections.rs"]
mod selection_tests;
