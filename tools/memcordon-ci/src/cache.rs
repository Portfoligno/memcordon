//! Cache identities describe actual inputs. Unknown native inputs use clean builds.
use crate::{
    CiError, Result,
    command::CommandSpec,
    release::{artifacts, distribution, git::Git},
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Serialize)]
pub struct CacheContext {
    pub revision: u32,
    pub usable: bool,
    pub inputs: BTreeMap<String, String>,
    pub partitions: BTreeMap<String, String>,
    pub entries: BTreeMap<String, OptionalCache>,
    pub diagnostics: CacheDiagnostics,
}

#[derive(Clone, Debug, Serialize)]
pub struct CacheEntry {
    pub exact_key: String,
    pub restore_prefix: Option<String>,
    pub paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum OptionalCache {
    Available { entry: CacheEntry },
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct CacheDiagnostics {
    pub source_commit: String,
    pub source_tree: String,
    pub unavailable_reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsumerProfile {
    Ordinary,
    Readiness,
}

pub fn emit_consumer_downloads(channel: &str, profile: ConsumerProfile) -> Result<()> {
    // Current generated consumers own relocated temporary source/target roots.
    // They deliberately use D downloads, not an unvalidated C target import.
    // Public compiler-capture targets must also remain freshly compiled.
    crate::workflow_output::write(&[
        ("compiled-cache-usable", "false".into()),
        ("product-key", String::new()),
        ("consumer-key", String::new()),
        ("product-restore-prefix", String::new()),
        ("consumer-restore-prefix", String::new()),
        ("product-paths", String::new()),
        ("consumer-paths", String::new()),
    ])?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "revision": 4, "channel": channel, "profile": profile,
            "compiled": "unavailable: current generated source roots relocate; no established dependency freshness/import boundary",
            "downloads": "seeded inside each newly owned Cargo home; selected public images excluded from public acquisition",
        }))?
    );
    Ok(())
}

fn query(root: &Path, program: impl Into<std::ffi::OsString>, args: &[&str]) -> Result<String> {
    let output = CommandSpec::new(PathBuf::from(program.into()), root, Duration::from_secs(30))
        .args(args.iter().copied())
        .bootstrap_environment()
        .output_quiet()?;
    if !output.status.success() {
        return Err(CiError::Message("native cache version query failed".into()));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| CiError::Message("native cache identity not UTF-8".into()))?;
    if text.is_empty() || text.len() > 64 * 1024 {
        return Err(CiError::Message(
            "native cache identity absent/oversized".into(),
        ));
    }
    Ok(text)
}

fn native_recipe(purpose: &str) -> Option<Vec<Vec<&'static str>>> {
    let release = match purpose {
        "native-debug" => false,
        "native-release" | "native-readiness" | "windows-working" | "private" => true,
        _ => return None,
    };
    Some(
        crate::native_test_plan::commands(release)
            .into_iter()
            .map(|command| command.arguments)
            .collect(),
    )
}

fn tool_compiler_jobs(root: &Path, purpose: &str, shard: &str) -> Result<usize> {
    let workers = crate::preparation::compiler_budget();
    let parallel = match shard {
        "complete" => return Ok(workers),
        "supply-pair-v1" => true,
        "preparation-pair-v1" => {
            crate::performance_plan::PerformancePlan::read(root)?
                .preparation
                .selected
                == crate::performance_plan::Layout::Parallel
        }
        _ => {
            return Err(CiError::Message(
                "unsupported tool allocation recipe".into(),
            ));
        }
    };
    Ok(tool_jobs_for_scope(
        workers,
        parallel,
        crate::preparation::active_group().is_some_and(|group| group.inside_parallel_lane()),
        purpose,
        shard,
    ))
}

fn tool_jobs_for_scope(
    workers: usize,
    parallel: bool,
    nested: bool,
    purpose: &str,
    shard: &str,
) -> usize {
    if shard == "complete" {
        return workers;
    }
    let allocation = crate::preparation::allocate_pair(
        std::num::NonZeroUsize::new(workers).expect("positive inherited compiler budget"),
        parallel,
        nested,
        crate::preparation::PairClass::Balanced,
    );
    // Preparation's existing source owner gets floor(root/2); its auxiliary
    // owner gets the remainder, equal to Balanced.first (ceil), not its ordinal.
    if shard == "preparation-pair-v1" || purpose == "cargo-audit" {
        allocation.first.get()
    } else {
        allocation.second.get()
    }
}

#[cfg(test)]
#[path = "../tests/private/cache_allocation.rs"]
mod cache_allocation_tests;

/// Remove only selection differences absent from the actual compilation recipe.
pub fn partition_compatibility(
    purpose: &str,
    partition: crate::cache_restore::CompiledPartition,
    mut inputs: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    use crate::cache_restore::CompiledPartition;
    inputs.insert("partition".into(), serde_json::to_string(&partition)?);
    if partition == CompiledPartition::NativeTests {
        let recipe = native_recipe(purpose)
            .ok_or_else(|| CiError::Message("purpose has no native-test recipe".into()))?;
        inputs.remove("purpose");
        inputs.remove("shard");
        inputs.retain(|name, _| !name.starts_with("product-") && !name.starts_with("consumer-"));
        inputs.insert(
            "profile".into(),
            if purpose == "native-debug" {
                "dev"
            } else {
                "release"
            }
            .into(),
        );
        inputs.insert(
            "compilation-arguments".into(),
            serde_json::to_string(recipe.first().expect("native compile recipe"))?,
        );
    }
    if partition == CompiledPartition::FuzzTargets {
        inputs.remove("shard");
        inputs.insert(
            "instrumentation".into(),
            "cargo-fuzz-default-libfuzzer-release".into(),
        );
    }
    Ok(inputs)
}

pub fn context(
    root: &Path,
    purpose: &str,
    shard: &str,
    external: &[PathBuf],
) -> Result<CacheContext> {
    context_partition(root, purpose, shard, external, None)
}

pub fn context_partition(
    root: &Path,
    purpose: &str,
    shard: &str,
    external: &[PathBuf],
    partition: Option<crate::cache_restore::CompiledPartition>,
) -> Result<CacheContext> {
    let mode = crate::preparation::active_group().map_or(
        crate::failure_mode::FailureMode::StopAfterFailure,
        |group| group.mode(),
    );
    crate::preparation::with_operation(
        mode,
        std::time::Instant::now() + Duration::from_secs(240),
        || context_partition_inner(root, purpose, shard, external, partition),
    )
}

fn context_partition_inner(
    root: &Path,
    purpose: &str,
    shard: &str,
    external: &[PathBuf],
    partition: Option<crate::cache_restore::CompiledPartition>,
) -> Result<CacheContext> {
    if let Some(partition) = partition {
        crate::cache_restore::partition_layout(purpose, shard, Some(partition))?;
    }
    if purpose.is_empty()
        || shard.is_empty()
        || !purpose
            .bytes()
            .chain(shard.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(CiError::Message("invalid cache purpose/shard".into()));
    }
    match collect_context(root, purpose, shard, external, partition) {
        Ok(context) => Ok(context),
        Err(error) if crate::work_outcome::has_unresolved_owner(&error) => Err(error),
        Err(error) => {
            eprintln!("compiled cache projection unavailable: {error}");
            let unavailable = OptionalCache::Unavailable {
                reason: "required compiled inputs unavailable".into(),
            };
            let entries: BTreeMap<String, OptionalCache> = BTreeMap::from([
                (
                    "source".into(),
                    crate::download_cache::context(
                        root,
                        crate::download_cache::DownloadFamily::for_purpose(purpose),
                    )?,
                ),
                ("product".into(), unavailable.clone()),
                ("consumer".into(), unavailable),
            ]);
            let partitions = entries
                .iter()
                .filter_map(|(name, value)| match value {
                    OptionalCache::Available { entry } => {
                        Some((name.clone(), entry.exact_key.clone()))
                    }
                    _ => None,
                })
                .collect();
            Ok(CacheContext {
                revision: 6,
                usable: false,
                inputs: BTreeMap::new(),
                partitions,
                entries,
                diagnostics: CacheDiagnostics {
                    source_commit: String::new(),
                    source_tree: String::new(),
                    unavailable_reasons: vec!["compiled-input-projection-unavailable".into()],
                },
            })
        }
    }
}

fn collect_context(
    root: &Path,
    purpose: &str,
    shard: &str,
    external: &[PathBuf],
    partition: Option<crate::cache_restore::CompiledPartition>,
) -> Result<CacheContext> {
    if purpose.is_empty()
        || shard.is_empty()
        || !purpose
            .bytes()
            .chain(shard.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(CiError::Message("invalid cache purpose/shard".into()));
    }
    let mut inputs = BTreeMap::new();
    let mut usable = true;
    let mut local_usable = true;
    let tool_purpose = matches!(purpose, "cargo-audit" | "cargo-deny" | "cargo-fuzz");
    let configurations = if tool_purpose {
        crate::cache_inputs::install_configs(root)
    } else {
        // Ordinary source-test/fuzz recipes use implicit-host compilation. A
        // global target override would change that recipe rather than select
        // the target represented by its explicit-target product sibling.
        crate::cache_inputs::cargo_configs_for_target(
            root,
            (partition == Some(crate::cache_restore::CompiledPartition::Product))
                .then(distribution::native_target)
                .transpose()?,
        )
    };
    match &configurations {
        Ok(configuration) => inputs.extend(configuration.clone()),
        Err(_) => usable = false,
    }
    let git = Git::new(root)?;
    let mut diagnostics = CacheDiagnostics {
        source_commit: git.text(["rev-parse", "--verify", "HEAD"])?,
        source_tree: git.text(["rev-parse", "--verify", "HEAD^{tree}"])?,
        unavailable_reasons: Vec::new(),
    };
    if configurations.is_err() {
        diagnostics
            .unavailable_reasons
            .push("cargo-configuration-unmodeled".into());
    }
    if !git
        .text(["status", "--porcelain=v1", "--untracked-files=no"])?
        .is_empty()
    {
        local_usable = false;
        diagnostics
            .unavailable_reasons
            .push("product-dirty-tracked-source".into());
    }
    let tracked = git.text(["ls-files", "--stage"])?;
    for line in tracked.lines() {
        if line.starts_with("160000 ") {
            let (metadata, path) = line
                .split_once('\t')
                .ok_or_else(|| CiError::Message("invalid submodule inventory".into()))?;
            let selected = metadata
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| CiError::Message("submodule object absent".into()))?;
            let actual = Git::new(&root.join(path))
                .and_then(|submodule| submodule.text(["rev-parse", "HEAD"]));
            if let Err(error) = &actual
                && crate::work_outcome::has_unresolved_owner(error)
            {
                return actual.map(|_| unreachable!());
            }
            if actual.as_deref().ok() != Some(selected) {
                local_usable = false;
                diagnostics
                    .unavailable_reasons
                    .push("product-submodule-selection-differs".into());
            }
            inputs.insert(format!("submodule:{path}"), selected.into());
        }
    }
    // LFS pointer identity alone cannot identify the populated external bytes.
    if root.join(".gitattributes").exists()
        && String::from_utf8_lossy(&artifacts::read_file(&root.join(".gitattributes"))?)
            .contains("filter=lfs")
    {
        local_usable = false;
        diagnostics
            .unavailable_reasons
            .push("product-lfs-bytes-unidentified".into());
    }
    let pins = crate::config::toolchains(root)?;
    let selected_toolchain = if purpose.starts_with("miri") || purpose.starts_with("fuzz") {
        &pins.miri
    } else if purpose == "msrv" {
        &pins.msrv
    } else {
        &pins.stable
    };
    for (name, arguments) in [
        ("rustc", vec!["run", selected_toolchain, "rustc", "-vV"]),
        ("cargo", vec!["run", selected_toolchain, "cargo", "-V"]),
    ] {
        match query(root, "rustup", &arguments) {
            Ok(value) => {
                inputs.insert(name.into(), value);
            }
            Err(error) if crate::work_outcome::has_unresolved_owner(&error) => return Err(error),
            Err(error) => {
                usable = false;
                diagnostics
                    .unavailable_reasons
                    .push(format!("compiler-query-unavailable:{name}"));
                eprintln!("optional compiled cache probe unavailable: {error}");
            }
        }
    }
    inputs.insert("target".into(), distribution::native_target()?.into());
    inputs.insert("purpose".into(), purpose.into());
    if purpose == "private"
        && matches!(
            partition,
            None | Some(crate::cache_restore::CompiledPartition::PrivateNativeTests)
        )
    {
        inputs.insert(
            "private-compiler-jobs".into(),
            crate::preparation::compiler_budget().to_string(),
        );
    }
    if matches!(
        purpose,
        "native-release" | "native-readiness" | "windows-working" | "private"
    ) && partition != Some(crate::cache_restore::CompiledPartition::PrivateNativeTests)
    {
        // Exactly the allocator used by release::target::compile_native_pair.
        let allocation = crate::preparation::allocate_pair(
            std::num::NonZeroUsize::new(crate::preparation::compiler_budget())
                .expect("positive budget"),
            true,
            crate::preparation::active_group().is_some_and(|group| group.inside_parallel_lane()),
            crate::preparation::PairClass::ProductAndNative,
        );
        if partition != Some(crate::cache_restore::CompiledPartition::NativeTests) {
            inputs.insert(
                "product-compiler-jobs".into(),
                allocation.first.get().to_string(),
            );
        }
        if partition != Some(crate::cache_restore::CompiledPartition::Product) {
            inputs.insert(
                "native-compiler-jobs".into(),
                allocation.second.get().to_string(),
            );
        }
    } else if purpose == "native-debug" {
        inputs.insert(
            "native-compiler-jobs".into(),
            crate::preparation::compiler_budget().to_string(),
        );
    }
    if purpose.starts_with("quality-compiler-") || purpose.starts_with("quality-documentation-") {
        let workers = crate::preparation::compiler_budget();
        let jobs = if purpose.contains("-local-") {
            let allocation = crate::preparation::allocate_pair(
                std::num::NonZeroUsize::new(workers).expect("positive budget"),
                crate::performance_plan::PerformancePlan::read(root)?
                    .quality
                    .selected
                    == crate::performance_plan::Layout::Parallel,
                crate::preparation::active_group()
                    .is_some_and(|group| group.inside_parallel_lane()),
                crate::preparation::PairClass::Balanced,
            );
            if purpose.starts_with("quality-compiler-") {
                allocation.second.get()
            } else {
                allocation.first.get()
            }
        } else {
            workers
        };
        inputs.insert("quality-compiler-jobs".into(), jobs.to_string());
        inputs.insert(
            "quality-leaf-recipe".into(),
            if purpose.starts_with("quality-compiler-") {
                "check-clippy-workspace-all-targets-all-features-locked-deny-warnings-v1"
            } else {
                "rustdoc-public-package-libraries-all-features-locked-deny-warnings-v1"
            }
            .into(),
        );
    }
    inputs.insert("toolchain".into(), selected_toolchain.clone());
    inputs.insert("shard".into(), shard.into());
    if purpose == "ci-driver-build" {
        inputs.insert("profile".into(), "release".into());
        inputs.insert(
            "driver-recipe".into(),
            serde_json::to_string(&(
                "memcordon-ci",
                "memcordon-ci",
                "release",
                distribution::native_target()?,
                "target/ci-driver-build",
                Vec::<String>::new(),
                "bootstrap-abi-v1",
            ))?,
        );
    }
    if partition != Some(crate::cache_restore::CompiledPartition::NativeTests)
        && matches!(
            purpose,
            "consumer-readiness" | "native-readiness" | "windows-working" | "private"
        )
    {
        let selected = distribution::Distribution::read(root)?
            .consumer_readiness()?
            .native()?
            .clone();
        inputs.insert(
            "consumer-runtime-selection".into(),
            serde_json::to_string(&selected)?,
        );
        inputs.insert(
            "consumer-readiness-inventory".into(),
            artifacts::checksum(&artifacts::read_file(
                &root.join("ci/consumer-readiness-v1.toml"),
            )?),
        );
        inputs.insert("consumer-profile".into(), "selected-product:release;owned-fixture:release;driver:release;generated-consumer:dev+release".into());
    }
    if let Some(recipe) = native_recipe(purpose) {
        inputs.insert(
            "native-test-arguments".into(),
            serde_json::to_string(&recipe)?,
        );
        inputs.insert(
            "profile".into(),
            if purpose == "native-debug" {
                "source-tests:dev"
            } else {
                "source-tests:release;product:release"
            }
            .into(),
        );
        if partition != Some(crate::cache_restore::CompiledPartition::NativeTests)
            && matches!(
                purpose,
                "native-release" | "native-readiness" | "windows-working" | "private"
            )
        {
            inputs.insert("product-package".into(), "memcordon".into());
            inputs.insert("product-profile".into(), "release".into());
            match distribution::Distribution::read(root).and_then(|selected| {
                let selected =
                    if matches!(purpose, "native-readiness" | "windows-working" | "private") {
                        selected.consumer_readiness()?
                    } else {
                        selected
                    };
                Ok(selected.native()?.clone())
            }) {
                Ok(selected) => {
                    inputs.insert(
                        "product-distribution".into(),
                        serde_json::to_string(&selected)?,
                    );
                }
                Err(_) => {
                    usable = false;
                    inputs.insert("product-distribution".into(), "unknown-selection".into());
                }
            }
        }
    } else {
        inputs.insert(
            "profile".into(),
            "source-tests:dev+release;product:release;consumer:dev+release;driver:dev".into(),
        );
    }
    if !tool_purpose {
        inputs.insert(
            "distribution".into(),
            artifacts::checksum(&artifacts::read_file(&root.join("ci/distribution.toml"))?),
        );
        inputs.insert(
            "lock".into(),
            artifacts::checksum(&artifacts::read_file(&root.join("Cargo.lock"))?),
        );
    }
    for name in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "MACOSX_DEPLOYMENT_TARGET",
        "SDKROOT",
    ] {
        if let Some(value) = std::env::var_os(name) {
            inputs.insert(name.into(), value.to_string_lossy().into_owned());
        }
    }
    for path in external {
        match artifacts::read_file(path) {
            Ok(bytes) => {
                inputs.insert(path.display().to_string(), artifacts::checksum(&bytes));
            }
            Err(_) => {
                usable = false;
                inputs.insert(path.display().to_string(), "unknown-external-input".into());
            }
        }
    }
    for (name, _value) in std::env::vars_os() {
        let name = name.to_string_lossy().to_ascii_uppercase();
        if name == "CARGO_BUILD_JOBS" {
            continue;
        }
        if name == "CARGO_ENCODED_RUSTFLAGS" {
            let flags = std::env::var(&name)
                .ok()
                .and_then(|value| crate::cache_inputs::encoded_rustflags(&value).ok());
            match flags {
                Some(flags) if !inputs.keys().any(|key| key.starts_with("profile.")) => {
                    inputs.insert(name, serde_json::to_string(&flags)?);
                    continue;
                }
                _ => {}
            }
        }
        if name == "CARGO_INCREMENTAL" {
            let value = std::env::var(&name)
                .ok()
                .and_then(|value| crate::cache_inputs::incremental_setting(&value).ok());
            match value {
                Some(value)
                    if !inputs
                        .keys()
                        .any(|key| key == "build.incremental" || key.ends_with(".incremental")) =>
                {
                    inputs.insert(name, value.to_string());
                    continue;
                }
                _ => {}
            }
        }
        if matches!(
            name.as_ref(),
            "CC" | "CXX"
                | "AR"
                | "CFLAGS"
                | "CXXFLAGS"
                | "LDFLAGS"
                | "CPATH"
                | "C_INCLUDE_PATH"
                | "CPLUS_INCLUDE_PATH"
                | "LIBRARY_PATH"
                | "RUSTC"
                | "RUSTFLAGS"
                | "RUSTDOCFLAGS"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
        ) || name.starts_with("CARGO_TARGET_")
            || name.starts_with("CARGO_BUILD_")
            || name.starts_with("CARGO_PROFILE_")
            || name.starts_with("CARGO_ENCODED_")
            || name == "CARGO_INCREMENTAL"
            || name.starts_with("HOST_")
            || name.starts_with("TARGET_")
            || ["CC_", "CXX_", "AR_", "CFLAGS_", "CXXFLAGS_", "LDFLAGS_"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        {
            // Overrides may select otherwise unidentified tools/headers. They
            // remain usable for clean builds, with affected reuse disabled.
            usable = false;
            if diagnostics.unavailable_reasons.len() < 16 {
                diagnostics
                    .unavailable_reasons
                    .push(format!("compiler-override:{name}"));
            }
        }
    }
    if purpose.starts_with("fuzz") {
        match crate::preparation::auxiliary_tool(root, "cargo-fuzz")
            .and_then(|path| query(root, path.as_os_str(), &["--version"]))
        {
            Ok(value) => {
                inputs.insert("cargo-fuzz".into(), value);
            }
            Err(error) if crate::work_outcome::has_unresolved_owner(&error) => return Err(error),
            Err(_) => usable = false,
        }
    }
    if purpose.starts_with("miri") {
        match query(
            root,
            "rustup",
            &["run", selected_toolchain, "cargo", "miri", "--version"],
        ) {
            Ok(value) => {
                inputs.insert("miri".into(), value);
            }
            Err(error) if crate::work_outcome::has_unresolved_owner(&error) => return Err(error),
            Err(_) => usable = false,
        }
    }
    match std::env::consts::OS {
        "linux" => {
            for (name, program, args) in [
                ("cc", "cc", vec!["--version"]),
                ("ld", "ld", vec!["--version"]),
                ("libc", "ldd", vec!["--version"]),
            ] {
                match query(root, program, &args) {
                    Ok(value) => {
                        inputs.insert(name.into(), value);
                    }
                    Err(error) if crate::work_outcome::has_unresolved_owner(&error) => {
                        return Err(error);
                    }
                    Err(_) => {
                        usable = false;
                        diagnostics
                            .unavailable_reasons
                            .push(format!("native-tool-unavailable:{name}"));
                    }
                }
            }
        }
        "macos" => {
            for (name, args) in [
                ("xcode", vec!["-version"]),
                ("sdk", vec!["-version", "-sdk", "macosx"]),
            ] {
                match query(root, "xcodebuild", &args) {
                    Ok(value) => {
                        inputs.insert(name.into(), value);
                    }
                    Err(error) if crate::work_outcome::has_unresolved_owner(&error) => {
                        return Err(error);
                    }
                    Err(_) => {
                        usable = false;
                        diagnostics
                            .unavailable_reasons
                            .push(format!("native-tool-unavailable:{name}"));
                    }
                }
            }
        }
        "windows" => {
            #[cfg(windows)]
            match crate::windows_cache_identity::discover_native(
                distribution::native_target()?,
                std::time::Instant::now() + Duration::from_secs(30),
            ) {
                Ok(identity) => inputs.extend(identity),
                Err(error) if crate::work_outcome::has_unresolved_owner(&error) => {
                    return Err(error);
                }
                Err(error) => {
                    usable = false;
                    diagnostics
                        .unavailable_reasons
                        .push(format!("Windows native selection unavailable: {error}"));
                }
            }
        }
        _ => usable = false,
    }
    for name in ["ImageOS", "ImageVersion"] {
        match std::env::var(name) {
            Ok(value) if !value.is_empty() => {
                inputs.insert(name.into(), value);
            }
            _ => {
                usable = false;
                diagnostics
                    .unavailable_reasons
                    .push(format!("image-identity-unavailable:{name}"));
            }
        }
    }
    let revision = 4;
    let mut entries: BTreeMap<String, OptionalCache> = BTreeMap::new();
    if matches!(purpose, "cargo-audit" | "cargo-deny" | "cargo-fuzz") {
        let pins = crate::config::tools(root)?;
        let version = match purpose {
            "cargo-audit" => pins.cargo_audit,
            "cargo-deny" => pins.cargo_deny,
            "cargo-fuzz" => pins.cargo_fuzz,
            _ => unreachable!(),
        };
        let mut compatibility = inputs.clone();
        for field in ["purpose", "shard", "lock", "distribution", "profile"] {
            compatibility.remove(field);
        }
        compatibility.retain(|name, _| !name.starts_with("submodule:"));
        let content = BTreeMap::from([
            ("package".into(), purpose.into()),
            ("version".into(), version),
            ("recipe".into(), "cargo-install-locked-stable".into()),
        ]);
        for (name, family, path) in [
            (
                "tool",
                "tool",
                root.join("target/ci-tools/bin").join(if cfg!(windows) {
                    format!("{purpose}.exe")
                } else {
                    purpose.into()
                }),
            ),
            (
                "tool-build",
                "tool-build",
                root.join("target/ci-tools-build").join(purpose),
            ),
        ] {
            let entry = if usable {
                if family == "tool-build" {
                    compatibility.insert(
                        "tool-compiler-jobs".into(),
                        tool_compiler_jobs(root, purpose, shard)?.to_string(),
                    );
                }
                compatibility.insert("tool-package".into(), purpose.into());
                compatibility.insert(
                    "tool-build-root".into(),
                    root.join("target/ci-tools-build")
                        .join(purpose)
                        .display()
                        .to_string(),
                );
                compatibility.insert(
                    "registry-source-root".into(),
                    crate::download_cache::cargo_home(root)?
                        .join("registry/src")
                        .display()
                        .to_string(),
                );
                compatibility.insert(
                    "tool-build-recipe".into(),
                    "install-locked-stable-release-default-features-per-tool-staging-bounded-jobs-v2".into(),
                );
                compatibility.insert(
                    "cargo-home".into(),
                    crate::download_cache::cargo_home(root)?
                        .canonicalize()?
                        .display()
                        .to_string(),
                );
                compatibility.insert(
                    "compiler-source-root".into(),
                    root.canonicalize()?.display().to_string(),
                );
                let (exact_key, prefix) =
                    crate::cache_inputs::keys(&crate::cache_inputs::KeyInputs {
                        family: family.into(),
                        layout_revision: if family == "tool-build" { 6 } else { revision },
                        compatibility: compatibility.clone(),
                        content: content.clone(),
                    })?;
                OptionalCache::Available {
                    entry: CacheEntry {
                        exact_key,
                        restore_prefix: (family == "tool-build").then_some(prefix),
                        paths: vec![path],
                    },
                }
            } else {
                OptionalCache::Unavailable {
                    reason: "unidentified tool compiler compatibility".into(),
                }
            };
            entries.insert(name.into(), entry);
        }
    }
    entries.insert(
        "source".into(),
        crate::download_cache::context(
            root,
            crate::download_cache::DownloadFamily::for_purpose(purpose),
        )?,
    );
    let stable_reader = query(root, "rustup", &["run", &pins.stable, "cargo", "-V"]);
    if let Err(error) = &stable_reader
        && crate::work_outcome::has_unresolved_owner(error)
    {
        return stable_reader.map(|_| unreachable!());
    }
    if let (Ok(configuration), Some(selected_reader), Ok(stable_reader)) =
        (&configurations, inputs.get("cargo"), stable_reader)
    {
        let readers = BTreeMap::from([
            ("driver-reader".into(), stable_reader),
            ("selected-reader".into(), selected_reader.clone()),
            ("index-os".into(), std::env::consts::OS.into()),
        ]);
        let (exact_key, _) = crate::cache_inputs::keys(&crate::cache_inputs::KeyInputs {
            family: "index".into(),
            layout_revision: revision,
            compatibility: readers,
            content: configuration.clone(),
        })?;
        entries.insert(
            "index".into(),
            OptionalCache::Available {
                entry: CacheEntry {
                    exact_key,
                    restore_prefix: None,
                    paths: vec!["~/.cargo/registry/index".into()],
                },
            },
        );
    }
    let local = crate::cache_inputs::local_files(root, purpose);
    if let Err(error) = &local
        && crate::work_outcome::has_unresolved_owner(error)
    {
        return local.map(|_| unreachable!());
    }
    usable &= local_usable;
    if local.is_err() {
        usable = false;
        diagnostics
            .unavailable_reasons
            .push("product-local-inputs-unmodeled".into());
    }
    let layout = crate::cache_restore::partition_layout(purpose, shard, partition);
    let paths = layout.as_ref().map(|layout| layout.archive_members());
    if paths.is_err() || !external.is_empty() {
        usable = false;
        diagnostics
            .unavailable_reasons
            .push("product-output-ownership-unestablished".into());
    }
    // Consumer archive envelopes are integrity inputs, not a compiler projection.
    // No compiled consumer entry is emitted until its current builder owns a seed root.
    entries.insert(
        "consumer".into(),
        OptionalCache::Unavailable {
            reason: "fresh public capture or unassociated generated consumer root".into(),
        },
    );
    let mut compatibility = inputs.clone();
    compatibility.remove("lock");
    compatibility.remove("distribution");
    compatibility.remove("native-test-arguments");
    compatibility.insert(
        "cargo-home".into(),
        crate::download_cache::cargo_home(root)?
            .canonicalize()?
            .display()
            .to_string(),
    );
    if let Some(partition) = partition {
        compatibility = partition_compatibility(purpose, partition, compatibility)?;
    }
    if purpose == "native-auxiliary" {
        compatibility.insert(
            "profile".into(),
            "nested-auxiliary:dev+release;implicit-host".into(),
        );
        compatibility.insert(
            "compilation-arguments".into(),
            "current-nested-workspace-cargo-build-recipes".into(),
        );
    }
    if let Some(recipe) = native_recipe(purpose) {
        let compilation = recipe.into_iter().next().unwrap_or_default();
        compatibility.insert(
            "compilation-arguments".into(),
            serde_json::to_string(&compilation)?,
        );
    }
    compatibility.insert(
        "compiler-source-root".into(),
        root.canonicalize()?.display().to_string(),
    );
    if usable {
        let (exact_key, restore_prefix) =
            crate::cache_inputs::keys(&crate::cache_inputs::KeyInputs {
                family: "workspace".into(),
                layout_revision: layout.as_ref().expect("usable layout").revision,
                compatibility,
                content: {
                    let mut content = local?;
                    if partition == Some(crate::cache_restore::CompiledPartition::FuzzTargets) {
                        content.insert("selected-shard".into(), shard.into());
                    }
                    content
                },
            })?;
        entries.insert(
            "product".into(),
            OptionalCache::Available {
                entry: CacheEntry {
                    exact_key,
                    restore_prefix: Some(restore_prefix),
                    paths: paths.expect("usable layout"),
                },
            },
        );
    } else {
        entries.insert(
            "product".into(),
            OptionalCache::Unavailable {
                reason: "unidentified compiler inputs or output ownership".into(),
            },
        );
    }
    let partitions = entries
        .iter()
        .filter_map(|(name, optional)| match optional {
            OptionalCache::Available { entry } => Some((name.clone(), entry.exact_key.clone())),
            OptionalCache::Unavailable { .. } => None,
        })
        .collect();
    diagnostics.unavailable_reasons.sort();
    diagnostics.unavailable_reasons.dedup();
    diagnostics.unavailable_reasons.truncate(16);
    Ok(CacheContext {
        revision,
        usable,
        inputs,
        partitions,
        entries,
        diagnostics,
    })
}

pub fn emit(root: &Path, purpose: &str, shard: &str, external: &[PathBuf]) -> Result<()> {
    emit_with_intent(root, purpose, shard, external, false)
}

pub fn emit_with_intent(
    root: &Path,
    purpose: &str,
    shard: &str,
    external: &[PathBuf],
    for_save: bool,
) -> Result<()> {
    emit_partition(root, purpose, shard, external, for_save, None)
}

pub fn emit_partition(
    root: &Path,
    purpose: &str,
    shard: &str,
    external: &[PathBuf],
    for_save: bool,
    partition: Option<crate::cache_restore::CompiledPartition>,
) -> Result<()> {
    let context = context_partition(root, purpose, shard, external, partition)?;
    let mut outputs = vec![("compiled-cache-usable", "false".to_owned())];
    outputs.push((
        "bootstrap-home-matches",
        crate::download_cache::bootstrap_home_matches(root).to_string(),
    ));
    outputs.push((
        "payload-ready",
        (for_save
            && if matches!(purpose, "cargo-audit" | "cargo-deny" | "cargo-fuzz") {
                let layout = crate::cache_restore::tool_build_layout(purpose, shard)?;
                let target = crate::cache_restore::safe_root(root, &layout.directories[0])?;
                let locks = crate::cache_restore::settled_locks(std::slice::from_ref(&target))?;
                let ready = crate::cache_restore::cargo_marker_present(&target)?
                    && walkdir::WalkDir::new(&target)
                        .follow_links(false)
                        .into_iter()
                        .filter_map(std::result::Result::ok)
                        .any(|entry| {
                            entry.file_type().is_file()
                                && entry.file_name() != "CACHEDIR.TAG"
                                && entry.file_name() != ".cargo-lock"
                        });
                drop(locks);
                ready
            } else {
                crate::cache_restore::partition_payload_ready(root, purpose, shard, partition)?
            })
        .to_string(),
    ));
    if context.usable {
        outputs[0].1 = "true".into();
    }
    for (partition, key_output, prefix_output, paths_output) in [
        (
            "source",
            "source-key",
            "source-restore-prefix",
            "source-paths",
        ),
        (
            "product",
            "product-key",
            "product-restore-prefix",
            "product-paths",
        ),
        (
            "consumer",
            "consumer-key",
            "consumer-restore-prefix",
            "consumer-paths",
        ),
    ] {
        let entry = match &context.entries[partition] {
            OptionalCache::Available { entry } => Some(entry),
            OptionalCache::Unavailable { .. } => None,
        };
        outputs.push((
            key_output,
            entry.map_or_else(String::new, |entry| entry.exact_key.clone()),
        ));
        outputs.push((
            prefix_output,
            entry
                .and_then(|entry| entry.restore_prefix.clone())
                .unwrap_or_default(),
        ));
        outputs.push((
            paths_output,
            entry
                .map(|entry| crate::workflow_output::action_paths(&entry.paths))
                .transpose()?
                .unwrap_or_default(),
        ));
    }
    for (name, key_output, path_output) in [
        ("tool", "tool-key", "tool-path"),
        ("tool-build", "tool-build-key", "tool-build-path"),
        ("index", "index-key", "index-path"),
    ] {
        if let Some(OptionalCache::Available { entry }) = context.entries.get(name) {
            outputs.push((key_output, entry.exact_key.clone()));
            outputs.push((
                path_output,
                crate::workflow_output::action_paths(&entry.paths)?,
            ));
        } else {
            outputs.push((key_output, String::new()));
            outputs.push((path_output, String::new()));
        }
    }
    outputs.push((
        "tool-build-restore-prefix",
        match context.entries.get("tool-build") {
            Some(OptionalCache::Available { entry }) => {
                entry.restore_prefix.clone().unwrap_or_default()
            }
            _ => String::new(),
        },
    ));
    crate::workflow_output::write(&outputs)?;
    println!("{}", serde_json::to_string_pretty(&context)?);
    Ok(())
}
