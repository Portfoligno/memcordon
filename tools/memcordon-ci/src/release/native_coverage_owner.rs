//! Source-bound owners for distributed native Cargo compilation and execution.
use super::{
    artifacts,
    distribution::TargetDistribution,
    source::{self, BuildSourceIdentity},
};
use crate::{
    CiError, Result,
    command::{CiPhase, CommandSpec},
    native_coverage::*,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const SHARD_COUNT: usize = 4;
const LEDGER_BYTES: usize = 64 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageDeadline {
    format: String,
    revision: u32,
    source: BuildSourceIdentity,
    target: String,
    started_unix_millis: u64,
    work_deadline_unix_millis: u64,
    cleanup_deadline_unix_millis: u64,
}
fn unix_millis() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| error("coverage wall clock precedes epoch"))?
            .as_millis(),
    )
    .map_err(|_| error("coverage wall clock overflow"))
}
pub fn original_cutoff(
    root: &Path,
    selected: &BuildSourceIdentity,
    target: &str,
) -> Result<Instant> {
    selected.validate()?;
    let sampled = Instant::now();
    let now = unix_millis()?;
    let record: CoverageDeadline = serde_json::from_slice(&artifacts::read_file(
        &root.join(".release/native-coverage-deadline.json"),
    )?)?;
    if record.format != "memcordon.native-coverage.original-deadline"
        || record.revision != 1
        || record.source != *selected
        || record.target != target
        || record.started_unix_millis > now
        || record.started_unix_millis.checked_add(140 * 60 * 1000)
            != Some(record.work_deadline_unix_millis)
        || record.started_unix_millis.checked_add(155 * 60 * 1000)
            != Some(record.cleanup_deadline_unix_millis)
    {
        return Err(error(
            "original distributed native coverage deadline binding differs",
        ));
    }
    let remaining = record
        .work_deadline_unix_millis
        .checked_sub(now)
        .and_then(|value| value.checked_sub(1))
        .filter(|value| *value > 0)
        .ok_or_else(|| error("original distributed native cutoff exhausted"))?;
    sampled
        .checked_add(Duration::from_millis(remaining))
        .ok_or_else(|| error("distributed native monotonic cutoff overflow"))
}

fn error(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| error("native coverage text field absent"))
}
fn relative(root: &Path, path: &str) -> Result<String> {
    let path = Path::new(path)
        .strip_prefix(root)
        .map_err(|_| error("native coverage source escapes selected checkout"))?;
    Ok(super::artifacts::safe_relative(path)?
        .to_string_lossy()
        .replace('\\', "/"))
}
fn cargo(root: &Path, toolchain: &str, budget: Duration, cutoff: Instant) -> CommandSpec {
    CommandSpec::cargo("rustup", root, toolchain, budget)
        .bounded_until(cutoff)
        .output_limit(LEDGER_BYTES)
}
fn output(command: CommandSpec) -> Result<Vec<u8>> {
    let result = command.run_owned();
    if !result.writers().permits_reading() {
        return Err(error("native coverage command writers did not settle"));
    }
    result.into_result()
}

pub struct PreparedPlan {
    pub plan: Plan,
    packages: BTreeMap<String, String>,
}

fn fixture_owner(plan: &Plan) -> Result<usize> {
    let requirement = plan
        .requirements
        .iter()
        .find(|requirement| {
            requirement.target.name == "memcordon-test-fixture"
                && requirement.variant == Variant::OrdinaryBinarySupport
        })
        .ok_or_else(|| error("ordinary fixture support requirement absent"))?;
    let group = plan
        .groups
        .iter()
        .position(|group| group.requirements.contains(&requirement.id))
        .ok_or_else(|| error("ordinary fixture selector owner absent"))?;
    plan.shards
        .iter()
        .find(|shard| shard.groups.contains(&group))
        .map(|shard| shard.id)
        .ok_or_else(|| error("ordinary fixture shard owner absent"))
}

pub fn selection_command(
    root: &Path,
    toolchain: &str,
    directory: &Path,
    selectors: &[String],
    compile: bool,
    failure_mode: crate::failure_mode::FailureMode,
    cutoff: Instant,
) -> CommandSpec {
    let recipes = crate::native_test_plan::commands_for_platform(
        true,
        failure_mode,
        crate::native_test_plan::NativePlatform::MacOs,
    );
    let mut command = cargo(
        root,
        toolchain,
        recipes[usize::from(!compile)].deadline,
        cutoff,
    )
    .args(["test", "--target-dir"])
    .arg(directory)
    .args(selectors)
    .arg("--message-format=json-render-diagnostics")
    .phase(if compile {
        CiPhase::NativeCompile
    } else {
        CiPhase::NativeExecute
    });
    if compile {
        command = command.args(["--no-run", "--verbose"]);
    } else if failure_mode == crate::failure_mode::FailureMode::CollectAll {
        command = command.arg("--no-fail-fast");
    }
    command
}

pub fn support_command(
    root: &Path,
    toolchain: &str,
    directory: &Path,
    selectors: &[String],
    compile: bool,
    failure_mode: crate::failure_mode::FailureMode,
    cutoff: Instant,
) -> CommandSpec {
    let recipes = crate::native_test_plan::commands_for_platform(
        true,
        failure_mode,
        crate::native_test_plan::NativePlatform::MacOs,
    );
    cargo(
        root,
        toolchain,
        recipes[usize::from(!compile)].deadline,
        cutoff,
    )
    .args(["build", "--target-dir"])
    .arg(directory)
    .args(selectors)
    .arg("--message-format=json-render-diagnostics")
    .phase(if compile {
        CiPhase::NativeCompile
    } else {
        CiPhase::NativeExecute
    })
}

/// Project only measured Cargo metadata and selected manifest/configuration bytes.
pub fn prepare(
    root: &Path,
    selected: &BuildSourceIdentity,
    target: &str,
    cutoff: Instant,
) -> Result<PreparedPlan> {
    selected.recheck(root)?;
    if Instant::now() >= cutoff {
        return Err(error("native coverage original cutoff exhausted"));
    }
    if target != super::distribution::native_target()? {
        return Err(error("native coverage requires the actual native target"));
    }
    let toolchain = crate::config::toolchains(root)?.stable;
    let rustc = output(
        CommandSpec::toolchain_program(
            "rustup",
            root,
            &toolchain,
            "rustc",
            Duration::from_secs(60),
        )
        .arg("-vV")
        .bounded_until(cutoff),
    )?;
    let rustc_text =
        std::str::from_utf8(&rustc).map_err(|_| error("native rustc identity is not UTF8"))?;
    let host = rustc_text
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or_else(|| error("native rustc host absent"))?;
    if host != target
        || !rustc_text
            .lines()
            .any(|line| line.strip_prefix("release: ") == Some("1.97.1"))
    {
        return Err(error(
            "native coverage compiler host or pinned release differs",
        ));
    }
    let cargo_version =
        output(cargo(root, &toolchain, Duration::from_secs(60), cutoff).arg("--version"))?;
    let cargo_version =
        String::from_utf8(cargo_version).map_err(|_| error("Cargo version is not UTF8"))?;
    let bytes = output(
        cargo(root, &toolchain, Duration::from_secs(120), cutoff).args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
        ]),
    )?;
    let metadata: Value = serde_json::from_slice(&bytes)?;
    let members = metadata["workspace_members"]
        .as_array()
        .ok_or_else(|| error("workspace members absent"))?;
    let all_packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| error("workspace packages absent"))?;
    let root_manifest = artifacts::read_file(&root.join("Cargo.toml"))?;
    let manifest: toml::Value = toml::from_str(
        std::str::from_utf8(&root_manifest).map_err(|_| error("manifest UTF8 differs"))?,
    )?;
    let mut configuration: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    if manifest
        .get("profile")
        .and_then(|value| value.get("release"))
        .and_then(|value| value.get("package"))
        .and_then(toml::Value::as_table)
        .is_some_and(|overrides| {
            overrides.keys().any(|name| {
                !all_packages.iter().any(|package| {
                    members.contains(&package["id"])
                        && package["name"].as_str() == Some(name.as_str())
                })
            })
        })
    {
        return Err(error(
            "native coverage wildcard or qualified package profile requires explicit projection",
        ));
    }
    configuration.insert("Cargo.toml".into(), root_manifest);
    configuration.insert(
        "original-native-deadline.json".into(),
        artifacts::read_file(&root.join(".release/native-coverage-deadline.json"))?,
    );
    for ancestor in root.ancestors() {
        for name in ["config", "config.toml"] {
            let path = ancestor.join(".cargo").join(name);
            if path.try_exists()? {
                if ancestor != root {
                    return Err(error(
                        "native coverage refuses inherited ancestor Cargo configuration",
                    ));
                }
                let bytes = artifacts::read_file(&path)?;
                let config: toml::Value = toml::from_str(
                    std::str::from_utf8(&bytes)
                        .map_err(|_| error("Cargo configuration UTF8 differs"))?,
                )?;
                validate_config(&config)?;
                configuration.insert(
                    relative(
                        root,
                        path.to_str()
                            .ok_or_else(|| error("Cargo configuration path UTF8 differs"))?,
                    )?,
                    bytes,
                );
            }
        }
    }
    if let Some(home) = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
        })
    {
        for name in ["config", "config.toml"] {
            let path = home.join(name);
            if path.try_exists()? {
                let bytes = artifacts::read_file(&path)?;
                let config: toml::Value = toml::from_str(
                    std::str::from_utf8(&bytes)
                        .map_err(|_| error("Cargo home configuration UTF8 differs"))?,
                )?;
                validate_config(&config)?;
                configuration.insert(
                    Path::new("cargo-home")
                        .join(name)
                        .to_string_lossy()
                        .into_owned(),
                    bytes,
                );
            }
        }
    }
    // No unrecorded environment override may change the admitted graph/profile.
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy();
        if name.starts_with("CARGO_PROFILE_")
            || name.starts_with("CARGO_TARGET_")
            || matches!(
                name.as_ref(),
                "CARGO_BUILD_TARGET"
                    | "CARGO_BUILD_RUSTFLAGS"
                    | "RUSTFLAGS"
                    | "CARGO_ENCODED_RUSTFLAGS"
                    | "RUSTC_WRAPPER"
                    | "RUSTC_WORKSPACE_WRAPPER"
                    | "RUSTC"
                    | "RUSTDOC"
                    | "RUSTDOCFLAGS"
            )
        {
            return Err(error(
                "native coverage refuses ambient compiler/profile overrides",
            ));
        }
    }
    let mut packages = BTreeMap::new();
    let mut targets = Vec::new();
    let mut features = BTreeMap::new();
    for package in all_packages
        .iter()
        .filter(|package| members.contains(&package["id"]))
    {
        let key = relative(root, text(package, "manifest_path")?)?;
        packages.insert(text(package, "id")?.to_owned(), key.clone());
        let package_manifest = artifacts::read_file(&root.join(&key))?;
        let package_table: toml::Value = toml::from_str(
            std::str::from_utf8(&package_manifest)
                .map_err(|_| error("package manifest UTF8 differs"))?,
        )?;
        configuration.insert(key.clone(), package_manifest);
        let node = metadata["resolve"]["nodes"]
            .as_array()
            .and_then(|nodes| nodes.iter().find(|node| node["id"] == package["id"]))
            .ok_or_else(|| error("workspace resolved feature node absent"))?;
        let resolved: Vec<String> = serde_json::from_value(node["features"].clone())?;
        features.insert(key.clone(), resolved);
        let package_name = text(package, "name")?;
        let profile = release_profile(&manifest, package_name)?;
        for target in package["targets"]
            .as_array()
            .ok_or_else(|| error("package target inventory absent"))?
        {
            let kinds: Vec<String> = serde_json::from_value(target["kind"].clone())?;
            let kind = crate::native_coverage::target_kind(&kinds).map_err(CiError::Message)?;
            if kind == TargetKind::CustomBuild {
                continue;
            }
            let name = text(target, "name")?.to_owned();
            let manifest_section = match kind {
                TargetKind::Lib | TargetKind::ProcMacro => "lib",
                TargetKind::Bin => "bin",
                TargetKind::Test => "test",
                TargetKind::Example => "example",
                TargetKind::Bench => "bench",
                TargetKind::CustomBuild => unreachable!("build scripts excluded above"),
            };
            let declared = if manifest_section == "lib" {
                package_table.get(manifest_section)
            } else {
                package_table
                    .get(manifest_section)
                    .and_then(toml::Value::as_array)
                    .and_then(|entries| {
                        entries.iter().find(|entry| {
                            entry.get("name").and_then(toml::Value::as_str) == Some(name.as_str())
                        })
                    })
            };
            let harness = declared
                .and_then(|entry| entry.get("harness"))
                .and_then(toml::Value::as_bool)
                .unwrap_or(true);
            targets.push(TargetSpec {
                package: key.clone(),
                name,
                kind,
                source: relative(root, text(target, "src_path")?)?,
                required_features: target
                    .get("required-features")
                    .map(|value| serde_json::from_value(value.clone()))
                    .transpose()?
                    .unwrap_or_default(),
                harness,
                test: target
                    .get("test")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| error("target test flag absent"))?,
                expected_profile: profile.clone(),
            });
        }
    }
    let tree = output(
        CommandSpec::new("git", root, Duration::from_secs(120))
            .args(["archive", "--format=tar", "HEAD"])
            .bounded_until(cutoff)
            .output_limit(source::MAX_SOURCE_ARCHIVE_BYTES),
    )?;
    if tree.len() >= source::MAX_SOURCE_ARCHIVE_BYTES {
        return Err(error("native coverage source archive exceeds bound"));
    }
    let identity = CoverageIdentity {
        source: selected.clone(),
        source_tree_sha256: artifacts::checksum(&tree),
        lock_sha256: artifacts::checksum(&artifacts::read_file(&root.join("Cargo.lock"))?),
        configuration_sha256: artifacts::checksum(&serde_json::to_vec(&configuration)?),
        toolchain,
        cargo_version: cargo_version.trim().to_owned(),
        rustc_verbose_sha256: artifacts::checksum(&rustc),
        host: host.to_owned(),
        target: target.to_owned(),
        profile: "release".into(),
        all_features: true,
    };
    let spec = WorkspaceSpec {
        identity,
        packages: packages.values().cloned().collect(),
        package_features: features,
        targets,
    };
    if Instant::now() >= cutoff {
        return Err(error(
            "native coverage original cutoff exhausted during projection",
        ));
    }
    Ok(PreparedPlan {
        plan: Plan::build(spec, SHARD_COUNT).map_err(CiError::Message)?,
        packages,
    })
}

fn validate_config(config: &toml::Value) -> Result<()> {
    if config.get("profile").is_some()
        || config.get("target").is_some()
        || config.get("env").is_some()
        || config
            .get("build")
            .and_then(toml::Value::as_table)
            .is_some_and(|table| {
                table.keys().any(|key| {
                    matches!(
                        key.as_str(),
                        "target"
                            | "rustflags"
                            | "rustc"
                            | "rustc-wrapper"
                            | "rustc-workspace-wrapper"
                            | "rustdoc"
                    )
                })
            })
    {
        return Err(error(
            "native coverage Cargo graph/profile overrides require explicit projection",
        ));
    }
    Ok(())
}

fn release_profile(manifest: &toml::Value, package: &str) -> Result<Value> {
    let mut profile = json!({"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":true});
    let release = manifest
        .get("profile")
        .and_then(|value| value.get("release"));
    for entry in [
        release,
        release
            .and_then(|value| value.get("package"))
            .and_then(|value| value.get(package)),
    ]
    .into_iter()
    .flatten()
    {
        if entry.get("inherits").is_some() {
            return Err(error(
                "native coverage release inheritance is not projected",
            ));
        }
        for (key, field) in [
            ("debug-assertions", "debug_assertions"),
            ("overflow-checks", "overflow_checks"),
        ] {
            if let Some(value) = entry.get(key) {
                profile[field] = json!(
                    value
                        .as_bool()
                        .ok_or_else(|| error("profile boolean differs"))?
                );
            }
        }
        if let Some(value) = entry.get("opt-level") {
            profile["opt_level"] = json!(
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.as_integer().map(|number| number.to_string()))
                    .ok_or_else(|| error("profile optimization differs"))?
            );
        }
        if let Some(value) = entry.get("debug") {
            profile["debuginfo"] = match value {
                toml::Value::Boolean(false) => json!(0),
                toml::Value::Boolean(true) => json!(2),
                toml::Value::Integer(number) => json!(number),
                _ => return Err(error("profile debug mode is not projected")),
            };
        }
    }
    Ok(profile)
}

fn kind(value: &Value) -> Result<TargetKind> {
    let kinds: Vec<String> = serde_json::from_value(value.clone())?;
    crate::native_coverage::target_kind(&kinds).map_err(CiError::Message)
}

fn ledger(root: &Path, prepared: &PreparedPlan, bytes: &[u8]) -> Result<Vec<UnitObservation>> {
    if bytes.len() >= LEDGER_BYTES {
        return Err(error("native coverage output ledger overflow"));
    }
    let mut finished = false;
    let mut units = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.len() > 1024 * 1024 {
            return Err(error("native coverage record exceeds bound"));
        }
        let Ok(record) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if record["reason"] == "build-finished" {
            if finished || record["success"] != true {
                return Err(error("Cargo build-finished receipt differs"));
            }
            finished = true;
        }
        if record["reason"] != "compiler-artifact" {
            continue;
        }
        if units.len() >= 8192 {
            return Err(error("native coverage unit inventory overflow"));
        }
        let raw_package = text(&record, "package_id")?;
        let package = prepared
            .packages
            .get(raw_package)
            .cloned()
            .unwrap_or_else(|| raw_package.to_owned());
        let target = &record["target"];
        let source = if prepared.packages.contains_key(raw_package) {
            relative(root, text(target, "src_path")?)?
        } else {
            // A dependency's package identity is stable; checkout/cache roots are not.
            Path::new(text(target, "src_path")?)
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| error("dependency source basename absent"))?
                .to_owned()
        };
        let executable = match record.get("executable").and_then(Value::as_str) {
            Some(path) => {
                let relative_path = Path::new(path)
                    .strip_prefix(root.join("target/ci/native"))
                    .map_err(|_| error("coverage executable escapes its owner tree"))?;
                artifacts::safe_relative(relative_path)?;
                let bytes = artifacts::read_file(Path::new(path))?;
                Some(ExecutableRecord {
                    length: bytes.len() as u64,
                    sha256: artifacts::checksum(&bytes),
                })
            }
            None => None,
        };
        let mut raw_target = target.clone();
        raw_target["src_path"] = json!(source);
        let mut features: Vec<String> = serde_json::from_value(record["features"].clone())?;
        features.sort();
        units.push(UnitObservation {
            package,
            target_name: text(target, "name")?.to_owned(),
            target_kind: kind(&target["kind"])?,
            source,
            raw_target,
            profile: record["profile"].clone(),
            features,
            executable,
        });
    }
    if !finished || units.is_empty() {
        return Err(error("native coverage completion or unit inventory absent"));
    }
    Ok(units)
}

/// One runner owns both phases and its writable target tree until settlement.
pub fn run_shard(
    root: &Path,
    selected: &BuildSourceIdentity,
    target: &str,
    shard: usize,
    destination: &Path,
    failure_mode: crate::failure_mode::FailureMode,
) -> Result<()> {
    let cutoff = original_cutoff(root, selected, target)?;
    crate::preparation::with_operation(failure_mode, cutoff, || {
        crate::workflow_output::revoke_compilation("compiled-native-complete")?;
        let prepared = prepare(root, selected, target, cutoff)?;
        validate_original_plan(root, &prepared.plan)?;
        let selectors = prepared.plan.selectors(shard).map_err(CiError::Message)?;
        let support_selectors = prepared
            .plan
            .support_selectors(shard)
            .map_err(CiError::Message)?;
        let selection_sha256 = prepared
            .plan
            .selection_sha256(shard)
            .map_err(CiError::Message)?;
        if destination.try_exists()? {
            return Err(error("coverage receipt owner requires a fresh destination"));
        }
        std::fs::create_dir_all(destination)?;
        source::write_json(&destination.join("plan.json"), &prepared.plan)?;
        let mut inventories = Vec::new();
        let mut phases = Vec::new();
        for compile in [true, false] {
            let started = Instant::now();
            let supporting_units = if support_selectors.is_empty() {
                Vec::new()
            } else {
                let outcome = support_command(
                    root,
                    &prepared.plan.spec.identity.toolchain,
                    Path::new("target/ci/native"),
                    &support_selectors,
                    compile,
                    failure_mode,
                    cutoff,
                )
                .selection(selected, Some(target))
                .run_owned();
                let settled = outcome.writers().permits_reading();
                let bytes = outcome.into_result()?;
                if !settled || Instant::now() >= cutoff {
                    return Err(error(
                        "coverage support did not settle under its original cutoff",
                    ));
                }
                selected.recheck(root)?;
                ledger(root, &prepared, &bytes)?
            };
            let command = selection_command(
                root,
                &prepared.plan.spec.identity.toolchain,
                Path::new("target/ci/native"),
                &selectors,
                compile,
                failure_mode,
                cutoff,
            )
            .selection(selected, Some(target));
            let outcome = command.run_owned();
            let settled = outcome.writers().permits_reading();
            let bytes = outcome.into_result()?;
            let complete = Instant::now() < cutoff;
            if !settled || !complete {
                return Err(error(
                    "coverage owner did not complete under its original cutoff",
                ));
            }
            inventories.push(
                merge_units(supporting_units, ledger(root, &prepared, &bytes)?)
                    .map_err(CiError::Message)?,
            );
            phases.push(PhaseReceipt {
                selection_sha256: selection_sha256.clone(),
                success: true,
                writers_settled: settled,
                completed_before_deadline: complete,
            });
            source::write_json(
                &destination.join(if compile {
                    "compile-unit-completion.json"
                } else {
                    "execute-unit-completion.json"
                }),
                &json!({"source":selected,"plan_sha256":prepared.plan.sha256,"shard":shard,"phase":if compile {"compile"}else{"execute"},"elapsed_millis":started.elapsed().as_millis(),"unit_count":inventories.last().map(Vec::len),"writers_settled":settled,"original_cutoff_remaining_millis":cutoff.saturating_duration_since(Instant::now()).as_millis()}),
            )?;
        }
        selected.recheck(root)?;
        let receipt = ShardReceipt {
            schema_version: 1,
            identity: prepared.plan.spec.identity.clone(),
            plan_sha256: prepared.plan.sha256.clone(),
            shard_id: shard,
            compile: phases.remove(0),
            execute: phases.remove(0),
            compiled_units: inventories.remove(0),
            executed_units: inventories.remove(0),
        };
        // Validate the full local contract before transporting a receipt.
        prepared
            .plan
            .validate_receipt(&receipt)
            .map_err(CiError::Message)?;
        // Exactly one selector owner exports the ordinary fixture, never a target tree.
        if fixture_owner(&prepared.plan)? == shard {
            let bytes = artifacts::read_file(
                &root.join("target/ci/native/release/memcordon-test-fixture"),
            )?;
            std::fs::write(destination.join("memcordon-test-fixture"), bytes)?;
        }
        if Instant::now() >= cutoff {
            return Err(error(
                "native coverage original cutoff exhausted before receipt publication",
            ));
        }
        source::write_json(&destination.join("receipt.json"), &receipt)?;
        if Instant::now() >= cutoff {
            return Err(error(
                "native coverage original cutoff exhausted before owner completion",
            ));
        }
        crate::workflow_output::compilation_complete("compiled-native-complete")?;
        Ok(())
    })
}

pub fn validate_all(
    root: &Path,
    selected: &BuildSourceIdentity,
    distribution: &TargetDistribution,
    receipts: &Path,
    cutoff: Instant,
) -> Result<()> {
    let prepared = prepare(root, selected, &distribution.target, cutoff)?;
    validate_original_plan(root, &prepared.plan)?;
    let mut measured = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(receipts)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(error(
                    "coverage aggregate contains an unexpected non-owner member",
                ));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| error("coverage owner name is not UTF8"))
        })
        .collect::<Result<_>>()?;
    names.sort();
    let mut expected_names: Vec<_> = prepared
        .plan
        .shards
        .iter()
        .map(|shard| shard.id.to_string())
        .collect();
    expected_names.sort();
    if names != expected_names {
        return Err(error(
            "coverage aggregate owner set differs from original plan",
        ));
    }
    for shard in &prepared.plan.shards {
        let owner = receipts.join(shard.id.to_string());
        let receipt: ShardReceipt =
            serde_json::from_slice(&artifacts::read_file(&owner.join("receipt.json"))?)?;
        measured.push(receipt);
    }
    prepared
        .plan
        .aggregate(&measured)
        .map_err(CiError::Message)?;
    if Instant::now() >= cutoff {
        return Err(error(
            "native coverage original cutoff exhausted during aggregation",
        ));
    }
    let fixture_owner = fixture_owner(&prepared.plan)?;
    let bytes = artifacts::read_file(
        &receipts
            .join(fixture_owner.to_string())
            .join("memcordon-test-fixture"),
    )?;
    let fixture_requirement = prepared
        .plan
        .requirements
        .iter()
        .find(|requirement| {
            requirement.target.name == "memcordon-test-fixture"
                && requirement.variant == Variant::OrdinaryBinarySupport
        })
        .ok_or_else(|| error("ordinary fixture requirement absent"))?;
    let expected = measured
        .iter()
        .filter(|receipt| receipt.shard_id == fixture_owner)
        .flat_map(|receipt| &receipt.compiled_units)
        .find(|unit| {
            unit.target_name == fixture_requirement.target.name
                && unit.package == fixture_requirement.target.package
                && unit.source == fixture_requirement.target.source
                && unit.target_kind == fixture_requirement.target.kind
                && unit.profile["test"] == false
        })
        .and_then(|unit| unit.executable.as_ref())
        .ok_or_else(|| error("coverage fixture executable receipt absent"))?;
    if bytes.len() as u64 != expected.length || artifacts::checksum(&bytes) != expected.sha256 {
        return Err(error(
            "coverage fixture transport differs from actual compilation",
        ));
    }
    let native = root.join("target/ci/native/release");
    std::fs::create_dir_all(&native)?;
    let fixture_path = native.join("memcordon-test-fixture");
    std::fs::write(&fixture_path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fixture_path, std::fs::Permissions::from_mode(0o755))?;
    }
    if Instant::now() >= cutoff {
        return Err(error(
            "native coverage original cutoff exhausted before completion",
        ));
    }
    source::write_json(
        &root.join(".release/native-coverage-aggregate.json"),
        &json!({"plan":prepared.plan.sha256,"source":selected,"shards":measured.len(),"coverage_complete":true,"writers_settled":true}),
    )
}

fn validate_original_plan(root: &Path, actual: &Plan) -> Result<()> {
    let expected: Plan = serde_json::from_slice(&artifacts::read_file(
        &root.join(".release/native-coverage-plan.json"),
    )?)?;
    expected.validate().map_err(CiError::Message)?;
    if expected != *actual {
        return Err(error(
            "native coverage source projection differs from the original shared plan",
        ));
    }
    Ok(())
}

pub fn validate_product_plan(
    root: &Path,
    selected: &BuildSourceIdentity,
    target: &str,
    cutoff: Instant,
) -> Result<()> {
    let prepared = prepare(root, selected, target, cutoff)?;
    validate_original_plan(root, &prepared.plan)
}

pub fn publish_plan(root: &Path, selected: &BuildSourceIdentity, target: &str) -> Result<()> {
    if target != "x86_64-apple-darwin" {
        return Err(error("distributed native coverage requires macOS x64"));
    }
    selected.recheck(root)?;
    let now = unix_millis()?;
    let deadline = CoverageDeadline {
        format: "memcordon.native-coverage.original-deadline".into(),
        revision: 1,
        source: selected.clone(),
        target: target.to_owned(),
        started_unix_millis: now,
        work_deadline_unix_millis: now
            .checked_add(140 * 60 * 1000)
            .ok_or_else(|| error("coverage work cutoff overflow"))?,
        cleanup_deadline_unix_millis: now
            .checked_add(155 * 60 * 1000)
            .ok_or_else(|| error("coverage cleanup cutoff overflow"))?,
    };
    let mut record = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(".release/native-coverage-deadline.json"))?;
    record.write_all(&serde_json::to_vec(&deadline)?)?;
    record.sync_all()?;
    let cutoff = original_cutoff(root, selected, target)?;
    crate::preparation::with_operation(
        crate::failure_mode::FailureMode::StopAfterFailure,
        cutoff,
        || {
            let prepared = prepare(root, selected, target, cutoff)?;
            if prepared.plan.shards.len() != SHARD_COUNT {
                return Err(error(
                    "native coverage capacity policy requires four nonempty ownership groups",
                ));
            }
            source::write_json(
                &root.join(".release/native-coverage-plan.json"),
                &prepared.plan,
            )
        },
    )
}
