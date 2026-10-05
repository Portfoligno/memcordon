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
}

fn query(root: &Path, program: impl Into<std::ffi::OsString>, args: &[&str]) -> Result<String> {
    let output = CommandSpec::new(PathBuf::from(program.into()), root, Duration::from_secs(30))
        .args(args.iter().copied())
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
        "native-release" => true,
        _ => return None,
    };
    Some(
        crate::native_test_plan::commands(release)
            .into_iter()
            .map(|command| command.arguments)
            .collect(),
    )
}

pub fn context(
    root: &Path,
    purpose: &str,
    shard: &str,
    external: &[PathBuf],
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
    // Cargo merges ancestor and user-home configuration with the checkout's
    // own configuration. A repository tree hash does not identify these.
    let mut config_roots: Vec<PathBuf> = root.ancestors().map(Path::to_path_buf).collect();
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        config_roots.push(PathBuf::from(home));
    } else if let Some(home) = std::env::var_os("HOME") {
        config_roots.push(PathBuf::from(home).join(".cargo"));
    } else {
        usable = false;
    }
    for directory in config_roots {
        for path in [
            directory.join(".cargo/config"),
            directory.join(".cargo/config.toml"),
            directory.join("config"),
            directory.join("config.toml"),
        ] {
            match std::fs::symlink_metadata(&path) {
                Ok(_) => match artifacts::read_file(&path) {
                    Ok(bytes) => {
                        inputs.insert(path.display().to_string(), artifacts::checksum(&bytes));
                    }
                    Err(_) => {
                        usable = false;
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => {
                    usable = false;
                }
            }
        }
    }
    let git = Git::new(root)?;
    inputs.insert(
        "commit".into(),
        git.text(["rev-parse", "--verify", "HEAD"])?,
    );
    inputs.insert(
        "tree".into(),
        git.text(["rev-parse", "--verify", "HEAD^{tree}"])?,
    );
    if !git
        .text(["status", "--porcelain=v1", "--untracked-files=no"])?
        .is_empty()
    {
        usable = false;
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
            if actual.as_deref().ok() != Some(selected) {
                usable = false;
            }
            inputs.insert(format!("submodule:{path}"), selected.into());
        }
    }
    // LFS pointer identity alone cannot identify the populated external bytes.
    if root.join(".gitattributes").exists()
        && String::from_utf8_lossy(&artifacts::read_file(&root.join(".gitattributes"))?)
            .contains("filter=lfs")
    {
        usable = false;
    }
    let pins = crate::config::toolchains(root)?;
    let selected_toolchain = if purpose.starts_with("miri") || purpose.starts_with("fuzz") {
        &pins.miri
    } else if purpose == "msrv" {
        &pins.msrv
    } else {
        &pins.stable
    };
    inputs.insert(
        "rustc".into(),
        query(root, "rustup", &["run", selected_toolchain, "rustc", "-vV"])?,
    );
    inputs.insert(
        "cargo".into(),
        query(root, "rustup", &["run", selected_toolchain, "cargo", "-V"])?,
    );
    inputs.insert("target".into(), distribution::native_target()?.into());
    inputs.insert("purpose".into(), purpose.into());
    inputs.insert("toolchain".into(), selected_toolchain.clone());
    inputs.insert("shard".into(), shard.into());
    let revision = if let Some(recipe) = native_recipe(purpose) {
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
        if purpose == "native-release" {
            inputs.insert("product-package".into(), "memcordon".into());
            inputs.insert("product-profile".into(), "release".into());
            match distribution::Distribution::read(root)
                .and_then(|selected| Ok(selected.native()?.clone()))
            {
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
        2_u32
    } else {
        inputs.insert(
            "profile".into(),
            "source-tests:dev+release;product:release;consumer:dev+release;driver:dev".into(),
        );
        1_u32
    };
    inputs.insert(
        "distribution".into(),
        artifacts::checksum(&artifacts::read_file(&root.join("ci/distribution.toml"))?),
    );
    inputs.insert(
        "lock".into(),
        artifacts::checksum(&artifacts::read_file(&root.join("Cargo.lock"))?),
    );
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
    for path in [root.join(".cargo/config"), root.join(".cargo/config.toml")] {
        if path.exists() {
            inputs.insert(
                path.display().to_string(),
                artifacts::checksum(&artifacts::read_file(&path)?),
            );
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
    for (name, value) in std::env::vars_os() {
        let name = name.to_string_lossy();
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
            inputs.insert(name.into_owned(), value.to_string_lossy().into_owned());
            // Overrides may select otherwise unidentified tools/headers. They
            // remain usable for clean builds, with affected reuse disabled.
            usable = false;
        }
    }
    if purpose.starts_with("fuzz") {
        match crate::preparation::auxiliary_tool(root, "cargo-fuzz")
            .and_then(|path| query(root, path.as_os_str(), &["--version"]))
        {
            Ok(value) => {
                inputs.insert("cargo-fuzz".into(), value);
            }
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
                    Err(_) => usable = false,
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
                    Err(_) => usable = false,
                }
            }
        }
        "windows" => {
            for name in ["VCToolsVersion", "WindowsSDKVersion", "WindowsSdkDir"] {
                match std::env::var(name) {
                    Ok(value) if !value.is_empty() => {
                        inputs.insert(name.into(), value);
                    }
                    _ => usable = false,
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
            _ => usable = false,
        }
    }
    let mut partitions = BTreeMap::new();
    for partition in ["source", "product", "consumer"] {
        let mut selected = inputs.clone();
        selected.insert("partition".into(), partition.into());
        partitions.insert(
            partition.into(),
            artifacts::checksum(&serde_json::to_vec(&(revision, selected))?),
        );
    }
    Ok(CacheContext {
        revision,
        usable,
        inputs,
        partitions,
    })
}

pub fn emit(root: &Path, purpose: &str, shard: &str, external: &[PathBuf]) -> Result<()> {
    let context = context(root, purpose, shard, external)?;
    let mut outputs = vec![("compiled-cache-usable", "false".to_owned())];
    if context.usable {
        outputs[0].1 = "true".into();
    }
    for (partition, key) in &context.partitions {
        let output = match partition.as_str() {
            "source" => "source-key",
            "product" => "product-key",
            "consumer" => "consumer-key",
            _ => unreachable!(),
        };
        outputs.push((output, key.clone()));
    }
    crate::workflow_output::write(&outputs)?;
    println!("{}", serde_json::to_string_pretty(&context)?);
    Ok(())
}
