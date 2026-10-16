//! Generated standard-library reuse, separate from rustup and interpreted tests.
use crate::{
    CiError, Result,
    cache_inputs::{KeyInputs, keys},
    command::{CommandSpec, rustup_cargo},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub fn managed_root(root: &Path) -> Result<Option<PathBuf>> {
    if !native_setup_validated(
        crate::release::distribution::native_target()?,
        &crate::config::toolchains(root)?.miri,
    ) {
        return Ok(None);
    }
    if [
        "MIRI_SYSROOT",
        "MIRI_LIB_SRC",
        "MIRI_NO_STD",
        "MIRIFLAGS",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
        || crate::cache_inputs::cargo_configs(root).is_err()
    {
        return Ok(None);
    }
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().to_ascii_uppercase();
        if name == "CARGO_BUILD_JOBS" {
            continue;
        }
        if matches!(
            name.as_str(),
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
                | "SDKROOT"
                | "MACOSX_DEPLOYMENT_TARGET"
                | "CARGO_INCREMENTAL"
        ) || [
            "CARGO_TARGET_",
            "CARGO_PROFILE_",
            "CARGO_BUILD_",
            "HOST_",
            "TARGET_",
            "CC_",
            "CXX_",
            "AR_",
            "CFLAGS_",
            "CXXFLAGS_",
            "LDFLAGS_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        {
            return Ok(None);
        }
    }
    Ok(Some(crate::cache_restore::safe_root(
        root,
        Path::new("target/ci-miri-sysroot"),
    )?))
}

/// Managed reuse is activated only after the pinned native setup/transport
/// acceptance has run. No version string or cached readiness file enables it.
const VALIDATED_MIRI_SETUP: &[(&str, &str)] = &[("aarch64-apple-darwin", "nightly-2026-07-31")];

pub fn native_setup_validated(target: &str, nightly: &str) -> bool {
    VALIDATED_MIRI_SETUP.contains(&(target, nightly))
}

pub fn components(root: &Path, deadline: Instant) -> Result<()> {
    let pins = crate::config::toolchains(root)?;
    CommandSpec::new("rustup", root, Duration::from_secs(900))
        .args([
            "toolchain",
            "install",
            &pins.miri,
            "--profile",
            "minimal",
            "--component",
            "miri",
            "--component",
            "rust-src",
        ])
        .bounded_until(deadline)
        .run()?;
    crate::download_cache::fetch_until(
        root,
        crate::download_cache::DownloadFamily::Workspace,
        deadline,
        None,
    )
}

pub fn context(root: &Path) -> Result<()> {
    let result = identity(root);
    match result {
        Ok((key, path)) => crate::workflow_output::write(&[
            ("sysroot-key", key),
            ("sysroot-path", path.display().to_string()),
        ]),
        Err(error) => {
            eprintln!("Miri sysroot cache unavailable: {error}");
            crate::workflow_output::write(&[
                ("sysroot-key", String::new()),
                ("sysroot-path", String::new()),
            ])
        }
    }
}

pub fn identity(root: &Path) -> Result<(String, PathBuf)> {
    let path = managed_root(root)?
        .ok_or_else(|| CiError::Message("unmodeled Miri setup overrides".into()))?;
    let pins = crate::config::toolchains(root)?;
    let mut facts = crate::cache_inputs::cargo_configs(root)?;
    let home = crate::download_cache::cargo_home(root)?.canonicalize()?;
    let registry_sources = home.join("registry/src");
    crate::cache_snapshot::ordinary(&registry_sources)?;
    facts.insert("cargo-home".into(), home.display().to_string());
    facts.insert(
        "registry-source-root".into(),
        registry_sources.display().to_string(),
    );
    let native_queries: Vec<(&str, &str, Vec<&str>)> = match std::env::consts::OS {
        "linux" => vec![
            ("native-cc", "cc", vec!["--version"]),
            ("native-ld", "ld", vec!["--version"]),
            ("native-libc", "ldd", vec!["--version"]),
        ],
        "macos" => vec![
            ("native-cc", "cc", vec!["--version"]),
            ("native-sdk-path", "xcrun", vec!["--show-sdk-path"]),
            ("native-sdk-version", "xcrun", vec!["--show-sdk-version"]),
        ],
        "windows" => Vec::new(),
        _ => {
            return Err(CiError::Message(
                "Miri native setup platform unmodeled".into(),
            ));
        }
    };
    for (name, executable, arguments) in native_queries {
        let output = CommandSpec::new(executable, root, Duration::from_secs(30))
            .args(arguments)
            .defer_group_failure()
            .output_quiet()?;
        if !output.status.success() || output.stdout.len() > 64 * 1024 {
            return Err(CiError::Message(
                "Miri native setup identity unavailable".into(),
            ));
        }
        facts.insert(
            name.into(),
            String::from_utf8(output.stdout)
                .map_err(|_| CiError::Message("Miri native identity not UTF-8".into()))?,
        );
    }
    #[cfg(windows)]
    facts.extend(crate::windows_cache_identity::discover_native(
        crate::release::distribution::native_target()?,
        Instant::now() + Duration::from_secs(30),
    )?);
    for name in ["ImageOS", "ImageVersion"] {
        if let Ok(value) = std::env::var(name) {
            facts.insert(name.into(), value);
        }
    }
    for (name, args) in [
        ("rustc", vec!["run", pins.miri.as_str(), "rustc", "-vV"]),
        ("cargo", vec!["run", pins.miri.as_str(), "cargo", "-V"]),
        (
            "miri",
            vec!["run", pins.miri.as_str(), "cargo", "miri", "--version"],
        ),
        (
            "components",
            vec![
                "component",
                "list",
                "--installed",
                "--toolchain",
                pins.miri.as_str(),
            ],
        ),
        (
            "rustup-sysroot",
            vec!["run", pins.miri.as_str(), "rustc", "--print", "sysroot"],
        ),
    ] {
        let output = CommandSpec::new("rustup", root, Duration::from_secs(30))
            .args(args)
            .defer_group_failure()
            .output_quiet()?;
        if !output.status.success() || output.stdout.len() > 64 * 1024 {
            return Err(CiError::Message(
                "Miri component identity unavailable".into(),
            ));
        }
        facts.insert(
            name.into(),
            String::from_utf8(output.stdout)
                .map_err(|_| CiError::Message("Miri identity not UTF-8".into()))?,
        );
    }
    if !facts["components"]
        .lines()
        .any(|line| line.starts_with("rust-src"))
    {
        return Err(CiError::Message("Miri rust-src not provisioned".into()));
    }
    facts.insert(
        "target".into(),
        crate::release::distribution::native_target()?.into(),
    );
    facts.insert("managed-sysroot".into(), path.display().to_string());
    facts.insert(
        "recipe".into(),
        "explicit-pinned-cargo-miri-setup-std-v1".into(),
    );
    let (key, _) = keys(&KeyInputs {
        family: "miri-sysroot".into(),
        layout_revision: 6,
        compatibility: facts,
        content: BTreeMap::new(),
    })?;
    Ok((key, path))
}

pub fn ensure(root: &Path, nightly: &str, deadline: Instant) -> Result<Option<PathBuf>> {
    let path = managed_root(root)?;
    let command = rustup_cargo(root, nightly, ["miri", "setup"], Duration::from_secs(900))
        .bounded_until(deadline);
    let command = if let Some(path) = &path {
        command.miri_sysroot(path)
    } else {
        command
    };
    let result = command.run();
    if result.is_ok() {
        crate::workflow_output::write(&[
            ("miri-sysroot-ready", path.is_some().to_string()),
            ("miri-sysroot-quiescent", "true".into()),
        ])?;
    }
    result?;
    Ok(path)
}

pub fn prepare(root: &Path) -> Result<()> {
    let pins = crate::config::toolchains(root)?;
    ensure(root, &pins.miri, Instant::now() + Duration::from_secs(900)).map(|_| ())
}
