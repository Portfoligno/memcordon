//! Shared, dependency-free bootstrap and build environment policy.
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

pub fn reject_overrides(environment: &BTreeMap<OsString, OsString>) -> io::Result<()> {
    for key in environment.keys() {
        let Some(name) = key.to_str() else {
            return Err(io::Error::other(
                "non-Unicode environment name is unsupported",
            ));
        };
        if name.starts_with("CARGO_BUILD_")
            || name.starts_with("CARGO_TARGET_")
            || name.starts_with("CARGO_PROFILE_")
            || name.starts_with("CARGO_ENCODED_")
            || name.starts_with("CARGO_SOURCE_")
            || name.starts_with("CARGO_REGISTRIES_") && !name.ends_with("_TOKEN")
            || matches!(
                name,
                "RUSTC"
                    | "RUSTDOC"
                    | "RUSTC_WRAPPER"
                    | "RUSTC_WORKSPACE_WRAPPER"
                    | "RUSTFLAGS"
                    | "RUSTDOCFLAGS"
                    | "CC"
                    | "CXX"
                    | "AR"
                    | "LD"
                    | "CFLAGS"
                    | "CXXFLAGS"
                    | "CPPFLAGS"
                    | "LDFLAGS"
                    | "RUSTUP_TOOLCHAIN"
                    | "CARGO_HOME"
                    | "CARGO_TARGET_DIR"
            )
        {
            return Err(io::Error::other(format!(
                "managed build rejects ambient override {name}"
            )));
        }
    }
    Ok(())
}

pub fn closed_environment(
    ambient: &BTreeMap<OsString, OsString>,
) -> io::Result<BTreeMap<OsString, OsString>> {
    reject_overrides(ambient)?;
    let mut result = BTreeMap::new();
    for name in [
        "HOME",
        "USERPROFILE",
        "PATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "RUSTUP_HOME",
        "DEVELOPER_DIR",
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "INCLUDE",
        "LIB",
        "LIBPATH",
        "VCToolsInstallDir",
        "WindowsSdkDir",
    ] {
        if let Some(value) = ambient.get(OsStr::new(name)) {
            result.insert(OsString::from(name), value.clone());
        }
    }
    let paths: Vec<PathBuf> = std::env::split_paths(
        result
            .get(OsStr::new("PATH"))
            .ok_or_else(|| io::Error::other("PATH is required"))?,
    )
    .collect();
    if paths.is_empty() || paths.iter().any(|path| !path.is_absolute()) {
        return Err(io::Error::other(
            "managed PATH requires absolute, nonempty components",
        ));
    }
    result.insert(
        OsString::from("PATH"),
        std::env::join_paths(paths).map_err(io::Error::other)?,
    );
    result.insert(OsString::from("LANG"), OsString::from("C"));
    result.insert(OsString::from("LC_ALL"), OsString::from("C"));
    result.insert(OsString::from("TZ"), OsString::from("UTC"));
    Ok(result)
}

pub fn reject_cargo_configuration(directory: &Path, cargo_home: &Path) -> io::Result<()> {
    for ancestor in directory.ancestors() {
        reject_configuration_at(&ancestor.join(".cargo"))?;
    }
    reject_configuration_at(cargo_home)
}

fn reject_configuration_at(directory: &Path) -> io::Result<()> {
    for name in ["config", "config.toml"] {
        let path = directory.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "unapproved Cargo configuration: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn resolve_tool(
    name: &OsStr,
    environment: &BTreeMap<OsString, OsString>,
) -> io::Result<PathBuf> {
    let requested = Path::new(name);
    if requested.is_absolute() {
        return requested.canonicalize();
    }
    let path = environment
        .get(OsStr::new("PATH"))
        .ok_or_else(|| io::Error::other("PATH missing"))?;
    for directory in std::env::split_paths(path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return candidate.canonicalize();
        }
        #[cfg(windows)]
        {
            let candidate = candidate.with_extension("exe");
            if candidate.is_file() {
                return candidate.canonicalize();
            }
        }
    }
    Err(io::Error::other(format!(
        "managed tool unavailable: {name:?}"
    )))
}
