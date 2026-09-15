//! Shared, dependency-free bootstrap and build environment policy.
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

#[cfg_attr(not(windows), allow(dead_code))]
#[path = "ci-msvc-environment.rs"]
pub mod msvc;

#[cfg_attr(not(windows), allow(dead_code))]
#[path = "ci-windows-compiler.rs"]
pub mod windows_compiler;

#[path = "ci-command-path.rs"]
pub mod paths;
pub use paths::command_path;

#[path = "ci-progress.rs"]
pub mod progress;

/// Bootstrap prepares this tree; the controller enrolls it as immutable input.
pub const MANAGED_MIRI_SYSROOT_RELATIVE: &str = "target/ci/miri-sysroot";

/// Name matching is separate from host path syntax so both policies can be tested.
#[derive(Clone, Copy)]
pub enum EnvironmentNames {
    CaseSensitive,
    Windows,
}

impl EnvironmentNames {
    fn key(self, name: &str) -> String {
        match self {
            Self::CaseSensitive => name.to_owned(),
            Self::Windows => name.to_ascii_uppercase(),
        }
    }
}

fn reject_overrides(environment: &BTreeMap<OsString, OsString>) -> io::Result<()> {
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
    closed_environment_with_names(
        ambient,
        if cfg!(windows) {
            EnvironmentNames::Windows
        } else {
            EnvironmentNames::CaseSensitive
        },
    )
}

fn normalized_environment(
    ambient: &BTreeMap<OsString, OsString>,
    names: EnvironmentNames,
) -> io::Result<BTreeMap<OsString, OsString>> {
    let mut normalized = BTreeMap::new();
    for (key, value) in ambient {
        let name = key
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode environment name is unsupported"))?;
        let key = OsString::from(names.key(name));
        match normalized.insert(key, value.clone()) {
            Some(previous) if previous != *value => {
                return Err(io::Error::other(format!(
                    "conflicting environment aliases for {name}"
                )));
            }
            _ => {}
        }
    }
    Ok(normalized)
}

/// Windows installer discovery needs OS profile locations that are not admitted
/// to compilation. Only its validated selected toolchain enters the build context.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_discovery_environment(
    ambient: &BTreeMap<OsString, OsString>,
) -> io::Result<BTreeMap<OsString, OsString>> {
    let names = EnvironmentNames::Windows;
    let normalized = normalized_environment(ambient, names)?;
    let mut result = closed_environment_with_names(ambient, names)?;
    for name in [
        "ProgramData",
        "ALLUSERSPROFILE",
        "SystemDrive",
        "APPDATA",
        "LOCALAPPDATA",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
    ] {
        if let Some(value) = normalized.get(OsStr::new(&names.key(name))) {
            result.insert(name.into(), value.clone());
        }
    }
    Ok(result)
}

pub fn closed_environment_with_names(
    ambient: &BTreeMap<OsString, OsString>,
    names: EnvironmentNames,
) -> io::Result<BTreeMap<OsString, OsString>> {
    let normalized = normalized_environment(ambient, names)?;
    reject_overrides(&normalized)?;
    let mut result = BTreeMap::new();
    for name in [
        "HOME",
        "USERPROFILE",
        "PATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SystemRoot",
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
        "WindowsSDKVersion",
        "VCINSTALLDIR",
        "VSINSTALLDIR",
        "VCToolsVersion",
        "VSCMD_ARG_TGT_ARCH",
        "VSCMD_ARG_HOST_ARCH",
        "VisualStudioVersion",
    ] {
        if let Some(value) = normalized.get(OsStr::new(&names.key(name))) {
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
        // Executable aliases may dispatch by argv[0] (for example rustup).
        // Validate the target without replacing the invocation path.
        requested.metadata()?;
        return Ok(requested.to_owned());
    }
    let path = environment
        .get(OsStr::new("PATH"))
        .ok_or_else(|| io::Error::other("PATH missing"))?;
    for directory in std::env::split_paths(path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = candidate.with_extension("exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(io::Error::other(format!(
        "managed tool unavailable: {name:?}"
    )))
}
