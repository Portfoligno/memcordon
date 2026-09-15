//! Native MSVC layout selection shared by the dependency-free seed and controller.
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub enum Architecture {
    X64,
    Arm64,
}

impl Architecture {
    pub fn native() -> io::Result<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Self::X64),
            "aarch64" => Ok(Self::Arm64),
            other => Err(io::Error::other(format!(
                "unsupported MSVC host architecture: {other}"
            ))),
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }

    fn host_directory(self) -> &'static str {
        match self {
            Self::X64 => "Hostx64",
            Self::Arm64 => "Hostarm64",
        }
    }

    pub fn discovery_arguments(self) -> [&'static str; 8] {
        [
            "-latest",
            "-products",
            "*",
            "-requires",
            match self {
                Self::X64 => "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                Self::Arm64 => "Microsoft.VisualStudio.Component.VC.Tools.ARM64",
            },
            "-property",
            "installationPath",
            "-utf8",
        ]
    }
}

/// Also enrolled when the bootstrap has already populated VSINSTALLDIR: later
/// workflow steps start with their original environment and must rediscover it.
pub fn find_vswhere(environment: &BTreeMap<OsString, OsString>) -> io::Result<Option<PathBuf>> {
    for name in ["ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"] {
        if let Some(base) = environment.get(OsStr::new(name)) {
            let candidate = Path::new(base)
                .join("Microsoft Visual Studio")
                .join("Installer")
                .join("vswhere.exe");
            if candidate.is_file() {
                return absolute(&candidate).map(Some);
            }
        }
    }
    Ok(None)
}

pub fn selected_installation(
    environment: &BTreeMap<OsString, OsString>,
) -> io::Result<Option<PathBuf>> {
    if let Some(root) = environment.get(OsStr::new("VSINSTALLDIR")) {
        return absolute(Path::new(root)).map(Some);
    }
    if let Some(root) = environment.get(OsStr::new("VCINSTALLDIR")) {
        let root = absolute(Path::new(root))?;
        if !root
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case("VC"))
        {
            return Err(io::Error::other(
                "VCINSTALLDIR does not identify a Visual C++ installation",
            ));
        }
        return Ok(root.parent().map(Path::to_path_buf));
    }
    if let Some(root) = environment.get(OsStr::new("VCToolsInstallDir")) {
        let root = absolute(Path::new(root))?;
        let vc = root
            .ancestors()
            .find(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case("VC"))
            })
            .ok_or_else(|| {
                io::Error::other("VCToolsInstallDir is outside a Visual C++ installation")
            })?;
        return Ok(vc.parent().map(Path::to_path_buf));
    }
    Ok(None)
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::other(format!(
            "native compiler input requires an absolute path: {}",
            path.display()
        )));
    }
    // Keep the invocation path's spelling: canonicalized Windows verbatim paths
    // are not accepted by every MSVC tool. Content measurement resolves aliases.
    Ok(path.to_path_buf())
}

fn require_directory(path: &Path) -> io::Result<()> {
    absolute(path)?;
    if !path.is_dir() {
        return Err(io::Error::other(format!(
            "required MSVC/SDK directory missing: {}",
            path.display()
        )));
    }
    Ok(())
}

fn require_file(path: &Path) -> io::Result<()> {
    absolute(path)?;
    if !path.is_file() {
        return Err(io::Error::other(format!(
            "required MSVC/SDK file missing: {}",
            path.display()
        )));
    }
    Ok(())
}

fn version(value: &OsStr) -> io::Result<String> {
    let value = value
        .to_str()
        .ok_or_else(|| io::Error::other("non-Unicode MSVC/SDK version"))?
        .trim()
        .trim_end_matches(['\\', '/']);
    if value.is_empty()
        || value
            .split('.')
            .any(|part| part.is_empty() || part.parse::<u32>().is_err())
    {
        return Err(io::Error::other("invalid MSVC/SDK version selector"));
    }
    Ok(value.to_owned())
}

fn prepend(
    environment: &mut BTreeMap<OsString, OsString>,
    name: &str,
    selected: Vec<PathBuf>,
) -> io::Result<()> {
    let mut paths = selected;
    if let Some(existing) = environment.get(OsStr::new(name)) {
        for path in std::env::split_paths(existing) {
            if !path.is_absolute() {
                return Err(io::Error::other(format!(
                    "managed {name} requires absolute paths"
                )));
            }
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    environment.insert(
        name.into(),
        std::env::join_paths(paths).map_err(io::Error::other)?,
    );
    Ok(())
}

fn sdk_complete(root: &Path, version: &str, arch: Architecture) -> bool {
    let libraries = root.join("Lib").join(version);
    let include = root.join("Include").join(version);
    libraries
        .join("um")
        .join(arch.target())
        .join("kernel32.lib")
        .is_file()
        && libraries
            .join("ucrt")
            .join(arch.target())
            .join("ucrt.lib")
            .is_file()
        && ["ucrt", "um", "shared"]
            .iter()
            .all(|part| include.join(part).is_dir())
}

fn sdk(
    environment: &BTreeMap<OsString, OsString>,
    arch: Architecture,
) -> io::Result<(PathBuf, String)> {
    let roots: Vec<_> = if let Some(root) = environment.get(OsStr::new("WindowsSdkDir")) {
        vec![absolute(Path::new(root))?]
    } else {
        ["ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"]
            .iter()
            .filter_map(|name| environment.get(OsStr::new(name)))
            .map(|base| Path::new(base).join("Windows Kits").join("10"))
            .collect()
    };
    let selected = environment
        .get(OsStr::new("WindowsSDKVersion"))
        .map(|value| version(value))
        .transpose()?;
    let mut candidates = Vec::new();
    for root in roots {
        absolute(&root)?;
        let versions = match fs::read_dir(root.join("Lib")) {
            Ok(entries) => entries,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && !environment.contains_key(OsStr::new("WindowsSdkDir")) =>
            {
                continue;
            }
            Err(error) => {
                return Err(io::Error::other(format!(
                    "reading Windows SDK {}: {error}",
                    root.display()
                )));
            }
        };
        for entry in versions {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Ok(candidate) = version(&entry.file_name()) else {
                continue;
            };
            if selected
                .as_ref()
                .is_some_and(|selected| selected != &candidate)
            {
                continue;
            }
            if sdk_complete(&root, &candidate, arch) {
                let parts = candidate
                    .split('.')
                    .map(|part| part.parse::<u32>().expect("validated version"))
                    .collect::<Vec<_>>();
                candidates.push((parts, root.clone(), candidate));
            }
        }
    }
    candidates.sort();
    candidates
        .pop()
        .map(|(_, root, version)| (root, version))
        .ok_or_else(|| {
            io::Error::other(
                "no complete Windows SDK matches the selected native architecture/version",
            )
        })
}

/// Construct a complete native developer environment from a selected VS instance.
/// Returns the absolute linker selected ahead of all ambient PATH entries.
pub fn configure(
    environment: &mut BTreeMap<OsString, OsString>,
    installation: &Path,
    arch: Architecture,
) -> io::Result<PathBuf> {
    let installation = absolute(installation)?;
    let vc = installation.join("VC");
    match environment.get(OsStr::new("VCINSTALLDIR")) {
        Some(selected) if Path::new(selected).canonicalize()? != vc.canonicalize()? => {
            return Err(io::Error::other(
                "VCINSTALLDIR conflicts with selected VS installation",
            ));
        }
        _ => {}
    }
    let toolset_version = match environment.get(OsStr::new("VCToolsVersion")) {
        Some(value) => version(value)?,
        None => match environment.get(OsStr::new("VCToolsInstallDir")) {
            Some(path) => version(
                Path::new(path)
                    .file_name()
                    .ok_or_else(|| io::Error::other("invalid selected MSVC toolset path"))?,
            )?,
            None => version(OsStr::new(&fs::read_to_string(
                vc.join("Auxiliary")
                    .join("Build")
                    .join("Microsoft.VCToolsVersion.default.txt"),
            )?))?,
        },
    };
    let toolset = vc.join("Tools").join("MSVC").join(&toolset_version);
    match environment.get(OsStr::new("VCToolsInstallDir")) {
        Some(selected) if Path::new(selected).canonicalize()? != toolset.canonicalize()? => {
            return Err(io::Error::other(
                "VCToolsInstallDir conflicts with the selected VS installation/toolset",
            ));
        }
        _ => {}
    }
    let bin = toolset
        .join("bin")
        .join(arch.host_directory())
        .join(arch.target());
    for name in ["cl.exe", "link.exe", "lib.exe"] {
        require_file(&bin.join(name))?;
    }
    let include = toolset.join("include");
    let libraries = toolset.join("lib").join(arch.target());
    require_directory(&include)?;
    require_directory(&libraries)?;
    let (sdk, sdk_version) = sdk(environment, arch)?;
    let sdk_include = sdk.join("Include").join(&sdk_version);
    let sdk_libraries = sdk.join("Lib").join(&sdk_version);
    let mut configured = environment.clone();
    prepend(&mut configured, "PATH", vec![bin.clone()])?;
    prepend(
        &mut configured,
        "LIB",
        vec![
            libraries,
            sdk_libraries.join("um").join(arch.target()),
            sdk_libraries.join("ucrt").join(arch.target()),
        ],
    )?;
    prepend(
        &mut configured,
        "INCLUDE",
        vec![
            include,
            sdk_include.join("ucrt"),
            sdk_include.join("um"),
            sdk_include.join("shared"),
        ],
    )?;
    for (name, value) in [
        ("VSINSTALLDIR", installation.into_os_string()),
        ("VCINSTALLDIR", vc.into_os_string()),
        ("VCToolsInstallDir", toolset.into_os_string()),
        ("VCToolsVersion", toolset_version.into()),
        ("WindowsSdkDir", sdk.into_os_string()),
        ("WindowsSDKVersion", sdk_version.into()),
        ("VSCMD_ARG_TGT_ARCH", arch.target().into()),
        ("VSCMD_ARG_HOST_ARCH", arch.target().into()),
    ] {
        configured.insert(name.into(), value);
    }
    *environment = configured;
    Ok(bin.join("link.exe"))
}
