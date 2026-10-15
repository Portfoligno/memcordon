//! Narrow native MSVC observation. No environment activation or SDK census.
use crate::{CiError, Result, release::artifacts};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Instant,
};

fn normal(path: &Path, directory: bool) -> Result<PathBuf> {
    use std::os::windows::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(CiError::Message("native tool path not absolute".into()));
    }
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0 {
            return Err(CiError::Message("native tool path redirected".into()));
        }
    }
    let metadata = std::fs::metadata(path)?;
    if metadata.is_dir() != directory
        || (!directory && (!metadata.is_file() || metadata.len() > 32 * 1024 * 1024))
    {
        return Err(CiError::Message(
            "native tool path kind/bound differs".into(),
        ));
    }
    Ok(path.to_path_buf())
}

fn text(value: &std::ffi::OsStr) -> Result<String> {
    let text = value
        .to_str()
        .ok_or_else(|| CiError::Message("native selector not lossless Unicode".into()))?;
    if text.len() > 64 * 1024 {
        return Err(CiError::Message("native selector exceeds bound".into()));
    }
    Ok(text.into())
}

pub fn discover_native(target: &str, deadline: Instant) -> Result<BTreeMap<String, String>> {
    let arch = match (std::env::consts::ARCH, target) {
        ("x86_64", "x86_64-pc-windows-msvc") => "x64",
        ("aarch64", "aarch64-pc-windows-msvc") => "arm64",
        _ => return Err(CiError::Message("wrong native Windows architecture".into())),
    };
    let mut identity = BTreeMap::from([
        (
            "windows-resolver".into(),
            "find-msvc-tools-0.1.11-native-v1".into(),
        ),
        ("windows-host".into(), std::env::consts::ARCH.into()),
        ("windows-target".into(), target.into()),
    ]);
    let mut ambient = BTreeMap::new();
    for name in [
        "PATH",
        "INCLUDE",
        "LIB",
        "LIBPATH",
        "VCINSTALLDIR",
        "VSINSTALLDIR",
        "VCToolsInstallDir",
        "VCToolsVersion",
        "WindowsSdkDir",
        "WindowsSDKVersion",
        "UniversalCRTSdkDir",
        "UCRTVersion",
        "VisualStudioVersion",
        "VSCMD_ARG_HOST_ARCH",
        "VSCMD_ARG_TGT_ARCH",
        "VSTEL_MSBuildProjectFullPath",
        "VSCMD_ARG_VCVARS_SPECTRE",
        "ProgramFiles",
        "ProgramFiles(x86)",
    ] {
        if let Some(value) = std::env::var_os(name) {
            let value = text(&value)?;
            identity.insert(
                format!("windows-selector-{name}"),
                artifacts::checksum(value.as_bytes()),
            );
            ambient.insert(name.to_ascii_uppercase(), value);
        }
    }
    if ambient.contains_key("WINDOWSSDKDIR") != ambient.contains_key("WINDOWSSDKVERSION") {
        return Err(CiError::Message("partial SDK selectors".into()));
    }
    let mut selected_root = None;
    let mut environment = None;
    for name in ["link.exe", "cl.exe", "lib.exe"] {
        if Instant::now() >= deadline {
            return Err(CiError::Message("native discovery deadline elapsed".into()));
        }
        let tool = find_msvc_tools::find_tool(target, name)
            .ok_or_else(|| CiError::Message(format!("native tool unavailable: {name}")))?;
        let path = normal(tool.path(), false)?;
        let components = path
            .components()
            .map(|part| part.as_os_str().to_os_string())
            .collect::<Vec<_>>();
        let msvc = components
            .iter()
            .position(|part| {
                part.to_str()
                    .is_some_and(|part| part.eq_ignore_ascii_case("MSVC"))
            })
            .ok_or_else(|| CiError::Message("unmodeled MSVC installation".into()))?;
        let version = components
            .get(msvc + 1)
            .ok_or_else(|| CiError::Message("MSVC version absent".into()))?;
        let root = components.iter().take(msvc + 2).collect::<PathBuf>();
        let selected_arch = path
            .parent()
            .and_then(Path::file_name)
            .and_then(std::ffi::OsStr::to_str);
        if selected_arch != Some(arch) {
            return Err(CiError::Message(
                "native tool target architecture differs".into(),
            ));
        }
        let host = path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| CiError::Message("native tool host absent".into()))?;
        let expected_host = if arch == "x64" {
            "Hostx64"
        } else {
            "Hostarm64"
        };
        if !host.eq_ignore_ascii_case(expected_host) {
            return Err(CiError::Message(
                "native tool host architecture differs".into(),
            ));
        }
        for selector in ["VSCMD_ARG_HOST_ARCH", "VSCMD_ARG_TGT_ARCH"] {
            if ambient
                .get(selector)
                .is_some_and(|selected| !selected.eq_ignore_ascii_case(arch))
            {
                return Err(CiError::Message(
                    "developer architecture selector conflicts".into(),
                ));
            }
        }
        if let Some(previous) = &selected_root {
            if previous != &root {
                return Err(CiError::Message(
                    "native tools select different installations".into(),
                ));
            }
        }
        if let Some(expected) = ambient.get("VCTOOLSVERSION") {
            if expected.trim_end_matches(['\\', '/']) != text(version)? {
                return Err(CiError::Message("MSVC version selector conflicts".into()));
            }
        }
        selected_root = Some(root);
        let mut effective = ambient.clone();
        for (key, value) in find_msvc_tools::Tool::env(&tool) {
            effective.insert(text(key)?.to_ascii_uppercase(), text(value)?);
        }
        let search = ["INCLUDE", "LIB", "LIBPATH", "PATH"]
            .into_iter()
            .map(|key| {
                (
                    key.to_owned(),
                    effective.get(key).cloned().unwrap_or_default(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if let Some(previous) = &environment {
            if previous != &search {
                return Err(CiError::Message(
                    "native tools select conflicting search paths".into(),
                ));
            }
        }
        environment = Some(search);
        identity.insert(format!("windows-tool-{name}-path"), text(path.as_os_str())?);
        identity.insert(
            format!("windows-tool-{name}-digest"),
            artifacts::checksum(&artifacts::read_file(&path)?),
        );
    }
    let root = selected_root.expect("three native tools");
    if let Some(expected) = ambient.get("VCTOOLSINSTALLDIR") {
        if Path::new(expected).canonicalize()? != root.canonicalize()? {
            return Err(CiError::Message("MSVC root selector conflicts".into()));
        }
    }
    let environment = environment.expect("three native tool environments");
    let mut sdk = None;
    let mut sdk_version = None;
    let mut has_um = false;
    let mut has_ucrt = false;
    let mut include_um = false;
    let mut include_ucrt = false;
    for name in ["INCLUDE", "LIB"] {
        let value = environment.get(name).expect("finite search inventory");
        if value.is_empty() {
            return Err(CiError::Message("unknown SDK search selection".into()));
        }
        let paths = std::env::split_paths(value).collect::<Vec<_>>();
        if paths.len() > 64 {
            return Err(CiError::Message("native search path bound exceeded".into()));
        }
        for path in paths {
            let path = normal(&path, true)?;
            if path.starts_with(&root) {
                continue;
            }
            let parts = path
                .components()
                .map(|part| part.as_os_str().to_os_string())
                .collect::<Vec<_>>();
            let kits = parts
                .iter()
                .position(|part| {
                    part.to_str()
                        .is_some_and(|part| part.eq_ignore_ascii_case("Windows Kits"))
                })
                .ok_or_else(|| CiError::Message("unmodeled native include/library root".into()))?;
            let kit_root = parts.iter().take(kits + 2).collect::<PathBuf>();
            let version = parts
                .get(kits + 3)
                .ok_or_else(|| CiError::Message("SDK version absent".into()))?;
            let section = parts
                .get(kits + 4)
                .and_then(|part| part.to_str())
                .ok_or_else(|| CiError::Message("SDK section absent".into()))?;
            if !matches!(
                section.to_ascii_lowercase().as_str(),
                "um" | "ucrt" | "shared" | "winrt" | "cppwinrt"
            ) {
                return Err(CiError::Message("unmodeled SDK section".into()));
            }
            if sdk.as_ref().is_some_and(|previous| previous != &kit_root)
                || sdk_version
                    .as_ref()
                    .is_some_and(|previous| previous != version)
            {
                return Err(CiError::Message("native SDK selection ambiguous".into()));
            }
            if name == "LIB" {
                if path.file_name().and_then(std::ffi::OsStr::to_str) != Some(arch) {
                    return Err(CiError::Message("SDK library architecture differs".into()));
                }
                has_um |= section.eq_ignore_ascii_case("um");
                has_ucrt |= section.eq_ignore_ascii_case("ucrt");
            } else {
                include_um |= section.eq_ignore_ascii_case("um");
                include_ucrt |= section.eq_ignore_ascii_case("ucrt");
            }
            sdk = Some(kit_root);
            sdk_version = Some(version.clone());
        }
        identity.insert(
            format!("windows-effective-{name}"),
            artifacts::checksum(value.as_bytes()),
        );
    }
    if !has_um || !has_ucrt || !include_um || !include_ucrt {
        return Err(CiError::Message(
            "unknown SDK/UCRT library selection".into(),
        ));
    }
    let sdk = sdk.expect("SDK library selection");
    let sdk_version = text(sdk_version.as_ref().expect("SDK version"))?;
    for name in ["WINDOWSSDKVERSION", "UCRTVERSION"] {
        if let Some(expected) = ambient.get(name) {
            if expected.trim_end_matches(['\\', '/']) != sdk_version {
                return Err(CiError::Message(
                    "SDK/UCRT version selector conflicts".into(),
                ));
            }
        }
    }
    for name in ["WINDOWSSDKDIR", "UNIVERSALCRTSDKDIR"] {
        if let Some(expected) = ambient.get(name) {
            if Path::new(expected).canonicalize()? != sdk.canonicalize()? {
                return Err(CiError::Message("SDK/UCRT root selector conflicts".into()));
            }
        }
    }
    // PATH shadowing must match the resolver used by ordinary native builds.
    for name in ["link.exe", "cl.exe", "lib.exe"] {
        if let Some(path) = ambient.get("PATH").and_then(|value| {
            std::env::split_paths(value)
                .map(|path| path.join(name))
                .find(|path| path.is_file())
        }) {
            if text(path.as_os_str())? != identity[&format!("windows-tool-{name}-path")] {
                return Err(CiError::Message(
                    "ambient PATH shadows selected native tool".into(),
                ));
            }
        }
    }
    identity.insert("windows-sdk-root".into(), text(sdk.as_os_str())?);
    identity.insert("windows-sdk-version".into(), sdk_version);
    for (name, value) in environment {
        identity.insert(
            format!("windows-search-{name}"),
            artifacts::checksum(value.as_bytes()),
        );
    }
    Ok(identity)
}
