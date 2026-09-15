//! Positive tool-search admission for the Windows compilation recipe.
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

use super::msvc::Architecture;
type Environment = BTreeMap<OsString, OsString>;

pub struct Selection {
    pub rustup: PathBuf,
    pub input_roots: Vec<PathBuf>,
}

fn file(path: &Path) -> io::Result<PathBuf> {
    if !path.is_file() {
        return Err(io::Error::other(format!(
            "required Windows compiler helper missing: {path:?}"
        )));
    }
    path.canonicalize()?;
    super::paths::command_program(path)
}

fn directory(path: &Path) -> io::Result<PathBuf> {
    if !path.is_dir() {
        return Err(io::Error::other(format!(
            "required Windows compiler support directory missing: {path:?}"
        )));
    }
    super::command_path(path)
}

fn parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| io::Error::other("compiler helper has no parent"))
}

fn selected(name: &str, env: &Environment) -> io::Result<PathBuf> {
    let path = super::resolve_tool(OsStr::new(name), env).map_err(|error| {
        io::Error::other(format!("required Windows compiler helper {name}: {error}"))
    })?;
    file(&path)
}

fn variable(env: &Environment, name: &str) -> io::Result<PathBuf> {
    env.get(OsStr::new(name))
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other(format!("Windows compiler selector missing: {name}")))
}

/// Called after native MSVC selection, before any compilation. The input PATH
/// is discovery context only; no unselected directory survives in the output.
pub fn admit(env: &mut Environment, linker: &Path, arch: Architecture) -> io::Result<Selection> {
    let linker = file(linker)?;
    let msvc_bin = directory(parent(&linker)?)?;
    for name in ["cl.exe", "lib.exe"] {
        file(&msvc_bin.join(name))?;
    }
    let rustup = selected("rustup.exe", env)?;
    let rustup_bin = directory(parent(&rustup)?)?;
    let git = selected("git.exe", env)?;
    let git_bin = directory(parent(&git)?)?;
    if !git_bin
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("cmd") || name.eq_ignore_ascii_case("bin"))
    {
        return Err(io::Error::other(
            "selected Git helper requires an installed cmd/bin layout",
        ));
    }
    let git_root = directory(parent(&git_bin)?)?;
    if !["mingw64", "clangarm64", "mingw32"].iter().any(|layout| {
        git_root
            .join(layout)
            .join("libexec")
            .join("git-core")
            .is_dir()
    }) {
        return Err(io::Error::other(
            "selected Git installation lacks its native git-core helper tree",
        ));
    }
    let clang = selected("clang.exe", env)?;
    let llvm_bin = directory(parent(&clang)?)?;
    if !llvm_bin
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("bin"))
    {
        return Err(io::Error::other(
            "selected Clang helper requires an installed bin layout",
        ));
    }
    let llvm_root = directory(parent(&llvm_bin)?)?;
    directory(&llvm_root.join("lib").join("clang"))?;
    let sdk = variable(env, "WindowsSdkDir")?;
    let sdk_version = env
        .get(OsStr::new("WindowsSDKVersion"))
        .ok_or_else(|| io::Error::other("Windows SDK version missing after native selection"))?;
    let target = match arch {
        Architecture::X64 => "x64",
        Architecture::Arm64 => "arm64",
    };
    let sdk_bin = directory(&sdk.join("bin").join(sdk_version).join(target))?;
    for name in ["rc.exe", "mt.exe"] {
        file(&sdk_bin.join(name))?;
    }
    // Windows searches System32 independently of PATH. These enrolled recipe
    // helpers supplement the loader DLL baseline; this is not a host sandbox.
    let system = variable(env, "SystemRoot")?.join("System32");
    let mut roots = vec![
        git_root,
        llvm_root,
        file(&system.join("cmd.exe"))?,
        file(&system.join("ping.exe"))?,
    ];
    let mut path = Vec::new();
    for bin in [msvc_bin, rustup_bin, git_bin, llvm_bin, sdk_bin] {
        if !path.contains(&bin) {
            path.push(bin);
        }
    }
    roots.extend(path.iter().cloned());
    roots.sort();
    roots.dedup();
    let value = std::env::join_paths(&path).map_err(io::Error::other)?;
    env.insert("PATH".into(), value);
    Ok(Selection {
        rustup,
        input_roots: roots,
    })
}

/// Native installation discovery remains separate from the admitted child PATH.
pub fn configure(
    env: &mut Environment,
    discovery: &Environment,
    arch: Architecture,
    capture: impl FnOnce(&Path, &[&str], &Environment) -> io::Result<Vec<u8>>,
) -> io::Result<Selection> {
    let mut configured = env.clone();
    let installation = match super::msvc::selected_installation(&configured)? {
        Some(path) => path,
        None => {
            let query = super::msvc::vswhere(&configured)?;
            let arguments = arch.discovery_arguments();
            let value = String::from_utf8(capture(&query, &arguments, discovery)?)
                .map_err(io::Error::other)?;
            let mut lines = value.lines().filter(|line| !line.trim().is_empty());
            let installation = lines.next().ok_or_else(|| io::Error::other(format!("vswhere found no matching native MSVC installation: program={query:?} arguments={arguments:?}")))?;
            if lines.next().is_some() {
                return Err(io::Error::other(
                    "vswhere returned ambiguous MSVC installations",
                ));
            }
            PathBuf::from(installation.trim())
        }
    };
    let linker = super::msvc::configure(&mut configured, &installation, arch)?;
    let selection = admit(&mut configured, &linker, arch)?;
    *env = configured;
    Ok(selection)
}
