//! Closed compilation context. Cache manifests describe the very environment used
//! by Cargo; a restored controller is never used to authorize its own cache.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[path = "../../ci-build-environment.rs"]
pub mod environment;

use crate::inventory_progress::{InventoryProgress, Operation};
use crate::inventory_reader::{BUFFER_SIZE, digest_reader, open_sequential};
use crate::{CiError, Result};

#[cfg(windows)]
#[path = "inventory_native.rs"]
mod native_pipeline;

static ACTIVE: OnceLock<ValidatedBuildContext> = OnceLock::new();

#[path = "inventory_difference.rs"]
mod difference;

/// A content snapshot of a declared input tree, including modes and links.
/// Output paths are excluded only by the full managed profile, not this API.
#[derive(Clone, Debug)]
pub struct BuildInputSnapshot {
    root: PathBuf,
    inputs: Vec<Input>,
    native_discovery: bool,
}

impl BuildInputSnapshot {
    pub fn capture(root: &Path) -> Result<Self> {
        Self::capture_with_policy(root, false)
    }

    /// Measure a required native root, recording inaccessible descendants only
    /// when the build principal also lacks directory search permission.
    pub fn capture_native_tree(root: &Path) -> Result<Self> {
        Self::capture_with_policy(root, true)
    }

    fn capture_with_policy(root: &Path, native_discovery: bool) -> Result<Self> {
        let root = root.canonicalize().map_err(|error| {
            CiError::Message(format!(
                "resolving build input root {}: {error}",
                root.display()
            ))
        })?;
        let mut inputs = Vec::new();
        let scope = if native_discovery {
            MeasurementScope::NativeRoot
        } else {
            MeasurementScope::Required
        };
        measure_root(&root, scope, &mut inputs, &mut BTreeSet::new(), &mut None)?;
        inputs.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(Self {
            root,
            inputs,
            native_discovery,
        })
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(
            &self.inputs,
        )?)))
    }
    /// Complete canonical records for qualification comparisons. Consumers must
    /// not normalize these records when constructing runtime cache identities.
    pub(crate) fn inputs(&self) -> &[Input] {
        &self.inputs
    }
    pub fn audit(&self) -> Result<()> {
        let measured = Self::capture_with_policy(&self.root, self.native_discovery)?.inputs;
        if measured != self.inputs {
            return Err(CiError::Message(format!(
                "declared build inputs changed; {}",
                difference::describe(&self.inputs, &measured)
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) mode: u32,
    pub(crate) digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatedBuildContext {
    schema_version: u32,
    root: PathBuf,
    environment: Vec<(String, String)>,
    toolchains: BTreeMap<String, PathBuf>,
    input_roots: Vec<PathBuf>,
    discovery_roots: Vec<PathBuf>,
    inputs: Vec<Input>,
    worker: BTreeMap<String, String>,
}

fn native(value: &OsStr) -> String {
    hex::encode(value.as_encoded_bytes())
}

// Decoding uses native constructors, never a lossy UTF-8 conversion.
fn decode(value: &str) -> Result<OsString> {
    let bytes = hex::decode(value).map_err(|error| CiError::Message(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(OsString::from_vec(bytes))
    }
    #[cfg(windows)]
    {
        // WTF-8 must round-trip through serde's platform-independent UTF-8 boundary.
        // Managed Windows environment values outside Unicode are refused at planning.
        String::from_utf8(bytes)
            .map(OsString::from)
            .map_err(|error| CiError::Message(error.to_string()))
    }
}

fn file_digest(
    path: &Path,
    native: bool,
    progress: &InventoryProgress,
    buffer: &mut [u8],
) -> Result<String> {
    let mut file = match progress.run(Operation::Open, path, || open_sequential(path)) {
        Ok(file) => file,
        Err(error) => {
            #[cfg(target_os = "macos")]
            if native && error.kind() == io::ErrorKind::PermissionDenied {
                return progress.run(Operation::Access, path, || protected_native_digest(path));
            }
            let _ = native;
            return Err(error.into());
        }
    };
    progress.run(Operation::ReadHash, path, || {
        digest_reader(&mut file, buffer, progress).map_err(CiError::from)
    })
}

#[cfg(target_os = "macos")]
fn protected_native_digest(path: &Path) -> Result<String> {
    let canonical = crate::native_file_digest::validate_system_path(path)?;
    let helper = std::env::current_exe()?.with_file_name("memcordon-native-input-digest");
    let mut command = Command::new("/usr/bin/sudo");
    command
        .args(["-n", "--"])
        .arg(&helper)
        .arg("--path")
        .arg(&canonical)
        .current_dir("/")
        .env_clear()
        .envs(environment::closed_environment(
            &std::env::vars_os().collect(),
        )?);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(30),
        8192,
    )?;
    if !output.status.success() {
        return Err(CiError::Message(format!(
            "protected system digest failed for {}: {}",
            canonical.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    crate::native_file_digest::parse_digest_output(&output.stdout).map_err(Into::into)
}

/// Every permitted environment-selected native input is an explicit tree root.
pub fn native_environment_roots(
    environment: &BTreeMap<OsString, OsString>,
) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    for name in [
        "DEVELOPER_DIR",
        "SDKROOT",
        "VCToolsInstallDir",
        "WindowsSdkDir",
        "VCINSTALLDIR",
        "VSINSTALLDIR",
        "INCLUDE",
        "LIB",
        "LIBPATH",
    ] {
        if let Some(value) = environment.get(OsStr::new(name)) {
            let paths = if matches!(name, "INCLUDE" | "LIB" | "LIBPATH") {
                std::env::split_paths(value).collect::<Vec<_>>()
            } else {
                vec![PathBuf::from(value)]
            };
            if paths.is_empty() {
                return Err(CiError::Message("empty native input path list".into()));
            }
            for path in paths {
                if !path.is_absolute() {
                    return Err(CiError::Message(format!(
                        "native input {name} requires absolute paths"
                    )));
                }
                roots.push(path.canonicalize()?);
            }
        }
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

/// Discover Windows platform inputs from the canonical closed environment.
/// Keep selection separate from measurement so Windows name semantics can be
/// checked with a small fixture without traversing an installed SDK.
pub fn windows_native_roots(environment: &BTreeMap<OsString, OsString>) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    let mut sdk_found = false;
    let mut compiler_found = false;
    for name in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Some(base) = environment.get(OsStr::new(name)) {
            let base = PathBuf::from(base);
            let sdk = base.join("Windows Kits");
            if sdk.is_dir() {
                sdk_found = true;
                roots.push(sdk);
            }
            let compiler = base.join("Microsoft Visual Studio");
            if compiler.is_dir() {
                compiler_found = true;
                roots.push(compiler);
            }
        }
    }
    if !sdk_found || !compiler_found {
        return Err(CiError::Message(
            "native Windows SDK/MSVC input roots unavailable".into(),
        ));
    }
    let windows = environment
        .get(OsStr::new("SystemRoot"))
        .ok_or_else(|| CiError::Message("Windows system root unavailable".into()))?;
    for name in ["kernel32.dll", "ntdll.dll", "ucrtbase.dll", "msvcp_win.dll"] {
        roots.push(PathBuf::from(windows).join("System32").join(name));
    }
    Ok(roots)
}

fn mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.mode()
    }
    #[cfg(not(unix))]
    {
        u32::from(metadata.permissions().readonly())
    }
}

#[derive(Clone, Copy)]
enum MeasurementScope<'a> {
    Source(&'a Path),
    Required,
    NativeRoot,
    NativeDescendant,
}

impl<'a> MeasurementScope<'a> {
    fn child(self) -> Self {
        match self {
            Self::NativeRoot => Self::NativeDescendant,
            other => other,
        }
    }

    fn source(self) -> Option<&'a Path> {
        match self {
            Self::Source(root) => Some(root),
            _ => None,
        }
    }
}

// Use the kernel's effective-credential check on supported platforms,
// including ACLs, rather than access(2) or a mode-bit approximation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn inaccessible_directory_identity(path: &Path, metadata: &fs::Metadata) -> Result<Option<String>> {
    let Some(identity) = memcordon_testkit::unsearchable_directory(path, metadata)? else {
        return Ok(None);
    };
    Ok(Some(serde_json::to_string(&(
        identity.owner_uid,
        identity.owner_gid,
        (identity.effective_uid, identity.effective_gid),
        identity.supplementary_groups,
    ))?))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inaccessible_directory_identity(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<Option<String>> {
    Ok(None)
}

// Linux defines the null character device as major 1, minor 3. Its input
// behavior is EOF, so discovery can identify it without opening a device
// stream. Other devices remain unsupported, regardless of their pathname.
#[cfg(target_os = "linux")]
fn native_null_device_identity(metadata: &fs::Metadata) -> Result<Option<String>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let device = metadata.rdev();
    if !metadata.file_type().is_char_device()
        || libc::major(device) != 1
        || libc::minor(device) != 3
    {
        return Ok(None);
    }
    Ok(Some(serde_json::to_string(&(
        device,
        metadata.uid(),
        metadata.gid(),
    ))?))
}

#[cfg(not(target_os = "linux"))]
fn native_null_device_identity(_metadata: &fs::Metadata) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn inaccessible_symlink_identity(path: &Path) -> Result<Option<String>> {
    use std::collections::VecDeque;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let components = |path: &Path| {
        path.components()
            .map(|component| component.as_os_str().to_os_string())
            .collect::<VecDeque<_>>()
    };
    if !path.is_absolute() {
        return Err(CiError::Message(
            "native symlink route must be absolute".into(),
        ));
    }
    let mut pending = components(path);
    let mut current = PathBuf::from("/");
    let mut route = Vec::new();
    let mut expansions = 0;
    const MAX_SYMLINK_EXPANSIONS: usize = 32;
    while let Some(part) = pending.pop_front() {
        let part_path = Path::new(&part);
        let component = part_path
            .components()
            .next()
            .ok_or_else(|| CiError::Message("empty native symlink component".into()))?;
        if matches!(component, Component::RootDir) {
            current = PathBuf::from("/");
            continue;
        }
        current = current.canonicalize()?;
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir() {
            return Err(CiError::Message(
                "native symlink route traverses non-directory".into(),
            ));
        }
        let denial = inaccessible_directory_identity(&current, &metadata)?;
        route.push(Input {
            path: native(current.as_os_str()),
            kind: if denial.is_some() {
                "inaccessible-directory"
            } else {
                "route-directory"
            }
            .into(),
            mode: mode(&metadata),
            digest: match denial {
                Some(ref evidence) => evidence.clone(),
                None => serde_json::to_string(&(metadata.uid(), metadata.gid()))?,
            },
        });
        if denial.is_some() {
            return Ok(Some(serde_json::to_string(&route)?));
        }
        match component {
            Component::ParentDir => {
                current.pop();
            }
            Component::CurDir => {}
            Component::Normal(name) => {
                let next = current.join(name);
                let metadata = fs::symlink_metadata(&next)?;
                if metadata.file_type().is_symlink() {
                    expansions += 1;
                    if expansions > MAX_SYMLINK_EXPANSIONS {
                        return Err(CiError::Message(
                            "native symlink route expansion limit exceeded".into(),
                        ));
                    }
                    let target = fs::read_link(&next)?;
                    route.push(Input {
                        path: native(next.as_os_str()),
                        kind: "route-symlink".into(),
                        mode: mode(&metadata),
                        digest: serde_json::to_string(&(
                            native(target.as_os_str()),
                            metadata.uid(),
                            metadata.gid(),
                        ))?,
                    });
                    let mut expanded = components(&target);
                    expanded.append(&mut pending);
                    pending = expanded;
                } else {
                    current = next;
                }
            }
            _ => {
                return Err(CiError::Message(
                    "unsupported native symlink component".into(),
                ));
            }
        }
    }
    // An EACCES without independently observed search denial is never admitted.
    Ok(None)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inaccessible_symlink_identity(_path: &Path) -> Result<Option<String>> {
    Ok(None)
}

fn measure_root(
    path: &Path,
    scope: MeasurementScope<'_>,
    inputs: &mut Vec<Input>,
    visited: &mut BTreeSet<PathBuf>,
    session: &mut Option<crate::inventory_pipeline::InventorySession>,
) -> Result<()> {
    let kind = match scope {
        MeasurementScope::Source(_) => "source",
        MeasurementScope::Required => "required",
        MeasurementScope::NativeRoot | MeasurementScope::NativeDescendant => "native",
    };
    environment::progress::phase(&format!("inventory {kind} root {path:?}"), || {
        let mut progress = InventoryProgress::new(path);
        #[cfg(windows)]
        if scope.source().is_none() {
            if session.is_none() {
                *session = Some(crate::inventory_pipeline::InventorySession::new()?);
            }
            let result = session.as_ref().expect("native inventory session").measure(
                native_pipeline::Backend::new(&progress, path),
                native_pipeline::Entry::root(path, scope),
                visited,
            );
            let successful = result.is_ok();
            if let Ok(records) = &result {
                assert!(
                    records
                        .iter()
                        .all(|input| input.kind != "file" || !input.digest.is_empty())
                );
            }
            progress.finish(successful);
            inputs.extend(result?);
            return Ok(());
        }
        let _ = session;
        let mut reader = ContentReader::new();
        let result = measure(path, None, scope, inputs, visited, &progress, &mut reader);
        progress.finish(result.is_ok());
        result
    })
}

type PreparedInput = (fs::Metadata, PathBuf);

struct ContentReader {
    buffer: Vec<u8>,
}

impl ContentReader {
    fn new() -> Self {
        Self {
            buffer: vec![0; BUFFER_SIZE],
        }
    }
}

fn measure(
    path: &Path,
    prepared: Option<PreparedInput>,
    scope: MeasurementScope<'_>,
    inputs: &mut Vec<Input>,
    visited: &mut BTreeSet<PathBuf>,
    progress: &InventoryProgress,
    reader: &mut ContentReader,
) -> Result<()> {
    measure_path(path, prepared, scope, inputs, visited, progress, reader).map_err(|error| {
        CiError::Message(format!("measuring build input {}: {error}", path.display()))
    })
}

fn resolution_error(
    path: &Path,
    metadata: &fs::Metadata,
    error: io::Error,
    progress: &InventoryProgress,
) -> CiError {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            let evidence = progress.run(Operation::Access, path, || {
                memcordon_testkit::windows_reparse_data(path)
            });
            let diagnostic = match evidence {
                Ok(data) => crate::reparse_diagnostic::describe(&data)
                    .unwrap_or_else(|failure| format!("{failure}; raw_hex={}", hex::encode(data))),
                Err(failure) => format!("no-follow reparse probe failed: {failure}"),
            };
            return CiError::Message(format!(
                "resolving path: {error}; unresolved native reparse input (not admitted): {diagnostic}"
            ));
        }
    }
    let _ = (path, metadata, progress);
    CiError::Message(format!("resolving path: {error}"))
}

fn resolve_identity(
    path: &Path,
    metadata: &fs::Metadata,
    progress: &InventoryProgress,
) -> Result<PathBuf> {
    if metadata.file_type().is_symlink() {
        Ok(path.to_path_buf())
    } else {
        progress
            .run(Operation::Canonicalize, path, || path.canonicalize())
            .map_err(|error| resolution_error(path, metadata, error, progress))
    }
}

fn measure_path(
    path: &Path,
    prepared: Option<PreparedInput>,
    scope: MeasurementScope<'_>,
    inputs: &mut Vec<Input>,
    visited: &mut BTreeSet<PathBuf>,
    progress: &InventoryProgress,
    reader: &mut ContentReader,
) -> Result<()> {
    let source = scope.source();
    if let Some(root) = source {
        let relative = path
            .strip_prefix(root)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if ["fuzz/target", "fuzz/corpus", "fuzz/artifacts"]
            .iter()
            .any(|output| relative.starts_with(output))
        {
            return Ok(());
        }
        if relative.components().next().is_some_and(|part| {
            matches!(
                part.as_os_str().to_str(),
                Some(
                    "target"
                        | ".git"
                        | "ci-native-fingerprint"
                        | "ci-native-fingerprint.exe"
                        | "ci-native-fingerprint.pdb"
                )
            )
        }) {
            return Ok(());
        }
    }
    let (metadata, prepared_identity) = match prepared {
        Some((metadata, identity)) => (metadata, Some(identity)),
        None => (
            progress
                .run(Operation::Metadata, path, || fs::symlink_metadata(path))
                .map_err(|error| CiError::Message(format!("reading metadata: {error}")))?,
            None,
        ),
    };
    // Validate every declared discovery root even if a previous overlapping
    // traversal recorded that path as an inaccessible descendant.
    if matches!(scope, MeasurementScope::NativeRoot) && metadata.is_dir() {
        progress
            .run(Operation::Directory, path, || fs::read_dir(path))
            .map_err(|error| CiError::Message(format!("reading required native root: {error}")))?;
    }
    // Every ordinary path, not only symlink targets, enters the visited set.
    // Resolve ordinary aliases before descent so overlapping roots share work.
    // Symlinks retain their own path and identity even when a target was visited.
    let identity = match prepared_identity {
        Some(identity) => identity,
        None => resolve_identity(path, &metadata, progress)?,
    };
    if !visited.insert(identity.clone()) {
        return Ok(());
    }
    let (kind, digest) = if metadata.file_type().is_symlink() {
        let target = progress
            .run(Operation::Symlink, path, || fs::read_link(path))
            .map_err(|error| CiError::Message(format!("reading symlink: {error}")))?;
        match progress.run(Operation::Canonicalize, path, || path.canonicalize()) {
            Ok(resolved) => {
                if source.is_some_and(|root| !resolved.starts_with(root)) {
                    return Err(CiError::Message(
                        "source symlink escapes declared root".into(),
                    ));
                }
                if source.is_none() {
                    measure(&resolved, None, scope, inputs, visited, progress, reader)?;
                }
                (
                    "symlink",
                    serde_json::to_string(&[
                        native(target.as_os_str()),
                        native(resolved.as_os_str()),
                    ])?,
                )
            }
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    && matches!(scope, MeasurementScope::NativeDescendant) =>
            {
                let route = progress
                    .run(Operation::Access, path, || {
                        inaccessible_symlink_identity(path)
                    })?
                    .ok_or_else(|| {
                        CiError::Message(format!(
                            "resolving symlink without proven search denial: {error}"
                        ))
                    })?;
                (
                    "inaccessible-symlink",
                    serde_json::to_string(&(native(target.as_os_str()), route))?,
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && source.is_none() => {
                // Missing native link targets are a measured state, not an
                // ignored input. Appearance or retargeting changes the audit.
                ("dangling-symlink", native(target.as_os_str()))
            }
            Err(error) => {
                return Err(CiError::Message(format!("resolving symlink: {error}")));
            }
        }
    } else if metadata.is_dir() {
        let entries =
            match progress.run(Operation::Directory, &identity, || fs::read_dir(&identity)) {
                Ok(entries) => entries,
                Err(error) => {
                    if error.kind() == io::ErrorKind::PermissionDenied
                        && matches!(scope, MeasurementScope::NativeDescendant)
                        && let Some(digest) = progress.run(Operation::Access, &identity, || {
                            inaccessible_directory_identity(&identity, &metadata)
                        })?
                    {
                        inputs.push(Input {
                            path: native(identity.as_os_str()),
                            kind: "inaccessible-directory".into(),
                            mode: mode(&metadata),
                            digest,
                        });
                        return Ok(());
                    }
                    return Err(CiError::Message(format!("reading directory: {error}")));
                }
            };
        let children = progress.run(Operation::Directory, &identity, || {
            let mut children: Vec<_> = entries
                .collect::<io::Result<_>>()
                .map_err(|error| CiError::Message(format!("enumerating directory: {error}")))?;
            children.sort_by_key(|entry| entry.file_name());
            Ok::<_, CiError>(children)
        })?;
        for child in children {
            measure(
                &child.path(),
                None,
                scope.child(),
                inputs,
                visited,
                progress,
                reader,
            )?;
        }
        ("directory", String::new())
    } else if metadata.is_file() {
        (
            "file",
            file_digest(
                &identity,
                scope.source().is_none(),
                progress,
                &mut reader.buffer,
            )
            .map_err(|error| CiError::Message(format!("reading file contents: {error}")))?,
        )
    } else if matches!(scope, MeasurementScope::NativeDescendant)
        && let Some(digest) = native_null_device_identity(&metadata)?
    {
        ("linux-null-device", digest)
    } else {
        return Err(CiError::Message(format!(
            "unsupported build input: {}",
            path.display()
        )));
    };
    inputs.push(Input {
        path: native(identity.as_os_str()),
        kind: kind.into(),
        mode: mode(&metadata),
        digest,
    });
    Ok(())
}

fn output(
    program: &Path,
    args: &[&OsStr],
    env: &BTreeMap<OsString, OsString>,
    cwd: &Path,
) -> Result<Vec<u8>> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(environment::command_path(cwd)?)
        .env_clear()
        .envs(env);
    identity_output(&mut command)
}

/// Discover installed toolchains without activating the repository's component
/// override or allowing a missing selected toolchain to be installed implicitly.
pub fn installed_toolchains_command(
    program: &Path,
    pinned: &str,
    env: &BTreeMap<OsString, OsString>,
    cwd: &Path,
) -> Result<Command> {
    let mut command = Command::new(program);
    command
        .args(["toolchain", "list"])
        .current_dir(environment::command_path(cwd)?)
        .env_clear()
        .envs(env)
        .env("RUSTUP_TOOLCHAIN", pinned)
        .env("RUSTUP_AUTO_INSTALL", "0");
    Ok(command)
}

fn identity_output(command: &mut Command) -> Result<Vec<u8>> {
    let description = format!(
        "program={:?} arguments={:?}",
        command.get_program(),
        command.get_args().collect::<Vec<_>>()
    );
    let result = memcordon_testkit::run_with_deadline(command, Duration::from_secs(30)).map_err(
        |error| {
            CiError::Message(format!(
                "build identity command failed: {description}; {error}"
            ))
        },
    )?;
    if !result.status.success() {
        return Err(CiError::Message(format!(
            "build identity command failed: {description}; status={}; stderr={:?}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        )));
    }
    Ok(result.stdout)
}

impl ValidatedBuildContext {
    pub fn prepare(root: &Path) -> Result<Self> {
        environment::progress::phase("prepare build context", || Self::prepare_inner(root))
    }

    fn prepare_inner(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let command_root = environment::command_path(&root)?;
        let ambient: BTreeMap<_, _> = std::env::vars_os().collect();
        let mut env = environment::closed_environment(&ambient)?;
        #[cfg(windows)]
        let native_linker = {
            let installation =
                environment::msvc::selected_installation(&env)?.ok_or_else(|| {
                    CiError::Message(
                        "MSVC installation must be selected by the cold bootstrap".into(),
                    )
                })?;
            environment::msvc::configure(
                &mut env,
                &installation,
                environment::msvc::Architecture::native()?,
            )?
        };
        #[cfg(windows)]
        let admitted = environment::windows_compiler::admit(
            &mut env,
            &native_linker,
            environment::msvc::Architecture::native()?,
        )?;
        #[cfg(windows)]
        if env
            .iter()
            .any(|(key, value)| key.to_str().is_none() || value.to_str().is_none())
        {
            return Err(CiError::Message(
                "managed Windows build requires Unicode environment".into(),
            ));
        }
        let home = env
            .get(OsStr::new(if cfg!(windows) {
                "USERPROFILE"
            } else {
                "HOME"
            }))
            .ok_or_else(|| CiError::Message("managed home missing".into()))?;
        environment::reject_cargo_configuration(&root, &PathBuf::from(home).join(".cargo"))?;
        let cargo_home = command_root.join("target/ci/source-home");
        environment::reject_cargo_configuration(&root, &cargo_home)?;
        fs::create_dir_all(&cargo_home)?;
        env.insert("CARGO_HOME".into(), cargo_home.into_os_string());
        let rustup = environment::resolve_tool(OsStr::new("rustup"), &env)?;
        let config = crate::config::toolchains(&root)?;
        let mut toolchains = BTreeMap::new();
        let mut input_roots = vec![rustup.clone()];
        #[cfg(windows)]
        input_roots.push(native_linker);
        #[cfg(windows)]
        input_roots.extend(admitted.input_roots);
        let mut discovery_roots = Vec::new();
        input_roots.extend(native_environment_roots(&env)?);
        let tools = root.join("target/ci-tools/bin");
        if tools.exists() {
            input_roots.push(tools);
        }
        for relative in [
            "target/ci/source-home/registry/src",
            "target/ci/source-home/git/checkouts",
        ] {
            let source = root.join(relative);
            if source.exists() {
                input_roots.push(source);
            }
        }
        let installed = identity_output(&mut installed_toolchains_command(
            &rustup,
            &config.stable,
            &env,
            &root,
        )?)?;
        for toolchain in [&config.stable, &config.msrv, &config.miri] {
            if !String::from_utf8_lossy(&installed)
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .any(|installed| {
                    installed
                        .strip_prefix(toolchain)
                        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('-'))
                })
            {
                continue;
            }
            let bytes = output(
                &rustup,
                &[
                    OsStr::new("which"),
                    OsStr::new("--toolchain"),
                    OsStr::new(toolchain),
                    OsStr::new("cargo"),
                ],
                &env,
                &root,
            )?;
            let cargo = PathBuf::from(
                String::from_utf8(bytes)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .trim(),
            )
            .canonicalize()?;
            let sysroot = cargo
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| CiError::Message("invalid Cargo sysroot".into()))?
                .to_path_buf();
            input_roots.push(sysroot);
            toolchains.insert(toolchain.clone(), cargo);
        }
        if !toolchains.contains_key(&config.stable) {
            return Err(CiError::Message("pinned stable toolchain missing".into()));
        }
        if ambient
            .get(OsStr::new("GITHUB_JOB"))
            .and_then(|job| job.to_str())
            .is_some_and(|job| job.contains("miri"))
        {
            let bytes = output(
                &rustup,
                &[
                    OsStr::new("run"),
                    OsStr::new(&config.miri),
                    OsStr::new("cargo"),
                    OsStr::new("miri"),
                    OsStr::new("setup"),
                    OsStr::new("--print-sysroot"),
                ],
                &env,
                &root,
            )?;
            input_roots.push(
                PathBuf::from(
                    String::from_utf8(bytes)
                        .map_err(|error| CiError::Message(error.to_string()))?
                        .trim(),
                )
                .canonicalize()?,
            );
        }
        // The declared native input closure includes compiler/linker binaries,
        // SDK resources and system headers/libraries. These are content measured.
        #[cfg(target_os = "macos")]
        {
            let xcode = environment::resolve_tool(OsStr::new("xcode-select"), &env)?;
            let developer = output(&xcode, &[OsStr::new("--print-path")], &env, &root)?;
            input_roots.push(PathBuf::from(
                String::from_utf8(developer)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .trim(),
            ));
            discovery_roots.extend([
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin"),
            ]);
        }
        #[cfg(target_os = "linux")]
        discovery_roots.extend([
            PathBuf::from("/usr/include"),
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ]);
        #[cfg(windows)]
        input_roots.extend(windows_native_roots(&env)?);
        for path in std::env::split_paths(env.get(OsStr::new("PATH")).expect("validated PATH")) {
            if path.is_dir() && !path.starts_with(&root) {
                #[cfg(windows)]
                if path.components().any(|part| {
                    part.as_os_str()
                        .to_str()
                        .is_some_and(|part| part.eq_ignore_ascii_case("Windows"))
                }) {
                    continue;
                }
                discovery_roots.push(path.canonicalize()?);
            }
        }
        input_roots.sort();
        input_roots.dedup();
        discovery_roots.sort();
        discovery_roots.dedup();
        let worker = [
            "ImageOS",
            "ImageVersion",
            "RUNNER_OS",
            "RUNNER_ARCH",
            "GITHUB_JOB",
            "GITHUB_WORKFLOW",
            "GITHUB_SHA",
        ]
        .into_iter()
        .filter_map(|key| {
            ambient
                .get(OsStr::new(key))
                .map(|value| (key.to_owned(), native(value)))
        })
        .collect();
        let mut context = Self {
            schema_version: 3,
            root,
            environment: env
                .iter()
                .map(|(key, value)| (native(key), native(value)))
                .collect(),
            toolchains,
            input_roots,
            discovery_roots,
            inputs: Vec::new(),
            worker,
        };
        context.inputs = context.measure_inputs()?;
        Ok(context)
    }

    fn measure_inputs(&self) -> Result<Vec<Input>> {
        let mut inputs = Vec::new();
        let mut visited = BTreeSet::new();
        let mut session = None;
        measure_root(
            &self.root,
            MeasurementScope::Source(&self.root),
            &mut inputs,
            &mut visited,
            &mut session,
        )?;
        // Native inputs must not inherit source-output exclusions.
        visited.clear();
        for root in &self.input_roots {
            measure_root(
                root,
                MeasurementScope::Required,
                &mut inputs,
                &mut visited,
                &mut session,
            )?;
        }
        for root in &self.discovery_roots {
            measure_root(
                root,
                MeasurementScope::NativeRoot,
                &mut inputs,
                &mut visited,
                &mut session,
            )?;
        }
        // Every root has fenced its completions; close/join the shared pool before
        // accepting or serializing the complete measurement.
        drop(session);
        inputs.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(inputs)
    }

    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        let context: Self = serde_json::from_slice(&fs::read(path)?)?;
        if context.schema_version != 3 || context.inputs.is_empty() || context.toolchains.is_empty()
        {
            return Err(CiError::Message("incomplete managed build context".into()));
        }
        Ok(context)
    }

    pub fn audit(&self) -> Result<()> {
        environment::progress::phase("audit build context", || self.audit_inner())
    }

    fn audit_inner(&self) -> Result<()> {
        let env = self.environment()?;
        let cargo_home = env
            .get(OsStr::new("CARGO_HOME"))
            .ok_or_else(|| CiError::Message("missing managed Cargo home".into()))?;
        environment::reject_cargo_configuration(&self.root, Path::new(cargo_home))?;
        let measured = self.measure_inputs()?;
        if measured != self.inputs {
            return Err(CiError::Message(format!(
                "managed build inputs changed; cache publication and qualification rejected; {}",
                difference::describe(&self.inputs, &measured)
            )));
        }
        Ok(())
    }

    pub fn environment(&self) -> Result<BTreeMap<OsString, OsString>> {
        self.environment
            .iter()
            .map(|(key, value)| Ok((decode(key)?, decode(value)?)))
            .collect()
    }

    pub fn cargo_command(
        &self,
        toolchain: &str,
        arguments: &[OsString],
        directory: &Path,
    ) -> Result<Command> {
        let cargo = self
            .toolchains
            .get(toolchain)
            .ok_or_else(|| CiError::Message("toolchain not enrolled in build context".into()))?;
        if directory.canonicalize()? != self.root {
            return Err(CiError::Message(
                "unapproved Cargo working directory".into(),
            ));
        }
        if arguments.iter().any(|arg| {
            arg == "--config" || arg.to_str().is_some_and(|arg| arg.starts_with("--config="))
        }) {
            return Err(CiError::Message(
                "unapproved Cargo CLI configuration".into(),
            ));
        }
        self.toolchain_command(toolchain, cargo, arguments, directory)
    }

    pub fn toolchain_command(
        &self,
        toolchain: &str,
        executable: &Path,
        arguments: &[OsString],
        directory: &Path,
    ) -> Result<Command> {
        let cargo = self
            .toolchains
            .get(toolchain)
            .ok_or_else(|| CiError::Message("toolchain not enrolled in build context".into()))?;
        if directory.canonicalize()? != self.root {
            return Err(CiError::Message(
                "unapproved toolchain working directory".into(),
            ));
        }
        let tool_names = if cfg!(windows) {
            ["cargo-fuzz.exe", "cargo-audit.exe", "cargo-deny.exe"]
        } else {
            ["cargo-fuzz", "cargo-audit", "cargo-deny"]
        };
        let tool_directory = self.root.join("target/ci-tools/bin");
        let approved_tool = tool_names
            .iter()
            .any(|name| executable == tool_directory.join(name))
            && self.inputs.iter().any(|input| {
                input.path == native(executable.as_os_str())
                    && matches!(input.kind.as_str(), "file" | "symlink")
            });
        if executable != cargo && !approved_tool {
            return Err(CiError::Message("unenrolled toolchain executable".into()));
        }
        let mut command = Command::new(environment::paths::command_program(executable)?);
        let command_cargo = environment::paths::command_program(cargo)?;
        let bin = command_cargo.parent().expect("validated Cargo directory");
        let mut environment = self.environment()?;
        let mut paths = vec![bin.to_path_buf()];
        paths.extend(std::env::split_paths(
            environment
                .get(OsStr::new("PATH"))
                .ok_or_else(|| CiError::Message("managed PATH missing".into()))?,
        ));
        environment.insert(
            "PATH".into(),
            std::env::join_paths(paths).map_err(|error| CiError::Message(error.to_string()))?,
        );
        environment.insert("RUSTUP_TOOLCHAIN".into(), toolchain.into());
        if !arguments
            .first()
            .is_some_and(|arg| matches!(arg.to_str(), Some("install" | "publish")))
        {
            environment.insert("CARGO_NET_OFFLINE".into(), "true".into());
        }
        command
            .args(arguments)
            .current_dir(environment::command_path(&self.root)?)
            .env_clear()
            .envs(environment)
            .env(
                "RUSTC",
                bin.join(if cfg!(windows) { "rustc.exe" } else { "rustc" }),
            )
            .env(
                "RUSTDOC",
                bin.join(if cfg!(windows) {
                    "rustdoc.exe"
                } else {
                    "rustdoc"
                }),
            );
        Ok(command)
    }
}

pub fn activate(context: ValidatedBuildContext) -> Result<()> {
    context.audit()?;
    ACTIVE
        .set(context)
        .map_err(|_| CiError::Message("build context already active".into()))
}

pub fn active() -> Option<&'static ValidatedBuildContext> {
    ACTIVE.get()
}

/// Generated/package-source qualification is a separate, uncached operation.
/// Its output and Cargo home live in a fresh temporary directory, and its source
/// identity is recorded and audited independently of the checkout cache context.
pub fn run_isolated_cargo(
    directory: &Path,
    toolchain: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    deadline: Duration,
    install_root: Option<&Path>,
) -> Result<Vec<u8>> {
    let directory = directory.canonicalize()?;
    let temporary = tempfile::tempdir()?;
    let arguments: Vec<OsString> = arguments
        .into_iter()
        .map(|value| value.as_ref().to_os_string())
        .collect();
    let mut rewritten = Vec::new();
    let mut outputs = Vec::new();
    let mut iterator = arguments.iter();
    while let Some(argument) = iterator.next() {
        if argument == "--target-dir" {
            iterator
                .next()
                .ok_or_else(|| CiError::Message("target directory argument missing".into()))?;
            continue;
        }
        if argument.to_str().is_some_and(|value| {
            value.starts_with("--target-dir=")
                || value.starts_with("--root=")
                || value.starts_with("--config=")
        }) || argument == "--config"
        {
            return Err(CiError::Message(
                "isolated target directory must be a separate native argument".into(),
            ));
        }
        rewritten.push(argument.clone());
        if argument == "--root" {
            let output = iterator
                .next()
                .ok_or_else(|| CiError::Message("install root argument missing".into()))?;
            let output = directory.join(output);
            if output
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
                || install_root != Some(output.as_path())
            {
                return Err(CiError::Message(
                    "isolated installation output escapes source operation".into(),
                ));
            }
            outputs.push(output.clone());
            rewritten.push(environment::paths::command_output_path(&output)?.into_os_string());
        } else if argument == "--manifest-path" || argument == "--path" {
            let input = iterator
                .next()
                .ok_or_else(|| CiError::Message("Cargo input path missing".into()))?;
            rewritten.push(environment::command_path(&directory.join(input))?.into_os_string());
        }
    }
    let acquisition = rewritten
        .first()
        .is_some_and(|value| value == "generate-lockfile");
    if acquisition {
        outputs.push(directory.join("Cargo.lock"));
    }
    let snapshot = |root: &Path| -> Result<BuildInputSnapshot> {
        let mut snapshot = BuildInputSnapshot::capture(root)?;
        snapshot.inputs.retain(|input| {
            decode(&input.path).is_ok_and(|path| {
                !outputs
                    .iter()
                    .any(|output| Path::new(&path).starts_with(output))
            })
        });
        Ok(snapshot)
    };
    let before = snapshot(&directory)?;
    validate_generated_configuration(&directory, &temporary.path().join("cargo-home"))?;
    let mut command = if let Some(context) = active() {
        let cargo = context
            .toolchains
            .get(toolchain)
            .ok_or_else(|| CiError::Message("isolated toolchain not enrolled".into()))?;
        context.toolchain_command(toolchain, cargo, &rewritten, &context.root)?
    } else {
        let ambient = std::env::vars_os()
            .filter(|(key, _)| key != "RUSTUP_TOOLCHAIN" && key != "CARGO_HOME")
            .collect();
        let environment = environment::closed_environment(&ambient)?;
        #[cfg(windows)]
        let environment = {
            let mut environment = environment;
            let discovery = environment::windows_discovery_environment(&ambient)?;
            environment::windows_compiler::configure(
                &mut environment,
                &discovery,
                environment::msvc::Architecture::native()?,
                |program, arguments, discovery| {
                    let arguments: Vec<_> = arguments.iter().map(OsStr::new).collect();
                    output(program, &arguments, discovery, &directory).map_err(io::Error::other)
                },
            )?;
            environment
        };
        let rustup = environment::resolve_tool(OsStr::new("rustup"), &environment)?;
        let mut command = Command::new(rustup);
        command
            .args(["run", toolchain, "cargo"])
            .args(&rewritten)
            .env_clear()
            .envs(environment);
        command
    };
    let command_temporary = environment::command_path(temporary.path())?;
    command
        .current_dir(environment::command_path(&directory)?)
        .env("CARGO_HOME", command_temporary.join("cargo-home"))
        .env("CARGO_TARGET_DIR", command_temporary.join("target"))
        .env("CARGO_NET_OFFLINE", "false");
    let output = memcordon_testkit::run_with_deadline(&mut command, deadline)?;
    let unchanged = snapshot(&directory)?.inputs == before.inputs;
    if let Some(context) = active() {
        let evidence = context.root.join("target/ci/isolated-evidence");
        fs::create_dir_all(&evidence)?;
        let record = serde_json::json!({"schema_version":1,"source_digest":before.digest()?,"source_unchanged":unchanged,"directory":native(directory.as_os_str()),"arguments":rewritten.iter().map(|value|native(value)).collect::<Vec<_>>(),"cache_eligible":false,"status":output.status.code()});
        let path = evidence
            .join(hex::encode(Sha256::digest(serde_json::to_vec(&record)?)))
            .with_extension("json");
        fs::write(path, serde_json::to_vec_pretty(&record)?)?;
    }
    if !unchanged {
        return Err(CiError::Message(
            "isolated package source changed during compilation".into(),
        ));
    }
    if !output.status.success() {
        return Err(CiError::Message(format!(
            "isolated Cargo failed: {}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

fn validate_generated_configuration(directory: &Path, home: &Path) -> Result<()> {
    if let Some(parent) = directory.parent() {
        environment::reject_cargo_configuration(parent, home)?;
    }
    if directory.join(".cargo/config").exists() {
        return Err(CiError::Message(
            "generated profile forbids legacy Cargo configuration".into(),
        ));
    }
    let configuration = directory.join(".cargo/config.toml");
    if !configuration.exists() {
        return Ok(());
    }
    let value: toml::Value = toml::from_str(&fs::read_to_string(configuration)?)?;
    let invalid = || {
        CiError::Message(
            "generated Cargo configuration may contain only local package patches".into(),
        )
    };
    let table = value.as_table().ok_or_else(invalid)?;
    if table.len() != 1 {
        return Err(invalid());
    }
    let patches = table
        .get("patch")
        .and_then(toml::Value::as_table)
        .ok_or_else(invalid)?;
    if patches.len() != 1 {
        return Err(invalid());
    }
    for specification in patches
        .get("crates-io")
        .and_then(toml::Value::as_table)
        .ok_or_else(invalid)?
        .values()
    {
        let specification = specification.as_table().ok_or_else(invalid)?;
        if specification.len() != 1 {
            return Err(invalid());
        }
        let path = specification
            .get("path")
            .and_then(toml::Value::as_str)
            .ok_or_else(invalid)?;
        if !directory.join(path).canonicalize()?.starts_with(directory) {
            return Err(invalid());
        }
    }
    Ok(())
}
