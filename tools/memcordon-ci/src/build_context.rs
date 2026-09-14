//! Closed compilation context. Cache manifests describe the very environment used
//! by Cargo; a restored controller is never used to authorize its own cache.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[path = "../../ci-build-environment.rs"]
pub mod environment;

use crate::{CiError, Result};

static ACTIVE: OnceLock<ValidatedBuildContext> = OnceLock::new();

/// A content snapshot of a declared input tree, including modes and links.
/// Output paths are excluded only by the full managed profile, not this API.
#[derive(Clone, Debug)]
pub struct BuildInputSnapshot {
    root: PathBuf,
    inputs: Vec<Input>,
}

impl BuildInputSnapshot {
    pub fn capture(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let mut inputs = Vec::new();
        measure(&root, None, &mut inputs, &mut BTreeSet::new())?;
        inputs.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(Self { root, inputs })
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(
            &self.inputs,
        )?)))
    }
    pub fn audit(&self) -> Result<()> {
        if Self::capture(&self.root)?.inputs != self.inputs {
            return Err(CiError::Message("declared build inputs changed".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Input {
    path: String,
    kind: String,
    mode: u32,
    digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatedBuildContext {
    schema_version: u32,
    root: PathBuf,
    environment: Vec<(String, String)>,
    toolchains: BTreeMap<String, PathBuf>,
    input_roots: Vec<PathBuf>,
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

fn file_digest(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
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

fn measure(
    path: &Path,
    source: Option<&Path>,
    inputs: &mut Vec<Input>,
    visited: &mut BTreeSet<PathBuf>,
) -> Result<()> {
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
                Some("target" | ".git" | "ci-native-fingerprint" | "ci-native-fingerprint.exe")
            )
        }) {
            return Ok(());
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    let (kind, digest) = if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)?;
        let resolved = path.canonicalize()?;
        if source.is_some_and(|root| !resolved.starts_with(root)) {
            return Err(CiError::Message(
                "source symlink escapes declared root".into(),
            ));
        }
        if source.is_none() && visited.insert(resolved.clone()) {
            measure(&resolved, None, inputs, visited)?;
        }
        ("symlink", native(target.as_os_str()))
    } else if metadata.is_dir() {
        let mut children: Vec<_> = fs::read_dir(path)?.collect::<io::Result<_>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            measure(&child.path(), source, inputs, visited)?;
        }
        ("directory", String::new())
    } else if metadata.is_file() {
        ("file", file_digest(path)?)
    } else {
        return Err(CiError::Message(format!(
            "unsupported build input: {}",
            path.display()
        )));
    };
    inputs.push(Input {
        path: native(path.as_os_str()),
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
    command.args(args).current_dir(cwd).env_clear().envs(env);
    let result = memcordon_testkit::run_with_deadline(&mut command, Duration::from_secs(30))?;
    if !result.status.success() {
        return Err(CiError::Message("build identity command failed".into()));
    }
    Ok(result.stdout)
}

impl ValidatedBuildContext {
    pub fn prepare(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let ambient: BTreeMap<_, _> = std::env::vars_os().collect();
        let mut env = environment::closed_environment(&ambient)?;
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
        let cargo_home = root.join("target/ci/source-home");
        environment::reject_cargo_configuration(&root, &cargo_home)?;
        fs::create_dir_all(&cargo_home)?;
        env.insert("CARGO_HOME".into(), cargo_home.into_os_string());
        let rustup = environment::resolve_tool(OsStr::new("rustup"), &env)?;
        let config = crate::config::toolchains(&root)?;
        let mut toolchains = BTreeMap::new();
        let mut input_roots = vec![rustup.clone()];
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
        let installed = output(
            &rustup,
            &[OsStr::new("toolchain"), OsStr::new("list")],
            &env,
            &root,
        )?;
        for toolchain in [&config.stable, &config.msrv, &config.miri] {
            if !String::from_utf8_lossy(&installed)
                .lines()
                .any(|line| line.starts_with(toolchain))
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
            input_roots.extend([
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin"),
            ]);
        }
        #[cfg(target_os = "linux")]
        input_roots.extend([
            PathBuf::from("/usr/include"),
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ]);
        #[cfg(windows)]
        {
            let mut sdk_found = false;
            let mut compiler_found = false;
            for name in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
                if let Some(base) = ambient.get(OsStr::new(name)) {
                    let base = PathBuf::from(base);
                    let sdk = base.join("Windows Kits");
                    if sdk.is_dir() {
                        sdk_found = true;
                        input_roots.push(sdk);
                    }
                    let compiler = base.join("Microsoft Visual Studio");
                    if compiler.is_dir() {
                        compiler_found = true;
                        input_roots.push(compiler);
                    }
                }
            }
            if !sdk_found || !compiler_found {
                return Err(CiError::Message(
                    "native Windows SDK/MSVC input roots unavailable".into(),
                ));
            }
            let windows = env
                .get(OsStr::new("SystemRoot"))
                .or_else(|| env.get(OsStr::new("SYSTEMROOT")))
                .ok_or_else(|| CiError::Message("Windows system root unavailable".into()))?;
            for name in ["kernel32.dll", "ntdll.dll", "ucrtbase.dll", "msvcp_win.dll"] {
                input_roots.push(PathBuf::from(windows).join("System32").join(name));
            }
        }
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
                input_roots.push(path.canonicalize()?);
            }
        }
        input_roots.sort();
        input_roots.dedup();
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
            schema_version: 2,
            root,
            environment: env
                .iter()
                .map(|(key, value)| (native(key), native(value)))
                .collect(),
            toolchains,
            input_roots,
            inputs: Vec::new(),
            worker,
        };
        context.inputs = context.measure_inputs()?;
        Ok(context)
    }

    fn measure_inputs(&self) -> Result<Vec<Input>> {
        let mut inputs = Vec::new();
        let mut visited = BTreeSet::new();
        measure(&self.root, Some(&self.root), &mut inputs, &mut visited)?;
        for root in &self.input_roots {
            measure(root, None, &mut inputs, &mut visited)?;
        }
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
        if context.schema_version != 2 || context.inputs.is_empty() || context.toolchains.is_empty()
        {
            return Err(CiError::Message("incomplete managed build context".into()));
        }
        Ok(context)
    }

    pub fn audit(&self) -> Result<()> {
        let env = self.environment()?;
        let cargo_home = env
            .get(OsStr::new("CARGO_HOME"))
            .ok_or_else(|| CiError::Message("missing managed Cargo home".into()))?;
        environment::reject_cargo_configuration(&self.root, Path::new(cargo_home))?;
        if self.measure_inputs()? != self.inputs {
            return Err(CiError::Message(
                "managed build inputs changed; cache publication and qualification rejected".into(),
            ));
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
        let approved_tool = self
            .root
            .join("target/ci-tools/bin")
            .join(if cfg!(windows) {
                "cargo-fuzz.exe"
            } else {
                "cargo-fuzz"
            });
        if executable != cargo && executable != approved_tool {
            return Err(CiError::Message("unenrolled toolchain executable".into()));
        }
        let mut command = Command::new(executable);
        let bin = cargo.parent().expect("validated Cargo directory");
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
            .current_dir(&self.root)
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
            rewritten.push(output.into_os_string());
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
        let environment = environment::closed_environment(
            &std::env::vars_os()
                .filter(|(key, _)| key != "RUSTUP_TOOLCHAIN" && key != "CARGO_HOME")
                .collect(),
        )?;
        let rustup = environment::resolve_tool(OsStr::new("rustup"), &environment)?;
        let mut command = Command::new(rustup);
        command
            .args(["run", toolchain, "cargo"])
            .args(&rewritten)
            .env_clear()
            .envs(environment);
        command
    };
    command
        .current_dir(&directory)
        .env("CARGO_HOME", temporary.path().join("cargo-home"))
        .env("CARGO_TARGET_DIR", temporary.path().join("target"))
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
