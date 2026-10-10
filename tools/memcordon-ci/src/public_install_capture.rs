//! Invocation-local synchronous custody of registry compiler executables.
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const WRAPPER_NAME: &str = "memcordon-public-install-capture";
pub const DESCRIPTOR_NAME: &str = "capture-descriptor.json";
const IMAGE_LIMIT: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub format: String,
    pub revision: u32,
    pub compiler: PathBuf,
    pub compiler_sha256: String,
    pub wrapper_sha256: String,
    pub target: String,
    pub registry_source: PathBuf,
    pub target_directory: PathBuf,
    pub capture_directory: PathBuf,
    pub package: String,
    pub version: String,
    pub binaries: Vec<String>,
    pub deadline_unix_millis: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format: String,
    pub revision: u32,
    pub descriptor_sha256: String,
    pub compiler: PathBuf,
    pub compiler_sha256: String,
    pub arguments: Vec<OsString>,
    pub working_directory: PathBuf,
    pub binary: String,
    pub target: String,
    pub source: PathBuf,
    pub manifest: PathBuf,
    pub original_output: PathBuf,
    pub cargo_output: PathBuf,
    pub retained_output: PathBuf,
    pub sha256: String,
    pub length: u64,
    pub status: i32,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

fn refuse(message: &str) -> CiError {
    CiError::Message(format!("public install compiler capture: {message}"))
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn pin(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    same_file(&file, path)?;
    Ok(file)
}

fn same_file(file: &std::fs::File, path: &Path) -> Result<()> {
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if !held.is_file()
        || !named.is_file()
        || held.len() != named.len()
        || held.modified()? != named.modified()?
    {
        return Err(refuse("pinned input differs from named file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
            return Err(refuse("pinned input inode differs"));
        }
    }
    #[cfg(windows)]
    {
        let mut options = std::fs::OpenOptions::new();
        use std::os::windows::fs::OpenOptionsExt;
        options.read(true).share_mode(1).custom_flags(0x00200000);
        if windows_identity(file)? != windows_identity(&options.open(path)?)? {
            return Err(refuse("pinned Windows input differs"));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_identity(file: &std::fs::File) -> Result<(u32, u64, u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live held file and initialized writable native output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & 0x410 != 0 || info.nNumberOfLinks == 0 {
        return Err(refuse("source input is reparse, directory or unlinked"));
    }
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        info.dwFileAttributes,
        info.nNumberOfLinks,
    ))
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    bounded_mode(path, limit, false)
}

fn private_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    bounded_mode(path, limit, true)
}

fn bounded_mode(path: &Path, limit: u64, exclusive: bool) -> Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file() || before.len() > limit {
        let encoded = path.as_os_str().as_encoded_bytes();
        let prefix = &encoded[..encoded.len().min(512)];
        return Err(refuse(&format!(
            "input is not bounded ordinary regular custody; path={:?}; path-truncated={}; regular={}; symlink={}; length={}; limit={limit}; exclusive={exclusive}",
            String::from_utf8_lossy(prefix),
            encoded.len() > prefix.len(),
            before.is_file(),
            before.file_type().is_symlink(),
            before.len(),
        )));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x00200000);
    }
    let mut file = options.open(path)?;
    #[cfg(windows)]
    let identity = windows_identity(&file)?;
    let held = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if exclusive && held.nlink() != 1 {
            return Err(refuse("retained authority has link aliases"));
        }
    }
    #[cfg(windows)]
    if exclusive && identity.3 != 1 {
        return Err(refuse("retained authority has link aliases"));
    }
    if !held.is_file() || held.len() != before.len() {
        return Err(refuse("opened input differs from named input"));
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    #[cfg(windows)]
    if windows_identity(&file)? != identity || windows_identity(&options.open(path)?)? != identity {
        return Err(refuse("Windows input identity changed during capture"));
    }
    if bytes.len() as u64 != held.len()
        || after.len() != held.len()
        || named.len() != held.len()
        || !named.is_file()
        || after.modified()? != held.modified()?
        || named.modified()? != held.modified()?
    {
        return Err(refuse("input changed during capture"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino()) != (held.dev(), held.ino())
            || (after.dev(), after.ino()) != (held.dev(), held.ino())
            || (named.dev(), named.ino()) != (held.dev(), held.ino())
        {
            return Err(refuse("input inode changed during capture"));
        }
        if held.nlink() != after.nlink() || held.nlink() != named.nlink() {
            return Err(refuse("source link count changed during capture"));
        }
    }
    Ok(bytes)
}

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn load_receipt(descriptor: &Descriptor, binary: &str) -> Result<Receipt> {
    let directory = &descriptor.capture_directory;
    if binary.is_empty()
        || !binary
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(refuse("invalid capture binary name"));
    }
    let bytes = private_bytes(&directory.join(format!("{binary}.json")), 1024 * 1024)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
        .map_err(CiError::Message)?;
    let receipt: Receipt = serde_json::from_slice(&bytes)?;
    if receipt.format != "memcordon.public-install-compiler-output"
        || receipt.revision != 1
        || receipt.binary != binary
        || receipt.status != 0
        || receipt.compiler != descriptor.compiler
        || receipt.compiler_sha256 != descriptor.compiler_sha256
        || receipt.target != descriptor.target
        || receipt.descriptor_sha256 != hash(&serde_json::to_vec(descriptor)?)
        || receipt.retained_output != directory.join(format!("{binary}.bin"))
    {
        return Err(refuse("capture receipt identity differs"));
    }
    let selected = selected_output_in(descriptor, &receipt.arguments, &receipt.working_directory)?
        .ok_or_else(|| refuse("receipt does not select a compiler binary"))?;
    if selected
        != (
            receipt.binary.clone(),
            receipt.source.clone(),
            receipt.original_output.clone(),
            receipt.cargo_output.clone(),
        )
    {
        return Err(refuse("receipt compiler output mapping differs"));
    }
    let image = private_bytes(&receipt.retained_output, IMAGE_LIMIT)?;
    if image.len() as u64 != receipt.length
        || hash(&image) != receipt.sha256
        || hash(&private_bytes(
            &directory.join(format!("{binary}.stdout.bin")),
            16 * 1024 * 1024,
        )?) != receipt.stdout_sha256
        || hash(&private_bytes(
            &directory.join(format!("{binary}.stderr.bin")),
            16 * 1024 * 1024,
        )?) != receipt.stderr_sha256
    {
        return Err(refuse("capture receipt bytes differ"));
    }
    Ok(receipt)
}

fn option(args: &[String], key: &str) -> Result<Option<String>> {
    let mut found = None;
    for (index, arg) in args.iter().enumerate() {
        let value = if arg == key {
            Some(
                args.get(index + 1)
                    .ok_or_else(|| refuse("option value absent"))?
                    .clone(),
            )
        } else {
            arg.strip_prefix(&format!("{key}=")).map(str::to_owned)
        };
        if value.and_then(|value| found.replace(value)).is_some() {
            return Err(refuse("duplicate compiler option"));
        }
    }
    Ok(found)
}

pub fn selected_output(
    descriptor: &Descriptor,
    arguments: &[OsString],
) -> Result<Option<(String, PathBuf, PathBuf, PathBuf)>> {
    selected_output_in(descriptor, arguments, &std::env::current_dir()?)
}

fn selected_output_in(
    descriptor: &Descriptor,
    arguments: &[OsString],
    cwd: &Path,
) -> Result<Option<(String, PathBuf, PathBuf, PathBuf)>> {
    let args = arguments
        .iter()
        .map(|arg| {
            arg.to_str()
                .map(str::to_owned)
                .ok_or_else(|| refuse("non-UTF8 compiler argument"))
        })
        .collect::<Result<Vec<_>>>()?;
    let argument_bytes = args.iter().try_fold(0usize, |total, arg| {
        total
            .checked_add(arg.len())
            .ok_or_else(|| refuse("compiler argument size overflow"))
    })?;
    if argument_bytes > 128 * 1024
        || args.len() > 4096
        || args.iter().any(|arg| arg.starts_with('@'))
    {
        return Err(refuse("compiler argument count or response file differs"));
    }
    let Some(crate_name) = option(&args, "--crate-name")? else {
        return Ok(None);
    };
    let matches = descriptor
        .binaries
        .iter()
        .filter(|name| name.replace('-', "_") == crate_name)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Ok(None);
    }
    if matches.len() != 1 {
        return Err(refuse("ambiguous selected crate name"));
    }
    if option(&args, "--crate-type")?.as_deref() != Some("bin") {
        return Ok(None);
    }
    if option(&args, "--target")?.as_deref() != Some(&descriptor.target) {
        return Err(refuse("selected compiler target differs"));
    }
    if option(&args, "-o")?.is_some() || args.iter().any(|arg| arg.starts_with("-o") && arg != "-o")
    {
        return Err(refuse("explicit compiler output is unsupported"));
    }
    let profile = descriptor
        .target_directory
        .join(&descriptor.target)
        .join("release");
    if option(&args, "--out-dir")?.map(PathBuf::from) != Some(profile.join("deps")) {
        return Err(refuse("selected output directory differs"));
    }
    let emit = option(&args, "--emit")?.ok_or_else(|| refuse("selected emit absent"))?;
    if !emit.split(',').any(|value| value == "link")
        || emit.split(',').any(|value| value.starts_with("link="))
    {
        return Err(refuse("selected link emission differs"));
    }
    let mut extra = None;
    for (index, arg) in args.iter().enumerate() {
        let codegen = if arg == "-C" {
            args.get(index + 1).map(String::as_str)
        } else {
            arg.strip_prefix("-C")
        };
        if codegen
            .and_then(|value| value.strip_prefix("extra-filename="))
            .and_then(|value| extra.replace(value.to_owned()))
            .is_some()
        {
            return Err(refuse("duplicate output suffix"));
        }
    }
    let extra = extra.ok_or_else(|| refuse("selected output suffix absent"))?;
    if extra.len() < 2
        || !extra.starts_with('-')
        || !extra[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
        || extra.len() > 65
    {
        return Err(refuse("selected output suffix differs"));
    }
    let sources = args
        .iter()
        .filter(|arg| arg.ends_with(".rs"))
        .collect::<Vec<_>>();
    if sources.len() != 1 {
        return Err(refuse("selected source is ambiguous"));
    }
    if !cwd.is_absolute() {
        return Err(refuse("compiler working directory is relative"));
    }
    let source = std::fs::canonicalize(cwd.join(sources[0]))?;
    if !source.starts_with(std::fs::canonicalize(&descriptor.registry_source)?) {
        return Err(refuse("selected source is outside isolated registry"));
    }
    let suffix = if descriptor.target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let original = profile
        .join("deps")
        .join(format!("{crate_name}{extra}{suffix}"));
    let cargo = profile.join(format!("{}{suffix}", matches[0]));
    Ok(Some((matches[0].clone(), source, original, cargo)))
}

pub fn run_if_wrapper() -> Result<Option<std::process::ExitStatus>> {
    let executable = std::env::current_exe()?;
    if executable.file_stem().and_then(|name| name.to_str()) != Some(WRAPPER_NAME) {
        return Ok(None);
    }
    let parent = executable
        .parent()
        .ok_or_else(|| refuse("wrapper parent absent"))?;
    let descriptor_path = parent.join(DESCRIPTOR_NAME);
    let descriptor_pin = pin(&descriptor_path)?;
    let wrapper_pin = pin(&executable)?;
    let descriptor_bytes = private_bytes(&parent.join(DESCRIPTOR_NAME), 64 * 1024)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&descriptor_bytes)
        .map_err(CiError::Message)?;
    let descriptor: Descriptor = serde_json::from_slice(&descriptor_bytes)?;
    if serde_json::to_vec(&descriptor)? != descriptor_bytes {
        return Err(refuse("descriptor encoding is not canonical"));
    }
    if descriptor.format != "memcordon.public-install-capture"
        || descriptor.revision != 1
        || descriptor.binaries.is_empty()
        || descriptor.binaries.len() > 16
        || descriptor.target.is_empty()
        || !descriptor
            .target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || descriptor.binaries.iter().any(|name| {
            name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        || [
            &descriptor.compiler,
            &descriptor.registry_source,
            &descriptor.target_directory,
            &descriptor.capture_directory,
        ]
        .iter()
        .any(|path| !path.is_absolute())
        || hash(&private_bytes(&executable, IMAGE_LIMIT)?) != descriptor.wrapper_sha256
    {
        return Err(refuse("wrapper descriptor or identity differs"));
    }
    let mut args = std::env::args_os().skip(1);
    let compiler = PathBuf::from(
        args.next()
            .ok_or_else(|| refuse("compiler argument absent"))?,
    );
    let compiler_pin = pin(&compiler)?;
    if compiler != descriptor.compiler
        || hash(&bounded(&compiler, IMAGE_LIMIT)?) != descriptor.compiler_sha256
    {
        return Err(refuse("actual compiler identity differs"));
    }
    let arguments = args.collect::<Vec<_>>();
    let selected = selected_output(&descriptor, &arguments)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| refuse("clock before epoch"))?
        .as_millis();
    let remaining = u128::from(descriptor.deadline_unix_millis)
        .checked_sub(now)
        .ok_or_else(|| refuse("original compile deadline passed"))?;
    let mut command = std::process::Command::new(&compiler);
    command
        .args(&arguments)
        .stdin(std::process::Stdio::inherit());
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        std::time::Duration::from_millis(
            u64::try_from(remaining).map_err(|_| refuse("deadline overflow"))?,
        ),
        16 * 1024 * 1024,
    )?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    let selected = if output.status.success() {
        selected
    } else {
        None
    };
    if let Some((binary, source, original_output, cargo_output)) = selected {
        same_file(&compiler_pin, &compiler)?;
        same_file(&wrapper_pin, &executable)?;
        same_file(&descriptor_pin, &descriptor_path)?;
        if private_bytes(&parent.join(DESCRIPTOR_NAME), 64 * 1024)? != descriptor_bytes
            || hash(&bounded(&compiler, IMAGE_LIMIT)?) != descriptor.compiler_sha256
            || hash(&private_bytes(&executable, IMAGE_LIMIT)?) != descriptor.wrapper_sha256
        {
            return Err(refuse(
                "compiler capture authority changed during invocation",
            ));
        }
        let notifications = output
            .stderr
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .filter(|value| value.get("emit").and_then(|value| value.as_str()) == Some("link"))
            .collect::<Vec<_>>();
        if notifications.len() != 1
            || notifications[0]
                .get("artifact")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
                != Some(original_output.clone())
        {
            return Err(refuse("actual compiler link notification differs"));
        }
        let manifest = std::fs::canonicalize(
            PathBuf::from(
                std::env::var_os("CARGO_MANIFEST_DIR")
                    .ok_or_else(|| refuse("manifest directory absent"))?,
            )
            .join("Cargo.toml"),
        )?;
        if std::env::var("CARGO_PKG_NAME").ok().as_deref() != Some(&descriptor.package)
            || std::env::var("CARGO_PKG_VERSION").ok().as_deref() != Some(&descriptor.version)
            || !source.starts_with(
                manifest
                    .parent()
                    .ok_or_else(|| refuse("manifest parent absent"))?,
            )
        {
            return Err(refuse("selected package manifest context differs"));
        }
        let bytes = bounded(&original_output, IMAGE_LIMIT)?;
        let retained_output = descriptor.capture_directory.join(format!("{binary}.bin"));
        publish(&retained_output, &bytes)?;
        let receipt = Receipt {
            format: "memcordon.public-install-compiler-output".into(),
            revision: 1,
            descriptor_sha256: hash(&descriptor_bytes),
            compiler,
            compiler_sha256: descriptor.compiler_sha256,
            arguments,
            working_directory: std::env::current_dir()?,
            binary: binary.clone(),
            target: descriptor.target,
            source,
            manifest,
            original_output,
            cargo_output,
            retained_output,
            sha256: hash(&bytes),
            length: bytes.len() as u64,
            status: 0,
            stdout_sha256: hash(&output.stdout),
            stderr_sha256: hash(&output.stderr),
        };
        publish(
            &descriptor
                .capture_directory
                .join(format!("{binary}.stdout.bin")),
            &output.stdout,
        )?;
        publish(
            &descriptor
                .capture_directory
                .join(format!("{binary}.stderr.bin")),
            &output.stderr,
        )?;
        let receipt_bytes = serde_json::to_vec(&receipt)?;
        if receipt_bytes.len() > 1024 * 1024 {
            return Err(refuse("compiler receipt exceeds bound"));
        }
        publish(
            &descriptor.capture_directory.join(format!("{binary}.json")),
            &receipt_bytes,
        )?;
    }
    Ok(Some(output.status))
}

/// Propagate the actual compiler termination after its bounded streams settle.
#[cfg_attr(unix, allow(unsafe_code))]
pub fn exit_wrapper(status: std::process::ExitStatus) -> ! {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            // SAFETY: restore and raise only this process's observed terminating
            // signal; no other process, token or authority is affected.
            unsafe {
                let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
                if libc::sigemptyset(set.as_mut_ptr()) != 0 {
                    std::process::exit(1);
                }
                let mut set = set.assume_init();
                if libc::sigaddset(&mut set, signal) != 0
                    || libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) != 0
                {
                    std::process::exit(1);
                }
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            std::process::exit(1);
        }
    }
    std::process::exit(status.code().unwrap_or(1))
}
