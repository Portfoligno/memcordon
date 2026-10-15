//! Restore sanitation for finite, CI-owned Cargo compilation roots.
use crate::{CiError, Result, command::rustup_cargo};
use clap::ValueEnum;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RestoreMode {
    Exact,
    Compatible,
    Discard,
}

pub fn roots(purpose: &str, shard: &str) -> Result<Vec<PathBuf>> {
    let paths: &[&str] = match (purpose, shard) {
        ("quality", "complete") => &["target/ci/quality", "target/ci/quality-doc"],
        ("msrv", "complete") => &["target/ci/msrv"],
        ("native-debug", "complete") => &["target/ci/native"],
        ("native-auxiliary", "complete") => &["target/debug", "target/release"],
        ("private", "complete") => &[
            "target/ci-build/product",
            "target/ci/native",
            "target/ci-build/private-native-tests",
        ],
        ("native-release" | "native-readiness" | "windows-working", "complete") => {
            &["target/ci/native", "target/ci-build/product"]
        }
        ("miri", "first") => &["target/ci/miri-first"],
        ("miri", "second") => &["target/ci/miri-second"],
        ("miri", "complete") => &["target/ci/miri-first", "target/ci/miri-second"],
        ("fuzz", "complete") => &["fuzz/target"],
        (
            "fuzz",
            "quarter-one" | "quarter-two" | "quarter-three" | "quarter-four" | "first" | "second",
        ) => &["fuzz/target"],
        ("rehearsal-tool", "complete") => &["target/ci/rehearsal-build"],
        ("stress", "complete") => &["target/ci/stress"],
        ("stress-packages", "complete") => &["target/ci/stress-packages"],
        ("stress-lifecycle", "complete") => &["target/ci/stress-lifecycle"],
        ("macos", "combined" | "native") => &[
            "target/ci/backend-macos",
            "target/ci/deadline-build",
            "target/ci/deadline-oracle-build",
        ],
        ("macos", "acceptance") => &["target/ci/backend-macos"],
        ("backend", "complete") => &["target/ci/standard-backend"],
        ("deadline", "complete") => &[
            "target/ci/deadline-build",
            "target/ci/deadline-oracle-build",
        ],
        _ => {
            return Err(CiError::Message(
                "cache purpose has no owned compiled roots".into(),
            ));
        }
    };
    Ok(paths.iter().map(PathBuf::from).collect())
}

fn safe_root(repository: &Path, relative: &Path) -> Result<PathBuf> {
    let repository = repository.canonicalize()?;
    let mut path = repository.clone();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(CiError::Message("cache root is not relative".into()));
        };
        path.push(component);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(CiError::Message(
                    "cache root traverses unsafe file kind".into(),
                ));
            }
            Ok(_) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if std::fs::symlink_metadata(&path)?.file_attributes() & 0x400 != 0 {
                        return Err(CiError::Message(
                            "cache root traverses reparse point".into(),
                        ));
                    }
                }
                if !path.canonicalize()?.starts_with(&repository) {
                    return Err(CiError::Message("cache root escapes checkout".into()));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    if std::env::current_exe()?.canonicalize()?.starts_with(&path) {
        return Err(CiError::Message(
            "cache root contains running CI driver".into(),
        ));
    }
    if path.try_exists()? {
        for (index, entry) in walkdir::WalkDir::new(&path)
            .follow_links(false)
            .into_iter()
            .enumerate()
        {
            if index >= 500_000 {
                return Err(CiError::Message(
                    "cache tree exceeds sanitation bounds".into(),
                ));
            }
            let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
                return Err(CiError::Message(
                    "unsafe file kind in restored cache".into(),
                ));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(CiError::Message("reparse point in restored cache".into()));
                }
            }
        }
    }
    Ok(path)
}

fn settled_locks(targets: &[PathBuf]) -> Result<Vec<std::fs::File>> {
    let mut locks = Vec::new();
    for target in targets {
        if !target.try_exists()? {
            continue;
        }
        for entry in walkdir::WalkDir::new(target).follow_links(false) {
            let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
            if entry.file_name() != ".cargo-lock" {
                continue;
            }
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.share_mode(0);
            }
            let file = options.open(entry.path())?;
            #[cfg(unix)]
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| {
                    CiError::Message("restored cache has an active Cargo writer".into())
                })?;
            locks.push(file);
        }
    }
    Ok(locks)
}

fn cargo_marker_present(target: &Path) -> Result<bool> {
    use std::io::Read;
    const SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";
    let marker = target.join("CACHEDIR.TAG");
    let metadata = match std::fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CiError::Message("unsafe Cargo marker file kind".into()));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(CiError::Message("Cargo marker is a reparse point".into()));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(&marker) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(CiError::Message("Cargo marker is a reparse point".into()));
        }
    }
    if !metadata.is_file() {
        return Err(CiError::Message(
            "unsafe opened Cargo marker file kind".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(SIGNATURE.len());
    file.take(SIGNATURE.len() as u64).read_to_end(&mut bytes)?;
    Ok(bytes == SIGNATURE)
}

pub fn prepare(root: &Path, purpose: &str, shard: &str, mode: RestoreMode) -> Result<()> {
    let roots = roots(purpose, shard)?;
    // Validate every root before making the first mutation.
    let targets: Vec<_> = roots
        .iter()
        .map(|path| safe_root(root, path))
        .collect::<Result<_>>()?;
    if matches!(mode, RestoreMode::Discard) {
        let locks = settled_locks(&targets)?;
        // Windows denies removal of an open lock file. Observe all locks before
        // dropping the handles; workflow ordering forbids any owner starting
        // until this sanitation command has returned successfully.
        #[cfg(windows)]
        drop(locks);
        for target in targets {
            if target.try_exists()? {
                std::fs::remove_dir_all(target)?;
            }
        }
        #[cfg(not(windows))]
        drop(locks);
        return Ok(());
    }
    let cleanup_targets = if purpose == "native-auxiliary" {
        // These payloads contain profiles only; Cargo's genuine marker belongs
        // to their common parent, which is never a disposal root.
        vec![root.join("target")]
    } else {
        targets
    };
    for target in &cleanup_targets {
        if target.try_exists()? && !cargo_marker_present(target)? {
            // An optional seed without Cargo's marker cannot authorize cleanup.
            // Discard only this role's prevalidated payloads before cold work.
            return prepare(root, purpose, shard, RestoreMode::Discard);
        }
    }
    let pins = crate::config::toolchains(root)?;
    let toolchain = if purpose == "msrv" {
        &pins.msrv
    } else if purpose == "miri" || purpose == "fuzz" {
        &pins.miri
    } else {
        &pins.stable
    };
    let mut packages = Vec::new();
    // Clean all current local packages even on an exact match. This covers the
    // CLI's reverse local dependents and path relocation without guessing Cargo
    // fingerprint names. External registry/Git compilation remains reusable.
    let manifest: toml::Value = toml::from_str(&std::fs::read_to_string(root.join("Cargo.toml"))?)?;
    let members = manifest["workspace"]["members"]
        .as_array()
        .ok_or_else(|| CiError::Message("workspace package inventory absent".into()))?;
    for member in members {
        let member = member
            .as_str()
            .ok_or_else(|| CiError::Message("invalid workspace member".into()))?;
        let manifest: toml::Value = toml::from_str(&std::fs::read_to_string(
            root.join(member).join("Cargo.toml"),
        )?)?;
        let name = manifest["package"]["name"]
            .as_str()
            .ok_or_else(|| CiError::Message("local package identity absent".into()))?;
        packages.push(name.to_owned());
    }
    let deadline = Instant::now() + Duration::from_secs(5 * 60);
    for target in cleanup_targets {
        if !target.try_exists()? {
            continue;
        }
        let mut command = rustup_cargo(root, toolchain, ["clean"], Duration::from_secs(120))
            .arg("--target-dir")
            .arg(&target)
            .bounded_until(deadline);
        for package in &packages {
            command = command.arg("--package").arg(package);
        }
        command.run()?;
        command.clone().arg("--release").run()?;
        if purpose == "fuzz" {
            let command = rustup_cargo(
                &root.join("fuzz"),
                toolchain,
                ["clean", "--package", "memcordon-fuzz"],
                Duration::from_secs(120),
            )
            .arg("--target-dir")
            .arg(&target)
            .bounded_until(deadline);
            command.run()?;
            command.clone().arg("--release").run()?;
            let explicit = command
                .arg("--target")
                .arg(crate::release::distribution::native_target()?);
            explicit.run()?;
            explicit.arg("--release").run()?;
        }
        // Native producers also use an explicit target triple. Cargo's default
        // clean does not stand in for cleaning that target's package outputs.
        if matches!(
            purpose,
            "native-release" | "native-readiness" | "windows-working" | "private" | "fuzz"
        ) {
            let mut command = rustup_cargo(root, toolchain, ["clean"], Duration::from_secs(120))
                .arg("--target-dir")
                .arg(&target)
                .arg("--target")
                .arg(crate::release::distribution::native_target()?)
                .bounded_until(deadline);
            for package in &packages {
                command = command.arg("--package").arg(package);
            }
            command.run()?;
            command.arg("--release").run()?;
        }
    }
    Ok(())
}
