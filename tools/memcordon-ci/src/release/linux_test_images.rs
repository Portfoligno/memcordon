//! Native source copying and caller workload recipe data for the current profile.
#![cfg(target_os = "linux")]
pub(super) fn monotonic_millis() -> crate::Result<u64> {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds =
        u64::try_from(time.tv_sec).map_err(|error| crate::CiError::Message(error.to_string()))?;
    let nanos =
        u64::try_from(time.tv_nsec).map_err(|error| crate::CiError::Message(error.to_string()))?;
    seconds
        .checked_mul(1000)
        .and_then(|value| value.checked_add(nanos / 1_000_000))
        .ok_or_else(|| crate::CiError::Message("native monotonic clock overflow".into()))
}
use super::installed_consumer::MaterializedPayload;
use crate::{CiError, Result, command::CommandSpec};
use memcordon_core::{
    BoundedVec, DiagnosticSha256,
    identifiers::LogicalId,
    workload_bundle::SnapshotManifestV1,
    workload_files::{ImageEntryV1, ImageEntrypointV1, RootRelativePath},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

struct ImageBuilder {
    root: PathBuf,
    entries: BTreeMap<RootRelativePath, ImageEntryV1>,
    originals: BTreeMap<RootRelativePath, PathBuf>,
    toolchain_searches: Vec<(RootRelativePath, String, String)>,
    total_bytes: u64,
    deadline: std::time::Instant,
}
impl ImageBuilder {
    fn new(root: PathBuf, deadline: std::time::Instant) -> Result<Self> {
        if std::time::Instant::now() >= deadline {
            return Err(CiError::Message(
                "native image acquisition exhausted its original work cutoff".into(),
            ));
        }
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root,
            entries: BTreeMap::new(),
            originals: BTreeMap::new(),
            toolchain_searches: Vec::new(),
            total_bytes: 0,
            deadline,
        })
    }
    fn regular(&mut self, source: &Path, member: &Path) -> Result<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(CiError::Message(
                "native image copy exhausted its original work cutoff".into(),
            ));
        }
        let relative = path(member)?;
        if self.entries.contains_key(&relative) {
            return Ok(());
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source)?;
        let before = held.metadata()?;
        if !before.is_file() || before.len() > memcordon_core::workload_bundle::MEMBER_BYTES {
            return Err(CiError::Message(
                "toolchain input is not a bounded native regular file".into(),
            ));
        }
        let total = self
            .total_bytes
            .checked_add(before.len())
            .ok_or_else(|| CiError::Message("image byte inventory overflow".into()))?;
        if self.entries.len() >= 16384 || total > memcordon_core::workload_bundle::IMAGE_BYTES {
            return Err(CiError::Message(
                "native image inventory exceeds its finite bound before copying".into(),
            ));
        }
        let mut bytes = Vec::new();
        let mut reader = held.try_clone()?.take(before.len() + 1);
        let mut chunk = [0u8; 64 * 1024];
        loop {
            if std::time::Instant::now() >= self.deadline {
                return Err(CiError::Message(
                    "native image read exhausted its original work cutoff".into(),
                ));
            }
            let count = reader.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        let after = held.metadata()?;
        if (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        ) || bytes.len() as u64 != before.len()
        {
            return Err(CiError::Message(
                "native toolchain input changed while copied".into(),
            ));
        }
        let output = self.root.join(member);
        std::fs::create_dir_all(
            output
                .parent()
                .ok_or_else(|| CiError::Message("member parent absent".into()))?,
        )?;
        let executable = before.mode() & 0o111 != 0;
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        for chunk in bytes.chunks(64 * 1024) {
            if std::time::Instant::now() >= self.deadline {
                return Err(CiError::Message(
                    "native image write exhausted its original work cutoff".into(),
                ));
            }
            target.write_all(chunk)?;
        }
        target.set_permissions(std::fs::Permissions::from_mode(if executable {
            0o555
        } else {
            0o444
        }))?;
        target.sync_all()?;
        self.entries.insert(
            relative.clone(),
            ImageEntryV1::Regular {
                path: relative.clone(),
                sha256: DiagnosticSha256::from_bytes(Sha256::digest(&bytes).into()),
                size: bytes.len() as u64,
                executable,
            },
        );
        self.originals.insert(relative, source.to_path_buf());
        self.total_bytes = total;
        Ok(())
    }
    fn tree(&mut self, source: &Path, member: &Path, native_target: &str) -> Result<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(CiError::Message(
                "native image traversal exhausted its original work cutoff".into(),
            ));
        }
        let metadata = std::fs::symlink_metadata(source)?;
        if metadata.file_type().is_symlink() {
            // Fresh regular copies eliminate caller aliases. The imported image
            // never shares the original inode or follows a link during import.
            return self.regular(&std::fs::canonicalize(source)?, member);
        }
        if metadata.is_file() {
            return self.regular(source, member);
        }
        if !metadata.is_dir() {
            return Err(CiError::Message(
                "toolchain source includes a special object".into(),
            ));
        }
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let name = entry.file_name();
            if member == Path::new("toolchain/lib/rustlib") {
                let text = name.to_string_lossy();
                if text.contains("-unknown-") && text != native_target {
                    continue;
                }
            }
            if member == Path::new("toolchain/share") && name == "doc" {
                continue;
            }
            self.tree(&entry.path(), &member.join(name), native_target)?;
        }
        Ok(())
    }
    fn host_member(&mut self, source: &Path) -> Result<()> {
        let canonical = std::fs::canonicalize(source)?;
        self.regular(
            &canonical,
            source
                .strip_prefix("/")
                .map_err(|e| CiError::Message(e.to_string()))?,
        )
    }
    fn dependencies(&mut self, target: &str, libraries: &[PathBuf]) -> Result<()> {
        let mut checked = BTreeSet::new();
        loop {
            let pending = self
                .originals
                .iter()
                .find(|(member, _)| !checked.contains(*member))
                .map(|(member, source)| (member.clone(), source.clone()));
            let Some((member, _source)) = pending else {
                break;
            };
            checked.insert(member.clone());
            let held = File::open(self.root.join(member.as_str()))?;
            let length = held.metadata()?.len();
            let Some(elf) = memcordon_core::elf_closure::inspect(
                |offset, buffer| {
                    held.read_exact_at(buffer, offset)
                        .map_err(|e| e.to_string())
                },
                length,
                target,
            )
            .map_err(CiError::Message)?
            else {
                continue;
            };
            if member.as_str().starts_with("toolchain/") {
                for search in &elf.search_paths {
                    if search.contains("$ORIGIN") || search.contains("${ORIGIN}") {
                        let directory =
                            super::native_toolchain_search::directory(member.as_str(), search)
                                .map_err(CiError::Message)?;
                        if self.toolchain_searches.len() >= 16384 {
                            return Err(CiError::Message(
                                "toolchain search evidence exceeds image inventory bound".into(),
                            ));
                        }
                        self.toolchain_searches
                            .push((member.clone(), search.clone(), directory));
                    }
                }
            }
            if let Some(interpreter) = elf.interpreter {
                self.host_member(Path::new(&interpreter))?;
            }
            for needed in elf.needed {
                let selected = libraries
                    .iter()
                    .map(|directory| directory.join(&needed))
                    .find(|candidate| candidate.is_file())
                    .ok_or_else(|| {
                        CiError::Message(format!(
                            "native ELF dependency missing from measured compiler SDK: {needed}"
                        ))
                    })?;
                if !self.originals.values().any(|source| source == &selected) {
                    self.host_member(&selected)?;
                }
            }
        }
        Ok(())
    }
    fn definition(
        self,
        target: &str,
        entrypoints: Vec<ImageEntrypointV1>,
        libraries: &[PathBuf],
    ) -> Result<SnapshotManifestV1> {
        let mut library_directories = libraries
            .iter()
            .filter_map(|directory| directory.strip_prefix("/").ok())
            .map(path)
            .collect::<Result<Vec<_>>>()?;
        library_directories.retain(|directory| {
            self.entries
                .values()
                .any(|entry| memcordon_core::workload_files::is_beneath(entry.path(), directory))
        });
        let value = SnapshotManifestV1 {
            format: "memcordon.workload-snapshot".into(),
            revision: 1,
            target: target.into(),
            entries: bounded(self.entries.into_values())?,
            entrypoints: bounded(entrypoints)?,
            library_directories: bounded(library_directories)?,
        };
        value.validate().map_err(CiError::Message)?;
        Ok(value)
    }
}

/// Explicit recipe inputs are application requests, not acceptance predicates.
/// These are actual input image bytes consumed by the running tests.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedImages {
    pub runtime: SnapshotManifestV1,
    pub minimal_runtime: SnapshotManifestV1,
    pub minimal_runtime_source: PathBuf,
    pub input: SnapshotManifestV1,
    pub runtime_source: PathBuf,
    pub input_source: PathBuf,
}

fn id(value: &str) -> Result<LogicalId> {
    LogicalId::new(value.into()).map_err(CiError::Message)
}

fn path(value: &Path) -> Result<RootRelativePath> {
    RootRelativePath::new(
        value
            .to_str()
            .ok_or_else(|| CiError::Message("image path not UTF-8".into()))?
            .into(),
    )
    .map_err(CiError::Message)
}

fn bounded<T, const N: usize>(values: impl IntoIterator<Item = T>) -> Result<BoundedVec<T, N>> {
    let mut result = BoundedVec::default();
    for value in values {
        result.try_push(value).map_err(|_| {
            CiError::Message("owned image inventory exceeds frozen native bound".into())
        })?;
    }
    Ok(result)
}

pub fn materialize_until(
    payload: &MaterializedPayload,
    workspace: &Path,
    output: &Path,
    deadline: std::time::Instant,
) -> Result<PreparedImages> {
    if std::time::Instant::now() >= deadline {
        return Err(CiError::Message(
            "mixed materialization exhausted its original work cutoff".into(),
        ));
    }
    if !payload.distribution.target.ends_with("linux-gnu")
        || payload.distribution.target != super::distribution::native_target()?
        || rustix::process::geteuid().is_root()
    {
        return Err(CiError::Message(
            "Linux image preparation requires the matching unprivileged native host".into(),
        ));
    }
    std::fs::create_dir(output)?;
    std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700))?;
    let fixture = workspace.join("target/ci/native/release/memcordon-linux-readiness-fixture");
    let fixture_bytes = std::fs::read(&fixture).map_err(|error| {
        CiError::Message(format!(
            "required Linux readiness fixture {} could not be read: {error}",
            fixture.display()
        ))
    })?;
    super::target::validate_executable(&fixture_bytes, &payload.distribution.target)?;
    let rustc = CommandSpec::new("rustup", workspace, Duration::from_secs(30))
        .bounded_until(deadline)
        .arg("which")
        .arg("--toolchain")
        .arg("1.97.1")
        .arg("rustc")
        .run()?;
    let rustc = PathBuf::from(
        std::str::from_utf8(&rustc)
            .map_err(|e| CiError::Message(e.to_string()))?
            .trim(),
    );
    let sysroot = CommandSpec::new(&rustc, workspace, Duration::from_secs(30))
        .bounded_until(deadline)
        .arg("--print")
        .arg("sysroot")
        .run()?;
    let sysroot = PathBuf::from(
        std::str::from_utf8(&sysroot)
            .map_err(|e| CiError::Message(e.to_string()))?
            .trim(),
    );
    let machine = if payload.distribution.target.starts_with("x86_64-") {
        "x86_64-linux-gnu"
    } else {
        "aarch64-linux-gnu"
    };
    let mut libraries = vec![
        Path::new("/lib").join(machine),
        Path::new("/usr/lib").join(machine),
        PathBuf::from("/lib64"),
        PathBuf::from("/usr/lib64"),
        PathBuf::from("/lib"),
        PathBuf::from("/usr/lib"),
    ];
    let runtime_source = output.join("runtime-source");
    let input_source = output.join("input-source");
    let mut runtime = ImageBuilder::new(runtime_source.clone(), deadline)?;
    runtime.tree(
        &sysroot,
        Path::new("toolchain"),
        &payload.distribution.target,
    )?;
    runtime.regular(&fixture, Path::new("bin/owned-readiness"))?;
    for executable in ["/usr/bin/cc", "/usr/bin/as", "/usr/bin/ld"] {
        runtime.host_member(Path::new(executable))?;
    }
    let gcc = Path::new("/usr/lib/gcc").join(machine);
    if gcc.is_dir() {
        runtime.tree(
            &gcc,
            gcc.strip_prefix("/")
                .map_err(|e| CiError::Message(e.to_string()))?,
            &payload.distribution.target,
        )?;
    }
    if gcc.is_dir() {
        for version in std::fs::read_dir(&gcc)? {
            let directory = version?.path();
            if directory.is_dir() {
                libraries.push(directory);
            }
        }
    }
    let search = CommandSpec::new("/usr/bin/cc", workspace, Duration::from_secs(30))
        .bounded_until(deadline)
        .arg("-print-search-dirs")
        .run()?;
    let search = std::str::from_utf8(&search).map_err(|e| CiError::Message(e.to_string()))?;
    for directory in search
        .lines()
        .find_map(|line| line.strip_prefix("libraries: ="))
        .ok_or_else(|| CiError::Message("native compiler SDK library catalogue absent".into()))?
        .split(':')
    {
        let source = Path::new(directory);
        if source.is_absolute() && source.is_dir() {
            let canonical = std::fs::canonicalize(source)?;
            if !libraries.contains(&canonical) {
                libraries.push(canonical);
            }
        }
    }
    for support in [
        "crt1.o",
        "Scrt1.o",
        "crti.o",
        "crtn.o",
        "crtbegin.o",
        "crtbeginS.o",
        "crtend.o",
        "crtendS.o",
        "libgcc.a",
        "libgcc_s.so",
        "libgcc_s.so.1",
        "libc.so",
        "libc.so.6",
        "libc_nonshared.a",
        "libpthread.a",
        "librt.a",
        "libdl.a",
        "libutil.a",
        "libm.so",
        "libm.so.6",
        "libmvec.so",
        "libmvec.so.1",
    ] {
        for directory in &libraries {
            let discovered = directory.join(support);
            if discovered.is_file() {
                runtime.host_member(&discovered)?;
            }
        }
    }
    let mut source_libraries = vec![
        sysroot.join("lib"),
        sysroot
            .join("lib/rustlib")
            .join(&payload.distribution.target)
            .join("lib"),
    ];
    source_libraries.extend(libraries.iter().cloned());
    runtime.dependencies(&payload.distribution.target, &source_libraries)?;
    let minimal_runtime_source = output.join("minimal-runtime-source");
    let mut minimal = ImageBuilder::new(minimal_runtime_source.clone(), deadline)?;
    minimal.regular(&fixture, Path::new("bin/owned-readiness"))?;
    minimal.dependencies(&payload.distribution.target, &source_libraries)?;
    let minimal_libraries = minimal
        .entries
        .keys()
        .filter(|member| member.as_str() != "bin/owned-readiness")
        .filter_map(|member| Path::new(member.as_str()).parent())
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| Path::new("/").join(parent))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let minimal_runtime = minimal.definition(
        &payload.distribution.target,
        vec![ImageEntrypointV1 {
            id: id("owned-readiness")?,
            path: path(Path::new("bin/owned-readiness"))?,
        }],
        &minimal_libraries,
    )?;
    let mut input = ImageBuilder::new(input_source.clone(), deadline)?;
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "src/main.rs",
        "tests/generated_child.rs",
    ] {
        input.regular(
            &workspace
                .join("tests/fixtures/linux_readiness")
                .join(relative),
            &Path::new("owned-source").join(relative),
        )?;
    }
    libraries.insert(0, PathBuf::from("/toolchain/lib"));
    libraries.insert(
        1,
        Path::new("/toolchain/lib/rustlib")
            .join(&payload.distribution.target)
            .join("lib"),
    );
    let mut declared = libraries
        .iter()
        .map(|directory| {
            directory
                .to_string_lossy()
                .trim_start_matches('/')
                .to_owned()
        })
        .collect::<Vec<_>>();
    for (_, _, directory) in &runtime.toolchain_searches {
        let copied = runtime.root.join(directory);
        let present = match std::fs::symlink_metadata(&copied) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            _ => {
                return Err(CiError::Message(
                    "toolchain search aliases copied file authority".into(),
                ));
            }
        };
        let prefix = format!("{directory}/");
        let contents = runtime
            .entries
            .values()
            .filter(|entry| entry.path().as_str().starts_with(&prefix))
            .collect::<Vec<_>>();
        if !present && !contents.is_empty() {
            return Err(CiError::Message(
                "absent toolchain search has copied members".into(),
            ));
        }
        super::native_toolchain_search::declare(&mut declared, directory.clone())
            .map_err(CiError::Message)?;
    }
    libraries = declared
        .into_iter()
        .map(|directory| Path::new("/").join(directory))
        .collect();
    let runtime = runtime.definition(
        &payload.distribution.target,
        vec![ImageEntrypointV1 {
            id: id("owned-readiness")?,
            path: path(Path::new("bin/owned-readiness"))?,
        }],
        &libraries,
    )?;
    let input = input.definition(&payload.distribution.target, Vec::new(), &[])?;
    Ok(PreparedImages {
        runtime,
        minimal_runtime,
        minimal_runtime_source,
        input,
        runtime_source,
        input_source,
    })
}
