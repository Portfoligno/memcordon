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
use crate::{CiError, Result, command::CommandSpec, readiness_identity::SourceIdentity};
use memcordon_core::{
    BoundedVec, DiagnosticSha256,
    identifiers::LogicalId,
    workload_bundle::SnapshotManifestV1,
    workload_files::{ImageEntryV1, ImageEntrypointV1, RootRelativePath},
};
use memcordon_readiness_verifier::ProductKey;
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
/// Their keys remain in the outer finite manifest even if execution fails.
#[derive(Clone)]
pub struct CurrentRecipe {
    pub key: memcordon_readiness_verifier::CaseKey,
    pub mode: String,
    pub arguments: Vec<std::ffi::OsString>,
    pub requirements: Vec<memcordon_core::workload_requirements::RequirementRequestV1>,
    pub output_files: Vec<RootRelativePath>,
    pub memory: std::ffi::OsString,
    pub product_deadline: std::ffi::OsString,
    pub observation_limit: Duration,
}

/// Source-controlled recipes for the already implemented native fixture
/// modes. Unlisted manifest rows remain missing until their distinct driver is
/// implemented; this list never narrows the independent required inventory.
pub fn owned_fixture_recipes(cell: &ProductKey) -> Result<Vec<CurrentRecipe>> {
    use memcordon_core::workload_requirements::{
        DeniedOperationRequestV1 as D, LocalPortRequestV1, PrivatePeerRequestV1,
        RequirementRequestV1 as R,
    };
    use memcordon_readiness_verifier::{CaseKey, EvidenceClass};
    let tcp = R::TcpListener {
        id: id("tcp")?,
        local_port: LocalPortRequestV1::KernelAssigned,
        peer: PrivatePeerRequestV1::DynamicLoopbackWithinThisAttempt,
    };
    let unix = vec![
        R::UnixStreamPair { id: id("pair")? },
        R::UnixPathStream {
            id: id("pathname")?,
            writable_root: id("work")?,
        },
        R::UnixAbstractStream {
            id: id("abstract")?,
        },
        R::IntraAttemptDescriptorTransfer { id: id("rights")? },
    ];
    let child_error_pair = R::UnixSeqpacketPair {
        id: id("child-error-pair")?,
    };
    let mut result = Vec::new();
    let mut add = |family: &str,
                   scenario: &str,
                   mode: &str,
                   args: Vec<std::ffi::OsString>,
                   mut requirements: Vec<R>,
                   outputs: Vec<RootRelativePath>,
                   deadline: &str| {
        if requirements
            .iter()
            .any(|requirement| matches!(requirement, R::GeneratedExecutable { .. }))
        {
            requirements.push(child_error_pair.clone());
        }
        result.push(CurrentRecipe {
            key: CaseKey {
                target: cell.target.clone(),
                channel: Some(cell.channel.clone()),
                evidence_class: EvidenceClass::InstalledProduct,
                family: family.into(),
                scenario: scenario.into(),
            },
            mode: mode.into(),
            arguments: args,
            requirements,
            output_files: outputs,
            memory: "+2GiB".into(),
            product_deadline: format!("+{deadline}").into(),
            observation_limit: Duration::from_secs(600),
        });
    };
    let mut joint = vec![tcp.clone()];
    joint.extend(unix.clone());
    joint.push(R::GeneratedExecutable {
        id: id("generated")?,
        writable_root: id("work")?,
    });
    let build_args = vec![
        "/work",
        "/toolchain/bin/cargo",
        "/toolchain/bin/rustc",
        "/usr/bin/cc",
        "/owned-source/Cargo.toml",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<Vec<_>>();
    let exports = [
        "generated-readiness-artifact.bin",
        "generated-child-executable.bin",
        "generated-child-created.json",
        "generated-child-retired.json",
    ]
    .iter()
    .map(|name| path(&Path::new("work").join(name)))
    .collect::<Result<Vec<_>>>()?;
    add(
        "L-MIX-01",
        "joint-build-tcp-unix-http",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports.clone(),
        "300s",
    );
    add(
        "L-IMG-03",
        "dynamic-rust-build-and-exec",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports.clone(),
        "300s",
    );
    add(
        "L-IMG-03",
        "image-only-entrypoint",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports,
        "300s",
    );
    for scenario in ["deadline", "memory", "cancellation", "reserved-target-exit"] {
        add(
            "L-LIFE-03",
            scenario,
            match scenario {
                "memory" => "joint-memory",
                "reserved-target-exit" => "joint-reserved-exit",
                _ => "joint",
            },
            build_args.clone(),
            joint.clone(),
            Vec::new(),
            "300s",
        );
    }
    add(
        "C-STATUS",
        "memory",
        "population-deadline",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "300s",
    );
    add(
        "L-MIX-02",
        "endpoint-mismatch",
        "endpoint-mismatch",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    add(
        "L-MIX-03",
        "listener-and-file-transfer",
        "unix-rights",
        vec!["/work".into()],
        unix.clone(),
        Vec::new(),
        "30s",
    );
    add(
        "L-MIX-04",
        "cooperation",
        "cooperation",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    add(
        "C-IO",
        "binary-streams",
        "raw-byte-streams",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "30s",
    );
    add(
        "L-MIX-05",
        "binary-streams",
        "raw-byte-streams",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "30s",
    );
    for family in ["C-IO", "L-MIX-05"] {
        add(
            family,
            "empty-message",
            "empty-message",
            Vec::new(),
            vec![R::UnixStreamPair {
                id: id("empty-pair")?,
            }],
            Vec::new(),
            "30s",
        );
    }
    add(
        "C-IO",
        "binary-file",
        "binary-file",
        Vec::new(),
        Vec::new(),
        vec![path(Path::new("work/binary-file.bin"))?],
        "30s",
    );
    for family in ["C-IO", "L-MIX-05"] {
        add(
            family,
            "empty-input",
            "empty-input",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "30s",
        );
        add(
            family,
            "bounded-large-output",
            "bounded-large-output",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "30s",
        );
    }
    for (scenario, mode, operation) in [
        ("ipv6", "authority-denial", D::Inet6),
        ("udp", "authority-denial", D::Udp),
        ("raw", "authority-denial", D::Raw),
        ("packet", "authority-denial", D::Packet),
        ("netlink", "authority-denial", D::Netlink),
    ] {
        add(
            "L-ISO-01",
            scenario,
            mode,
            vec![scenario.into()],
            vec![
                tcp.clone(),
                R::ExpectedDenial {
                    id: id("denial")?,
                    operation,
                },
            ],
            Vec::new(),
            "30s",
        );
    }
    add(
        "L-ISO-01",
        "host-tcp",
        "forbidden-tcp",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("host-tcp-denial")?,
                operation: D::HostTcp,
            },
        ],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-01",
        "nonloopback",
        "forbidden-tcp",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("nonloopback-denial")?,
                operation: D::HostTcp,
            },
        ],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-03",
        "host-abstract",
        "forbidden-abstract",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("host-abstract-denial")?,
                operation: D::HostUnixAbstract,
            },
        ],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-03",
        "other-attempt-abstract",
        "forbidden-abstract",
        Vec::new(),
        vec![
            R::UnixAbstractStream {
                id: id("own-abstract")?,
            },
            R::ExpectedDenial {
                id: id("other-attempt-denial")?,
                operation: D::OtherAttempt,
            },
        ],
        Vec::new(),
        "30s",
    );
    for scenario in ["host-run-socket", "host-temp-socket"] {
        add(
            "L-ISO-02",
            scenario,
            "forbidden-unix-path",
            Vec::new(),
            vec![
                R::UnixStreamPair { id: id("pair")? },
                R::ExpectedDenial {
                    id: id("host-path-denial")?,
                    operation: D::HostUnixPath,
                },
            ],
            Vec::new(),
            "30s",
        );
    }
    for scenario in ["input-socket", "imported-socket", "caller-writable-tree"] {
        add(
            "L-ISO-02",
            scenario,
            "forbidden-unix-path",
            Vec::new(),
            vec![R::UnixStreamPair { id: id("pair")? }],
            Vec::new(),
            "30s",
        );
    }
    add(
        "L-ISO-03",
        "own-abstract-positive",
        "own-abstract",
        Vec::new(),
        vec![R::UnixAbstractStream {
            id: id("own-abstract")?,
        }],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-06",
        "same-uid-process",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-06",
        "account-alias",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-06",
        "stale-reservation",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    for (scenario, operation) in [
        ("pidfd-getfd", D::ProcessImport),
        ("ptrace", D::ProcessImport),
        ("namespace-entry", D::NamespaceEntry),
    ] {
        add(
            "L-ISO-05",
            scenario,
            "authority-denial",
            vec![scenario.into()],
            vec![
                tcp.clone(),
                R::ExpectedDenial {
                    id: id("denial")?,
                    operation,
                },
            ],
            Vec::new(),
            "30s",
        );
    }
    for scenario in ["stdio-host-socket", "extra-host-fd"] {
        add(
            "L-ISO-05",
            scenario,
            "descriptor-isolation",
            Vec::new(),
            vec![R::UnixStreamPair { id: id("pair")? }],
            Vec::new(),
            "30s",
        );
    }
    for (scenario, status) in [
        ("zero", 0),
        ("nonzero", 42),
        ("exit-123", 123),
        ("exit-124", 124),
        ("exit-125", 125),
        ("exit-126", 126),
        ("exit-127", 127),
    ] {
        add(
            "C-STATUS",
            scenario,
            "bytes-argv-status",
            vec![status.to_string().into()],
            Vec::new(),
            Vec::new(),
            "30s",
        );
    }
    add(
        "C-PARSER",
        "valid-current-result",
        "bytes-argv-status",
        vec!["0".into()],
        Vec::new(),
        Vec::new(),
        "30s",
    );
    let orphan_output = vec![
        path(Path::new("work/orphan-descendant.bin"))?,
        path(Path::new("work/orphan-completion.json"))?,
    ];
    for actor in ["frontend", "worker", "guardian", "control"] {
        for phase in ["allocation", "release", "drain"] {
            add(
                "L-LIFE-02",
                &format!("{actor}-{phase}"),
                if phase == "drain" {
                    "root-first"
                } else {
                    "held-tree"
                },
                Vec::new(),
                Vec::new(),
                if phase == "drain" {
                    orphan_output.clone()
                } else {
                    Vec::new()
                },
                "300s",
            );
        }
    }
    add(
        "L-LIFE-01",
        "root-first-resource-descendant",
        "root-first",
        Vec::new(),
        Vec::new(),
        orphan_output.clone(),
        "30s",
    );
    add(
        "L-LIFE-05",
        "relay-backpressure",
        "relay-backpressure",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "30s",
    );
    for scenario in [
        "symlink",
        "dotdot",
        "proc-root",
        "proc-cwd",
        "proc-fd",
        "hardlink",
        "opath",
        "mount-alias",
    ] {
        add(
            "L-ISO-04",
            scenario,
            "outside-file",
            vec![scenario.into()],
            Vec::new(),
            Vec::new(),
            "30s",
        );
    }
    add(
        "L-LIFE-05",
        "report-persistence-failure",
        "bytes-argv-status",
        vec!["0".into()],
        Vec::new(),
        Vec::new(),
        "300s",
    );
    add(
        "C-LIFETIME",
        "root-first",
        "root-first",
        Vec::new(),
        Vec::new(),
        orphan_output,
        "30s",
    );
    add(
        "C-STATUS",
        "deadline",
        "population-deadline",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "2s",
    );
    add(
        "C-ADMISSION",
        "positive",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    use std::os::unix::ffi::OsStringExt;
    add(
        "C-IO",
        "native-argv",
        "bytes-argv-status",
        vec![
            "0".into(),
            std::ffi::OsString::from_vec(vec![0x61, 0xff, 0x62]),
        ],
        Vec::new(),
        Vec::new(),
        "30s",
    );
    Ok(result)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSourceImages {
    pub runtime: SnapshotManifestV1,
    pub minimal_runtime: SnapshotManifestV1,
    pub minimal_runtime_source: PathBuf,
    pub input: SnapshotManifestV1,
    pub runtime_definition: PathBuf,
    pub input_definition: PathBuf,
    pub runtime_source: PathBuf,
    pub input_source: PathBuf,
    pub fixture_sha256: String,
    pub native_linker: PathBuf,
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

pub(super) fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| CiError::Message(format!("create retained evidence {path:?}: {error}")))?;
    file.write_all(bytes)
        .map_err(|error| CiError::Message(format!("write retained evidence {path:?}: {error}")))?;
    file.sync_all()
        .map_err(|error| CiError::Message(format!("sync retained evidence {path:?}: {error}")))?;
    Ok(())
}

pub fn materialize_until(
    payload: &MaterializedPayload,
    workspace: &Path,
    output: &Path,
    identity: &SourceIdentity,
    cell: &ProductKey,
    deadline: std::time::Instant,
) -> Result<CurrentSourceImages> {
    if std::time::Instant::now() >= deadline {
        return Err(CiError::Message(
            "mixed materialization exhausted its original work cutoff".into(),
        ));
    }
    if !cell.target.ends_with("linux-gnu")
        || payload.distribution.target != cell.target
        || identity.run_id.is_empty()
        || payload.source.commit() != identity.source_commit
        || payload.source.version().to_string() != identity.version
    {
        return Err(CiError::Message(
            "mixed materialization product/source cell differs".into(),
        ));
    }
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(CiError::Message(
            "owned native mixed materialization requires the outer installed owner's root helper"
                .into(),
        ));
    }
    std::fs::create_dir(output)?;
    std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700))?;
    let build = output.join("fixture-build");
    CommandSpec::cargo("rustup", workspace, "1.97.1", Duration::from_secs(600))
        .bounded_until(deadline)
        .arg("build")
        .arg("--locked")
        .arg("--package")
        .arg("memcordon")
        .arg("--features")
        .arg("test-fixtures")
        .arg("--bin")
        .arg("memcordon-linux-readiness-fixture")
        .arg("--target")
        .arg(&cell.target)
        .arg("--target-dir")
        .arg(&build)
        .run()?;
    let fixture = build
        .join(&cell.target)
        .join("debug/memcordon-linux-readiness-fixture");
    let fixture_bytes = std::fs::read(&fixture)?;
    super::target::validate_executable(&fixture_bytes, &cell.target)?;
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
    let machine = if cell.target.starts_with("x86_64-") {
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
    runtime.tree(&sysroot, Path::new("toolchain"), &cell.target)?;
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
            &cell.target,
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
        sysroot.join("lib/rustlib").join(&cell.target).join("lib"),
    ];
    source_libraries.extend(libraries.iter().cloned());
    runtime.dependencies(&cell.target, &source_libraries)?;
    let minimal_runtime_source = output.join("minimal-runtime-source");
    let mut minimal = ImageBuilder::new(minimal_runtime_source.clone(), deadline)?;
    minimal.regular(&fixture, Path::new("bin/owned-readiness"))?;
    minimal.dependencies(&cell.target, &source_libraries)?;
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
        &cell.target,
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
            .join(&cell.target)
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
    let mut search_evidence = Vec::new();
    for (member, search, directory) in &runtime.toolchain_searches {
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
        let entry = runtime
            .entries
            .get(member)
            .expect("inspected copied ELF member");
        search_evidence.push(serde_json::json!({"member":entry,"search":search,"directory":directory,"copied_directory_present":present,"member_count":contents.len(),"members_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&contents)?))}));
        super::native_toolchain_search::declare(&mut declared, directory.clone())
            .map_err(CiError::Message)?;
    }
    retain(
        &output.join("toolchain-loader-search.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.original-toolchain-loader-search","revision":1,"target":cell.target,"observations":search_evidence}),
        )?,
    )?;
    libraries = declared
        .into_iter()
        .map(|directory| PathBuf::from(format!("/{directory}")))
        .collect();
    let runtime = runtime.definition(
        &cell.target,
        vec![ImageEntrypointV1 {
            id: id("owned-readiness")?,
            path: path(Path::new("bin/owned-readiness"))?,
        }],
        &libraries,
    )?;
    let input = input.definition(&cell.target, Vec::new(), &[])?;
    let runtime_definition = output.join("runtime-image.json");
    let input_definition = output.join("input-image.json");
    retain(&runtime_definition, &serde_json::to_vec(&runtime)?)?;
    retain(&input_definition, &serde_json::to_vec(&input)?)?;
    Ok(CurrentSourceImages {
        runtime,
        minimal_runtime,
        minimal_runtime_source,
        input,
        runtime_definition,
        input_definition,
        runtime_source,
        input_source,
        fixture_sha256: hex::encode(Sha256::digest(fixture_bytes)),
        native_linker: PathBuf::from("/usr/bin/cc"),
    })
}
