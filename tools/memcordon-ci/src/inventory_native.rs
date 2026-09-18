//! Platform native filesystem protocol used by the ordered inventory engine.
use super::*;
use crate::inventory_pipeline::{InventoryBackend, Node, ValidatedDigest};
use crate::inventory_progress::{TaskClass, TaskState};

pub(super) struct Entry {
    path: PathBuf,
    entry: Option<fs::DirEntry>,
    scope: MeasurementScope<'static>,
    leaf_hint: bool,
}

impl Entry {
    pub(super) fn root(path: &Path, scope: MeasurementScope<'_>) -> Self {
        let scope = match scope {
            MeasurementScope::Required => MeasurementScope::Required,
            MeasurementScope::NativeRoot => MeasurementScope::NativeRoot,
            MeasurementScope::NativeDescendant => MeasurementScope::NativeDescendant,
            MeasurementScope::Source(_) => panic!("source inventory cannot enter native pipeline"),
        };
        Self {
            path: path.to_path_buf(),
            entry: None,
            scope,
            leaf_hint: false,
        }
    }
}

pub(super) struct Prepared {
    path: PathBuf,
    identity: PathBuf,
    metadata: fs::Metadata,
    scope: MeasurementScope<'static>,
}

pub(super) struct FileRequest {
    path: PathBuf,
    expected: fs::Metadata,
}

pub(super) struct Backend {
    progress: InventoryProgress,
    root: PathBuf,
}

impl Backend {
    pub(super) fn new(progress: &InventoryProgress, root: &Path) -> Self {
        Self {
            progress: progress.worker(),
            root: root.to_path_buf(),
        }
    }

    fn record(prepared: &Prepared, kind: &str, digest: String) -> Input {
        Input {
            path: native(prepared.identity.as_os_str()),
            kind: kind.into(),
            mode: mode(&prepared.metadata),
            digest,
        }
    }

    fn expand_inner(&self, prepared: Prepared) -> Result<(Vec<Entry>, Input)> {
        self.check_cancelled()?;
        if prepared.metadata.file_type().is_symlink() {
            let target = self.progress.run(Operation::Symlink, &prepared.path, || {
                fs::read_link(&prepared.path)
            })?;
            self.check_cancelled()?;
            let (children, kind, digest) =
                match self
                    .progress
                    .run(Operation::Canonicalize, &prepared.path, || {
                        prepared.path.canonicalize()
                    }) {
                    Ok(resolved) => {
                        let digest = serde_json::to_string(&[
                            native(target.as_os_str()),
                            native(resolved.as_os_str()),
                        ])?;
                        let child = Entry {
                            path: resolved,
                            entry: None,
                            scope: prepared.scope,
                            leaf_hint: false,
                        };
                        (vec![child], "symlink", digest)
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::PermissionDenied
                            && matches!(prepared.scope, MeasurementScope::NativeDescendant) =>
                    {
                        let route = self
                            .progress
                            .run(Operation::Access, &prepared.path, || {
                                inaccessible_symlink_identity(&prepared.path)
                            })?
                            .ok_or_else(|| {
                                CiError::Message(format!(
                                    "resolving symlink without proven search denial: {error}"
                                ))
                            })?;
                        (
                            Vec::new(),
                            "inaccessible-symlink",
                            serde_json::to_string(&(native(target.as_os_str()), route))?,
                        )
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        (Vec::new(), "dangling-symlink", native(target.as_os_str()))
                    }
                    Err(error) => {
                        return Err(CiError::Message(format!("resolving symlink: {error}")));
                    }
                };
            return Ok((children, Self::record(&prepared, kind, digest)));
        }
        let entries = match self
            .progress
            .run(Operation::DirectoryOpen, &prepared.identity, || {
                fs::read_dir(&prepared.identity)
            }) {
            Ok(entries) => entries,
            Err(error) => {
                if error.kind() == io::ErrorKind::PermissionDenied
                    && matches!(prepared.scope, MeasurementScope::NativeDescendant)
                    && let Some(digest) =
                        self.progress
                            .run(Operation::Access, &prepared.identity, || {
                                inaccessible_directory_identity(
                                    &prepared.identity,
                                    &prepared.metadata,
                                )
                            })?
                {
                    return Ok((
                        Vec::new(),
                        Self::record(&prepared, "inaccessible-directory", digest),
                    ));
                }
                return Err(CiError::Message(format!("reading directory: {error}")));
            }
        };
        let mut entries =
            self.progress
                .run(Operation::DirectoryNext, &prepared.identity, || {
                    entries
                        .map(|entry| {
                            self.check_cancelled()?;
                            let entry = entry?;
                            // Cache on this worker inside the enumeration span;
                            // classification remains authoritative.
                            let leaf_hint = entry.file_type().is_ok_and(|kind| kind.is_file());
                            Ok((entry, leaf_hint))
                        })
                        .collect::<Result<Vec<_>>>()
                })?;
        self.progress
            .run(Operation::DirectorySort, &prepared.identity, || {
                entries.sort_by_key(|(entry, _)| entry.file_name());
                Ok::<_, CiError>(())
            })?;
        let children = entries
            .into_iter()
            .map(|(entry, leaf_hint)| Entry {
                path: entry.path(),
                entry: Some(entry),
                scope: prepared.scope.child(),
                leaf_hint,
            })
            .collect();
        Ok((
            children,
            Self::record(&prepared, "directory", String::new()),
        ))
    }
}

impl InventoryBackend for Backend {
    type Entry = Entry;
    type Prepared = Prepared;
    type Expansion = Prepared;
    type File = FileRequest;
    type Record = Input;

    fn is_leaf_hint(&self, entry: &Entry) -> bool {
        entry.leaf_hint
    }

    fn prepare(&self, entry: Entry) -> Result<Prepared> {
        let result: Result<Prepared> = (|| {
            self.check_cancelled()?;
            let metadata =
                self.progress
                    .run(Operation::Metadata, &entry.path, || match entry.entry {
                        Some(entry) => entry.metadata(),
                        None => fs::symlink_metadata(&entry.path),
                    })?;
            // Every declared discovery root is checked before alias suppression.
            if matches!(entry.scope, MeasurementScope::NativeRoot) && metadata.is_dir() {
                self.progress
                    .run(Operation::DirectoryOpen, &entry.path, || {
                        fs::read_dir(&entry.path)
                    })
                    .map_err(|error| {
                        CiError::Message(format!("reading required native root: {error}"))
                    })?;
            }
            self.check_cancelled()?;
            let identity = resolve_identity(&entry.path, &metadata, &self.progress)?;
            Ok(Prepared {
                path: entry.path.clone(),
                identity,
                metadata,
                scope: entry.scope,
            })
        })();
        result.map_err(|error| {
            CiError::Message(format!(
                "measuring build input {}: {error}",
                entry.path.display()
            ))
        })
    }

    fn classify(
        &self,
        prepared: Prepared,
        visited: &mut BTreeSet<PathBuf>,
    ) -> Result<Node<Prepared, FileRequest, Input>> {
        if !visited.insert(prepared.identity.clone()) {
            return Ok(Node::Skip);
        }
        if prepared.metadata.file_type().is_symlink() || prepared.metadata.is_dir() {
            return Ok(Node::Expand(prepared));
        }
        if prepared.metadata.is_file() {
            let record = Self::record(&prepared, "file", String::new());
            return Ok(Node::File(
                FileRequest {
                    path: prepared.identity,
                    expected: prepared.metadata,
                },
                record,
            ));
        }
        if matches!(prepared.scope, MeasurementScope::NativeDescendant)
            && let Some(digest) = native_null_device_identity(&prepared.metadata)?
        {
            return Ok(Node::Record(Self::record(
                &prepared,
                "linux-null-device",
                digest,
            )));
        }
        Err(CiError::Message(format!(
            "unsupported build input: {}",
            prepared.path.display()
        )))
    }

    fn expand(&self, prepared: Prepared) -> Result<(Vec<Entry>, Input)> {
        let path = prepared.path.clone();
        self.expand_inner(prepared).map_err(|error| {
            CiError::Message(format!("measuring build input {}: {error}", path.display()))
        })
    }

    fn read(&self, request: FileRequest, buffer: &mut [u8]) -> Result<ValidatedDigest> {
        #[cfg(windows)]
        use crate::inventory_reader::digest_native_file as digest_file;
        #[cfg(target_os = "linux")]
        use crate::inventory_reader::digest_unix_file as digest_file;
        digest_file(
            &request.path,
            &request.expected,
            buffer,
            &self.progress,
            |_| Ok(()),
        )
    }

    fn set_digest(&self, record: &mut Input, digest: ValidatedDigest) {
        record.digest = digest.digest;
        self.progress.file_committed(digest.bytes);
    }

    fn check_cancelled(&self) -> Result<()> {
        self.progress.cancellation().check().map_err(Into::into)
    }

    fn transition(&self, id: u64, class: TaskClass, state: TaskState) -> Result<()> {
        self.progress
            .task_transition(id, class, state)
            .map_err(Into::into)
    }

    fn observe_wait<T>(&self, draining: bool, action: impl FnOnce() -> Result<T>) -> Result<T> {
        self.progress.run(
            if draining {
                Operation::RootDrain
            } else {
                Operation::QueueWait
            },
            &self.root,
            action,
        )
    }

    fn task_dependency(&self, id: u64, parent: Option<u64>, ordinal: Option<u64>) -> Result<()> {
        self.progress
            .task_dependency(id, parent, ordinal)
            .map_err(Into::into)
    }
}
