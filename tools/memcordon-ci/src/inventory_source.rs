//! Source traversal on the shared executor, retaining the source reader contract.
use super::*;
use crate::inventory_pipeline::{InventoryBackend, Node, ValidatedDigest};
use crate::inventory_progress::{TaskClass, TaskState};

pub(super) struct Entry {
    path: PathBuf,
    leaf_hint: bool,
}

impl Entry {
    pub(super) fn root(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            leaf_hint: false,
        }
    }
}

pub(super) struct Prepared {
    path: PathBuf,
    identity: PathBuf,
    metadata: fs::Metadata,
}

pub(super) struct Backend {
    root: PathBuf,
    progress: InventoryProgress,
}

impl Backend {
    pub(super) fn new(progress: &InventoryProgress, root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            progress: progress.worker(),
        }
    }

    fn excluded(&self, path: &Path) -> Result<bool> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|error| CiError::Message(error.to_string()))?;
        Ok(["fuzz/target", "fuzz/corpus", "fuzz/artifacts"]
            .iter()
            .any(|output| relative.starts_with(output))
            || relative.components().next().is_some_and(|part| {
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
            }))
    }

    fn record(prepared: &Prepared, kind: &str, digest: String) -> Input {
        Input {
            path: native(prepared.identity.as_os_str()),
            kind: kind.into(),
            mode: mode(&prepared.metadata),
            digest,
        }
    }
}

impl InventoryBackend for Backend {
    type Entry = Entry;
    type Prepared = Option<Prepared>;
    type Expansion = Prepared;
    type File = PathBuf;
    type Record = Input;

    fn is_leaf_hint(&self, entry: &Entry) -> bool {
        entry.leaf_hint
    }

    fn prepare(&self, entry: Entry) -> Result<Option<Prepared>> {
        let result: Result<Option<Prepared>> = (|| {
            self.check_cancelled()?;
            // Exclusion happens before metadata, including dangling output links.
            if self.excluded(&entry.path)? {
                return Ok(None);
            }
            let metadata = self
                .progress
                .run(Operation::Metadata, &entry.path, || {
                    fs::symlink_metadata(&entry.path)
                })
                .map_err(|error| CiError::Message(format!("reading metadata: {error}")))?;
            let identity = resolve_identity(&entry.path, &metadata, &self.progress)?;
            Ok(Some(Prepared {
                path: entry.path.clone(),
                identity,
                metadata,
            }))
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
        prepared: Option<Prepared>,
        visited: &mut BTreeSet<PathBuf>,
    ) -> Result<Node<Prepared, PathBuf, Input>> {
        let Some(prepared) = prepared else {
            return Ok(Node::Skip);
        };
        if !visited.insert(prepared.identity.clone()) {
            return Ok(Node::Skip);
        }
        if prepared.metadata.file_type().is_symlink() || prepared.metadata.is_dir() {
            return Ok(Node::Expand(prepared));
        }
        if prepared.metadata.is_file() {
            let record = Self::record(&prepared, "file", String::new());
            return Ok(Node::File(prepared.identity, record));
        }
        Err(CiError::Message(format!(
            "unsupported build input: {}",
            prepared.path.display()
        )))
    }

    fn expand(&self, prepared: Prepared) -> Result<(Vec<Entry>, Input)> {
        let result = (|| {
            self.check_cancelled()?;
            if prepared.metadata.file_type().is_symlink() {
                let target = self
                    .progress
                    .run(Operation::Symlink, &prepared.path, || {
                        fs::read_link(&prepared.path)
                    })
                    .map_err(|error| CiError::Message(format!("reading symlink: {error}")))?;
                let resolved = self
                    .progress
                    .run(Operation::Canonicalize, &prepared.path, || {
                        prepared.path.canonicalize()
                    })
                    .map_err(|error| CiError::Message(format!("resolving symlink: {error}")))?;
                if !resolved.starts_with(&self.root) {
                    return Err(CiError::Message(
                        "source symlink escapes declared root".into(),
                    ));
                }
                return Ok((
                    Vec::new(),
                    Self::record(
                        &prepared,
                        "symlink",
                        serde_json::to_string(&[
                            native(target.as_os_str()),
                            native(resolved.as_os_str()),
                        ])?,
                    ),
                ));
            }
            let entries = self
                .progress
                .run(Operation::DirectoryOpen, &prepared.identity, || {
                    fs::read_dir(&prepared.identity)
                })
                .map_err(|error| CiError::Message(format!("reading directory: {error}")))?;
            // Commit children only after the complete listing succeeds.
            let mut children = self
                .progress
                .run(Operation::DirectoryNext, &prepared.identity, || {
                    entries.collect::<io::Result<Vec<_>>>()
                })
                .map_err(|error| CiError::Message(format!("enumerating directory: {error}")))?;
            self.progress
                .run(Operation::DirectorySort, &prepared.identity, || {
                    children.sort_by_key(|entry| entry.file_name());
                    Ok::<_, CiError>(())
                })?;
            let mut admitted = Vec::new();
            for child in children {
                let path = child.path();
                if self.excluded(&path)? {
                    continue;
                }
                // A failed hint is harmless; prepare remains authoritative.
                let leaf_hint = child.file_type().is_ok_and(|kind| kind.is_file());
                admitted.push(Entry { path, leaf_hint });
            }
            Ok((
                admitted,
                Self::record(&prepared, "directory", String::new()),
            ))
        })();
        result.map_err(|error| {
            CiError::Message(format!(
                "measuring build input {}: {error}",
                prepared.path.display()
            ))
        })
    }

    fn read(&self, path: PathBuf, buffer: &mut [u8]) -> Result<ValidatedDigest> {
        let result: Result<ValidatedDigest> = (|| {
            self.check_cancelled()?;
            let mut file = self
                .progress
                .run(Operation::Open, &path, || open_sequential(&path))?;
            let (digest, bytes) = self.progress.run(Operation::ReadHash, &path, || {
                crate::inventory_reader::digest_reader_with_length(
                    &mut file,
                    buffer,
                    &self.progress,
                    None,
                )
            })?;
            self.progress.file_validated(bytes);
            Ok(ValidatedDigest { digest, bytes })
        })();
        result.map_err(|error| {
            CiError::Message(format!(
                "measuring build input {}: reading file contents: {error}",
                path.display()
            ))
        })
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
