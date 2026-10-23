//! Fixed public projection publication within the trusted CI runner's sudo role.
//! This grants no acquisition, cleanup, or arbitrary filesystem write authority.
use crate::consumer_readiness_ledger::SourceIdentity;
use crate::preparation_tools::ReadinessHelperContext;
use rustix::fs::{AtFlags, Mode, OFlags, openat, unlinkat};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const LIMIT: usize = memcordon_readiness_verifier::MAX_INDEX_BYTES;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub invocation: ReadinessHelperContext,
    pub identity: SourceIdentity,
    pub job: String,
    pub runner_uid: u32,
    pub helper_sha256: String,
    pub cell_sha256: String,
    pub manifest_sha256: String,
    pub publication_deadline_unix_millis: u64,
}

pub fn publication_cutoff(absolute: u64) -> Result<Instant, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis();
    let remaining = u128::from(absolute)
        .checked_sub(now)
        .filter(|v| *v > 0 && *v <= 60_000)
        .ok_or("original publication-only cutoff expired or exceeds 60s")?;
    Instant::now()
        .checked_add(Duration::from_millis(remaining as u64))
        .ok_or_else(|| "publication cutoff overflow".into())
}

fn live(deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline {
        Err("original publication-only cutoff exhausted".into())
    } else {
        Ok(())
    }
}

fn native<T>(value: rustix::io::Result<T>) -> Result<T, String> {
    value.map_err(|e| e.to_string())
}

fn directory(parent: &File, name: &std::ffi::OsStr) -> Result<File, String> {
    native(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ))
    .map(File::from)
}

fn root(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("publication workspace is not absolute".into());
    }
    let mut held = File::open("/").map_err(|e| e.to_string())?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => held = directory(&held, name)?,
            _ => return Err("publication path is not normalized".into()),
        }
    }
    Ok(held)
}

pub fn read_input(workspace: &Path, relative: &Path) -> Result<Vec<u8>, String> {
    let mut parent = root(workspace)?;
    for component in relative
        .parent()
        .ok_or("publication input parent absent")?
        .components()
    {
        let Component::Normal(name) = component else {
            return Err("publication input escapes workspace".into());
        };
        parent = directory(&parent, name)?;
    }
    let name = relative
        .file_name()
        .ok_or("publication input leaf absent")?;
    let file = File::from(native(openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ))?);
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.nlink() != 1 || before.len() > LIMIT as u64 {
        return Err("publication input kind/bound differs".into());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != before.len()
        || key(&before) != key(&file.metadata().map_err(|e| e.to_string())?)
    {
        return Err("publication input changed while reading".into());
    }
    Ok(bytes)
}

fn key(m: &std::fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.nlink(),
        m.uid(),
        m.mode(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
    )
}

pub fn selected_paths(
    workspace: &Path,
    acquisition: &Path,
    cell: &Path,
    output: &Path,
) -> Result<(), String> {
    if acquisition != workspace.join(".release/readiness-cell")
        || cell != acquisition.join("producer/cell.json")
        || output != acquisition.join("producer-packed/producer-manifest.json")
    {
        return Err("publication paths differ from selected acquisition projection".into());
    }
    for path in [workspace, acquisition, cell, output] {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err("publication path is not normalized".into());
        }
    }
    Ok(())
}

pub struct Scope {
    workspace: PathBuf,
    acquisition: File,
    producer: File,
    cell: File,
    cell_bytes: Vec<u8>,
    cell_stamp: (u64, u64, u64, u32, u32, u64, i64, i64),
    deadline: Instant,
    producer_uid: u32,
}

impl Scope {
    pub fn open(
        workspace: &Path,
        acquisition: &Path,
        cell: &Path,
        output: &Path,
        runner_uid: u32,
        deadline: Instant,
    ) -> Result<Self, String> {
        selected_paths(workspace, acquisition, cell, output)?;
        live(deadline)?;
        let workspace_file = root(workspace)?;
        let workspace_stamp = workspace_file.metadata().map_err(|e| e.to_string())?;
        if workspace_stamp.uid() != runner_uid || workspace_stamp.mode() & 0o022 != 0 {
            return Err("publication workspace ownership/mode differs".into());
        }
        let release = directory(&workspace_file, std::ffi::OsStr::new(".release"))?;
        let stamp = release.metadata().map_err(|e| e.to_string())?;
        if stamp.uid() != runner_uid || stamp.mode() & 0o022 != 0 {
            return Err("publication .release ownership/mode differs".into());
        }
        let acquisition = directory(&release, std::ffi::OsStr::new("readiness-cell"))?;
        let stamp = acquisition.metadata().map_err(|e| e.to_string())?;
        if stamp.uid() != runner_uid || stamp.mode() & 0o022 != 0 {
            return Err("publication acquisition ownership/mode differs".into());
        }
        let producer = directory(&acquisition, std::ffi::OsStr::new("producer"))?;
        let stamp = producer.metadata().map_err(|e| e.to_string())?;
        if stamp.uid() != 0 || stamp.mode() & 0o7777 != 0o755 {
            return Err("publication producer is not root-owned0755".into());
        }
        let cell = File::from(native(openat(
            &producer,
            "cell.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ))?);
        let before = cell.metadata().map_err(|e| e.to_string())?;
        if !before.is_file()
            || before.uid() != 0
            || before.mode() & 0o7777 != 0o644
            || before.nlink() != 1
            || before.len() > LIMIT as u64
        {
            return Err("publication cell custody/bound differs".into());
        }
        let mut cell_bytes = Vec::new();
        (&cell)
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut cell_bytes)
            .map_err(|e| e.to_string())?;
        if cell_bytes.len() as u64 != before.len()
            || key(&before) != key(&cell.metadata().map_err(|e| e.to_string())?)
        {
            return Err("publication cell changed while reading".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&cell_bytes)?;
        let scope = Self {
            workspace: workspace.to_owned(),
            acquisition,
            producer,
            cell,
            cell_bytes,
            cell_stamp: key(&before),
            deadline,
            producer_uid: 0,
        };
        scope.verify_named()?;
        Ok(scope)
    }

    pub fn cell_bytes(&self) -> &[u8] {
        &self.cell_bytes
    }

    pub fn acquisition_failed(&self) -> Result<bool, String> {
        for name in ["acquisition-failure.json", "always-cleanup-failure.json"] {
            match openat(
                &self.acquisition,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => {
                    let metadata = File::from(fd).metadata().map_err(|e| e.to_string())?;
                    if !metadata.is_file() || metadata.len() > LIMIT as u64 {
                        return Err("publication failure marker custody/bound differs".into());
                    }
                    return Ok(true);
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(format!("publication failure marker {name}: {e}")),
            }
        }
        Ok(false)
    }

    fn verify_named(&self) -> Result<(), String> {
        live(self.deadline)?;
        if key(&self.cell.metadata().map_err(|e| e.to_string())?) != self.cell_stamp {
            return Err("publication cell changed after validation".into());
        }
        let named = root(&self.workspace.join(".release/readiness-cell"))?;
        let producer = directory(&named, std::ffi::OsStr::new("producer"))?;
        let cell = File::from(native(openat(
            &producer,
            "cell.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ))?);
        for (held, current) in [
            (&self.acquisition, &named),
            (&self.producer, &producer),
            (&self.cell, &cell),
        ] {
            if key(&held.metadata().map_err(|e| e.to_string())?)
                != key(&current.metadata().map_err(|e| e.to_string())?)
            {
                return Err("publication named custody changed".into());
            }
        }
        Ok(())
    }

    pub fn publish_packed(
        &self,
        producer: &memcordon_readiness_verifier::ProducerManifest,
    ) -> Result<(), String> {
        use super::readiness_artifact_catalog::PackedCatalog;
        use crate::release::consumer_readiness_cell::public_projection as projection;
        self.verify_named()?;
        memcordon_readiness_verifier::storage::validate_cell(producer, &self.cell_bytes)?;
        // Only this fresh derivative is writable; original captures remain untouched.
        native(rustix::fs::mkdirat(
            &self.acquisition,
            "producer-packed",
            Mode::from_bits_truncate(0o755),
        ))?;
        let packed = directory(&self.acquisition, std::ffi::OsStr::new("producer-packed"))?;
        native(rustix::fs::fchmod(&packed, Mode::from_bits_truncate(0o755)))?;
        let stamp = packed.metadata().map_err(|e| e.to_string())?;
        if stamp.uid() != self.producer_uid || stamp.mode() & 0o7777 != 0o755 {
            return Err("packed derivative ownership differs".into());
        }
        let catalog = PackedCatalog::capture(
            &producer.artifacts,
            self.cell_bytes.len() as u64,
            self.deadline,
            |record| {
                self.verify_named().map_err(crate::CiError::Message)?;
                let relative = Path::new(&record.path);
                let parent = projection::parent(&self.producer, relative, false)?;
                projection::capture_selected(
                    &parent,
                    relative.file_name().ok_or_else(|| {
                        crate::CiError::Message("logical member name absent".into())
                    })?,
                    record,
                )
            },
            |object, bytes, existing| {
                projection::retain_packed_object(&packed, object, bytes, existing)
            },
        )
        .map_err(|e| e.to_string())?;
        projection::write_new(&packed, std::ffi::OsStr::new("cell.json"), &self.cell_bytes)
            .map_err(|e| e.to_string())?;
        let envelope = memcordon_readiness_verifier::storage::PackedProducerManifestV1 {
            format: "memcordon.consumer-readiness.packed-producer".into(),
            revision: 1,
            producer: producer.clone(),
            objects: catalog.objects,
            bindings: catalog.bindings,
        };
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| e.to_string())?;
        let (_, storage) = memcordon_readiness_verifier::storage::decode_producer(&bytes)?;
        storage.check_budget(self.cell_bytes.len() as u64 + bytes.len() as u64 + 1)?;
        // Check every selected source again before sealing; never substitute an earlier object.
        for record in &producer.artifacts {
            live(self.deadline)?;
            let relative = Path::new(&record.path);
            let parent =
                projection::parent(&self.producer, relative, false).map_err(|e| e.to_string())?;
            projection::read_selected(
                &parent,
                relative.file_name().ok_or("logical member name absent")?,
                record,
            )
            .map_err(|e| e.to_string())?;
        }
        for record in &envelope.objects {
            live(self.deadline)?;
            let relative = Path::new(&record.path);
            let parent = projection::parent(&packed, relative, false).map_err(|e| e.to_string())?;
            projection::read_selected(
                &parent,
                relative.file_name().ok_or("physical member name absent")?,
                record,
            )
            .map_err(|e| e.to_string())?;
        }
        publish_held(&packed, &bytes, self.producer_uid, self.deadline, || {
            self.verify_named()?;
            let named = directory(&self.acquisition, std::ffi::OsStr::new("producer-packed"))?;
            let current = named.metadata().map_err(|e| e.to_string())?;
            if current.dev() != stamp.dev()
                || current.ino() != stamp.ino()
                || current.uid() != stamp.uid()
            {
                return Err("packed derivative named identity changed".into());
            }
            Ok(())
        })
    }
}

/// Publish through an already held directory capability. This function does
/// not acquire privileges or admit a projection; the root role requires Scope.
pub fn publish_held(
    producer: &File,
    bytes: &[u8],
    expected_uid: u32,
    deadline: Instant,
    verify_selected: impl Fn() -> Result<(), String>,
) -> Result<(), String> {
    live(deadline)?;
    if bytes.len() >= LIMIT {
        return Err("producer manifest exceeds publication bound".into());
    }
    let mut file = File::from(native(openat(
        producer,
        "producer-manifest.json",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o644),
    ))?);
    let original = match file.metadata() {
        Ok(metadata) => metadata,
        Err(primary) => {
            return Err(format!(
                "new producer-manifest metadata unavailable: {primary}; empty partial output ownership unverified, cleanup not attempted"
            ));
        }
    };
    let result = (|| {
        native(rustix::fs::fchmod(&file, Mode::from_bits_truncate(0o644)))?;
        if !original.is_file() || original.uid() != expected_uid || original.nlink() != 1 {
            return Err("published manifest ownership/kind differs".into());
        }
        file.write_all(bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("write/sync producer-manifest.json: {e}"))?;
        producer.sync_all().map_err(|e| e.to_string())?;
        live(deadline)?;
        verify_selected()?;
        let named = File::from(native(openat(
            producer,
            "producer-manifest.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ))?);
        let actual = named.metadata().map_err(|e| e.to_string())?;
        if actual.dev() != original.dev()
            || actual.ino() != original.ino()
            || actual.nlink() != 1
            || actual.uid() != expected_uid
            || actual.mode() & 0o7777 != 0o644
            || actual.len() != bytes.len() as u64 + 1
        {
            return Err("published manifest named custody differs".into());
        }
        let mut readback = Vec::new();
        named
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut readback)
            .map_err(|e| e.to_string())?;
        if readback.strip_suffix(b"\n") != Some(bytes) {
            return Err("published manifest readback differs".into());
        }
        live(deadline)?;
        Ok(())
    })();
    if let Err(primary) = &result {
        // Remove only the exact inode this call created, never a replacement.
        let cleanup = (|| {
            let named = openat(
                producer,
                "producer-manifest.json",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            );
            match named {
                Ok(named) => {
                    let stamp = File::from(named).metadata().map_err(|e| e.to_string())?;
                    if stamp.dev() == original.dev() && stamp.ino() == original.ino() {
                        native(unlinkat(
                            producer,
                            "producer-manifest.json",
                            AtFlags::empty(),
                        ))?;
                        producer.sync_all().map_err(|e| e.to_string())?;
                    } else {
                        return Err(
                            "named output was replaced; unrelated inode left untouched".into()
                        );
                    }
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(format!("cannot inspect named partial output: {error}")),
            }
            Ok::<(), String>(())
        })();
        if let Err(cleanup) = cleanup {
            return Err(format!(
                "{}; owned partial manifest cleanup: {cleanup}",
                primary
            ));
        }
    }
    result
}
