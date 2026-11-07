//! A fresh declared private-input experiment; never changes installed consumer selection.
#[cfg(windows)]
pub mod native {
    use crate::{
        CiError, Result,
        windows_installed_cases::SelectedArtifact,
        windows_native_files::{self, HeldWindowsArtifact},
        windows_provider_projection_record::{Candidate, CatalogSnapshot, PrivateInput},
    };
    use memcordon_platform::windows_private_input_record::{Context, ObjectRole};
    use std::{
        fs,
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            fs::OpenOptionsExt,
        },
        path::{Path, PathBuf},
        sync::Arc,
        time::Instant,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    fn live(work: Instant) -> Result<()> {
        if Instant::now() >= work {
            Err(CiError::Message(
                "private input original work cutoff exhausted".into(),
            ))
        } else {
            Ok(())
        }
    }
    fn seal(
        path: &Path,
        directory: bool,
        sid: &str,
        work: Instant,
        role: ObjectRole,
        object_index: Option<u32>,
    ) -> Result<serde_json::Value> {
        live(work)?;
        let _parents = windows_native_files::hold_ancestors(
            path.parent()
                .ok_or_else(|| CiError::Message("private input parent absent".into()))?,
        )?;
        live(work)?;
        let file = fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        live(work)?;
        let identity = windows_native_files::native_file_identity(&file, directory, path)?;
        live(work)?;
        let mut record =
            memcordon_platform::test_support::windows_private_input::seal_read_execute(
                &file,
                directory,
                sid,
                work,
                &Context {
                    role,
                    directory,
                    object_index,
                    volume_serial: Some(identity.0),
                    file_index: Some(identity.1),
                },
            )?;
        live(work)?;
        if windows_native_files::native_file_identity(&file, directory, path)? != identity {
            return Err(CiError::Message(
                "same-held private security file identity differs".into(),
            ));
        }
        record["volume_serial"] = serde_json::json!(identity.0);
        record["file_index"] = serde_json::json!(identity.1);
        record["caller_request"] =
            serde_json::json!(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES);
        live(work)?;
        Ok(record)
    }

    pub struct Deployment {
        owner: Option<tempfile::TempDir>,
        pub fixture: SelectedArtifact,
        pub input_root: PathBuf,
        pub output_root: PathBuf,
        pub local: PathBuf,
        marker: Option<Arc<HeldWindowsArtifact>>,
        files: Vec<(PathBuf, Arc<HeldWindowsArtifact>)>,
        witnesses: Vec<PrivateInput>,
        directories: Vec<Arc<fs::File>>,
        output_directories: Vec<Arc<fs::File>>,
        declared_output: Option<PathBuf>,
        custody: Option<Arc<crate::windows_private_custody::PrivateFixtureCustody>>,
        pub inventory: serde_json::Value,
        sealed: bool,
        launched: bool,
        retired: bool,
        quarantined: bool,
    }
    impl Deployment {
        pub fn create(
            source: &SelectedArtifact,
            target: &str,
            parent: &Path,
            work: Instant,
            dot_local_file: bool,
        ) -> Result<Self> {
            live(work)?;
            let _parents = windows_native_files::hold_ancestors(parent)?;
            live(work)?;
            let owner = tempfile::Builder::new()
                .prefix("declared-provider-input-")
                .tempdir_in(parent)?;
            live(work)?;
            let base = std::path::absolute(owner.path())?;
            let input_root = base.join("inputs");
            let output_root = base.join("outputs");
            fs::create_dir(&input_root)?;
            live(work)?;
            fs::create_dir(&output_root)?;
            live(work)?;
            let directories = windows_native_files::hold_ancestors(&input_root)?;
            live(work)?;
            let path = input_root.join(
                source
                    .path
                    .file_name()
                    .ok_or_else(|| CiError::Message("selected fixture leaf absent".into()))?,
            );
            let held =
                windows_native_files::copy_owned_artifact(&source.path, &path, &source.sha256)?;
            live(work)?;
            crate::release::target::validate_executable(&held.bytes, target)?;
            let manifest = crate::windows_pe_manifest::inventory(&held.bytes);
            live(work)?;
            if manifest["parser_complete"] != true || manifest["status"] != "complete_no_manifest" {
                return Err(CiError::Message(
                    "fresh experimental fixture does not have complete no-manifest input facts"
                        .into(),
                ));
            }
            let path = fs::canonicalize(path)?;
            live(work)?;
            let mut local = path.file_name().unwrap().to_os_string();
            local.push(".local");
            let local = input_root.join(local);
            // The newly owned input directory contains only the exact copied fixture.
            if fs::read_dir(&input_root)?.take(2).count() != 1 {
                return Err(CiError::Message(
                    "fresh private fixture has unexpected siblings".into(),
                ));
            }
            live(work)?;
            let mut directories = directories;
            let marker = if dot_local_file {
                drop(windows_native_files::publish_owned_file(&local, &[])?);
                live(work)?;
                Some(Arc::new(windows_native_files::hold_artifact(
                    &local, None, 0,
                )?))
            } else {
                fs::create_dir(&local)?;
                live(work)?;
                directories.extend(windows_native_files::hold_ancestors(&local)?);
                None
            };
            let local = if dot_local_file {
                fs::canonicalize(local)?
            } else {
                local
            };
            let fixture = SelectedArtifact {
                path: path.clone(),
                sha256: held.sha256.clone(),
            };
            live(work)?;
            Ok(Self {
                owner: Some(owner),
                fixture,
                input_root,
                output_root,
                local,
                marker,
                files: vec![(path, Arc::new(held))],
                witnesses: Vec::new(),
                directories: directories.into_iter().map(Arc::new).collect(),
                output_directories: Vec::new(),
                declared_output: None,
                custody: None,
                inventory: serde_json::json!({"format":"memcordon.declared-provider-inputs","revision":1,"layout":if dot_local_file {"file-marker-siblings"} else {"directory"},"diagnostic_only":true,"acceptance_authority":false,"original_file_identities_preserved":false,"fixture_manifest":manifest,"sources":[],"sealed":false}),
                launched: false,
                retired: false,
                quarantined: false,
                sealed: false,
            })
        }
        pub fn copy_providers(
            &mut self,
            candidates: &[Candidate],
            catalog: &CatalogSnapshot,
            target: &str,
            work: Instant,
        ) -> Result<()> {
            if candidates.is_empty() || candidates.len() > 8 || self.files.len() != 1 {
                return Err(CiError::Message(
                    "private provider set is not a fresh finite declaration".into(),
                ));
            }
            let mut bytes = 0usize;
            let mut records = Vec::new();
            for candidate in candidates {
                live(work)?;
                let source = PathBuf::from(std::ffi::OsString::from_wide(&candidate.expanded_path));
                let held = windows_native_files::HeldProviderSource::hold(&source, work)?;
                live(work)?;
                bytes = bytes
                    .checked_add(held.bytes.len())
                    .ok_or_else(|| CiError::Message("provider input byte overflow".into()))?;
                if bytes > 256 * 1024 * 1024 {
                    return Err(CiError::Message("provider input total byte bound".into()));
                }
                crate::release::target::validate_executable(&held.bytes, target)?;
                live(work)?;
                let source_identity = (held.metadata.volume_serial, held.metadata.file_index);
                live(work)?;
                let destination = if self.marker.is_some() {
                    &self.input_root
                } else {
                    &self.local
                }
                .join(&candidate.basename);
                if self.files.iter().any(|(path, _)| path == &destination)
                    || destination == self.local
                {
                    return Err(CiError::Message(
                        "private provider collides with fixture or marker".into(),
                    ));
                }
                let copied = held.publish(&destination, work)?;
                live(work)?;
                held.verify(work)?;
                live(work)?;
                if copied.bytes != held.bytes {
                    return Err(CiError::Message(
                        "private provider exact copy differs".into(),
                    ));
                }
                let destination = fs::canonicalize(destination)?;
                live(work)?;
                let native_path = copied.native_path()?;
                live(work)?;
                let private_identity = copied.identity(&destination)?;
                self.witnesses.push(PrivateInput {
                    original_path: candidate.expanded_path.clone(),
                    private_native_path: native_path.clone(),
                    volume_serial: private_identity.0,
                    file_index: private_identity.1,
                    bytes: copied.bytes.len() as u64,
                    sha256: copied.sha256.clone(),
                });
                records.push(serde_json::json!({"catalog_ids":candidate.catalog_ids,"provider_ids":candidate.provider_ids,"original_path_utf16":candidate.expanded_path,"original_volume_serial":source_identity.0,"original_file_index":source_identity.1,"borrowed_source_metadata":held.metadata,"source_exclusive_ownership_proved":false,"private_path_utf16":destination.as_os_str().encode_wide().collect::<Vec<_>>(),"private_native_path_utf16":native_path,"private_identity":private_identity,"bytes":copied.bytes.len(),"sha256":copied.sha256,"source_view":"native","changed_file_identity":true}));
                self.files.push((destination, Arc::new(copied)));
            }
            self.inventory["catalog"] = serde_json::to_value(catalog)?;
            self.inventory["sources"] = serde_json::json!(records);
            if self.marker.is_some() {
                let observed = fs::read_dir(&self.input_root)?
                    .map(|entry| fs::canonicalize(entry?.path()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                let expected = self
                    .paths()
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>();
                if observed
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    != expected
                {
                    return Err(CiError::Message(
                        "file-marker input namespace has unexpected siblings".into(),
                    ));
                }
            }
            live(work)
        }
        pub fn seal(&mut self, sid: &str, work: Instant) -> Result<()> {
            let mut security = Vec::new();
            for (index, (path, held)) in self.files.iter().enumerate() {
                live(work)?;
                let object_index = u32::try_from(index)
                    .map_err(|_| CiError::Message("private input object index overflow".into()))?;
                security.push(seal(
                    path,
                    false,
                    sid,
                    work,
                    if index == 0 {
                        ObjectRole::Fixture
                    } else {
                        ObjectRole::Provider
                    },
                    Some(object_index),
                )?);
                windows_native_files::verify_named_artifact(held, path)?;
            }
            if let Some(marker) = &self.marker {
                security.push(seal(
                    &self.local,
                    false,
                    sid,
                    work,
                    ObjectRole::LocalMarkerFile,
                    None,
                )?);
                windows_native_files::verify_named_artifact(marker, &self.local)?;
            } else {
                security.push(seal(
                    &self.local,
                    true,
                    sid,
                    work,
                    ObjectRole::LocalDirectory,
                    None,
                )?);
            }
            security.push(seal(
                &self.input_root,
                true,
                sid,
                work,
                ObjectRole::InputDirectory,
                None,
            )?);
            // Declare the new owned ancestor too; host ancestors remain untouched.
            let base = self
                .input_root
                .parent()
                .ok_or_else(|| CiError::Message("owned input ancestor absent".into()))?;
            security.push(seal(base, true, sid, work, ObjectRole::OwnedBase, None)?);
            self.inventory["security"] = serde_json::json!(security);
            self.inventory["sealed"] = serde_json::json!(true);
            live(work)?;
            self.sealed = true;
            Ok(())
        }
        pub fn paths(&self) -> Vec<PathBuf> {
            let mut paths = self
                .files
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>();
            if self.marker.is_some() {
                paths.insert(1, self.local.clone());
            }
            paths
        }
        pub fn witnesses(&self) -> &[PrivateInput] {
            &self.witnesses
        }
        pub fn verify(&self, work: Instant) -> Result<()> {
            if !self.sealed {
                return Err(CiError::Message(
                    "private input sealing not complete".into(),
                ));
            }
            for (path, held) in &self.files {
                live(work)?;
                windows_native_files::verify_named_artifact(held, path)?;
            }
            if let Some(marker) = &self.marker {
                live(work)?;
                windows_native_files::verify_named_artifact(marker, &self.local)?;
            }
            live(work)
        }
        pub fn fixture_binding(
            &self,
            work: Instant,
        ) -> Result<memcordon_platform::windows_private_fixture_binding::PrivateFixtureBinding>
        {
            use memcordon_platform::{
                test_support::windows_held_file_metadata,
                windows_private_fixture_binding::{
                    DotLocalInput, PrivateFixtureAncestor, PrivateFixtureFile,
                },
            };
            self.verify(work)?;
            let output = self.declared_output.as_ref().ok_or_else(|| {
                CiError::Message("private output custody was not prepared".into())
            })?;
            let output_paths = output.ancestors().collect::<Vec<_>>();
            if output_paths.len() != self.output_directories.len() {
                return Err(CiError::Message(
                    "held private output chain extent differs".into(),
                ));
            }
            let mut output_ancestors = Vec::new();
            for (path, file) in output_paths.into_iter().rev().zip(&self.output_directories) {
                live(work)?;
                let identity = windows_native_files::native_file_identity(file, true, path)?;
                let metadata = windows_held_file_metadata(file)?;
                let named = fs::OpenOptions::new()
                    .access_mode(FILE_READ_ATTRIBUTES)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                    .open(path)?;
                live(work)?;
                if windows_native_files::native_file_identity(&named, true, path)? != identity {
                    return Err(CiError::Message(
                        "same-held private output ancestry changed".into(),
                    ));
                }
                output_ancestors.push(PrivateFixtureAncestor {
                    path: path.to_owned(),
                    volume_serial: identity.0,
                    file_index: identity.1,
                    attributes: metadata.attributes,
                });
            }
            let (path, held) = self
                .files
                .first()
                .ok_or_else(|| CiError::Message("held private fixture absent".into()))?;
            if path != &self.fixture.path || held.sha256 != self.fixture.sha256 {
                return Err(CiError::Message(
                    "held private fixture selection differs".into(),
                ));
            }
            let local = match &self.marker {
                Some(marker) => marker.private_file(),
                None => self
                    .directories
                    .last()
                    .ok_or_else(|| CiError::Message("held private local directory absent".into()))?
                    .as_ref(),
            };
            // Use the declared fixture's immediate namespace spelling, joined
            // back to the original held directory by native identity below.
            let declared_local =
                path.parent()
                    .ok_or_else(|| CiError::Message("held private fixture parent absent".into()))?
                    .join(self.local.file_name().ok_or_else(|| {
                        CiError::Message("held private local leaf absent".into())
                    })?);
            live(work)?;
            let directory = self.marker.is_none();
            let identity =
                windows_native_files::native_file_identity(local, directory, &declared_local)?;
            let metadata = windows_held_file_metadata(local)?;
            let named = fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(&declared_local)?;
            live(work)?;
            if windows_native_files::native_file_identity(&named, directory, &declared_local)?
                != identity
            {
                return Err(CiError::Message(
                    "held private local directory changed".into(),
                ));
            }
            let local_input = if let Some(marker) = &self.marker {
                if !marker.bytes.is_empty() || metadata.length != 0 || metadata.links != 1 {
                    return Err(CiError::Message(
                        "held .local marker is not an empty single-link file".into(),
                    ));
                }
                DotLocalInput::File(PrivateFixtureFile {
                    path: declared_local,
                    volume_serial: identity.0,
                    file_index: identity.1,
                    attributes: metadata.attributes,
                    links: metadata.links,
                    bytes: metadata.length,
                    sha256: marker.sha256.clone(),
                    native_path_utf16: marker.native_path()?,
                })
            } else {
                DotLocalInput::Directory(PrivateFixtureAncestor {
                    path: declared_local,
                    volume_serial: identity.0,
                    file_index: identity.1,
                    attributes: metadata.attributes,
                })
            };
            let binding =
                held.private_fixture_binding(path, local_input, output_ancestors, work)?;
            binding.validate(&self.paths()).map_err(CiError::Message)?;
            binding.validate_output(output).map_err(CiError::Message)?;
            live(work)?;
            Ok(binding)
        }

        pub(crate) fn prepare_fixture_custody(
            &mut self,
            output: &Path,
            work: Instant,
        ) -> Result<Arc<crate::windows_private_custody::PrivateFixtureCustody>> {
            let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(work)
                .map_err(std::io::Error::other)?;
            let primary = self.prepare_fixture_custody_inner(output, work);
            let settled = timer
                .finish()
                .map_err(std::io::Error::other)
                .map_err(CiError::from);
            match (primary, settled) {
                (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(secondary)) => Err(secondary),
                (Ok(custody), Ok(())) => {
                    live(work)?;
                    Ok(custody)
                }
            }
        }
        fn prepare_fixture_custody_inner(
            &mut self,
            output: &Path,
            work: Instant,
        ) -> Result<Arc<crate::windows_private_custody::PrivateFixtureCustody>> {
            live(work)?;
            if self.custody.is_some()
                || !output.starts_with(&self.output_root)
                || output.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || output.ancestors().count() > 64
            {
                return Err(CiError::Message(
                    "private output custody is not a fresh finite owned chain".into(),
                ));
            }
            let _base = windows_native_files::hold_ancestors(&self.output_root)?;
            live(work)?;
            fs::create_dir_all(output)?;
            live(work)?;
            self.output_directories = windows_native_files::hold_ancestors(output)?
                .into_iter()
                .map(Arc::new)
                .collect();
            self.declared_output = Some(output.to_owned());
            let binding = self.fixture_binding(work)?;
            let fixture = Arc::clone(
                &self
                    .files
                    .first()
                    .ok_or_else(|| {
                        CiError::Message("original private fixture owner absent".into())
                    })?
                    .1,
            );
            let local = if let Some(marker) = &self.marker {
                crate::windows_private_custody::LocalInputCustody::File(Arc::clone(marker))
            } else {
                crate::windows_private_custody::LocalInputCustody::Directory(Arc::clone(
                    self.directories.last().ok_or_else(|| {
                        CiError::Message("original private local owner absent".into())
                    })?,
                ))
            };
            let custody = Arc::new(crate::windows_private_custody::PrivateFixtureCustody::new(
                fixture,
                local,
                self.output_directories.clone(),
                binding,
            ));
            self.custody = Some(Arc::clone(&custody));
            Ok(custody)
        }
        /// Borrowing this Deployment keeps its prelaunch guards alive throughout
        /// the synchronous root/peer execution, including failed retirement.
        pub fn with_fixture_custody<T>(
            &self,
            binding: &memcordon_platform::windows_private_fixture_binding::PrivateFixtureBinding,
            work: Instant,
            operation: impl FnOnce() -> Result<T>,
        ) -> Result<T> {
            struct Custody<'a>(&'a Deployment);
            let custody = Custody(self);
            if custody.0.fixture_binding(work)? != *binding {
                return Err(CiError::Message(
                    "prelaunch fixture custody declaration differs".into(),
                ));
            }
            let primary = operation();
            let checked = custody.0.fixture_binding(work).and_then(|observed| {
                if observed == *binding {
                    Ok(())
                } else {
                    Err(CiError::Message(
                        "postexecution fixture custody declaration differs".into(),
                    ))
                }
            });
            match (primary, checked) {
                (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(_), Err(secondary)) => Err(secondary),
                (Ok(value), Ok(())) => Ok(value),
            }
        }
        pub fn launched(&mut self) {
            self.launched = true;
        }
        pub fn retired(&mut self, cleanup: Instant) -> Result<()> {
            self.custody
                .as_ref()
                .ok_or_else(|| CiError::Message("original private family custody absent".into()))?
                .prove_retired(cleanup)?;
            self.retired = true;
            Ok(())
        }
        pub fn finish(&mut self, cleanup: Instant) -> Result<()> {
            if self.quarantined {
                return Err(CiError::Message(
                    "private custody quarantine cannot be released by retry".into(),
                ));
            }
            if self.launched && !self.retired {
                return Err(CiError::Message(
                    "private namespace retained because original retirement is unproved".into(),
                ));
            }
            if Instant::now() >= cleanup {
                return Err(CiError::Message(
                    "original private namespace cleanup cutoff expired".into(),
                ));
            }
            if self
                .custody
                .as_ref()
                .is_some_and(|custody| Arc::strong_count(custody) != 1)
            {
                self.quarantined = true;
                return Err(CiError::Message(
                    "private custody borrowers remain live after native retirement".into(),
                ));
            }
            self.files.clear();
            self.marker.take();
            self.directories.clear();
            self.custody.take();
            self.output_directories.clear();
            if let Some(owner) = self.owner.take() {
                owner.close()?;
            }
            if Instant::now() >= cleanup {
                return Err(CiError::Message(
                    "owned namespace deletion returned after original cleanup cutoff".into(),
                ));
            }
            Ok(())
        }
    }
    impl Drop for Deployment {
        fn drop(&mut self) {
            if (self.launched && !self.retired) || self.quarantined {
                // Bounded failed-attempt quarantine: retain the readonly leaf
                // and no-delete ancestry guards until this controller exits.
                // Releasing them here would unlock input while a root may live.
                std::mem::forget(std::mem::take(&mut self.files));
                std::mem::forget(std::mem::take(&mut self.directories));
                std::mem::forget(std::mem::take(&mut self.output_directories));
                if let Some(custody) = self.custody.take() {
                    std::mem::forget(custody);
                }
                if let Some(owner) = self.owner.take() {
                    let _retained = owner.keep();
                    let _=std::io::Write::write_all(&mut std::io::stderr().lock(),b"private provider inputs, directory guards and native process owners retained: family retirement or custody settlement unproved; controller-lifetime quarantine only\n");
                }
            } else {
                self.files.clear();
                self.directories.clear();
                self.custody.take();
                self.output_directories.clear();
            }
        }
    }
}
