//! A fresh declared private-input experiment; never changes installed consumer selection.
#[cfg(windows)]
pub mod native {
    use crate::{
        CiError, Result,
        windows_installed_cases::SelectedArtifact,
        windows_native_files::{self, HeldWindowsArtifact},
        windows_provider_projection_record::{Candidate, CatalogSnapshot, PrivateInput},
    };
    use std::{
        fs,
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            fs::OpenOptionsExt,
        },
        path::{Path, PathBuf},
        time::Instant,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
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
    fn seal(path: &Path, directory: bool, sid: &str, work: Instant) -> Result<serde_json::Value> {
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
                &file, directory, sid, work,
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
        files: Vec<(PathBuf, HeldWindowsArtifact)>,
        witnesses: Vec<PrivateInput>,
        directories: Vec<fs::File>,
        pub inventory: serde_json::Value,
        launched: bool,
        retired: bool,
    }
    impl Deployment {
        pub fn create(
            source: &SelectedArtifact,
            target: &str,
            parent: &Path,
            work: Instant,
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
            fs::create_dir(&local)?;
            live(work)?;
            let mut directories = directories;
            directories.extend(windows_native_files::hold_ancestors(&local)?);
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
                files: vec![(path, held)],
                witnesses: Vec::new(),
                directories,
                inventory: serde_json::json!({"format":"memcordon.declared-provider-inputs","revision":1,"diagnostic_only":true,"acceptance_authority":false,"original_file_identities_preserved":false,"fixture_manifest":manifest,"sources":[],"sealed":false}),
                launched: false,
                retired: false,
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
                let held = windows_native_files::hold_artifact(&source, None, 64 * 1024 * 1024)?;
                live(work)?;
                bytes = bytes
                    .checked_add(held.bytes.len())
                    .ok_or_else(|| CiError::Message("provider input byte overflow".into()))?;
                if bytes > 256 * 1024 * 1024 {
                    return Err(CiError::Message("provider input total byte bound".into()));
                }
                crate::release::target::validate_executable(&held.bytes, target)?;
                live(work)?;
                let source_identity = held.identity(&source)?;
                live(work)?;
                let destination = self.local.join(&candidate.basename);
                let copied =
                    windows_native_files::copy_owned_artifact(&source, &destination, &held.sha256)?;
                live(work)?;
                windows_native_files::verify_named_artifact(&held, &source)?;
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
                records.push(serde_json::json!({"catalog_ids":candidate.catalog_ids,"provider_ids":candidate.provider_ids,"original_path_utf16":candidate.expanded_path,"original_volume_serial":source_identity.0,"original_file_index":source_identity.1,"private_path_utf16":destination.as_os_str().encode_wide().collect::<Vec<_>>(),"private_native_path_utf16":native_path,"private_identity":private_identity,"bytes":copied.bytes.len(),"sha256":copied.sha256,"source_view":"native","changed_file_identity":true}));
                self.files.push((destination, copied));
            }
            self.inventory["catalog"] = serde_json::to_value(catalog)?;
            self.inventory["sources"] = serde_json::json!(records);
            live(work)
        }
        pub fn seal(&mut self, sid: &str, work: Instant) -> Result<()> {
            let mut security = Vec::new();
            for (path, held) in &self.files {
                live(work)?;
                security.push(seal(path, false, sid, work)?);
                windows_native_files::verify_named_artifact(held, path)?;
            }
            security.push(seal(&self.local, true, sid, work)?);
            security.push(seal(&self.input_root, true, sid, work)?);
            // Declare the new owned ancestor too; host ancestors remain untouched.
            let base = self
                .input_root
                .parent()
                .ok_or_else(|| CiError::Message("owned input ancestor absent".into()))?;
            security.push(seal(base, true, sid, work)?);
            self.inventory["security"] = serde_json::json!(security);
            self.inventory["sealed"] = serde_json::json!(true);
            live(work)
        }
        pub fn paths(&self) -> Vec<PathBuf> {
            self.files.iter().map(|(path, _)| path.clone()).collect()
        }
        pub fn witnesses(&self) -> &[PrivateInput] {
            &self.witnesses
        }
        pub fn verify(&self, work: Instant) -> Result<()> {
            if self.inventory["sealed"] != true {
                return Err(CiError::Message(
                    "private input sealing not complete".into(),
                ));
            }
            for (path, held) in &self.files {
                live(work)?;
                windows_native_files::verify_named_artifact(held, path)?;
            }
            live(work)
        }
        pub fn launched(&mut self) {
            self.launched = true;
        }
        pub fn retired(&mut self) {
            self.retired = true;
        }
        pub fn finish(&mut self, cleanup: Instant) -> Result<()> {
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
            self.files.clear();
            self.directories.clear();
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
            if self.launched && !self.retired {
                // Bounded failed-attempt quarantine: retain the readonly leaf
                // and no-delete ancestry guards until this controller exits.
                // Releasing them here would unlock input while a root may live.
                std::mem::forget(std::mem::take(&mut self.files));
                std::mem::forget(std::mem::take(&mut self.directories));
                if let Some(owner) = self.owner.take() {
                    let _retained = owner.keep();
                    let _=std::io::Write::write_all(&mut std::io::stderr().lock(),b"private provider inputs and guards retained: original family retirement unproved\n");
                }
            } else {
                self.files.clear();
                self.directories.clear();
            }
        }
    }
}
