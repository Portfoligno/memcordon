//! Exact immutable input dispatch for runner-local publication rehearsal.
use super::{
    artifacts::FileRecord,
    bundle::{CandidateBundle, LoadedBundle, PreparedBundle},
    publish::PublicationView,
};
use crate::{CiError, Result};
use std::{collections::BTreeSet, fs, path::Path};

pub enum RehearsalInput {
    Tagged(LoadedBundle),
    Candidate {
        metadata: CandidateBundle,
        payloads: Vec<Vec<u8>>,
    },
}

impl RehearsalInput {
    pub fn load(directory: &Path) -> Result<Self> {
        let tagged = directory.join("prepared.json").is_file();
        let candidate = directory.join("candidate.json").is_file();
        match (tagged, candidate) {
            (true, false) => {
                let bundle = PreparedBundle::load(directory)?;
                let expected: BTreeSet<_> = bundle
                    .metadata
                    .files
                    .iter()
                    .map(|file| file.name.clone())
                    .chain(["prepared.json".to_owned()])
                    .collect();
                let actual = fs::read_dir(directory)?
                    .map(|entry| {
                        let entry = entry?;
                        if !entry.file_type()?.is_file() {
                            return Err(CiError::Message(
                                "rehearsal input contains nonfile".into(),
                            ));
                        }
                        entry
                            .file_name()
                            .into_string()
                            .map_err(|_| CiError::Message("rehearsal filename is not UTF-8".into()))
                    })
                    .collect::<Result<BTreeSet<_>>>()?;
                if actual != expected {
                    return Err(CiError::Message("rehearsal input inventory differs".into()));
                }
                Ok(Self::Tagged(bundle))
            }
            (false, true) => {
                let (metadata, payloads) = CandidateBundle::load(directory)?;
                Ok(Self::Candidate { metadata, payloads })
            }
            _ => Err(CiError::Message(
                "exactly one rehearsal envelope required".into(),
            )),
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Tagged(_) => "tagged",
            Self::Candidate { .. } => "candidate",
        }
    }
    pub fn version(&self) -> &semver::Version {
        match self {
            Self::Tagged(bundle) => &bundle.metadata.source.version,
            Self::Candidate { metadata, .. } => metadata.source.version(),
        }
    }
    pub fn commit(&self) -> &str {
        match self {
            Self::Tagged(bundle) => &bundle.metadata.source.commit,
            Self::Candidate { metadata, .. } => metadata.source.commit(),
        }
    }
    pub fn files(&self) -> &[FileRecord] {
        match self {
            Self::Tagged(bundle) => &bundle.metadata.files,
            Self::Candidate { metadata, .. } => &metadata.files,
        }
    }
    pub fn notes(&self) -> &str {
        match self {
            Self::Tagged(bundle) => &bundle.metadata.notes,
            Self::Candidate { metadata, .. } => metadata
                .notes
                .as_deref()
                .unwrap_or("Candidate notes unavailable; fixture-only publication rehearsal."),
        }
    }
    pub fn notes_placeholder(&self) -> bool {
        matches!(self, Self::Candidate { metadata, .. } if metadata.notes.is_none())
    }
    pub fn repository(&self) -> &str {
        match self {
            Self::Tagged(bundle) => &bundle.metadata.source.repository,
            Self::Candidate { .. } => "fixture/memcordon",
        }
    }
    pub(crate) fn view<'a>(&'a self, fixture_ref: &'a str) -> PublicationView<'a> {
        let payloads = match self {
            Self::Tagged(bundle) => &bundle.payloads,
            Self::Candidate { payloads, .. } => payloads,
        };
        PublicationView {
            version: self.version(),
            commit: self.commit(),
            repository: self.repository(),
            tag_ref: fixture_ref,
            notes: self.notes(),
            files: self.files(),
            payloads,
        }
    }
}
