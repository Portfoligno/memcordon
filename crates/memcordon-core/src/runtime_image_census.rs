//! Read-only observations of the complete protected, manifest-projected image.
use crate::DiagnosticSha256;
use crate::workload_contract_v3::{BoundObjectRef, RootRelativePath};
use crate::workload_registry_v3::{ImageEntryV1, RuntimeImageDefinitionV1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeImageCensusIdentityV1 {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub length: u64,
}

impl RuntimeImageCensusIdentityV1 {
    fn protected_directory(&self) -> bool {
        self.inode != 0
            && self.uid == 0
            && self.mode & 0o170000 == 0o040000
            && self.mode & 0o022 == 0
            && self.nlink != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeImageCensusObjectV1 {
    Directory,
    Regular {
        sha256: DiagnosticSha256,
        capability_absent: bool,
    },
    Symlink {
        target: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeImageCensusMemberV1 {
    pub path: RootRelativePath,
    pub identity: RuntimeImageCensusIdentityV1,
    pub object: RuntimeImageCensusObjectV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeImageCensusV1 {
    pub format: String,
    pub revision: u32,
    pub reference: BoundObjectRef,
    pub target: String,
    pub definition_sha256: DiagnosticSha256,
    pub cutoff_unix_millis: u64,
    pub store: RuntimeImageCensusIdentityV1,
    pub root: RuntimeImageCensusIdentityV1,
    pub members: Vec<RuntimeImageCensusMemberV1>,
}

impl RuntimeImageCensusV1 {
    pub fn expected_paths(
        definition: &RuntimeImageDefinitionV1,
    ) -> Result<Vec<RootRelativePath>, String> {
        expected_members(definition)?
            .into_keys()
            .map(RootRelativePath::new)
            .collect()
    }

    /// This validates an observation, not runtime admission or execution authority.
    pub fn validate_for_definition(
        &self,
        definition: &RuntimeImageDefinitionV1,
        definition_sha256: &DiagnosticSha256,
    ) -> Result<(), String> {
        definition.validate()?;
        if self.format != "memcordon.runtime-image-census"
            || self.revision != 1
            || self.reference != definition.reference()?
            || self.target != definition.target
            || &self.definition_sha256 != definition_sha256
            || self.cutoff_unix_millis == 0
            || !self.store.protected_directory()
            || !self.root.protected_directory()
            || self.root.device != self.store.device
            || (self.root.device, self.root.inode) == (self.store.device, self.store.inode)
        {
            return Err("installed image census root/reference/definition differs".into());
        }
        let expected = expected_members(definition)?;
        if self.members.len() != expected.len() {
            return Err("installed image census population differs".into());
        }
        let mut identities = std::collections::BTreeSet::from([
            (self.store.device, self.store.inode),
            (self.root.device, self.root.inode),
        ]);
        for ((path, entry), actual) in expected.iter().zip(&self.members) {
            let identity = &actual.identity;
            if actual.path.as_str() != path
                || identity.device != self.root.device
                || identity.inode == 0
                || identity.uid != 0
                || identity.nlink == 0
                || !identities.insert((identity.device, identity.inode))
            {
                return Err("installed image census member identity/path differs".into());
            }
            match (entry, &actual.object) {
                (None, RuntimeImageCensusObjectV1::Directory)
                    if path != ".memcordon-image.json" && identity.protected_directory() => {}
                (
                    None,
                    RuntimeImageCensusObjectV1::Regular {
                        sha256,
                        capability_absent: true,
                    },
                ) if path == ".memcordon-image.json"
                    && sha256 == definition_sha256
                    && identity.nlink == 1
                    && identity.mode == 0o100444 => {}
                (
                    Some(ImageEntryV1::Regular {
                        sha256,
                        size,
                        executable,
                        ..
                    }),
                    RuntimeImageCensusObjectV1::Regular {
                        sha256: observed,
                        capability_absent: true,
                    },
                ) if sha256 == observed
                    && identity.length == *size
                    && identity.nlink == 1
                    && identity.mode == if *executable { 0o100555 } else { 0o100444 } => {}
                (
                    Some(ImageEntryV1::Symlink { path, target }),
                    RuntimeImageCensusObjectV1::Symlink { target: observed },
                ) => {
                    let parents = path.as_str().split('/').count().saturating_sub(1);
                    let mut components = vec![".."; parents];
                    components.extend(target.as_str().split('/'));
                    if *observed != components.join("/")
                        || identity.nlink != 1
                        || identity.mode != 0o120777
                    {
                        return Err("installed image census declared link differs".into());
                    }
                }
                _ => {
                    return Err("installed image census member type/content/custody differs".into());
                }
            }
        }
        Ok(())
    }
}

fn expected_members(
    definition: &RuntimeImageDefinitionV1,
) -> Result<BTreeMap<String, Option<&ImageEntryV1>>, String> {
    definition.validate()?;
    let mut expected = BTreeMap::new();
    expected.insert(".memcordon-image.json".to_owned(), None);
    for entry in definition.entries.as_slice() {
        let components: Vec<_> = entry.path().as_str().split('/').collect();
        for count in 1..components.len() {
            let parent = components[..count].join("/");
            if parent == ".memcordon-image.json"
                || expected
                    .insert(parent, None)
                    .is_some_and(|prior| prior.is_some())
            {
                return Err("image census has a declared object as directory".into());
            }
        }
        if expected
            .insert(entry.path().as_str().to_owned(), Some(entry))
            .is_some()
        {
            return Err("image census definition overlaps reserved/directory members".into());
        }
    }
    Ok(expected)
}
