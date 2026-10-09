//! Administrator-owned image, root and exclusive-account definitions for V3.
//! Resolution is advisory; only the native owner can turn it into release authority.
use std::collections::BTreeSet;
use std::num::{NonZeroU32, NonZeroU64};

use crate::workload_codec::{Encoder, hash_bytes};
use crate::workload_contract::{LogicalId, PolicyEpoch, ProfileRef, reject_duplicate_json_keys};
use crate::workload_contract_v3::*;
use crate::workload_registry::{CallerSelector, GrantChangeDisposition};
use crate::{BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};

pub const IMAGE_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const IMAGE_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;
pub const IMAGE_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const IMAGE_ENTRIES: usize = 16_384;

/// Semantic definition changes require a new profile identity and reviewed vectors.
pub fn profile_reference() -> ProfileRef {
    ProfileRef {
        id: LogicalId::new(PROFILE.into()).expect("fixed profile identifier"),
        semantic_digest: hash_bytes(b"memcordon.profile/linux-tcp4-unix-private-v1\0ipv4-tcp-loopback-only-all-ports;unix-stream-pair-path-abstract;scm-rights-intra-attempt;no-ipv6-udp-raw-packet-netlink;fresh-mount-pid-net-ipc-root;immutable-image-input;declared-generated-exec-work;exclusive-admin-nonroot;no-new-privileges-no-caps;stdio-byte-pipes-three;no-host-proc-or-fd-import;closed-native-abi;clone3-enosys;native-exec-observed;aggregate-empty-before-root-export-retire-account"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ImageEntryV1 {
    Regular {
        path: RootRelativePath,
        sha256: DiagnosticSha256,
        size: u64,
        executable: bool,
    },
    /// The target is another manifest entry; installers reconstruct the link,
    /// never follow a source link or import its inode.
    Symlink {
        path: RootRelativePath,
        target: RootRelativePath,
    },
}
impl ImageEntryV1 {
    pub fn path(&self) -> &RootRelativePath {
        match self {
            Self::Regular { path, .. } | Self::Symlink { path, .. } => path,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageEntrypointV1 {
    pub id: LogicalId,
    pub path: RootRelativePath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupVariableV1 {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeImageDefinitionV1 {
    pub format: String,
    pub revision: u32,
    pub image_id: LogicalId,
    pub target: String,
    pub entries: BoundedVec<ImageEntryV1, IMAGE_ENTRIES>,
    pub entrypoints: BoundedVec<ImageEntrypointV1, 16>,
    /// Absolute-in-target-root library search paths, represented root-relative.
    pub library_directories: BoundedVec<RootRelativePath, 32>,
    pub startup_environment: BoundedVec<StartupVariableV1, 32>,
}

impl RuntimeImageDefinitionV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > IMAGE_MANIFEST_BYTES {
            return Err("image manifest exceeds byte bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.runtime-image"
            || self.revision != 1
            || !matches!(
                self.target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
            || self.entries.as_slice().is_empty()
        {
            return Err("invalid image format/target/empty inventory".into());
        }
        let mut paths = BTreeSet::new();
        let mut bytes = 0_u64;
        for entry in self.entries.as_slice() {
            if !paths.insert(entry.path()) || entry.path().as_str().split('/').count() > 64 {
                return Err("duplicate or excessively deep image path".into());
            }
            if let ImageEntryV1::Regular { size, .. } = entry {
                if *size > IMAGE_ENTRY_BYTES {
                    return Err("image member exceeds byte bound".into());
                }
                bytes = bytes
                    .checked_add(*size)
                    .ok_or("image byte count overflow")?;
                if bytes > IMAGE_TOTAL_BYTES {
                    return Err("image exceeds total byte bound".into());
                }
            }
        }
        for entry in self.entries.as_slice() {
            // A file or symlink must never also be a parent directory.
            let path = entry.path().as_str();
            let mut parents = path.rsplit('/');
            let mut prefix = path;
            while parents.next().is_some() {
                let Some((parent, _)) = prefix.rsplit_once('/') else {
                    break;
                };
                if paths.iter().any(|path| path.as_str() == parent) {
                    return Err("image member aliases parent directory".into());
                }
                prefix = parent;
            }
            if let ImageEntryV1::Symlink { path, target } = entry {
                if path == target || !paths.contains(target) {
                    return Err("image link target is absent or self-referential".into());
                }
                let mut current = target;
                let mut seen = BTreeSet::from([path]);
                loop {
                    if !seen.insert(current) {
                        return Err("image symlink cycle".into());
                    }
                    match self
                        .entries
                        .as_slice()
                        .iter()
                        .find(|entry| entry.path() == current)
                    {
                        Some(ImageEntryV1::Symlink { target, .. }) => current = target,
                        Some(ImageEntryV1::Regular { .. }) => break,
                        None => return Err("missing resolved image object".into()),
                    }
                }
            }
        }
        let mut ids = BTreeSet::new();
        for entrypoint in self.entrypoints.as_slice() {
            if !ids.insert(&entrypoint.id) || !self.entries.as_slice().iter().any(|entry|
                matches!(entry, ImageEntryV1::Regular {path,executable:true,..} if path == &entrypoint.path))
            { return Err("invalid or duplicate executable entrypoint".into()); }
        }
        let mut names = BTreeSet::new();
        for variable in self.startup_environment.as_slice() {
            if variable.name.is_empty()
                || variable.name.len() > 128
                || variable.value.len() > 4096
                || !variable
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || variable.value.as_bytes().contains(&0)
                || !names.insert(&variable.name)
                || variable.name.starts_with("LD_")
                || variable.name.starts_with("DYLD_")
                || matches!(
                    variable.name.as_str(),
                    "GLIBC_TUNABLES"
                        | "GCONV_PATH"
                        | "LOCPATH"
                        | "LIBRARY_PATH"
                        | "RUSTC_WRAPPER"
                        | "RUSTC_WORKSPACE_WRAPPER"
                        | "RUSTFLAGS"
                        | "CARGO_ENCODED_RUSTFLAGS"
                )
            {
                return Err("unsafe or duplicate trusted-startup environment".into());
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut e = Encoder::new(b"memcordon.runtime-image/version1", IMAGE_MANIFEST_BYTES)?;
        e.id(&self.image_id)?;
        encode_text(&mut e, &self.target)?;
        let mut entries: Vec<_> = self.entries.as_slice().iter().collect();
        entries.sort_by_key(|entry| entry.path());
        e.count(entries.len())?;
        for entry in entries {
            encode_text(&mut e, entry.path().as_str())?;
            match entry {
                ImageEntryV1::Regular {
                    sha256,
                    size,
                    executable,
                    ..
                } => {
                    e.byte(1)?;
                    e.digest(sha256)?;
                    e.u64(*size)?;
                    e.byte(u8::from(*executable))?;
                }
                ImageEntryV1::Symlink { target, .. } => {
                    e.byte(2)?;
                    encode_text(&mut e, target.as_str())?;
                }
            }
        }
        let mut entrypoints: Vec<_> = self.entrypoints.as_slice().iter().collect();
        entrypoints.sort_by_key(|item| &item.id);
        e.count(entrypoints.len())?;
        for item in entrypoints {
            e.id(&item.id)?;
            encode_text(&mut e, item.path.as_str())?;
        }
        // Search order is meaningful and must not be sorted.
        e.count(self.library_directories.as_slice().len())?;
        for path in self.library_directories.as_slice() {
            encode_text(&mut e, path.as_str())?;
        }
        let mut variables: Vec<_> = self.startup_environment.as_slice().iter().collect();
        variables.sort_by_key(|item| &item.name);
        e.count(variables.len())?;
        for item in variables {
            encode_text(&mut e, &item.name)?;
            encode_text(&mut e, &item.value)?;
        }
        Ok(e.finish())
    }
    pub fn reference(&self) -> Result<BoundObjectRef, String> {
        Ok(BoundObjectRef {
            id: self.image_id.clone(),
            digest: hash_bytes(&self.canonical_bytes()?),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WritableRootV1 {
    pub id: LogicalId,
    pub path: RootRelativePath,
    pub byte_limit: NonZeroU64,
    pub generated_execution: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootLayoutDefinitionV1 {
    pub format: String,
    pub revision: u32,
    pub layout_id: LogicalId,
    pub runtime_image: BoundObjectRef,
    pub input_image: BoundObjectRef,
    pub writable_roots: BoundedVec<WritableRootV1, 16>,
    pub output_files: BoundedVec<RootRelativePath, 64>,
}
impl RootLayoutDefinitionV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.root-layout"
            || self.revision != 1
            || self.writable_roots.as_slice().is_empty()
        {
            return Err("invalid root layout".into());
        }
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for root in self.writable_roots.as_slice() {
            if !ids.insert(&root.id)
                || !paths.insert(&root.path)
                || root.byte_limit.get() > IMAGE_TOTAL_BYTES
                || matches!(
                    root.path.as_str().split('/').next(),
                    Some("proc" | "dev" | "sys" | "etc" | "run")
                )
            {
                return Err("unsafe or duplicate writable root".into());
            }
            for other in self.writable_roots.as_slice() {
                if root.id != other.id && is_beneath(&root.path, &other.path) {
                    return Err("overlapping writable roots".into());
                }
            }
        }
        let mut outputs = BTreeSet::new();
        for output in self.output_files.as_slice() {
            if !outputs.insert(output)
                || !self
                    .writable_roots
                    .as_slice()
                    .iter()
                    .any(|root| is_beneath(output, &root.path))
            {
                return Err("duplicate or ungranted output".into());
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut e = Encoder::new(b"memcordon.root-layout/version1", 64 * 1024)?;
        e.id(&self.layout_id)?;
        for reference in [&self.runtime_image, &self.input_image] {
            e.id(&reference.id)?;
            e.digest(&reference.digest)?;
        }
        let mut roots: Vec<_> = self.writable_roots.as_slice().iter().collect();
        roots.sort_by_key(|root| &root.id);
        e.count(roots.len())?;
        for root in roots {
            e.id(&root.id)?;
            encode_text(&mut e, root.path.as_str())?;
            e.u64(root.byte_limit.get())?;
            e.byte(u8::from(root.generated_execution))?;
        }
        let mut outputs: Vec<_> = self.output_files.as_slice().iter().collect();
        outputs.sort();
        e.count(outputs.len())?;
        for path in outputs {
            encode_text(&mut e, path.as_str())?;
        }
        Ok(e.finish())
    }
    pub fn reference(&self) -> Result<BoundObjectRef, String> {
        Ok(BoundObjectRef {
            id: self.layout_id.clone(),
            digest: hash_bytes(&self.canonical_bytes()?),
        })
    }
}

pub fn is_beneath(path: &RootRelativePath, root: &RootRelativePath) -> bool {
    path.as_str()
        .strip_prefix(root.as_str())
        .is_some_and(|suffix| suffix.starts_with('/'))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExclusiveIdentityDefinitionV3 {
    pub identity_id: LogicalId,
    pub enabled: bool,
    pub uid: NonZeroU32,
    pub gid: NonZeroU32,
    pub supplementary_groups: BoundedVec<NonZeroU32, 32>,
    pub exclusive_use_policy: BoundObjectRef,
    pub reservation_key: LogicalId,
}
impl ExclusiveIdentityDefinitionV3 {
    pub fn reference(&self) -> Result<ExclusiveAdministratorIdentityRef, String> {
        let mut groups: Vec<_> = self
            .supplementary_groups
            .as_slice()
            .iter()
            .map(|gid| gid.get())
            .collect();
        groups.sort();
        if groups.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("duplicate exclusive identity group".into());
        }
        let mut e = Encoder::new(b"memcordon.exclusive-identity/version1", 4096)?;
        e.id(&self.identity_id)?;
        e.u64(u64::from(self.uid.get()))?;
        e.u64(u64::from(self.gid.get()))?;
        e.count(groups.len())?;
        for gid in groups {
            e.u64(u64::from(gid))?;
        }
        e.id(&self.exclusive_use_policy.id)?;
        e.digest(&self.exclusive_use_policy.digest)?;
        e.id(&self.reservation_key)?;
        Ok(ExclusiveAdministratorIdentityRef {
            identity: BoundObjectRef {
                id: self.identity_id.clone(),
                digest: hash_bytes(&e.finish()),
            },
            exclusive_use_policy: self.exclusive_use_policy.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrantV3 {
    pub id: LogicalId,
    pub revision: NonZeroU64,
    pub enabled: bool,
    pub callers: BoundedVec<CallerSelector, 4>,
    pub approved_plans: BoundedVec<DiagnosticSha256, 16>,
    pub profile: ProfileRef,
    pub execution_identity: ExclusiveAdministratorIdentityRef,
    pub runtime_image: BoundObjectRef,
    pub input_image: BoundObjectRef,
    pub root_layout: BoundObjectRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePrivatePolicyRegistryV3 {
    pub format: String,
    pub revision: u32,
    /// Explicit old registry; no conversion silently authorizes the new profile.
    pub legacy: crate::workload_registry_v2::RuntimePrivatePolicyRegistry,
    pub execution_identities: BoundedVec<ExclusiveIdentityDefinitionV3, 32>,
    pub images: BoundedVec<RuntimeImageDefinitionV1, 16>,
    pub root_layouts: BoundedVec<RootLayoutDefinitionV1, 16>,
    pub grants: BoundedVec<PolicyGrantV3, 128>,
    pub active_attempt_disposition: GrantChangeDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionCodeV3 {
    StaleEpoch,
    UnauthorizedCaller,
    UnauthorizedPlan,
    UnauthorizedProfile,
    UnauthorizedImage,
    UnauthorizedIdentity,
    UnauthorizedRoot,
    DisabledGrant,
    WrongGrantRevision,
    IncompatibleRequirement,
}

pub struct ResolvedV3<'a> {
    pub grant: &'a PolicyGrantV3,
    pub identity: &'a ExclusiveIdentityDefinitionV3,
    pub image: &'a RuntimeImageDefinitionV1,
    pub input: &'a RuntimeImageDefinitionV1,
    pub layout: &'a RootLayoutDefinitionV1,
}

impl RuntimePrivatePolicyRegistryV3 {
    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        Ok(hash_bytes(&self.canonical_bytes()?))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut e = Encoder::new(
            b"memcordon.local-private-policy/version2",
            IMAGE_MANIFEST_BYTES,
        )?;
        e.digest(&self.legacy.canonical_digest()?)?;
        e.byte(match self.active_attempt_disposition {
            GrantChangeDisposition::DrainExisting => 1,
            GrantChangeDisposition::RevokeActive => 2,
        })?;
        let mut identities: Vec<_> = self.execution_identities.as_slice().iter().collect();
        identities.sort_by_key(|identity| &identity.identity_id);
        e.count(identities.len())?;
        for identity in identities {
            let reference = identity.reference()?;
            e.id(&reference.identity.id)?;
            e.digest(&reference.identity.digest)?;
            e.byte(u8::from(identity.enabled))?;
        }
        let mut images: Vec<_> = self.images.as_slice().iter().collect();
        images.sort_by_key(|image| &image.image_id);
        e.count(images.len())?;
        for image in images {
            let reference = image.reference()?;
            e.id(&reference.id)?;
            e.digest(&reference.digest)?;
        }
        let mut layouts: Vec<_> = self.root_layouts.as_slice().iter().collect();
        layouts.sort_by_key(|layout| &layout.layout_id);
        e.count(layouts.len())?;
        for layout in layouts {
            let reference = layout.reference()?;
            e.id(&reference.id)?;
            e.digest(&reference.digest)?;
        }
        let mut grants: Vec<_> = self.grants.as_slice().iter().collect();
        grants.sort_by_key(|grant| &grant.id);
        e.count(grants.len())?;
        for grant in grants {
            e.id(&grant.id)?;
            e.u64(grant.revision.get())?;
            e.byte(u8::from(grant.enabled))?;
            let mut callers: Vec<_> = grant
                .callers
                .as_slice()
                .iter()
                .map(|caller| match caller {
                    CallerSelector::Linux { uid } => Ok(*uid),
                    _ => Err("combined canonical caller is not Linux"),
                })
                .collect::<Result<_, _>>()?;
            callers.sort();
            e.count(callers.len())?;
            for uid in callers {
                e.u64(u64::from(uid))?;
            }
            let mut plans: Vec<_> = grant.approved_plans.as_slice().iter().collect();
            plans.sort_by_key(|plan| plan.bytes());
            e.count(plans.len())?;
            for plan in plans {
                e.digest(plan)?;
            }
            e.id(&grant.profile.id)?;
            e.digest(&grant.profile.semantic_digest)?;
            for reference in [
                &grant.execution_identity.identity,
                &grant.execution_identity.exclusive_use_policy,
                &grant.runtime_image,
                &grant.input_image,
                &grant.root_layout,
            ] {
                e.id(&reference.id)?;
                e.digest(&reference.digest)?;
            }
        }
        Ok(e.finish())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > IMAGE_MANIFEST_BYTES {
            return Err("combined registry exceeds byte bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.local-private-policy" || self.revision != 2 {
            return Err("combined registry requires revision two".into());
        }
        self.legacy.validate()?;
        let mut identities = BTreeSet::new();
        let mut uids = BTreeSet::new();
        let mut reservations = BTreeSet::new();
        for identity in self.execution_identities.as_slice() {
            identity.reference()?;
            if !identities.insert(&identity.identity_id)
                || !uids.insert(identity.uid)
                || !reservations.insert(&identity.reservation_key)
                || self
                    .legacy
                    .execution_identities
                    .as_slice()
                    .iter()
                    .any(|legacy| {
                        legacy.uid == identity.uid || legacy.reference.id == identity.identity_id
                    })
                || self.legacy.grants.as_slice().iter().any(|grant| {
                    grant.callers.as_slice().contains(&CallerSelector::Linux {
                        uid: identity.uid.get(),
                    })
                })
            {
                return Err(
                    "exclusive account id/uid/reservation alias across current or legacy policy"
                        .into(),
                );
            }
        }
        let mut images = BTreeSet::new();
        for image in self.images.as_slice() {
            image.validate()?;
            if !images.insert(&image.image_id) {
                return Err("duplicate image".into());
            }
        }
        let mut layouts = BTreeSet::new();
        for layout in self.root_layouts.as_slice() {
            layout.validate()?;
            if !layouts.insert(&layout.layout_id)
                || !self
                    .images
                    .as_slice()
                    .iter()
                    .any(|image| image.reference().ok().as_ref() == Some(&layout.runtime_image))
                || !self
                    .images
                    .as_slice()
                    .iter()
                    .any(|image| image.reference().ok().as_ref() == Some(&layout.input_image))
            {
                return Err("root layout image binding missing".into());
            }
            let selected: Vec<_> = self
                .images
                .as_slice()
                .iter()
                .filter(|image| {
                    image.reference().ok().as_ref() == Some(&layout.runtime_image)
                        || image.reference().ok().as_ref() == Some(&layout.input_image)
                })
                .collect();
            if selected.len() != 2 || selected[0].target != selected[1].target {
                return Err("root layout must bind two images of the same native target".into());
            }
            if layout.runtime_image == layout.input_image {
                return Err("runtime and input images must have distinct identities".into());
            }
            let entries: Vec<_> = selected
                .iter()
                .flat_map(|image| image.entries.as_slice())
                .collect();
            for (index, entry) in entries.iter().enumerate() {
                if entries[..index].iter().any(|prior| {
                    prior.path() == entry.path()
                        || is_beneath(prior.path(), entry.path())
                        || is_beneath(entry.path(), prior.path())
                }) {
                    return Err("merged immutable image aliases file or directory authority".into());
                }
                if layout.writable_roots.as_slice().iter().any(|root| {
                    root.path == *entry.path()
                        || is_beneath(entry.path(), &root.path)
                        || is_beneath(&root.path, entry.path())
                }) {
                    return Err("writable root overlaps immutable image member".into());
                }
            }
            for image in &selected {
                for directory in image.library_directories.as_slice() {
                    if layout.writable_roots.as_slice().iter().any(|root| {
                        root.path == *directory
                            || is_beneath(directory, &root.path)
                            || is_beneath(&root.path, directory)
                    }) {
                        return Err("loader search directory overlaps writable root".into());
                    }
                }
                for variable in image.startup_environment.as_slice() {
                    if variable.name == "PATH" {
                        for value in variable.value.split(':') {
                            let path = RootRelativePath::new(
                                value
                                    .strip_prefix('/')
                                    .ok_or("trusted PATH must be absolute inside image")?
                                    .into(),
                            )?;
                            if !image
                                .entries
                                .as_slice()
                                .iter()
                                .any(|entry| is_beneath(entry.path(), &path))
                                || layout.writable_roots.as_slice().iter().any(|root| {
                                    root.path == path
                                        || is_beneath(&path, &root.path)
                                        || is_beneath(&root.path, &path)
                                })
                            {
                                return Err("trusted PATH is absent from immutable image or overlaps writable root".into());
                            }
                        }
                    }
                }
            }
        }
        let mut grants = BTreeSet::new();
        for grant in self.grants.as_slice() {
            if !grants.insert(&grant.id)
                || grant.profile != profile_reference()
                || grant.callers.as_slice().is_empty()
                || grant.approved_plans.as_slice().is_empty()
                || !self.execution_identities.as_slice().iter().any(|identity| {
                    identity.reference().ok().as_ref() == Some(&grant.execution_identity)
                })
                || !self.root_layouts.as_slice().iter().any(|layout| {
                    layout.reference().ok().as_ref() == Some(&grant.root_layout)
                        && layout.runtime_image == grant.runtime_image
                        && layout.input_image == grant.input_image
                })
            {
                return Err("invalid combined grant or object binding".into());
            }
            let mut callers = BTreeSet::new();
            for caller in grant.callers.as_slice() {
                let CallerSelector::Linux { uid } = caller else {
                    return Err("combined grant requires native Linux caller".into());
                };
                if !callers.insert(*uid)
                    || self
                        .execution_identities
                        .as_slice()
                        .iter()
                        .any(|identity| identity.uid.get() == *uid)
                {
                    return Err("combined caller must differ from exclusive target".into());
                }
            }
            let mut plans = BTreeSet::new();
            for plan in grant.approved_plans.as_slice() {
                if !plans.insert(plan.bytes()) {
                    return Err("duplicate approved plan".into());
                }
            }
        }
        Ok(())
    }
    pub fn resolve<'a>(
        &'a self,
        request: &WorkloadContractV3,
        caller_uid: u32,
        epoch: &PolicyEpoch,
    ) -> Result<ResolvedV3<'a>, AdmissionCodeV3> {
        if request.validate().is_err() {
            return Err(AdmissionCodeV3::IncompatibleRequirement);
        }
        if &request.expected_epoch != epoch {
            return Err(AdmissionCodeV3::StaleEpoch);
        }
        let grant = self
            .grants
            .as_slice()
            .iter()
            .find(|grant| grant.id == request.authorization.grant_id)
            .ok_or(AdmissionCodeV3::DisabledGrant)?;
        if !grant.enabled {
            return Err(AdmissionCodeV3::DisabledGrant);
        }
        if grant.revision != request.authorization.grant_revision {
            return Err(AdmissionCodeV3::WrongGrantRevision);
        }
        if !grant
            .callers
            .as_slice()
            .contains(&CallerSelector::Linux { uid: caller_uid })
        {
            return Err(AdmissionCodeV3::UnauthorizedCaller);
        }
        if !grant
            .approved_plans
            .as_slice()
            .contains(&request.workload_plan_digest)
        {
            return Err(AdmissionCodeV3::UnauthorizedPlan);
        }
        if grant.profile != request.authorized_profile || grant.profile != profile_reference() {
            return Err(AdmissionCodeV3::UnauthorizedProfile);
        }
        if grant.execution_identity != request.execution_identity {
            return Err(AdmissionCodeV3::UnauthorizedIdentity);
        }
        if grant.runtime_image != request.runtime_image || grant.input_image != request.input_image
        {
            return Err(AdmissionCodeV3::UnauthorizedImage);
        }
        if grant.root_layout != request.root_layout {
            return Err(AdmissionCodeV3::UnauthorizedRoot);
        }
        let identity = self
            .execution_identities
            .as_slice()
            .iter()
            .find(|value| {
                value.enabled
                    && value.reference().ok().as_ref() == Some(&request.execution_identity)
            })
            .ok_or(AdmissionCodeV3::UnauthorizedIdentity)?;
        let image = self
            .images
            .as_slice()
            .iter()
            .find(|value| value.reference().ok().as_ref() == Some(&request.runtime_image))
            .ok_or(AdmissionCodeV3::UnauthorizedImage)?;
        let input = self
            .images
            .as_slice()
            .iter()
            .find(|value| value.reference().ok().as_ref() == Some(&request.input_image))
            .ok_or(AdmissionCodeV3::UnauthorizedImage)?;
        let layout = self
            .root_layouts
            .as_slice()
            .iter()
            .find(|value| value.reference().ok().as_ref() == Some(&request.root_layout))
            .ok_or(AdmissionCodeV3::UnauthorizedRoot)?;
        if !image
            .entrypoints
            .as_slice()
            .iter()
            .any(|entry| entry.id == request.launch.entrypoint)
        {
            return Err(AdmissionCodeV3::UnauthorizedImage);
        }
        if !layout.writable_roots.as_slice().iter().any(|root| {
            root.path == request.launch.working_directory
                || is_beneath(&request.launch.working_directory, &root.path)
        }) {
            return Err(AdmissionCodeV3::UnauthorizedRoot);
        }
        for requirement in request.requirements.as_slice() {
            match requirement {
                RequirementV3::UnixPathStream { writable_root, .. }
                    if !layout
                        .writable_roots
                        .as_slice()
                        .iter()
                        .any(|root| &root.id == writable_root) =>
                {
                    return Err(AdmissionCodeV3::IncompatibleRequirement);
                }
                RequirementV3::GeneratedExecutable { writable_root, .. }
                    if !layout
                        .writable_roots
                        .as_slice()
                        .iter()
                        .any(|root| &root.id == writable_root && root.generated_execution) =>
                {
                    return Err(AdmissionCodeV3::IncompatibleRequirement);
                }
                _ => {}
            }
        }
        Ok(ResolvedV3 {
            grant,
            identity,
            image,
            input,
            layout,
        })
    }
}
