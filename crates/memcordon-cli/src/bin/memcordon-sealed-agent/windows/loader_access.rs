use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, c_void};
use std::fmt::Write as _;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CompareObjectHandles, GetLastError, HANDLE, STATUS_ACCESS_DENIED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, GetFileInformationByHandle, GetFinalPathNameByHandleW, OPEN_EXISTING,
    ReadFile,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use super::pipe::OwnedHandle;

pub(crate) const LOADER_ANCESTOR_IDENTITY_ACCESS: u32 = 0;
pub(crate) const LOADER_FILE_ACCESS: u32 = 0x0010_00a1;
pub(crate) const KNOWN_DLL_DIRECTORY_ACCESS: u32 = 0x0000_0003;
pub(crate) const KNOWN_DLL_SECTION_ACCESS: u32 = 0x0000_000d;
const LOADER_PIN_SHARE_MODE: u32 = FILE_SHARE_READ;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const SECTION_BASIC_INFORMATION_CLASS: u32 = 0;
const SECTION_IMAGE_INFORMATION_CLASS: u32 = 1;
const SEC_IMAGE: u32 = 0x0100_0000;
const MAX_LOADER_ANCESTORS: usize = 16;
const MAX_LOADER_MODULES: usize = 128;
const MAX_LOADER_GRAPH_EDGES: usize = 1_024;
const MAX_LOADER_GRAPH_DEPTH: usize = 16;
const MAX_LOADER_FORWARDER_HOPS: usize = 16;
const MAX_LOADER_BASENAME_BYTES: usize = 128;
const MAX_MAPPED_IMAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeLoaderProgressStage {
    SourceBootstrap,
    SourceSystemAncestry,
    SourceLoaderGraph,
    SourceKnownDlls,
    TargetBootstrap,
    TargetKnownDlls,
    TargetModules,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeLoaderProgress {
    pub(crate) stage: NativeLoaderProgressStage,
    pub(crate) completed: u32,
    // This is an exact stage total when known, never a capacity or estimate.
    // Recursive graph discovery freezes it only in the final closure frame.
    pub(crate) total: Option<u32>,
}

pub(crate) struct NativeLoaderAttestationBudget<'a> {
    deadline: Instant,
    publish: &'a mut dyn FnMut(NativeLoaderProgress) -> Result<(), String>,
}

impl<'a> NativeLoaderAttestationBudget<'a> {
    pub(crate) fn new(
        deadline: Instant,
        publish: &'a mut dyn FnMut(NativeLoaderProgress) -> Result<(), String>,
    ) -> Self {
        Self { deadline, publish }
    }

    fn check(
        &mut self,
        stage: NativeLoaderProgressStage,
        completed: usize,
        total: Option<usize>,
    ) -> Result<(), NativeLoaderAccessFailureV1> {
        self.check_deadline(stage, completed, total)?;
        let completed = u32::try_from(completed).map_err(|_| {
            contract_failure(
                "native-loader-attestation",
                Path::new(stage.diagnostic()),
                "progress-counter-width",
                "completed progress is not representable as u32",
            )
        })?;
        let total = total
            .map(|value| {
                u32::try_from(value).map_err(|_| {
                    contract_failure(
                        "native-loader-attestation",
                        Path::new(stage.diagnostic()),
                        "progress-counter-width",
                        "total progress is not representable as u32",
                    )
                })
            })
            .transpose()?;
        (self.publish)(NativeLoaderProgress {
            stage,
            completed,
            total,
        })
        .map_err(|detail| {
            contract_failure(
                "native-loader-attestation",
                Path::new(stage.diagnostic()),
                "progress-publication",
                detail,
            )
        })
    }

    fn check_deadline(
        &self,
        stage: NativeLoaderProgressStage,
        completed: usize,
        total: Option<usize>,
    ) -> Result<(), NativeLoaderAccessFailureV1> {
        if Instant::now() >= self.deadline {
            return Err(contract_failure(
                "native-loader-attestation",
                Path::new(stage.diagnostic()),
                "overall-deadline",
                format!(
                    "stage={} completed={completed} total={} overall deadline elapsed",
                    stage.diagnostic(),
                    total.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                ),
            ));
        }
        Ok(())
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl NativeLoaderProgressStage {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::SourceBootstrap => "source-bootstrap",
            Self::SourceSystemAncestry => "source-system-ancestry",
            Self::SourceLoaderGraph => "source-loader-graph",
            Self::SourceKnownDlls => "source-known-dlls",
            Self::TargetBootstrap => "target-bootstrap",
            Self::TargetKnownDlls => "target-known-dlls",
            Self::TargetModules => "target-modules",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LoaderPathRoleV1 {
    MemcordonInstallRoot,
    MemcordonBootstrapImage,
    ExternalInstallAncestor,
    SystemDirectory,
    SystemModule,
}

impl LoaderPathRoleV1 {
    const fn repair_scope(self) -> &'static str {
        match self {
            Self::MemcordonInstallRoot | Self::MemcordonBootstrapImage => "memcordon-owned",
            Self::ExternalInstallAncestor | Self::SystemDirectory | Self::SystemModule => {
                "external-never-repair"
            }
        }
    }

    const fn diagnostic(self) -> &'static str {
        match self {
            Self::MemcordonInstallRoot => "memcordon-install-root",
            Self::MemcordonBootstrapImage => "memcordon-bootstrap-image",
            Self::ExternalInstallAncestor => "external-install-ancestor",
            Self::SystemDirectory => "system-directory",
            Self::SystemModule => "system-module",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum KnownDllDispositionV1 {
    Section {
        requested_access: u32,
        granted_access: u32,
    },
    FileBacked {
        not_found_status: i32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderPathAccessEvidenceV1 {
    pub role: LoaderPathRoleV1,
    pub path_sha256: String,
    pub basename: String,
    pub requested_access: u32,
    pub granted_access: u32,
    pub volume_serial: u64,
    pub file_id_sha256: String,
    pub reparse_point: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderModuleAccessEvidenceV1 {
    pub import_contract: String,
    pub concrete_host: String,
    pub api_set_redirected: bool,
    // The paired KnownDll disposition selects this record's attestation meaning:
    // holder-retained physical-host provenance plus exact-target section-access attestation for
    // Section, or holder-retained exact-target file access for FileBacked. These holder resources
    // pin identity against mutation; they are non-inheritable and are not child loader capabilities.
    pub file: LoaderPathAccessEvidenceV1,
    pub pe_machine: u16,
    pub image_sha256: String,
    pub loader_contract_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LoaderRootPhaseV2 {
    StaticKernel,
    ExplicitSecurity,
    ExplicitUser,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderRootEvidenceV2 {
    pub phase: LoaderRootPhaseV2,
    pub descriptor_ordinal: Option<u32>,
    pub import_contract: String,
    pub concrete_host: String,
    pub export_contract_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderImportEdgeEvidenceV2 {
    pub phase: LoaderRootPhaseV2,
    pub depth: u32,
    pub parent_host: String,
    pub descriptor_ordinal: Option<u32>,
    pub requested_symbol: Option<String>,
    pub import_contract: String,
    pub concrete_host: String,
    pub resolved_target_symbol: Option<String>,
    pub api_set_redirected: bool,
    pub forwarder: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoaderObjectAccessEvidenceV1 {
    pub object_name_sha256: String,
    pub requested_access: u32,
    pub granted_access: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KnownDllSectionEvidenceV1 {
    pub concrete_host: String,
    pub disposition: KnownDllDispositionV1,
    pub read_map_attested: bool,
    pub execute_map_attested: bool,
    pub loader_contract_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeLoaderAccessEvidenceV2 {
    pub schema_version: u32,
    pub native_machine: u16,
    pub bootstrap_sha256: String,
    pub import_contract_sha256: String,
    pub ordered_root_sha256: String,
    pub loader_graph_sha256: String,
    pub impersonation_attested: bool,
    pub thread_token_absent_after_revert: bool,
    pub install_ancestors: Vec<LoaderPathAccessEvidenceV1>,
    pub bootstrap_file: LoaderPathAccessEvidenceV1,
    pub system_ancestors: Vec<LoaderPathAccessEvidenceV1>,
    pub system_modules: Vec<LoaderModuleAccessEvidenceV1>,
    pub loader_roots: Vec<LoaderRootEvidenceV2>,
    pub loader_edges: Vec<LoaderImportEdgeEvidenceV2>,
    pub known_dll_directory: LoaderObjectAccessEvidenceV1,
    pub known_dll_sections: Vec<KnownDllSectionEvidenceV1>,
    pub exact_target_import_tier_canary_attested: bool,
    pub evidence_sha256: String,
}

impl NativeLoaderAccessEvidenceV2 {
    pub(crate) fn mark_reverted_and_seal(mut self) -> Result<Self, String> {
        self.thread_token_absent_after_revert = true;
        (self.ordered_root_sha256, self.loader_graph_sha256) =
            loader_graph_digests(&self.loader_roots, &self.loader_edges, &self.system_modules);
        self.evidence_sha256.clear();
        let mut canonical = b"memcordon-native-loader-access-v2\0".to_vec();
        canonical.extend(serde_json::to_vec(&self).map_err(|error| error.to_string())?);
        self.evidence_sha256 = super::record::digest(&canonical);
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != 2
            || !matches!(
                self.native_machine,
                memcordon_core::WINDOWS_PE_MACHINE_AMD64 | memcordon_core::WINDOWS_PE_MACHINE_ARM64
            )
            || !self.impersonation_attested
            || !self.thread_token_absent_after_revert
            || self.install_ancestors.is_empty()
            || self.install_ancestors.len() > MAX_LOADER_ANCESTORS
            || self.system_ancestors.is_empty()
            || self.system_ancestors.len() > MAX_LOADER_ANCESTORS
            || self.system_modules.is_empty()
            || self.system_modules.len() > MAX_LOADER_MODULES
            || self.loader_roots.is_empty()
            || self.loader_roots.len() > MAX_LOADER_GRAPH_EDGES
            || self.loader_edges.is_empty()
            || self.loader_edges.len() > MAX_LOADER_GRAPH_EDGES
            || self.known_dll_sections.is_empty()
            || self.known_dll_sections.len() > MAX_LOADER_MODULES
            || !self.exact_target_import_tier_canary_attested
        {
            return Err("native loader access evidence shape is invalid".to_owned());
        }
        for path in self.install_ancestors.iter().chain(&self.system_ancestors) {
            validate_ancestor_identity_evidence(path)?;
        }
        validate_file_access_evidence(&self.bootstrap_file, LOADER_FILE_ACCESS)?;
        if self.bootstrap_sha256.len() != 64
            || self.import_contract_sha256.len() != 64
            || self.ordered_root_sha256.len() != 64
            || self.loader_graph_sha256.len() != 64
        {
            return Err("native loader content digest is invalid".to_owned());
        }
        let mut concrete_hosts = BTreeSet::new();
        let mut prior_module = None;
        for module in &self.system_modules {
            validate_file_access_evidence(&module.file, LOADER_FILE_ACCESS)?;
            if module.pe_machine != self.native_machine
                || module.import_contract.len() > MAX_LOADER_BASENAME_BYTES
                || module.concrete_host.len() > MAX_LOADER_BASENAME_BYTES
                || is_api_set_name(&module.concrete_host)
                || module.api_set_redirected != is_api_set_name(&module.import_contract)
                || (!module.api_set_redirected
                    && !module
                        .import_contract
                        .eq_ignore_ascii_case(&module.concrete_host))
                || !module
                    .file
                    .basename
                    .eq_ignore_ascii_case(&module.concrete_host)
                || module.image_sha256.len() != 64
                || module.loader_contract_sha256.len() != 64
            {
                return Err("native loader module evidence is invalid".to_owned());
            }
            concrete_hosts.insert(module.concrete_host.to_ascii_uppercase());
            let ordering = (
                module.concrete_host.to_ascii_uppercase(),
                module.import_contract.to_ascii_uppercase(),
            );
            if prior_module
                .as_ref()
                .is_some_and(|prior| prior >= &ordering)
            {
                return Err("native loader module inventory is noncanonical".to_owned());
            }
            prior_module = Some(ordering);
        }
        if self.known_dll_directory.requested_access != KNOWN_DLL_DIRECTORY_ACCESS
            || self.known_dll_directory.object_name_sha256.len() != 64
        {
            return Err("KnownDll directory evidence is noncanonical".to_owned());
        }
        require_access(
            KNOWN_DLL_DIRECTORY_ACCESS,
            self.known_dll_directory.granted_access,
            "known-dll-directory",
        )?;
        let mut section_hosts = BTreeSet::new();
        let mut prior_section = None;
        for section in &self.known_dll_sections {
            if section.concrete_host.len() > MAX_LOADER_BASENAME_BYTES
                || section.loader_contract_sha256.len() != 64
            {
                return Err("KnownDll section basename exceeds its bound".to_owned());
            }
            let host = section.concrete_host.to_ascii_uppercase();
            if !section_hosts.insert(host.clone())
                || prior_section.as_ref().is_some_and(|prior| prior >= &host)
            {
                return Err("KnownDll section inventory is noncanonical".to_owned());
            }
            prior_section = Some(host);
            match section.disposition {
                KnownDllDispositionV1::Section {
                    requested_access,
                    granted_access,
                } => {
                    if requested_access != KNOWN_DLL_SECTION_ACCESS {
                        return Err("KnownDll section requested mask is noncanonical".to_owned());
                    }
                    require_access(requested_access, granted_access, "known-dll-section")?;
                    if !section.read_map_attested || !section.execute_map_attested {
                        return Err(
                            "KnownDll section read/execute map evidence is incomplete".to_owned()
                        );
                    }
                }
                KnownDllDispositionV1::FileBacked { not_found_status }
                    if not_found_status == STATUS_OBJECT_NAME_NOT_FOUND =>
                {
                    if section.read_map_attested || section.execute_map_attested {
                        return Err("KnownDll file fallback claims section mapping".to_owned());
                    }
                }
                KnownDllDispositionV1::FileBacked { .. } => {
                    return Err("KnownDll file-backed status is noncanonical".to_owned());
                }
            }
        }
        if concrete_hosts != section_hosts {
            return Err("native loader module/KnownDll inventory is not bijective".to_owned());
        }
        let module_hosts = self
            .system_modules
            .iter()
            .map(|module| module.concrete_host.to_ascii_uppercase())
            .collect::<BTreeSet<_>>();
        let mut root_records = BTreeSet::new();
        let mut static_prior_ordinal = None;
        let mut security_roots = 0_usize;
        let mut user_roots = 0_usize;
        for root in &self.loader_roots {
            validate_graph_name(&root.import_contract)?;
            validate_graph_name(&root.concrete_host)?;
            if root.export_contract_sha256.len() != 64
                || !module_hosts.contains(&root.concrete_host.to_ascii_uppercase())
            {
                return Err("native loader graph root is invalid".to_owned());
            }
            if !root_records.insert(graph_root_canonical(root)) {
                return Err("native loader graph root is duplicated".to_owned());
            }
            match root.phase {
                LoaderRootPhaseV2::StaticKernel => {
                    let ordinal = root
                        .descriptor_ordinal
                        .ok_or_else(|| "static loader root has no descriptor ordinal".to_owned())?;
                    if static_prior_ordinal.is_some_and(|prior| prior >= ordinal) {
                        return Err("static loader roots lost descriptor order".to_owned());
                    }
                    static_prior_ordinal = Some(ordinal);
                }
                LoaderRootPhaseV2::ExplicitSecurity => {
                    security_roots += 1;
                    if root.descriptor_ordinal.is_some()
                        || !root.import_contract.eq_ignore_ascii_case("ADVAPI32.DLL")
                    {
                        return Err("explicit security loader root is noncanonical".to_owned());
                    }
                }
                LoaderRootPhaseV2::ExplicitUser => {
                    user_roots += 1;
                    if root.descriptor_ordinal.is_some()
                        || !root.import_contract.eq_ignore_ascii_case("USER32.DLL")
                    {
                        return Err("explicit USER loader root is noncanonical".to_owned());
                    }
                }
            }
        }
        if static_prior_ordinal.is_none() || security_roots != 1 || user_roots != 1 {
            return Err("native loader graph root phases are incomplete".to_owned());
        }
        let mut prior_edge = None;
        for edge in &self.loader_edges {
            validate_graph_name(&edge.parent_host)?;
            validate_graph_name(&edge.import_contract)?;
            validate_graph_name(&edge.concrete_host)?;
            if edge.depth as usize > MAX_LOADER_GRAPH_DEPTH
                || !module_hosts.contains(&edge.concrete_host.to_ascii_uppercase())
                || !module_hosts.contains(&edge.parent_host.to_ascii_uppercase())
                || edge.api_set_redirected != is_api_set_name(&edge.import_contract)
            {
                return Err("native loader graph edge is invalid".to_owned());
            }
            if edge.forwarder
                != (edge.descriptor_ordinal.is_none()
                    && edge.requested_symbol.is_some()
                    && edge.resolved_target_symbol.is_some())
                || (!edge.forwarder
                    && (edge.descriptor_ordinal.is_none()
                        || edge.requested_symbol.is_some()
                        || edge.resolved_target_symbol.is_some()))
            {
                return Err("native loader graph edge kind is inconsistent".to_owned());
            }
            if edge
                .requested_symbol
                .as_ref()
                .is_some_and(|value| value.len() > 256)
                || edge
                    .resolved_target_symbol
                    .as_ref()
                    .is_some_and(|value| value.len() > 256)
            {
                return Err("native loader graph symbol exceeds its bound".to_owned());
            }
            let canonical = graph_edge_canonical(edge);
            if prior_edge.as_ref().is_some_and(|prior| prior >= &canonical) {
                return Err("native loader graph edges are duplicated or noncanonical".to_owned());
            }
            prior_edge = Some(canonical);
        }
        let shortest_depths = loader_graph_shortest_depths(&self.loader_roots, &self.loader_edges);
        for edge in &self.loader_edges {
            let parent = (edge.phase, edge.parent_host.to_ascii_uppercase());
            let child = (edge.phase, edge.concrete_host.to_ascii_uppercase());
            if !shortest_depths.contains_key(&parent) {
                return Err("native loader graph edge parent is unreachable".to_owned());
            }
            let expected_depth = shortest_depths
                .get(&child)
                .ok_or_else(|| "native loader graph edge target is unreachable".to_owned())?;
            if usize::try_from(edge.depth).ok() != Some(*expected_depth) {
                return Err(
                    "native loader graph edge depth is not the canonical minimum".to_owned(),
                );
            }
        }
        let reachable = shortest_depths
            .iter()
            .map(|((_, host), _)| host.clone())
            .collect::<BTreeSet<_>>();
        if reachable != module_hosts {
            return Err("native loader graph has orphan or missing hosts".to_owned());
        }
        let (ordered_root_sha256, loader_graph_sha256) =
            loader_graph_digests(&self.loader_roots, &self.loader_edges, &self.system_modules);
        if self.ordered_root_sha256 != ordered_root_sha256
            || self.loader_graph_sha256 != loader_graph_sha256
        {
            return Err("native loader graph digest is mismatched".to_owned());
        }
        let dispositions = self
            .known_dll_sections
            .iter()
            .map(|section| (section.concrete_host.to_ascii_uppercase(), section))
            .collect::<BTreeMap<_, _>>();
        for module in &self.system_modules {
            let section = dispositions
                .get(&module.concrete_host.to_ascii_uppercase())
                .ok_or_else(|| {
                    "native loader module has no exact concrete-host disposition".to_owned()
                })?;
            if section.loader_contract_sha256 != module.loader_contract_sha256 {
                return Err("native loader module/section contract digest differs".to_owned());
            }
            match section.disposition {
                KnownDllDispositionV1::Section { .. }
                | KnownDllDispositionV1::FileBacked {
                    not_found_status: STATUS_OBJECT_NAME_NOT_FOUND,
                } => {}
                KnownDllDispositionV1::FileBacked { .. } => {
                    return Err("native loader module disposition is invalid".to_owned());
                }
            }
        }
        let mut canonical_copy = self.clone();
        canonical_copy.evidence_sha256.clear();
        let mut canonical = b"memcordon-native-loader-access-v2\0".to_vec();
        canonical.extend(serde_json::to_vec(&canonical_copy).map_err(|error| error.to_string())?);
        if self.evidence_sha256 != super::record::digest(&canonical) {
            return Err("native loader access evidence digest is mismatched".to_owned());
        }
        Ok(())
    }

    pub(crate) fn diagnostic(&self) -> String {
        let section_count = self
            .known_dll_sections
            .iter()
            .filter(|entry| matches!(entry.disposition, KnownDllDispositionV1::Section { .. }))
            .count();
        let file_fallback_count = self.known_dll_sections.len() - section_count;
        format!(
            "native_loader_preflight=passed schema=2 machine=0x{:04x} image_access={:#010x} install_ancestor_count={} system_module_count={} loader_root_count={} loader_edge_count={} known_dll_section_count={} file_fallback_count={} ordered_root_sha256={} loader_graph_sha256={} native_loader_evidence_sha256={}",
            self.native_machine,
            self.bootstrap_file.granted_access,
            self.install_ancestors.len(),
            self.system_modules.len(),
            self.loader_roots.len(),
            self.loader_edges.len(),
            section_count,
            file_fallback_count,
            self.ordered_root_sha256,
            self.loader_graph_sha256,
            self.evidence_sha256,
        )
    }
}

fn validate_graph_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_LOADER_BASENAME_BYTES
        || !value.is_ascii()
        || value.contains(['/', '\\'])
    {
        Err("native loader graph basename is invalid".to_owned())
    } else {
        Ok(())
    }
}

fn graph_root_canonical(root: &LoaderRootEvidenceV2) -> Vec<u8> {
    format!(
        "{:?}\0{:08x}\0{}\0{}\0{}\n",
        root.phase,
        root.descriptor_ordinal.unwrap_or(u32::MAX),
        root.import_contract.to_ascii_uppercase(),
        root.concrete_host.to_ascii_uppercase(),
        root.export_contract_sha256,
    )
    .into_bytes()
}

fn graph_edge_canonical(edge: &LoaderImportEdgeEvidenceV2) -> Vec<u8> {
    format!(
        "{:?}\0{:08x}\0{}\0{:08x}\0{}\0{}\0{}\0{}\0{}\0{}\n",
        edge.phase,
        edge.depth,
        edge.parent_host.to_ascii_uppercase(),
        edge.descriptor_ordinal.unwrap_or(u32::MAX),
        edge.requested_symbol.as_deref().unwrap_or(""),
        edge.import_contract.to_ascii_uppercase(),
        edge.concrete_host.to_ascii_uppercase(),
        edge.resolved_target_symbol.as_deref().unwrap_or(""),
        edge.api_set_redirected,
        edge.forwarder,
    )
    .into_bytes()
}

fn graph_edge_identity_canonical(edge: &LoaderImportEdgeEvidenceV2) -> Vec<u8> {
    format!(
        "{:?}\0{}\0{:08x}\0{}\0{}\0{}\0{}\0{}\0{}\n",
        edge.phase,
        edge.parent_host.to_ascii_uppercase(),
        edge.descriptor_ordinal.unwrap_or(u32::MAX),
        edge.requested_symbol.as_deref().unwrap_or(""),
        edge.import_contract.to_ascii_uppercase(),
        edge.concrete_host.to_ascii_uppercase(),
        edge.resolved_target_symbol.as_deref().unwrap_or(""),
        edge.api_set_redirected,
        edge.forwarder,
    )
    .into_bytes()
}

fn loader_graph_shortest_depths(
    roots: &[LoaderRootEvidenceV2],
    edges: &[LoaderImportEdgeEvidenceV2],
) -> BTreeMap<(LoaderRootPhaseV2, String), usize> {
    let mut depths = BTreeMap::new();
    let mut queue = VecDeque::new();
    for root in roots {
        let node = (root.phase, root.concrete_host.to_ascii_uppercase());
        if depths.insert(node.clone(), 0).is_none() {
            queue.push_back(node);
        }
    }
    while let Some((phase, parent_host)) = queue.pop_front() {
        let parent_depth = depths[&(phase, parent_host.clone())];
        for edge in edges.iter().filter(|edge| {
            edge.phase == phase && edge.parent_host.eq_ignore_ascii_case(&parent_host)
        }) {
            let child = (phase, edge.concrete_host.to_ascii_uppercase());
            let candidate = parent_depth + 1;
            if depths
                .get(&child)
                .is_none_or(|current| candidate < *current)
            {
                depths.insert(child.clone(), candidate);
                queue.push_back(child);
            }
        }
    }
    depths
}

fn canonicalize_loader_edge_depths(
    roots: &[LoaderRootEvidenceV2],
    edges: &mut [LoaderImportEdgeEvidenceV2],
    system_directory: &Path,
) -> Result<BTreeMap<(LoaderRootPhaseV2, String), usize>, NativeLoaderAccessFailureV1> {
    let depths = loader_graph_shortest_depths(roots, edges);
    for edge in edges {
        let parent = (edge.phase, edge.parent_host.to_ascii_uppercase());
        let child = (edge.phase, edge.concrete_host.to_ascii_uppercase());
        if !depths.contains_key(&parent) {
            return Err(contract_failure(
                "system-module",
                system_directory,
                "loader-graph-reachability",
                "recursive loader graph contains an unreachable edge parent",
            ));
        }
        let child_depth = *depths.get(&child).ok_or_else(|| {
            contract_failure(
                "system-module",
                system_directory,
                "loader-graph-reachability",
                "recursive loader graph contains an unreachable edge target",
            )
        })?;
        if child_depth > MAX_LOADER_GRAPH_DEPTH {
            return Err(contract_failure(
                "system-module",
                Path::new(&edge.concrete_host),
                "loader-graph-depth-bound",
                format!(
                    "minimum physical-host depth {child_depth} exceeds {MAX_LOADER_GRAPH_DEPTH}"
                ),
            ));
        }
        edge.depth = child_depth as u32;
    }
    Ok(depths)
}

fn loader_graph_digests(
    roots: &[LoaderRootEvidenceV2],
    edges: &[LoaderImportEdgeEvidenceV2],
    modules: &[LoaderModuleAccessEvidenceV1],
) -> (String, String) {
    let mut root_bytes = b"memcordon-native-loader-ordered-roots-v2\0".to_vec();
    for root in roots {
        root_bytes.extend(graph_root_canonical(root));
    }
    let ordered_root_sha256 = super::record::digest(&root_bytes);
    let mut graph_bytes = b"memcordon-native-loader-graph-v2\0".to_vec();
    graph_bytes.extend_from_slice(ordered_root_sha256.as_bytes());
    for edge in edges {
        graph_bytes.extend(graph_edge_canonical(edge));
    }
    for module in modules {
        graph_bytes.extend_from_slice(module.concrete_host.as_bytes());
        graph_bytes.push(0);
        graph_bytes.extend_from_slice(module.image_sha256.as_bytes());
        graph_bytes.push(0);
        graph_bytes.extend_from_slice(module.loader_contract_sha256.as_bytes());
        graph_bytes.push(b'\n');
    }
    (ordered_root_sha256, super::record::digest(&graph_bytes))
}

fn validate_path_identity(evidence: &LoaderPathAccessEvidenceV1) -> Result<(), String> {
    if evidence.reparse_point
        || evidence.volume_serial == 0
        || evidence.file_id_sha256.len() != 64
        || evidence.path_sha256.len() != 64
        || evidence.basename.len() > MAX_LOADER_BASENAME_BYTES
    {
        return Err(format!(
            "native loader path evidence is invalid for {}",
            evidence.role.diagnostic()
        ));
    }
    Ok(())
}

fn validate_ancestor_identity_evidence(
    evidence: &LoaderPathAccessEvidenceV1,
) -> Result<(), String> {
    if evidence.requested_access != LOADER_ANCESTOR_IDENTITY_ACCESS {
        return Err(format!(
            "native loader ancestor identity requested access is nonzero for {}",
            evidence.role.diagnostic()
        ));
    }
    validate_path_identity(evidence)
}

fn validate_file_access_evidence(
    evidence: &LoaderPathAccessEvidenceV1,
    expected: u32,
) -> Result<(), String> {
    if evidence.requested_access != expected {
        return Err(format!(
            "native loader path evidence is invalid for {}",
            evidence.role.diagnostic()
        ));
    }
    validate_path_identity(evidence)?;
    require_access(
        expected,
        evidence.granted_access,
        evidence.role.diagnostic(),
    )
}

fn require_access(requested: u32, granted: u32, resource: &str) -> Result<(), String> {
    if granted & requested == requested {
        Ok(())
    } else {
        Err(format!(
            "native loader access is incomplete resource_class={resource} requested={requested:#010x} granted={granted:#010x}"
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NativeLoaderObjectDomainV1 {
    File,
    ObjectManager,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeLoaderAccessFailureV1 {
    pub object_domain: NativeLoaderObjectDomainV1,
    pub resource_class: &'static str,
    pub resource_sha256: String,
    pub resource_basename: String,
    pub api: &'static str,
    pub requested: u32,
    pub granted: Option<u32>,
    pub native_code: Option<i32>,
    pub native_status: Option<i32>,
    pub repair_scope: &'static str,
    pub detail: String,
}

impl std::fmt::Display for NativeLoaderAccessFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "object_domain={} resource_class={} resource_sha256={} resource_basename={} api={} requested={:#010x} granted={} native_code={} nt_status={} repair_scope={} detail={}",
            match self.object_domain {
                NativeLoaderObjectDomainV1::File => "file",
                NativeLoaderObjectDomainV1::ObjectManager => "object-manager",
            },
            self.resource_class,
            self.resource_sha256,
            self.resource_basename,
            self.api,
            self.requested,
            self.granted.map_or_else(
                || "unavailable".to_owned(),
                |value| format!("{value:#010x}")
            ),
            self.native_code
                .map_or_else(|| "none".to_owned(), |value| value.to_string()),
            self.native_status.map_or_else(
                || "none".to_owned(),
                |value| format!("0x{:08x}", value as u32)
            ),
            self.repair_scope,
            bounded(&self.detail, 256),
        )
    }
}

#[derive(Debug)]
struct RetainedLoaderPathIdentityV1 {
    evidence: LoaderPathAccessEvidenceV1,
    final_path: PathBuf,
    file_id: u64,
    handle: OwnedHandle,
}

#[derive(Debug)]
struct ResolvedLoaderModuleV1 {
    import_contract: String,
    concrete_host: String,
    api_set_redirected: bool,
    api_set_selection: Option<ApiSetSelectionIdentityV6>,
    path: PathBuf,
    source_identity: RetainedLoaderPathIdentityV1,
    source_sha256: String,
    source_pe_machine: u16,
    source_loader_contract: memcordon_core::WindowsPeLoaderContract,
    source_loader_contract_sha256: String,
}

#[derive(Debug)]
struct ResolvedLoaderRequestV1 {
    import_contract: String,
    concrete_host: String,
    api_set_redirected: bool,
    api_set_selection: Option<ApiSetSelectionIdentityV6>,
    path: PathBuf,
}

#[derive(Debug)]
struct SourceKnownDllSectionV1 {
    concrete_host: String,
    not_found_status: Option<i32>,
    handle: Option<OwnedHandle>,
    allocation_attributes: u32,
    maximum_size: i64,
    image_machine: u16,
    image_characteristics: u16,
    image_file_size: u32,
    image_checksum: u32,
    mapped_loader_contract_sha256: Option<String>,
}

#[derive(Debug)]
struct SourceKnownDllResourcesV1 {
    directory: OwnedHandle,
    sections: Vec<SourceKnownDllSectionV1>,
}

#[derive(Debug)]
pub(crate) struct ResolvedNativeLoaderResourcesV1 {
    native_machine: u16,
    bootstrap: PathBuf,
    bootstrap_sha256: String,
    import_contract_sha256: String,
    loader_roots: Vec<LoaderRootEvidenceV2>,
    loader_edges: Vec<LoaderImportEdgeEvidenceV2>,
    bootstrap_source_identity: RetainedLoaderPathIdentityV1,
    install_ancestors: Vec<RetainedLoaderPathIdentityV1>,
    system_ancestors: Vec<RetainedLoaderPathIdentityV1>,
    modules: Vec<ResolvedLoaderModuleV1>,
    native_api: NativeObjectApi,
    source_known_dlls: SourceKnownDllResourcesV1,
}

#[derive(Debug)]
pub(crate) struct NativeLoaderAccessLeaseV1 {
    evidence: NativeLoaderAccessEvidenceV2,
    _source_resources: ResolvedNativeLoaderResourcesV1,
    _target_files: Vec<OwnedHandle>,
    _known_dll_directory: OwnedHandle,
    _known_dll_sections: Vec<OwnedHandle>,
}

impl NativeLoaderAccessLeaseV1 {
    pub(crate) fn mark_reverted_and_seal(mut self) -> Result<Self, String> {
        self.evidence = self.evidence.mark_reverted_and_seal()?;
        Ok(self)
    }

    pub(crate) fn evidence(&self) -> &NativeLoaderAccessEvidenceV2 {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug)]
struct NativeObjectApi {
    nt_open_directory_object: NtOpenDirectoryObjectFn,
    nt_open_section: NtOpenSectionFn,
    nt_query_section: NtQuerySectionFn,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SectionBasicInformation {
    base_address: *mut c_void,
    allocation_attributes: u32,
    maximum_size: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SectionImageInformation {
    transfer_address: *mut c_void,
    zero_bits: u32,
    maximum_stack_size: usize,
    committed_stack_size: usize,
    subsystem_type: u32,
    subsystem_version: u32,
    operating_system_version: u32,
    image_characteristics: u16,
    dll_characteristics: u16,
    machine: u16,
    image_contains_code: u8,
    image_flags: u8,
    loader_flags: u32,
    image_file_size: u32,
    checksum: u32,
}

type NtOpenDirectoryObjectFn =
    unsafe extern "system" fn(*mut HANDLE, u32, *const ObjectAttributes) -> i32;
type NtOpenSectionFn = unsafe extern "system" fn(*mut HANDLE, u32, *const ObjectAttributes) -> i32;
type NtQuerySectionFn =
    unsafe extern "system" fn(HANDLE, u32, *mut c_void, usize, *mut usize) -> i32;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn MapViewOfFile(
        file_mapping: HANDLE,
        desired_access: u32,
        file_offset_high: u32,
        file_offset_low: u32,
        bytes_to_map: usize,
    ) -> *mut c_void;
    fn UnmapViewOfFile(base_address: *const c_void) -> i32;
}

struct MappedSectionView(*mut c_void);

impl Drop for MappedSectionView {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                UnmapViewOfFile(self.0);
            }
        }
    }
}

pub(crate) fn resolve_native_loader_resources(
    bootstrap: &Path,
    budget: &mut NativeLoaderAttestationBudget<'_>,
) -> Result<ResolvedNativeLoaderResourcesV1, NativeLoaderAccessFailureV1> {
    budget.check(NativeLoaderProgressStage::SourceBootstrap, 0, None)?;
    if bootstrap != super::package::installed_target_desktop_bootstrap() {
        return Err(contract_failure(
            "memcordon-bootstrap-image",
            bootstrap,
            "resolve",
            "bootstrap path is not the exact installed image",
        ));
    }
    super::package::reject_reparse_components(bootstrap).map_err(|detail| {
        contract_failure(
            "memcordon-bootstrap-image",
            bootstrap,
            "reparse-preflight",
            detail,
        )
    })?;
    let contract =
        super::package::installed_target_desktop_bootstrap_contract().map_err(|detail| {
            contract_failure(
                "memcordon-bootstrap-image",
                bootstrap,
                "PE-import-verifier",
                detail,
            )
        })?;
    let native_machine = native_machine().map_err(|detail| {
        contract_failure(
            "memcordon-bootstrap-image",
            bootstrap,
            "native-machine",
            detail,
        )
    })?;
    if contract.imports.machine != native_machine || !contract.imports.delayed.is_empty() {
        return Err(contract_failure(
            "memcordon-bootstrap-image",
            bootstrap,
            "PE-import-verifier",
            "bootstrap machine/delay-load contract is nonnative",
        ));
    }
    let install_root = super::package::install_root();
    let install_ancestor_paths = ancestors_of_file(bootstrap)
        .into_iter()
        .map(|path| {
            let role = if path == install_root {
                LoaderPathRoleV1::MemcordonInstallRoot
            } else {
                LoaderPathRoleV1::ExternalInstallAncestor
            };
            (path, role)
        })
        .collect::<Vec<_>>();
    if install_ancestor_paths.len() > MAX_LOADER_ANCESTORS
        || !install_ancestor_paths
            .iter()
            .any(|(path, _)| path == &install_root)
    {
        return Err(contract_failure(
            "memcordon-install-root",
            &install_root,
            "ancestor-resolution",
            "installed image ancestry is noncanonical or exceeds its bound",
        ));
    }
    // These holder-primary opens are source mutation pins, not target-access evidence.
    // Keeping their handles live without write/delete sharing prevents a trusted path
    // component from being replaced between resolution and the child loader checks.
    let mut install_ancestors = Vec::with_capacity(install_ancestor_paths.len());
    for (path, role) in &install_ancestor_paths {
        install_ancestors.push(capture_source_ancestor(path, *role)?);
        budget.check(
            NativeLoaderProgressStage::SourceBootstrap,
            install_ancestors.len(),
            Some(install_ancestor_paths.len() + 1),
        )?;
    }
    let bootstrap_source_identity =
        capture_source_final_file(bootstrap, LoaderPathRoleV1::MemcordonBootstrapImage)?;
    let bootstrap_source_bytes = read_handle_bytes(bootstrap_source_identity.handle.raw())
        .map_err(|error| {
            file_failure(
                LoaderPathRoleV1::MemcordonBootstrapImage,
                bootstrap,
                "ReadFile",
                LOADER_FILE_ACCESS,
                Some(bootstrap_source_identity.evidence.granted_access),
                error,
            )
        })?;
    let bootstrap_source_sha256 = sha256_bytes(&bootstrap_source_bytes);
    if bootstrap_source_sha256 != contract.sha256 {
        return Err(contract_failure(
            "memcordon-bootstrap-image",
            bootstrap,
            "SHA256",
            "holder-pinned bootstrap differs from the admitted image",
        ));
    }
    let bootstrap_source_imports =
        memcordon_core::parse_windows_pe_imports(&bootstrap_source_bytes).map_err(|detail| {
            contract_failure(
                "memcordon-bootstrap-image",
                bootstrap,
                "PE-import-verifier",
                detail,
            )
        })?;
    if loader_import_contract_sha256(&bootstrap_source_imports) != contract.import_contract_sha256 {
        return Err(contract_failure(
            "memcordon-bootstrap-image",
            bootstrap,
            "PE-import-verifier",
            "holder-pinned bootstrap import contract changed during admission",
        ));
    }
    let bootstrap_loader_contract = memcordon_core::parse_windows_pe_loader_contract(
        &bootstrap_source_bytes,
    )
    .map_err(|detail| {
        contract_failure(
            "memcordon-bootstrap-image",
            bootstrap,
            "PE-loader-contract",
            detail,
        )
    })?;
    if bootstrap_loader_contract.machine != native_machine
        || !bootstrap_loader_contract.delayed.is_empty()
    {
        return Err(contract_failure(
            "memcordon-bootstrap-image",
            bootstrap,
            "PE-loader-contract",
            "bootstrap detailed loader contract is nonnative or delay-loaded",
        ));
    }
    budget.check(
        NativeLoaderProgressStage::SourceBootstrap,
        install_ancestor_paths.len() + 1,
        Some(install_ancestor_paths.len() + 1),
    )?;
    let system_directory = system_directory().map_err(|detail| {
        contract_failure(
            "system-directory",
            Path::new("System32"),
            "GetSystemDirectoryW",
            detail,
        )
    })?;
    super::package::reject_reparse_components(&system_directory).map_err(|detail| {
        contract_failure(
            "system-directory",
            &system_directory,
            "reparse-preflight",
            detail,
        )
    })?;
    let system_ancestor_paths = ancestors_including(&system_directory)
        .into_iter()
        .map(|path| (path, LoaderPathRoleV1::SystemDirectory))
        .collect::<Vec<_>>();
    if system_ancestor_paths.is_empty() || system_ancestor_paths.len() > MAX_LOADER_ANCESTORS {
        return Err(contract_failure(
            "system-directory",
            &system_directory,
            "ancestor-resolution",
            "System32 ancestry is empty or exceeds its bound",
        ));
    }
    let mut system_ancestors = Vec::with_capacity(system_ancestor_paths.len());
    budget.check(
        NativeLoaderProgressStage::SourceSystemAncestry,
        0,
        Some(system_ancestor_paths.len()),
    )?;
    for (path, role) in &system_ancestor_paths {
        system_ancestors.push(capture_source_ancestor(path, *role)?);
        budget.check(
            NativeLoaderProgressStage::SourceSystemAncestry,
            system_ancestors.len(),
            Some(system_ancestor_paths.len()),
        )?;
    }
    let (mut modules, loader_roots, loader_edges) = resolve_loader_graph(
        &bootstrap_loader_contract,
        &bootstrap_source_identity.evidence.basename,
        &system_directory,
        native_machine,
        budget,
    )?;
    modules.sort_by(|left, right| {
        (&left.concrete_host, &left.import_contract)
            .cmp(&(&right.concrete_host, &right.import_contract))
    });
    if modules.is_empty() || modules.len() > MAX_LOADER_MODULES {
        return Err(contract_failure(
            "system-module",
            &system_directory,
            "module-resolution",
            "resolved module inventory is empty or exceeds its bound",
        ));
    }
    let native_api = resolve_native_object_api().map_err(|detail| {
        contract_failure(
            "known-dll-directory",
            Path::new(r"\KnownDlls"),
            "GetProcAddress",
            detail,
        )
    })?;
    budget.check(
        NativeLoaderProgressStage::SourceKnownDlls,
        0,
        Some(modules.len()),
    )?;
    let source_known_dlls = admit_source_known_dlls(&native_api, &modules, native_machine, budget)?;
    Ok(ResolvedNativeLoaderResourcesV1 {
        native_machine,
        bootstrap: bootstrap.to_owned(),
        bootstrap_sha256: contract.sha256,
        import_contract_sha256: contract.import_contract_sha256,
        loader_roots,
        loader_edges,
        bootstrap_source_identity,
        install_ancestors,
        system_ancestors,
        modules,
        native_api,
        source_known_dlls,
    })
}

pub(crate) fn probe_native_loader_access_as_effective_thread(
    resources: ResolvedNativeLoaderResourcesV1,
    budget: &mut NativeLoaderAttestationBudget<'_>,
) -> Result<NativeLoaderAccessLeaseV1, NativeLoaderAccessFailureV1> {
    // Source ancestry was opened and pinned by the holder primary token. These
    // identity-only records are copied into schema V1, but the effective target
    // token never opens an ancestor directory. Its authority is proven only by
    // the exact final-file and native-object opens below.
    let install_ancestors = resources
        .install_ancestors
        .iter()
        .map(|identity| identity.evidence.clone())
        .collect::<Vec<_>>();
    let system_ancestors = resources
        .system_ancestors
        .iter()
        .map(|identity| identity.evidence.clone())
        .collect::<Vec<_>>();
    budget.check(NativeLoaderProgressStage::TargetBootstrap, 0, Some(1))?;
    let bootstrap_target_identity = probe_final_file_path_retained(
        &resources.bootstrap,
        LoaderPathRoleV1::MemcordonBootstrapImage,
    )?;
    require_same_final_identity(
        &resources.bootstrap,
        &resources.bootstrap_source_identity,
        &bootstrap_target_identity,
    )?;
    let bootstrap_target_bytes = read_handle_bytes(bootstrap_target_identity.handle.raw())
        .map_err(|error| {
            file_failure(
                LoaderPathRoleV1::MemcordonBootstrapImage,
                &resources.bootstrap,
                "ReadFile",
                LOADER_FILE_ACCESS,
                Some(bootstrap_target_identity.evidence.granted_access),
                error,
            )
        })?;
    let observed_bootstrap_sha256 = sha256_bytes(&bootstrap_target_bytes);
    if resources.bootstrap_sha256 != observed_bootstrap_sha256 {
        return Err(contract_failure(
            "memcordon-bootstrap-image",
            &resources.bootstrap,
            "SHA256",
            "opened bootstrap digest differs from the admitted image",
        ));
    }
    let target_bootstrap_imports =
        memcordon_core::parse_windows_pe_imports(&bootstrap_target_bytes).map_err(|detail| {
            contract_failure(
                "memcordon-bootstrap-image",
                &resources.bootstrap,
                "PE-import-verifier",
                detail,
            )
        })?;
    if target_bootstrap_imports.machine != resources.native_machine
        || !target_bootstrap_imports.delayed.is_empty()
        || loader_import_contract_sha256(&target_bootstrap_imports)
            != resources.import_contract_sha256
    {
        return Err(contract_failure(
            "memcordon-bootstrap-image",
            &resources.bootstrap,
            "PE-import-verifier",
            "target-opened bootstrap import contract or machine is mismatched",
        ));
    }
    budget.check(NativeLoaderProgressStage::TargetBootstrap, 1, Some(1))?;

    // Loader routing is KnownDll-first. The exact target opens the canonical
    // physical-host section before any System32 fallback is considered.
    budget.check(
        NativeLoaderProgressStage::TargetKnownDlls,
        0,
        Some(resources.source_known_dlls.sections.len()),
    )?;
    let (
        known_dll_directory,
        known_dll_sections,
        known_dll_directory_handle,
        known_dll_section_handles,
    ) = probe_known_dlls(&resources, budget)?;
    let known_dll_dispositions = known_dll_sections
        .iter()
        .map(|section| (section.concrete_host.as_str(), section.disposition))
        .collect::<BTreeMap<_, _>>();
    if known_dll_dispositions.len() != known_dll_sections.len() {
        return Err(contract_failure(
            "known-dll-section",
            Path::new(r"\KnownDlls"),
            "concrete-host-relation",
            "KnownDll disposition inventory is duplicated",
        ));
    }
    validate_exact_target_import_tier_canary(&known_dll_sections)?;

    let mut system_modules = Vec::with_capacity(resources.modules.len());
    let mut target_files = vec![bootstrap_target_identity.handle];
    for (module_index, module) in resources.modules.iter().enumerate() {
        budget.check(
            NativeLoaderProgressStage::TargetModules,
            module_index,
            Some(resources.modules.len()),
        )?;
        let disposition = known_dll_dispositions
            .get(module.concrete_host.as_str())
            .copied()
            .ok_or_else(|| {
                contract_failure(
                    "known-dll-section",
                    Path::new(&module.concrete_host),
                    "concrete-host-relation",
                    "resolved module has no exact concrete-host disposition",
                )
            })?;
        let (file, pe_machine) = match disposition {
            KnownDllDispositionV1::Section { .. } => {
                // A retained holder file proves the physical host's provenance;
                // the paired retained section handle attests exact-target-token access to the
                // intended object and pins its identity against mutation. Neither handle is
                // inherited or consumed by the child loader.
                (
                    module.source_identity.evidence.clone(),
                    module.source_pe_machine,
                )
            }
            KnownDllDispositionV1::FileBacked { not_found_status }
                if not_found_status == STATUS_OBJECT_NAME_NOT_FOUND =>
            {
                let target_identity =
                    probe_final_file_path_retained(&module.path, LoaderPathRoleV1::SystemModule)?;
                require_same_final_identity(
                    &module.path,
                    &module.source_identity,
                    &target_identity,
                )?;
                let target_bytes =
                    read_handle_bytes(target_identity.handle.raw()).map_err(|error| {
                        file_failure(
                            LoaderPathRoleV1::SystemModule,
                            &module.path,
                            "ReadFile",
                            LOADER_FILE_ACCESS,
                            Some(target_identity.evidence.granted_access),
                            error,
                        )
                    })?;
                let target_sha256 = sha256_bytes(&target_bytes);
                if target_sha256 != module.source_sha256 {
                    return Err(contract_failure(
                        "system-module",
                        &module.path,
                        "SHA256",
                        "target-opened module differs from the holder-pinned source image",
                    ));
                }
                let target_pe_machine = memcordon_core::parse_windows_pe_imports(&target_bytes)
                    .map_err(|detail| {
                        contract_failure("system-module", &module.path, "PE-machine", detail)
                    })?
                    .machine;
                if target_pe_machine != resources.native_machine
                    || target_pe_machine != module.source_pe_machine
                {
                    return Err(contract_failure(
                        "system-module",
                        &module.path,
                        "PE-machine",
                        "target-opened module machine differs from its pinned source/native machine",
                    ));
                }
                let target_loader_contract = memcordon_core::parse_windows_pe_loader_contract(
                    &target_bytes,
                )
                .map_err(|detail| {
                    contract_failure("system-module", &module.path, "PE-loader-contract", detail)
                })?;
                if loader_contract_sha256(&target_loader_contract)
                    != module.source_loader_contract_sha256
                {
                    return Err(contract_failure(
                        "system-module",
                        &module.path,
                        "PE-loader-contract",
                        "target-opened file loader contract differs from its pinned source",
                    ));
                }
                let RetainedLoaderPathIdentityV1 {
                    evidence, handle, ..
                } = target_identity;
                target_files.push(handle);
                (evidence, target_pe_machine)
            }
            KnownDllDispositionV1::FileBacked { .. } => {
                return Err(contract_failure(
                    "known-dll-section",
                    Path::new(&module.concrete_host),
                    "concrete-host-relation",
                    "file fallback was selected without exact KnownDll name absence",
                ));
            }
        };
        system_modules.push(LoaderModuleAccessEvidenceV1 {
            import_contract: module.import_contract.clone(),
            concrete_host: module.concrete_host.clone(),
            api_set_redirected: module.api_set_redirected,
            file,
            pe_machine,
            image_sha256: module.source_sha256.clone(),
            loader_contract_sha256: module.source_loader_contract_sha256.clone(),
        });
    }
    budget.check(
        NativeLoaderProgressStage::TargetModules,
        resources.modules.len(),
        Some(resources.modules.len()),
    )?;

    let bootstrap_file = bootstrap_target_identity.evidence;
    let (ordered_root_sha256, loader_graph_sha256) = loader_graph_digests(
        &resources.loader_roots,
        &resources.loader_edges,
        &system_modules,
    );
    let evidence = NativeLoaderAccessEvidenceV2 {
        schema_version: 2,
        native_machine: resources.native_machine,
        bootstrap_sha256: resources.bootstrap_sha256.clone(),
        import_contract_sha256: resources.import_contract_sha256.clone(),
        ordered_root_sha256,
        loader_graph_sha256,
        impersonation_attested: true,
        thread_token_absent_after_revert: false,
        install_ancestors,
        bootstrap_file,
        system_ancestors,
        system_modules,
        loader_roots: resources.loader_roots.clone(),
        loader_edges: resources.loader_edges.clone(),
        known_dll_directory,
        known_dll_sections,
        exact_target_import_tier_canary_attested: true,
        evidence_sha256: String::new(),
    };
    Ok(NativeLoaderAccessLeaseV1 {
        evidence,
        _source_resources: resources,
        _target_files: target_files,
        _known_dll_directory: known_dll_directory_handle,
        _known_dll_sections: known_dll_section_handles,
    })
}

fn validate_exact_target_import_tier_canary(
    sections: &[KnownDllSectionEvidenceV1],
) -> Result<(), NativeLoaderAccessFailureV1> {
    // This is deliberately an exact-target *access/map* canary. It runs while the holder's
    // thread is impersonating the target token and compares the core tier with the first
    // non-core direct root. It does not claim that the retained holder handles are inherited or
    // that the child loader consumed them; only the child trace can prove startup.
    for (index, host) in ["NTDLL.DLL", "KERNEL32.DLL", "ADVAPI32.DLL"]
        .into_iter()
        .enumerate()
    {
        let section = sections
            .iter()
            .find(|section| section.concrete_host.eq_ignore_ascii_case(host))
            .ok_or_else(|| {
                object_failure(
                    "exact-target-import-tier-canary",
                    host,
                    "KnownDll-tier-inventory",
                    KNOWN_DLL_SECTION_ACCESS,
                    None,
                    None,
                    format!("tier={index} host is absent from exact-target evidence"),
                )
            })?;
        if !matches!(section.disposition, KnownDllDispositionV1::Section { .. })
            || !section.read_map_attested
            || !section.execute_map_attested
        {
            return Err(object_failure(
                "exact-target-import-tier-canary",
                host,
                "KnownDll-read-execute-map",
                KNOWN_DLL_SECTION_ACCESS,
                match section.disposition {
                    KnownDllDispositionV1::Section { granted_access, .. } => Some(granted_access),
                    KnownDllDispositionV1::FileBacked { .. } => None,
                },
                match section.disposition {
                    KnownDllDispositionV1::FileBacked { not_found_status } => {
                        Some(not_found_status)
                    }
                    KnownDllDispositionV1::Section { .. } => Some(0),
                },
                format!(
                    "tier={index} exact-target KnownDll read/execute-map attestation is incomplete"
                ),
            ));
        }
    }
    Ok(())
}

fn capture_source_ancestor(
    path: &Path,
    role: LoaderPathRoleV1,
) -> Result<RetainedLoaderPathIdentityV1, NativeLoaderAccessFailureV1> {
    probe_path_retained(path, role, LOADER_ANCESTOR_IDENTITY_ACCESS, true)
}

fn capture_source_final_file(
    path: &Path,
    role: LoaderPathRoleV1,
) -> Result<RetainedLoaderPathIdentityV1, NativeLoaderAccessFailureV1> {
    probe_path_retained(path, role, LOADER_FILE_ACCESS, false)
}

fn probe_final_file_path_retained(
    path: &Path,
    role: LoaderPathRoleV1,
) -> Result<RetainedLoaderPathIdentityV1, NativeLoaderAccessFailureV1> {
    probe_path_retained(path, role, LOADER_FILE_ACCESS, false)
}

fn probe_path_retained(
    path: &Path,
    role: LoaderPathRoleV1,
    requested_access: u32,
    directory: bool,
) -> Result<RetainedLoaderPathIdentityV1, NativeLoaderAccessFailureV1> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            requested_access,
            LOADER_PIN_SHARE_MODE,
            ptr::null(),
            OPEN_EXISTING,
            flags,
            ptr::null_mut(),
        )
    };
    if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(file_failure(
            role,
            path,
            "CreateFileW",
            requested_access,
            None,
            io::Error::last_os_error(),
        ));
    }
    let handle = OwnedHandle::new(raw)
        .map_err(|detail| contract_failure(role.diagnostic(), path, "OwnedHandle", detail))?;
    let granted_access = super::token::granted_handle_access(handle.raw())
        .map_err(|detail| contract_failure(role.diagnostic(), path, "NtQueryObject", detail))?;
    require_access(requested_access, granted_access, role.diagnostic()).map_err(|detail| {
        NativeLoaderAccessFailureV1 {
            object_domain: NativeLoaderObjectDomainV1::File,
            resource_class: role.diagnostic(),
            resource_sha256: path_digest(path),
            resource_basename: safe_basename(path),
            api: "NtQueryObject",
            requested: requested_access,
            granted: Some(granted_access),
            native_code: None,
            native_status: None,
            repair_scope: role.repair_scope(),
            detail,
        }
    })?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle.raw(), &raw mut information) } == 0 {
        return Err(file_failure(
            role,
            path,
            "GetFileInformationByHandle",
            requested_access,
            Some(granted_access),
            io::Error::last_os_error(),
        ));
    }
    let reparse_point = information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    if reparse_point {
        return Err(contract_failure(
            role.diagnostic(),
            path,
            "GetFileInformationByHandle",
            "loader path resolved to a reparse point",
        ));
    }
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_directory != directory {
        return Err(contract_failure(
            role.diagnostic(),
            path,
            "GetFileInformationByHandle",
            if directory {
                "loader ancestor identity resolved to a non-directory"
            } else {
                "loader final file resolved to a directory"
            },
        ));
    }
    let final_path = final_path_by_handle(handle.raw(), 0).map_err(|detail| {
        contract_failure(role.diagnostic(), path, "GetFinalPathNameByHandleW", detail)
    })?;
    let file_id = ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64;
    if information.dwVolumeSerialNumber == 0 || file_id == 0 {
        return Err(contract_failure(
            role.diagnostic(),
            path,
            "GetFileInformationByHandle",
            "loader path identity contains a zero volume or file id",
        ));
    }
    let evidence = LoaderPathAccessEvidenceV1 {
        role,
        path_sha256: normalized_path_digest(&final_path),
        basename: safe_basename(&final_path),
        requested_access,
        granted_access,
        volume_serial: information.dwVolumeSerialNumber as u64,
        file_id_sha256: super::record::digest(
            format!("{:08x}:{file_id:016x}", information.dwVolumeSerialNumber).as_bytes(),
        ),
        reparse_point,
    };
    Ok(RetainedLoaderPathIdentityV1 {
        evidence,
        final_path,
        file_id,
        handle,
    })
}

fn require_same_final_identity(
    path: &Path,
    source: &RetainedLoaderPathIdentityV1,
    target: &RetainedLoaderPathIdentityV1,
) -> Result<(), NativeLoaderAccessFailureV1> {
    validate_same_final_identity(
        &source.final_path,
        &source.evidence,
        source.file_id,
        &target.final_path,
        &target.evidence,
        target.file_id,
    )
    .map_err(|detail| {
        contract_failure(
            target.evidence.role.diagnostic(),
            path,
            "final-handle-identity",
            detail,
        )
    })?;
    let expected_basename = safe_basename(path);
    if !target
        .evidence
        .basename
        .eq_ignore_ascii_case(&expected_basename)
    {
        return Err(contract_failure(
            target.evidence.role.diagnostic(),
            path,
            "GetFinalPathNameByHandleW",
            "target-opened final basename differs from the requested leaf",
        ));
    }
    Ok(())
}

fn validate_same_final_identity(
    source_final_path: &Path,
    source: &LoaderPathAccessEvidenceV1,
    source_file_id: u64,
    target_final_path: &Path,
    target: &LoaderPathAccessEvidenceV1,
    target_file_id: u64,
) -> Result<(), String> {
    if !same_path(source_final_path, target_final_path)
        || source.path_sha256 != target.path_sha256
        || !source.basename.eq_ignore_ascii_case(&target.basename)
        || source.volume_serial != target.volume_serial
        || source_file_id != target_file_id
        || source.file_id_sha256 != target.file_id_sha256
        || source.reparse_point
        || target.reparse_point
    {
        return Err(
            "target-opened final file differs from the holder-pinned source identity".to_owned(),
        );
    }
    Ok(())
}

fn read_handle_bytes(handle: HANDLE) -> Result<Vec<u8>, io::Error> {
    const MAX_LOADER_FILE_BYTES: u64 = 64 * 1024 * 1024;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let mut read = 0_u32;
        if unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &raw mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_LOADER_FILE_BYTES {
            return Err(io::Error::other(
                "loader file exceeds the preflight read bound",
            ));
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
    }
    Ok(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn loader_import_contract_sha256(imports: &memcordon_core::WindowsPeImports) -> String {
    let mut canonical = format!("machine={:04x}\n", imports.machine).into_bytes();
    for name in &imports.normal {
        canonical.extend_from_slice(b"normal=");
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(b'\n');
    }
    for name in &imports.delayed {
        canonical.extend_from_slice(b"delayed=");
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(b'\n');
    }
    super::record::digest(&canonical)
}

fn loader_symbol_name(symbol: &memcordon_core::WindowsPeImportSymbol) -> String {
    match symbol {
        memcordon_core::WindowsPeImportSymbol::Name { hint, name } => {
            format!("name:{name}:hint:{hint}")
        }
        memcordon_core::WindowsPeImportSymbol::Ordinal(ordinal) => format!("ordinal:{ordinal}"),
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LoaderSymbolKey {
    Name(String),
    Ordinal(u16),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ForwarderNodeKey {
    concrete_host: String,
    loader_contract_sha256: String,
    symbol: LoaderSymbolKey,
}

#[derive(Clone, Debug)]
struct ForwarderEdgeTemplate {
    parent_host: String,
    requested_symbol: String,
    import_contract: String,
    concrete_host: String,
    resolved_target_symbol: String,
    api_set_redirected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwarderStepFailure {
    Cycle { first_index: usize },
    HopBound { observed: usize },
}

impl LoaderSymbolKey {
    fn from_import(symbol: &memcordon_core::WindowsPeImportSymbol) -> Self {
        match symbol {
            memcordon_core::WindowsPeImportSymbol::Name { name, .. } => Self::Name(name.clone()),
            memcordon_core::WindowsPeImportSymbol::Ordinal(ordinal) => Self::Ordinal(*ordinal),
        }
    }

    fn evidence(&self) -> String {
        match self {
            Self::Name(name) => format!("name:{name}"),
            Self::Ordinal(ordinal) => format!("ordinal:{ordinal}"),
        }
    }
}

fn advance_forwarder_chain(
    active: &mut BTreeMap<ForwarderNodeKey, usize>,
    host: &str,
    loader_contract_sha256: &str,
    symbol: &memcordon_core::WindowsPeImportSymbol,
    hops: &mut usize,
) -> Result<usize, ForwarderStepFailure> {
    let key = ForwarderNodeKey {
        concrete_host: host.to_ascii_uppercase(),
        loader_contract_sha256: loader_contract_sha256.to_owned(),
        symbol: LoaderSymbolKey::from_import(symbol),
    };
    if let Some(first_index) = active.get(&key) {
        return Err(ForwarderStepFailure::Cycle {
            first_index: *first_index,
        });
    }
    active.insert(key, *hops);
    *hops += 1;
    if *hops > MAX_LOADER_FORWARDER_HOPS {
        return Err(ForwarderStepFailure::HopBound { observed: *hops });
    }
    Ok(*hops)
}

fn memoize_completed_forwarder_path(
    completed: &mut BTreeMap<ForwarderNodeKey, Vec<ForwarderEdgeTemplate>>,
    path: &[(ForwarderNodeKey, ForwarderEdgeTemplate)],
    mut suffix: Vec<ForwarderEdgeTemplate>,
) {
    for (state, step) in path.iter().rev() {
        let mut completed_suffix = Vec::with_capacity(suffix.len() + 1);
        completed_suffix.push(step.clone());
        completed_suffix.extend(suffix);
        completed
            .entry(state.clone())
            .or_insert_with(|| completed_suffix.clone());
        suffix = completed_suffix;
    }
}

fn loader_contract_sha256(contract: &memcordon_core::WindowsPeLoaderContract) -> String {
    let mut canonical = format!("machine={:04x}\n", contract.machine).into_bytes();
    for (kind, descriptors) in [("normal", &contract.normal), ("delayed", &contract.delayed)] {
        for descriptor in descriptors {
            canonical.extend_from_slice(
                format!(
                    "{kind}:descriptor={}:dll={}:lookup={:08x}:iat={:08x}:bound={:08x}\n",
                    descriptor.ordinal,
                    descriptor.dll,
                    descriptor.lookup_table_rva,
                    descriptor.iat_rva,
                    descriptor.bound_timestamp,
                )
                .as_bytes(),
            );
            for symbol in &descriptor.symbols {
                canonical.extend_from_slice(b"thunk=");
                canonical.extend_from_slice(loader_symbol_name(symbol).as_bytes());
                canonical.push(b'\n');
            }
        }
    }
    for export in &contract.exports {
        canonical.extend_from_slice(
            format!(
                "export={}:{}:",
                export.ordinal,
                export.name.as_deref().unwrap_or(""),
            )
            .as_bytes(),
        );
        match &export.target {
            memcordon_core::WindowsPeExportTarget::DirectRva(rva) => {
                canonical.extend_from_slice(format!("rva:{rva:08x}\n").as_bytes());
            }
            memcordon_core::WindowsPeExportTarget::Forwarder(value) => {
                canonical.extend_from_slice(b"forwarder:");
                canonical.extend_from_slice(value.as_bytes());
                canonical.push(b'\n');
            }
        }
    }
    super::record::digest(&canonical)
}

fn loader_exports_sha256(contract: &memcordon_core::WindowsPeLoaderContract) -> String {
    let mut canonical = b"memcordon-pe-exports-v1\0".to_vec();
    for export in &contract.exports {
        canonical.extend_from_slice(export.ordinal.to_le_bytes().as_slice());
        canonical.extend_from_slice(export.name.as_deref().unwrap_or("").as_bytes());
        canonical.push(0);
        match &export.target {
            memcordon_core::WindowsPeExportTarget::DirectRva(rva) => {
                canonical.push(b'D');
                canonical.extend_from_slice(&rva.to_le_bytes());
            }
            memcordon_core::WindowsPeExportTarget::Forwarder(value) => {
                canonical.push(b'F');
                canonical.extend_from_slice(value.as_bytes());
            }
        }
        canonical.push(b'\n');
    }
    super::record::digest(&canonical)
}

fn resolve_loader_request(
    import_contract: &str,
    parent_host: &str,
    api_set_schema: &ApiSetSchemaV6,
    system_directory: &Path,
) -> Result<ResolvedLoaderRequestV1, NativeLoaderAccessFailureV1> {
    validate_graph_name(import_contract).map_err(|detail| {
        contract_failure(
            "system-module",
            Path::new(import_contract),
            "module-resolution",
            detail,
        )
    })?;
    let api_set_redirected = is_api_set_name(import_contract);
    let (concrete_path, api_set_selection) = if api_set_redirected {
        let resolution = resolve_api_set(
            api_set_schema,
            import_contract,
            parent_host,
            system_directory,
        )
        .map_err(|detail| {
            contract_failure(
                "api-set-resolution",
                Path::new(import_contract),
                "api-set-parent-resolution",
                detail,
            )
        })?;
        (resolution.path, Some(resolution.selection))
    } else {
        let mut basename = import_contract.to_ascii_uppercase();
        if !basename.ends_with(".DLL") {
            basename.push_str(".DLL");
        }
        (system_directory.join(basename), None)
    };
    if concrete_path
        .parent()
        .is_none_or(|parent| !same_path(parent, system_directory))
    {
        return Err(contract_failure(
            "system-module",
            &concrete_path,
            "module-resolution",
            "resolved loader module escaped native System32",
        ));
    }
    let concrete_host = concrete_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| {
            contract_failure(
                "system-module",
                &concrete_path,
                "module-resolution",
                "resolved loader module has no Unicode basename",
            )
        })?
        .to_ascii_uppercase();
    validate_graph_name(&concrete_host).map_err(|detail| {
        contract_failure("system-module", &concrete_path, "module-resolution", detail)
    })?;
    if is_api_set_name(&concrete_host) {
        return Err(contract_failure(
            "system-module",
            &concrete_path,
            "module-resolution",
            "resolved physical module remained an API-set contract",
        ));
    }
    Ok(ResolvedLoaderRequestV1 {
        import_contract: import_contract.to_ascii_uppercase(),
        concrete_host,
        api_set_redirected,
        api_set_selection,
        path: concrete_path,
    })
}

fn admit_physical_loader_module(
    request: ResolvedLoaderRequestV1,
    native_machine: u16,
) -> Result<ResolvedLoaderModuleV1, NativeLoaderAccessFailureV1> {
    let ResolvedLoaderRequestV1 {
        import_contract,
        concrete_host,
        api_set_redirected,
        api_set_selection,
        path: concrete_path,
    } = request;
    super::package::reject_reparse_components(&concrete_path).map_err(|detail| {
        contract_failure("system-module", &concrete_path, "reparse-preflight", detail)
    })?;
    let source_identity =
        capture_source_final_file(&concrete_path, LoaderPathRoleV1::SystemModule)?;
    if !source_identity
        .evidence
        .basename
        .eq_ignore_ascii_case(&concrete_host)
    {
        return Err(contract_failure(
            "system-module",
            &concrete_path,
            "GetFinalPathNameByHandleW",
            "resolved module final basename differs from its concrete host",
        ));
    }
    let module_bytes = read_handle_bytes(source_identity.handle.raw()).map_err(|error| {
        file_failure(
            LoaderPathRoleV1::SystemModule,
            &concrete_path,
            "ReadFile",
            LOADER_FILE_ACCESS,
            Some(source_identity.evidence.granted_access),
            error,
        )
    })?;
    let source_sha256 = sha256_bytes(&module_bytes);
    let source_loader_contract = memcordon_core::parse_windows_pe_loader_contract(&module_bytes)
        .map_err(|detail| {
            contract_failure(
                "system-module",
                &concrete_path,
                "PE-loader-contract",
                detail,
            )
        })?;
    let source_pe_machine = source_loader_contract.machine;
    if source_pe_machine != native_machine {
        return Err(contract_failure(
            "system-module",
            &concrete_path,
            "PE-machine",
            format!(
                "expected native machine 0x{native_machine:04x}, found 0x{source_pe_machine:04x}"
            ),
        ));
    }
    let source_loader_contract_sha256 = loader_contract_sha256(&source_loader_contract);
    Ok(ResolvedLoaderModuleV1 {
        import_contract,
        concrete_host,
        api_set_redirected,
        api_set_selection,
        path: concrete_path,
        source_identity,
        source_sha256,
        source_pe_machine,
        source_loader_contract,
        source_loader_contract_sha256,
    })
}

fn admitted_physical_loader_index(
    module_indices: &BTreeMap<String, usize>,
    concrete_host: &str,
) -> Option<usize> {
    module_indices.get(concrete_host).copied()
}

pub(crate) fn physical_loader_admission_plan_for_test(
    concrete_hosts: &[&str],
) -> (usize, Vec<usize>) {
    let mut module_indices = BTreeMap::<String, usize>::new();
    let mut plan = Vec::with_capacity(concrete_hosts.len());
    for host in concrete_hosts {
        let host = host.to_ascii_uppercase();
        let index = if let Some(index) = admitted_physical_loader_index(&module_indices, &host) {
            index
        } else {
            let index = module_indices.len();
            module_indices.insert(host, index);
            index
        };
        plan.push(index);
    }
    (module_indices.len(), plan)
}

fn find_export<'a>(
    contract: &'a memcordon_core::WindowsPeLoaderContract,
    symbol: &memcordon_core::WindowsPeImportSymbol,
) -> Option<&'a memcordon_core::WindowsPeExport> {
    contract.exports.iter().find(|export| match symbol {
        memcordon_core::WindowsPeImportSymbol::Name { name, .. } => export
            .name
            .as_deref()
            .is_some_and(|export_name| export_name == name),
        memcordon_core::WindowsPeImportSymbol::Ordinal(ordinal) => {
            export.ordinal == u32::from(*ordinal)
        }
    })
}

fn parse_forwarder(value: &str) -> Result<(String, memcordon_core::WindowsPeImportSymbol), String> {
    let (module, symbol) = value
        .rsplit_once('.')
        .ok_or_else(|| "PE export forwarder lacks its module/symbol separator".to_owned())?;
    let mut module = module.to_ascii_uppercase();
    if !module.ends_with(".DLL") {
        module.push_str(".DLL");
    }
    validate_graph_name(&module)?;
    let symbol = if let Some(ordinal) = symbol.strip_prefix('#') {
        memcordon_core::WindowsPeImportSymbol::Ordinal(
            ordinal
                .parse::<u16>()
                .map_err(|_| "PE export forwarder ordinal is invalid".to_owned())?,
        )
    } else {
        if symbol.is_empty() || !symbol.is_ascii() || symbol.len() > 256 {
            return Err("PE export forwarder symbol is invalid".to_owned());
        }
        memcordon_core::WindowsPeImportSymbol::Name {
            hint: 0,
            name: symbol.to_owned(),
        }
    };
    Ok((module, symbol))
}

fn resolve_loader_graph(
    bootstrap: &memcordon_core::WindowsPeLoaderContract,
    bootstrap_parent_host: &str,
    system_directory: &Path,
    native_machine: u16,
    budget: &mut NativeLoaderAttestationBudget<'_>,
) -> Result<
    (
        Vec<ResolvedLoaderModuleV1>,
        Vec<LoaderRootEvidenceV2>,
        Vec<LoaderImportEdgeEvidenceV2>,
    ),
    NativeLoaderAccessFailureV1,
> {
    budget.check(NativeLoaderProgressStage::SourceLoaderGraph, 0, None)?;
    let overall_deadline = budget.deadline();
    let mut modules = Vec::<ResolvedLoaderModuleV1>::new();
    let mut module_indices = BTreeMap::<String, usize>::new();
    let mut identities = BTreeMap::<(u64, u64), String>::new();
    let mut roots = Vec::new();
    let mut edges_by_identity = BTreeMap::<Vec<u8>, LoaderImportEdgeEvidenceV2>::new();
    let mut queue = VecDeque::<(LoaderRootPhaseV2, String)>::new();
    let mut expanded = BTreeSet::<(LoaderRootPhaseV2, String)>::new();
    let mut completed_forwarders = BTreeMap::<ForwarderNodeKey, Vec<ForwarderEdgeTemplate>>::new();
    let api_set_schema = current_api_set_schema().map_err(|detail| {
        contract_failure(
            "api-set-schema",
            Path::new("PEB.ApiSetMap"),
            "api-set-schema-v6",
            detail,
        )
    })?;
    let mut api_set_selections = BTreeMap::<(String, String, String), String>::new();

    let mut add_module = |parent_host: &str,
                          import_contract: &str,
                          modules: &mut Vec<ResolvedLoaderModuleV1>,
                          module_indices: &mut BTreeMap<String, usize>,
                          identities: &mut BTreeMap<(u64, u64), String>|
     -> Result<usize, NativeLoaderAccessFailureV1> {
        let request = resolve_loader_request(
            import_contract,
            parent_host,
            &api_set_schema,
            system_directory,
        )?;
        if Instant::now() >= overall_deadline {
            return Err(contract_failure(
                "system-module",
                &request.path,
                "loader-graph-deadline",
                "overall loader-attestation deadline elapsed while resolving a module",
            ));
        }
        if request.api_set_redirected {
            let parent_key = normalize_api_set_parent(parent_host).map_err(|detail| {
                contract_failure(
                    "api-set-resolution",
                    Path::new(import_contract),
                    "api-set-parent-key",
                    detail,
                )
            })?;
            let selection = request.api_set_selection.as_ref().ok_or_else(|| {
                contract_failure(
                    "api-set-resolution",
                    Path::new(import_contract),
                    "api-set-contract-key",
                    "redirected module has no selected API-set schema identity",
                )
            })?;
            let selection_key = (
                api_set_schema.sha256.clone(),
                parent_key,
                selection.hash_key.clone(),
            );
            if let Some(prior) =
                api_set_selections.insert(selection_key, request.concrete_host.clone())
            {
                if prior != request.concrete_host {
                    return Err(contract_failure(
                        "api-set-resolution",
                        Path::new(import_contract),
                        "api-set-parent-resolution",
                        "one schema/parent/contract selection produced inconsistent hosts",
                    ));
                }
            }
        }
        if let Some(index) = admitted_physical_loader_index(module_indices, &request.concrete_host)
        {
            let existing = &modules[index];
            let replace_alias = (existing.api_set_redirected && !request.api_set_redirected)
                || (existing.api_set_redirected == request.api_set_redirected
                    && request.import_contract < existing.import_contract);
            if replace_alias {
                modules[index].import_contract = request.import_contract;
                modules[index].api_set_redirected = request.api_set_redirected;
            }
            return Ok(index);
        }
        let candidate = admit_physical_loader_module(request, native_machine)?;
        let identity = (
            candidate.source_identity.evidence.volume_serial,
            candidate.source_identity.file_id,
        );
        if let Some(other) = identities.insert(identity, candidate.concrete_host.clone()) {
            if other != candidate.concrete_host {
                return Err(contract_failure(
                    "system-module",
                    &candidate.path,
                    "physical-host-coalescing",
                    "distinct concrete hosts alias one physical file identity",
                ));
            }
        }
        let index = modules.len();
        module_indices.insert(candidate.concrete_host.clone(), index);
        modules.push(candidate);
        if modules.len() > MAX_LOADER_MODULES {
            return Err(contract_failure(
                "system-module",
                system_directory,
                "loader-graph-bound",
                "recursive loader graph exceeds its physical-host bound",
            ));
        }
        budget.check(
            NativeLoaderProgressStage::SourceLoaderGraph,
            modules.len(),
            None,
        )?;
        Ok(index)
    };

    let admit_edge = |edge: LoaderImportEdgeEvidenceV2,
                      edges: &mut BTreeMap<Vec<u8>, LoaderImportEdgeEvidenceV2>|
     -> Result<(), NativeLoaderAccessFailureV1> {
        let identity = graph_edge_identity_canonical(&edge);
        if edges.contains_key(&identity) {
            return Ok(());
        }
        if edges.len() == MAX_LOADER_GRAPH_EDGES {
            return Err(contract_failure(
                "system-module",
                Path::new(&edge.parent_host),
                "loader-graph-bound",
                "recursive loader graph exceeds its distinct logical edge bound",
            ));
        }
        edges.insert(identity, edge);
        Ok(())
    };

    for descriptor in &bootstrap.normal {
        let index = add_module(
            bootstrap_parent_host,
            &descriptor.dll,
            &mut modules,
            &mut module_indices,
            &mut identities,
        )?;
        let module = &modules[index];
        roots.push(LoaderRootEvidenceV2 {
            phase: LoaderRootPhaseV2::StaticKernel,
            descriptor_ordinal: Some(descriptor.ordinal),
            import_contract: descriptor.dll.clone(),
            concrete_host: module.concrete_host.clone(),
            export_contract_sha256: loader_exports_sha256(&module.source_loader_contract),
        });
        queue.push_back((
            LoaderRootPhaseV2::StaticKernel,
            module.concrete_host.clone(),
        ));
    }
    for (phase, contract) in [
        (LoaderRootPhaseV2::ExplicitSecurity, "ADVAPI32.DLL"),
        (LoaderRootPhaseV2::ExplicitUser, "USER32.DLL"),
    ] {
        let index = add_module(
            bootstrap_parent_host,
            contract,
            &mut modules,
            &mut module_indices,
            &mut identities,
        )?;
        let module = &modules[index];
        roots.push(LoaderRootEvidenceV2 {
            phase,
            descriptor_ordinal: None,
            import_contract: contract.to_owned(),
            concrete_host: module.concrete_host.clone(),
            export_contract_sha256: loader_exports_sha256(&module.source_loader_contract),
        });
        queue.push_back((phase, module.concrete_host.clone()));
    }

    while let Some((phase, parent_host)) = queue.pop_front() {
        if Instant::now() >= overall_deadline {
            return Err(contract_failure(
                "system-module",
                Path::new(&parent_host),
                "loader-graph-deadline",
                "overall loader-attestation deadline elapsed while expanding the graph",
            ));
        }
        if !expanded.insert((phase, parent_host.clone())) {
            continue;
        }
        let parent_index = *module_indices
            .get(&parent_host)
            .expect("queued loader graph host must be admitted");
        let descriptors = modules[parent_index].source_loader_contract.normal.clone();
        for descriptor in descriptors {
            if Instant::now() >= overall_deadline {
                return Err(contract_failure(
                    "system-module",
                    Path::new(&parent_host),
                    "loader-graph-deadline",
                    "overall loader-attestation deadline elapsed while resolving imports",
                ));
            }
            let child_index = add_module(
                &parent_host,
                &descriptor.dll,
                &mut modules,
                &mut module_indices,
                &mut identities,
            )?;
            let child_host = modules[child_index].concrete_host.clone();
            admit_edge(
                LoaderImportEdgeEvidenceV2 {
                    phase,
                    depth: 0,
                    parent_host: parent_host.clone(),
                    descriptor_ordinal: Some(descriptor.ordinal),
                    requested_symbol: None,
                    import_contract: descriptor.dll.clone(),
                    concrete_host: child_host.clone(),
                    resolved_target_symbol: None,
                    api_set_redirected: is_api_set_name(&descriptor.dll),
                    forwarder: false,
                },
                &mut edges_by_identity,
            )?;
            for symbol in &descriptor.symbols {
                let origin_symbol = LoaderSymbolKey::from_import(symbol).evidence();
                let mut current_host = child_host.clone();
                let mut current_symbol = symbol.clone();
                let mut active = BTreeMap::<ForwarderNodeKey, usize>::new();
                let mut resolution_path = Vec::<(ForwarderNodeKey, ForwarderEdgeTemplate)>::new();
                let mut forwarder_hops = 0_usize;
                loop {
                    if Instant::now() >= overall_deadline {
                        return Err(contract_failure(
                            "system-module",
                            Path::new(&current_host),
                            "loader-graph-deadline",
                            "overall loader-attestation deadline elapsed while resolving export forwarders",
                        ));
                    }
                    let current_index = *module_indices
                        .get(&current_host)
                        .expect("forwarder host must be admitted");
                    let current_key = ForwarderNodeKey {
                        concrete_host: current_host.to_ascii_uppercase(),
                        loader_contract_sha256: modules[current_index]
                            .source_loader_contract_sha256
                            .clone(),
                        symbol: LoaderSymbolKey::from_import(&current_symbol),
                    };
                    if !active.contains_key(&current_key) {
                        if let Some(completed_suffix) =
                            completed_forwarders.get(&current_key).cloned()
                        {
                            let observed_hops = forwarder_hops + completed_suffix.len();
                            if observed_hops > MAX_LOADER_FORWARDER_HOPS {
                                return Err(contract_failure(
                                    "system-module",
                                    Path::new(&current_host),
                                    "export-forwarder-hop-bound",
                                    format!(
                                        "origin_parent={} origin_import_contract={} origin_descriptor_ordinal={} origin_symbol={} current_host={} current_symbol={} raw_forwarder=cached-suffix forwarder_hop={observed_hops} forwarder_limit={MAX_LOADER_FORWARDER_HOPS} failure=hop-bound",
                                        bounded(&parent_host, MAX_LOADER_BASENAME_BYTES),
                                        bounded(&descriptor.dll, MAX_LOADER_BASENAME_BYTES),
                                        descriptor.ordinal,
                                        bounded(&origin_symbol, 256),
                                        bounded(
                                            &current_key.concrete_host,
                                            MAX_LOADER_BASENAME_BYTES
                                        ),
                                        bounded(&current_key.symbol.evidence(), 256),
                                    ),
                                ));
                            }
                            for step in &completed_suffix {
                                admit_edge(
                                    LoaderImportEdgeEvidenceV2 {
                                        phase,
                                        depth: 0,
                                        parent_host: step.parent_host.clone(),
                                        descriptor_ordinal: None,
                                        requested_symbol: Some(step.requested_symbol.clone()),
                                        import_contract: step.import_contract.clone(),
                                        concrete_host: step.concrete_host.clone(),
                                        resolved_target_symbol: Some(
                                            step.resolved_target_symbol.clone(),
                                        ),
                                        api_set_redirected: step.api_set_redirected,
                                        forwarder: true,
                                    },
                                    &mut edges_by_identity,
                                )?;
                                queue.push_back((phase, step.concrete_host.clone()));
                            }
                            memoize_completed_forwarder_path(
                                &mut completed_forwarders,
                                &resolution_path,
                                completed_suffix,
                            );
                            break;
                        }
                    }
                    let current_export = find_export(
                        &modules[current_index].source_loader_contract,
                        &current_symbol,
                    )
                    .ok_or_else(|| {
                        let api = if forwarder_hops == 0 {
                            "export-resolution"
                        } else {
                            "export-forwarder-resolution"
                        };
                        contract_failure(
                            "system-module",
                            &modules[current_index].path,
                            api,
                            format!(
                                "origin_parent={} origin_import_contract={} origin_descriptor_ordinal={} origin_symbol={} current_host={} current_symbol={} forwarder_hop={} failure=missing-exact-export",
                                bounded(&parent_host, MAX_LOADER_BASENAME_BYTES),
                                bounded(&descriptor.dll, MAX_LOADER_BASENAME_BYTES),
                                descriptor.ordinal,
                                bounded(&origin_symbol, 256),
                                bounded(&current_host, MAX_LOADER_BASENAME_BYTES),
                                bounded(
                                    &LoaderSymbolKey::from_import(&current_symbol).evidence(),
                                    256,
                                ),
                                forwarder_hops,
                            ),
                        )
                    })?
                    .target
                    .clone();
                    let memcordon_core::WindowsPeExportTarget::Forwarder(value) = current_export
                    else {
                        completed_forwarders.entry(current_key.clone()).or_default();
                        memoize_completed_forwarder_path(
                            &mut completed_forwarders,
                            &resolution_path,
                            Vec::new(),
                        );
                        break;
                    };
                    if let Err(failure) = advance_forwarder_chain(
                        &mut active,
                        &current_host,
                        &modules[current_index].source_loader_contract_sha256,
                        &current_symbol,
                        &mut forwarder_hops,
                    ) {
                        let (api, detail) = match failure {
                            ForwarderStepFailure::Cycle { first_index } => (
                                "export-forwarder-cycle",
                                format!(
                                    "origin_parent={} origin_import_contract={} origin_descriptor_ordinal={} origin_symbol={} current_host={} current_symbol={} raw_forwarder={} forwarder_hop={} cycle_first_index={first_index} failure=cycle",
                                    bounded(&parent_host, MAX_LOADER_BASENAME_BYTES),
                                    bounded(&descriptor.dll, MAX_LOADER_BASENAME_BYTES),
                                    descriptor.ordinal,
                                    bounded(&origin_symbol, 256),
                                    bounded(&current_key.concrete_host, MAX_LOADER_BASENAME_BYTES,),
                                    bounded(&current_key.symbol.evidence(), 256),
                                    bounded(&value, 384),
                                    forwarder_hops,
                                ),
                            ),
                            ForwarderStepFailure::HopBound { observed } => (
                                "export-forwarder-hop-bound",
                                format!(
                                    "origin_parent={} origin_import_contract={} origin_descriptor_ordinal={} origin_symbol={} current_host={} current_symbol={} raw_forwarder={} forwarder_hop={observed} forwarder_limit={MAX_LOADER_FORWARDER_HOPS} failure=hop-bound",
                                    bounded(&parent_host, MAX_LOADER_BASENAME_BYTES),
                                    bounded(&descriptor.dll, MAX_LOADER_BASENAME_BYTES),
                                    descriptor.ordinal,
                                    bounded(&origin_symbol, 256),
                                    bounded(&current_host, MAX_LOADER_BASENAME_BYTES),
                                    bounded(&current_key.symbol.evidence(), 256),
                                    bounded(&value, 384),
                                ),
                            ),
                        };
                        return Err(contract_failure(
                            "system-module",
                            Path::new(&current_host),
                            api,
                            detail,
                        ));
                    }
                    let (forward_contract, target_symbol) =
                        parse_forwarder(&value).map_err(|detail| {
                            contract_failure(
                                "system-module",
                                Path::new(&current_host),
                                "export-forwarder",
                                format!(
                                    "origin_parent={} origin_import_contract={} origin_descriptor_ordinal={} origin_symbol={} current_host={} current_symbol={} raw_forwarder={} forwarder_hop={} failure=malformed-forwarder detail={}",
                                    bounded(&parent_host, MAX_LOADER_BASENAME_BYTES),
                                    bounded(&descriptor.dll, MAX_LOADER_BASENAME_BYTES),
                                    descriptor.ordinal,
                                    bounded(&origin_symbol, 256),
                                    bounded(&current_host, MAX_LOADER_BASENAME_BYTES),
                                    bounded(&current_key.symbol.evidence(), 256),
                                    bounded(&value, 384),
                                    forwarder_hops,
                                    bounded(&detail, 384),
                                ),
                            )
                        })?;
                    let forward_index = add_module(
                        &current_host,
                        &forward_contract,
                        &mut modules,
                        &mut module_indices,
                        &mut identities,
                    )?;
                    let forward_host = modules[forward_index].concrete_host.clone();
                    let source_key = LoaderSymbolKey::from_import(&current_symbol);
                    let target_key = LoaderSymbolKey::from_import(&target_symbol);
                    let step = ForwarderEdgeTemplate {
                        parent_host: current_host.clone(),
                        requested_symbol: source_key.evidence(),
                        import_contract: forward_contract.clone(),
                        concrete_host: forward_host.clone(),
                        resolved_target_symbol: target_key.evidence(),
                        api_set_redirected: is_api_set_name(&forward_contract),
                    };
                    admit_edge(
                        LoaderImportEdgeEvidenceV2 {
                            phase,
                            depth: 0,
                            parent_host: step.parent_host.clone(),
                            descriptor_ordinal: None,
                            requested_symbol: Some(step.requested_symbol.clone()),
                            import_contract: step.import_contract.clone(),
                            concrete_host: step.concrete_host.clone(),
                            resolved_target_symbol: Some(step.resolved_target_symbol.clone()),
                            api_set_redirected: step.api_set_redirected,
                            forwarder: true,
                        },
                        &mut edges_by_identity,
                    )?;
                    resolution_path.push((current_key, step));
                    current_host = forward_host.clone();
                    current_symbol = target_symbol;
                    queue.push_back((phase, forward_host));
                }
            }
            queue.push_back((phase, child_host));
        }
    }

    drop(add_module);
    budget.check(
        NativeLoaderProgressStage::SourceLoaderGraph,
        modules.len(),
        Some(modules.len()),
    )?;

    let mut edges = edges_by_identity.into_values().collect::<Vec<_>>();
    let shortest_depths = canonicalize_loader_edge_depths(&roots, &mut edges, system_directory)?;
    let reachable_hosts = shortest_depths
        .keys()
        .map(|(_, host)| host.clone())
        .collect::<BTreeSet<_>>();
    if modules
        .iter()
        .any(|module| !reachable_hosts.contains(&module.concrete_host.to_ascii_uppercase()))
    {
        return Err(contract_failure(
            "system-module",
            system_directory,
            "loader-graph-reachability",
            "recursive loader graph contains an orphan physical host",
        ));
    }
    edges.sort_by_key(graph_edge_canonical);
    Ok((modules, roots, edges))
}

fn open_known_dll_directory(
    native_api: &NativeObjectApi,
) -> Result<(OwnedHandle, u32), NativeLoaderAccessFailureV1> {
    let mut name_storage = r"\KnownDlls".encode_utf16().collect::<Vec<_>>();
    let mut name = unicode_string(&mut name_storage).map_err(|detail| {
        object_failure(
            "known-dll-directory",
            r"\KnownDlls",
            "UNICODE_STRING",
            0,
            None,
            None,
            detail,
        )
    })?;
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: ptr::null_mut(),
        object_name: &raw mut name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };
    let mut raw_directory = ptr::null_mut();
    let status = unsafe {
        (native_api.nt_open_directory_object)(
            &raw mut raw_directory,
            KNOWN_DLL_DIRECTORY_ACCESS,
            &raw const attributes,
        )
    };
    if status < 0 {
        return Err(object_failure(
            "known-dll-directory",
            r"\KnownDlls",
            "NtOpenDirectoryObject",
            KNOWN_DLL_DIRECTORY_ACCESS,
            None,
            Some(status),
            "native object-directory open failed",
        ));
    }
    let directory = OwnedHandle::new(raw_directory).map_err(|detail| {
        object_failure(
            "known-dll-directory",
            r"\KnownDlls",
            "OwnedHandle",
            KNOWN_DLL_DIRECTORY_ACCESS,
            None,
            None,
            detail,
        )
    })?;
    let granted = super::token::granted_handle_access(directory.raw()).map_err(|detail| {
        object_failure(
            "known-dll-directory",
            r"\KnownDlls",
            "NtQueryObject",
            KNOWN_DLL_DIRECTORY_ACCESS,
            None,
            None,
            detail,
        )
    })?;
    require_access(KNOWN_DLL_DIRECTORY_ACCESS, granted, "known-dll-directory").map_err(
        |detail| {
            object_failure(
                "known-dll-directory",
                r"\KnownDlls",
                "NtQueryObject",
                KNOWN_DLL_DIRECTORY_ACCESS,
                Some(granted),
                None,
                detail,
            )
        },
    )?;
    Ok((directory, granted))
}

fn open_known_dll_section(
    native_api: &NativeObjectApi,
    directory: HANDLE,
    host: &str,
) -> Result<(i32, Option<(OwnedHandle, u32)>), NativeLoaderAccessFailureV1> {
    let mut section_storage = host.encode_utf16().collect::<Vec<_>>();
    let mut section_name = unicode_string(&mut section_storage).map_err(|detail| {
        object_failure(
            "known-dll-section",
            host,
            "UNICODE_STRING",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            detail,
        )
    })?;
    let section_attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: directory,
        object_name: &raw mut section_name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };
    let mut raw_section = ptr::null_mut();
    let status = unsafe {
        (native_api.nt_open_section)(
            &raw mut raw_section,
            KNOWN_DLL_SECTION_ACCESS,
            &raw const section_attributes,
        )
    };
    if status == STATUS_OBJECT_NAME_NOT_FOUND {
        return Ok((status, None));
    }
    if status < 0 {
        return Err(object_failure(
            "known-dll-section",
            host,
            "NtOpenSection",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            Some(status),
            if status == STATUS_ACCESS_DENIED {
                "KnownDll section denied exact token access"
            } else {
                "KnownDll section open returned an unexpected native status"
            },
        ));
    }
    let section = OwnedHandle::new(raw_section).map_err(|detail| {
        object_failure(
            "known-dll-section",
            host,
            "OwnedHandle",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            detail,
        )
    })?;
    let granted = super::token::granted_handle_access(section.raw()).map_err(|detail| {
        object_failure(
            "known-dll-section",
            host,
            "NtQueryObject",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            detail,
        )
    })?;
    require_access(KNOWN_DLL_SECTION_ACCESS, granted, "known-dll-section").map_err(|detail| {
        object_failure(
            "known-dll-section",
            host,
            "NtQueryObject",
            KNOWN_DLL_SECTION_ACCESS,
            Some(granted),
            Some(status),
            detail,
        )
    })?;
    Ok((status, Some((section, granted))))
}

fn query_section_basic_information(
    native_api: &NativeObjectApi,
    section: HANDLE,
    host: &str,
) -> Result<SectionBasicInformation, NativeLoaderAccessFailureV1> {
    let mut information = SectionBasicInformation::default();
    let mut returned = 0_usize;
    let status = unsafe {
        (native_api.nt_query_section)(
            section,
            SECTION_BASIC_INFORMATION_CLASS,
            (&raw mut information).cast::<c_void>(),
            std::mem::size_of::<SectionBasicInformation>(),
            &raw mut returned,
        )
    };
    if status < 0 {
        return Err(object_failure(
            "known-dll-section",
            host,
            "NtQuerySection",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            Some(status),
            "KnownDll section basic-information query failed",
        ));
    }
    if returned < std::mem::size_of::<SectionBasicInformation>()
        || information.allocation_attributes & SEC_IMAGE == 0
        || information.maximum_size <= 0
    {
        return Err(object_failure(
            "known-dll-section",
            host,
            "NtQuerySection",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            Some(status),
            "KnownDll section is not a nonempty SEC_IMAGE object",
        ));
    }
    Ok(information)
}

fn query_section_image_information(
    native_api: &NativeObjectApi,
    section: HANDLE,
    host: &str,
    native_machine: u16,
) -> Result<SectionImageInformation, NativeLoaderAccessFailureV1> {
    let mut information = SectionImageInformation::default();
    let mut returned = 0_usize;
    let status = unsafe {
        (native_api.nt_query_section)(
            section,
            SECTION_IMAGE_INFORMATION_CLASS,
            (&raw mut information).cast::<c_void>(),
            std::mem::size_of::<SectionImageInformation>(),
            &raw mut returned,
        )
    };
    if status < 0 {
        return Err(object_failure(
            "known-dll-section",
            host,
            "NtQuerySection",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            Some(status),
            "KnownDll section image-information query failed",
        ));
    }
    if returned < std::mem::size_of::<SectionImageInformation>()
        || information.machine != native_machine
        || information.image_file_size == 0
    {
        return Err(object_failure(
            "known-dll-section",
            host,
            "NtQuerySection",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            Some(status),
            "KnownDll section image metadata is nonnative or invalid",
        ));
    }
    Ok(information)
}

fn mapped_section_loader_contract_sha256(
    section: HANDLE,
    maximum_size: i64,
    host: &str,
) -> Result<String, NativeLoaderAccessFailureV1> {
    let size = usize::try_from(maximum_size).map_err(|_| {
        object_failure(
            "known-dll-section",
            host,
            "MapViewOfFile",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            "KnownDll mapped image size is not representable",
        )
    })?;
    if size == 0 || size > MAX_MAPPED_IMAGE_BYTES {
        return Err(object_failure(
            "known-dll-section",
            host,
            "MapViewOfFile",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            "KnownDll mapped image exceeds its parse bound",
        ));
    }
    let view = MappedSectionView(unsafe { MapViewOfFile(section, 0x0000_0004, 0, 0, size) });
    if view.0.is_null() {
        return Err(object_failure(
            "known-dll-section",
            host,
            "MapViewOfFile",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            format!(
                "KnownDll read-only image map failed: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(view.0.cast::<u8>(), size) };
    let contract =
        memcordon_core::parse_windows_pe_mapped_loader_contract(bytes).map_err(|detail| {
            object_failure(
                "known-dll-section",
                host,
                "PE-mapped-loader-contract",
                KNOWN_DLL_SECTION_ACCESS,
                None,
                None,
                detail,
            )
        })?;
    Ok(loader_contract_sha256(&contract))
}

fn attest_executable_section_map(
    section: HANDLE,
    maximum_size: i64,
    host: &str,
) -> Result<(), NativeLoaderAccessFailureV1> {
    let size = usize::try_from(maximum_size).map_err(|_| {
        object_failure(
            "known-dll-section",
            host,
            "MapViewOfFile-execute",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            "KnownDll executable image-map size is not representable",
        )
    })?;
    if size == 0 || size > MAX_MAPPED_IMAGE_BYTES {
        return Err(object_failure(
            "known-dll-section",
            host,
            "MapViewOfFile-execute",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            "KnownDll executable image map exceeds its bound",
        ));
    }
    const FILE_MAP_READ: u32 = 0x0000_0004;
    const FILE_MAP_EXECUTE: u32 = 0x0000_0020;
    let view = MappedSectionView(unsafe {
        MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, size)
    });
    if view.0.is_null() {
        return Err(object_failure(
            "known-dll-section",
            host,
            "MapViewOfFile-execute",
            KNOWN_DLL_SECTION_ACCESS,
            None,
            None,
            format!(
                "KnownDll executable image map failed: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

fn admit_source_known_dlls(
    native_api: &NativeObjectApi,
    modules: &[ResolvedLoaderModuleV1],
    native_machine: u16,
    budget: &mut NativeLoaderAttestationBudget<'_>,
) -> Result<SourceKnownDllResourcesV1, NativeLoaderAccessFailureV1> {
    let (directory, _) = open_known_dll_directory(native_api)?;
    let hosts = modules
        .iter()
        .map(|module| module.concrete_host.clone())
        .collect::<BTreeSet<_>>();
    let total = hosts.len();
    let mut sections = Vec::with_capacity(total);
    for (index, host) in hosts.into_iter().enumerate() {
        budget.check_deadline(
            NativeLoaderProgressStage::SourceKnownDlls,
            index,
            Some(total),
        )?;
        if modules
            .iter()
            .filter(|module| module.concrete_host == host)
            .any(|module| module.source_pe_machine != native_machine)
        {
            return Err(contract_failure(
                "known-dll-section",
                Path::new(&host),
                "source-machine-relation",
                "KnownDll source host is not related to the admitted native machine",
            ));
        }
        let (status, opened) = open_known_dll_section(native_api, directory.raw(), &host)?;
        match opened {
            Some((handle, _)) => {
                let information = query_section_basic_information(native_api, handle.raw(), &host)?;
                let image_information = query_section_image_information(
                    native_api,
                    handle.raw(),
                    &host,
                    native_machine,
                )?;
                let mapped_loader_contract_sha256 = mapped_section_loader_contract_sha256(
                    handle.raw(),
                    information.maximum_size,
                    &host,
                )?;
                attest_executable_section_map(handle.raw(), information.maximum_size, &host)?;
                let source_contract = modules
                    .iter()
                    .find(|module| module.concrete_host == host)
                    .ok_or_else(|| {
                        contract_failure(
                            "known-dll-section",
                            Path::new(&host),
                            "mapped-contract-relation",
                            "KnownDll host has no pinned System32 graph node",
                        )
                    })?;
                if mapped_loader_contract_sha256 != source_contract.source_loader_contract_sha256 {
                    return Err(object_failure(
                        "known-dll-section",
                        &host,
                        "PE-mapped-loader-contract",
                        KNOWN_DLL_SECTION_ACCESS,
                        None,
                        None,
                        "KnownDll mapped contract differs from pinned System32 bytes",
                    ));
                }
                sections.push(SourceKnownDllSectionV1 {
                    concrete_host: host,
                    not_found_status: None,
                    handle: Some(handle),
                    allocation_attributes: information.allocation_attributes,
                    maximum_size: information.maximum_size,
                    image_machine: image_information.machine,
                    image_characteristics: image_information.image_characteristics,
                    image_file_size: image_information.image_file_size,
                    image_checksum: image_information.checksum,
                    mapped_loader_contract_sha256: Some(mapped_loader_contract_sha256),
                });
            }
            None if status == STATUS_OBJECT_NAME_NOT_FOUND => {
                sections.push(SourceKnownDllSectionV1 {
                    concrete_host: host,
                    not_found_status: Some(status),
                    handle: None,
                    allocation_attributes: 0,
                    maximum_size: 0,
                    image_machine: 0,
                    image_characteristics: 0,
                    image_file_size: 0,
                    image_checksum: 0,
                    mapped_loader_contract_sha256: None,
                });
            }
            None => {
                return Err(contract_failure(
                    "known-dll-section",
                    Path::new(&host),
                    "source-disposition",
                    "source KnownDll disposition is noncanonical",
                ));
            }
        }
        budget.check(
            NativeLoaderProgressStage::SourceKnownDlls,
            index + 1,
            Some(total),
        )?;
    }
    Ok(SourceKnownDllResourcesV1 {
        directory,
        sections,
    })
}

fn probe_known_dlls(
    resources: &ResolvedNativeLoaderResourcesV1,
    budget: &mut NativeLoaderAttestationBudget<'_>,
) -> Result<
    (
        LoaderObjectAccessEvidenceV1,
        Vec<KnownDllSectionEvidenceV1>,
        OwnedHandle,
        Vec<OwnedHandle>,
    ),
    NativeLoaderAccessFailureV1,
> {
    let (directory, directory_granted) = open_known_dll_directory(&resources.native_api)?;
    if unsafe { CompareObjectHandles(resources.source_known_dlls.directory.raw(), directory.raw()) }
        == 0
    {
        return Err(object_failure(
            "known-dll-directory",
            r"\KnownDlls",
            "CompareObjectHandles",
            KNOWN_DLL_DIRECTORY_ACCESS,
            Some(directory_granted),
            None,
            format!(
                "source and exact-target KnownDll directory handles differ: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    let total = resources.source_known_dlls.sections.len();
    let mut sections = Vec::with_capacity(total);
    let mut retained_sections = Vec::with_capacity(total);
    for (index, source) in resources.source_known_dlls.sections.iter().enumerate() {
        budget.check_deadline(
            NativeLoaderProgressStage::TargetKnownDlls,
            index,
            Some(total),
        )?;
        let (target_status, target_opened) = open_known_dll_section(
            &resources.native_api,
            directory.raw(),
            &source.concrete_host,
        )?;
        let disposition = match (source.handle.as_ref(), target_opened) {
            (Some(source_handle), Some((target_handle, target_granted))) => {
                if unsafe { CompareObjectHandles(source_handle.raw(), target_handle.raw()) } == 0 {
                    return Err(object_failure(
                        "known-dll-section",
                        &source.concrete_host,
                        "CompareObjectHandles",
                        KNOWN_DLL_SECTION_ACCESS,
                        Some(target_granted),
                        Some(target_status),
                        format!(
                            "holder-admitted and exact-target KnownDll section handles differ: {}",
                            io::Error::last_os_error()
                        ),
                    ));
                }
                let target_information = query_section_basic_information(
                    &resources.native_api,
                    target_handle.raw(),
                    &source.concrete_host,
                )?;
                let target_image_information = query_section_image_information(
                    &resources.native_api,
                    target_handle.raw(),
                    &source.concrete_host,
                    resources.native_machine,
                )?;
                if target_information.allocation_attributes != source.allocation_attributes
                    || target_information.maximum_size != source.maximum_size
                    || target_image_information.machine != source.image_machine
                    || target_image_information.image_characteristics
                        != source.image_characteristics
                    || target_image_information.image_file_size != source.image_file_size
                    || target_image_information.checksum != source.image_checksum
                {
                    return Err(object_failure(
                        "known-dll-section",
                        &source.concrete_host,
                        "NtQuerySection",
                        KNOWN_DLL_SECTION_ACCESS,
                        Some(target_granted),
                        Some(target_status),
                        "holder-admitted and exact-target section metadata differs",
                    ));
                }
                let target_contract_sha256 = mapped_section_loader_contract_sha256(
                    target_handle.raw(),
                    target_information.maximum_size,
                    &source.concrete_host,
                )?;
                attest_executable_section_map(
                    target_handle.raw(),
                    target_information.maximum_size,
                    &source.concrete_host,
                )?;
                if source.mapped_loader_contract_sha256.as_deref()
                    != Some(target_contract_sha256.as_str())
                {
                    return Err(object_failure(
                        "known-dll-section",
                        &source.concrete_host,
                        "PE-mapped-loader-contract",
                        KNOWN_DLL_SECTION_ACCESS,
                        Some(target_granted),
                        Some(target_status),
                        "holder-admitted and exact-target mapped loader contracts differ",
                    ));
                }
                retained_sections.push(target_handle);
                KnownDllDispositionV1::Section {
                    requested_access: KNOWN_DLL_SECTION_ACCESS,
                    granted_access: target_granted,
                }
            }
            (None, None)
                if source.not_found_status == Some(STATUS_OBJECT_NAME_NOT_FOUND)
                    && target_status == STATUS_OBJECT_NAME_NOT_FOUND =>
            {
                KnownDllDispositionV1::FileBacked {
                    not_found_status: target_status,
                }
            }
            (Some(_), None) => {
                return Err(object_failure(
                    "known-dll-section",
                    &source.concrete_host,
                    "NtOpenSection",
                    KNOWN_DLL_SECTION_ACCESS,
                    None,
                    Some(target_status),
                    "holder-admitted KnownDll section disappeared before exact-target reopen",
                ));
            }
            (None, Some((_target_handle, target_granted))) => {
                return Err(object_failure(
                    "known-dll-section",
                    &source.concrete_host,
                    "NtOpenSection",
                    KNOWN_DLL_SECTION_ACCESS,
                    Some(target_granted),
                    Some(target_status),
                    "KnownDll section appeared after holder source admission",
                ));
            }
            (None, None) => {
                return Err(object_failure(
                    "known-dll-section",
                    &source.concrete_host,
                    "NtOpenSection",
                    KNOWN_DLL_SECTION_ACCESS,
                    None,
                    Some(target_status),
                    "source/target KnownDll absence relation is noncanonical",
                ));
            }
        };
        sections.push(KnownDllSectionEvidenceV1 {
            concrete_host: source.concrete_host.clone(),
            disposition,
            read_map_attested: matches!(disposition, KnownDllDispositionV1::Section { .. }),
            execute_map_attested: matches!(disposition, KnownDllDispositionV1::Section { .. }),
            loader_contract_sha256: source
                .mapped_loader_contract_sha256
                .clone()
                .or_else(|| {
                    resources
                        .modules
                        .iter()
                        .find(|module| module.concrete_host == source.concrete_host)
                        .map(|module| module.source_loader_contract_sha256.clone())
                })
                .ok_or_else(|| {
                    contract_failure(
                        "known-dll-section",
                        Path::new(&source.concrete_host),
                        "loader-contract-evidence",
                        "KnownDll disposition has no loader contract digest",
                    )
                })?,
        });
        budget.check(
            NativeLoaderProgressStage::TargetKnownDlls,
            index + 1,
            Some(total),
        )?;
    }
    Ok((
        LoaderObjectAccessEvidenceV1 {
            object_name_sha256: super::record::digest(r"\KnownDlls".as_bytes()),
            requested_access: KNOWN_DLL_DIRECTORY_ACCESS,
            granted_access: directory_granted,
        },
        sections,
        directory,
        retained_sections,
    ))
}

#[derive(Debug)]
struct ApiSetValueV6 {
    parent_alias: Option<String>,
    host: ApiSetHostV6,
}

#[derive(Debug)]
enum ApiSetMappingV6 {
    Mapped(Vec<ApiSetValueV6>),
    Unhosted,
}

#[derive(Debug)]
struct ApiSetContractV6 {
    namespace_name: String,
    hash_key: String,
    hashed_length: u32,
    hash_span: ApiSetHashSpanV6,
    namespace_kind: ApiSetNamespaceKindV6,
    request_name: Option<ApiSetRequestName>,
    mapping: ApiSetMappingV6,
}

#[derive(Debug)]
struct ApiSetHashEntryV6 {
    hash: u32,
    namespace_index: usize,
}

#[derive(Debug)]
struct ApiSetRequestName {
    full_name: String,
    revision_key: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ApiSetHashSpanV6 {
    WholeName,
    ProperPrefix,
}

impl ApiSetHashSpanV6 {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::WholeName => "whole-name",
            Self::ProperPrefix => "proper-prefix",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiSetNamespaceKindV6 {
    PublicContract,
    SchemaComposition,
    Opaque,
}

impl ApiSetNamespaceKindV6 {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::PublicContract => "public-contract",
            Self::SchemaComposition => "schema-composition",
            Self::Opaque => "opaque",
        }
    }
}

#[derive(Debug)]
struct ApiSetSelectionIdentityV6 {
    hash_key: String,
}

#[derive(Debug)]
struct ApiSetResolutionV6 {
    path: PathBuf,
    selection: ApiSetSelectionIdentityV6,
}

#[derive(Debug)]
enum ApiSetHostV6 {
    Hosted(String),
    Unhosted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiSetSelectionKindV6 {
    Default,
    ParentAlias,
}

impl ApiSetSelectionKindV6 {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ParentAlias => "parent-alias",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ApiSetSelectionV6<'a> {
    value_index: usize,
    kind: ApiSetSelectionKindV6,
    value: &'a ApiSetValueV6,
}

#[derive(Debug)]
struct ApiSetSchemaV6 {
    sha256: String,
    hash_factor: u32,
    entries: Vec<ApiSetContractV6>,
    hashes: Vec<ApiSetHashEntryV6>,
}

fn api_set_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "API-set schema field offset overflowed".to_owned())?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| "API-set schema field exceeds its mapped size".to_owned())?;
    Ok(u32::from_le_bytes(raw.try_into().expect("four-byte slice")))
}

fn api_set_utf16(bytes: &[u8], offset: u32, length: u32) -> Result<String, String> {
    if length % 2 != 0 {
        return Err("API-set schema string has an odd byte length".to_owned());
    }
    let start = usize::try_from(offset).map_err(|_| "API-set offset overflows usize".to_owned())?;
    let length =
        usize::try_from(length).map_err(|_| "API-set length overflows usize".to_owned())?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| "API-set schema string range overflowed".to_owned())?;
    let raw = bytes
        .get(start..end)
        .ok_or_else(|| "API-set schema string exceeds its mapped size".to_owned())?;
    let units = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| "API-set schema string is invalid UTF-16".to_owned())
}

fn normalize_api_set_namespace_identifier(
    value: &str,
    utf16_byte_length: u32,
    description: &str,
) -> Result<String, String> {
    let actual_utf16_byte_length = value
        .encode_utf16()
        .count()
        .checked_mul(2)
        .ok_or_else(|| format!("native API-set {description} UTF-16 length overflowed"))?;
    if actual_utf16_byte_length != utf16_byte_length as usize {
        return Err(format!(
            "native API-set {description} UTF-16 length does not match its declared byte length"
        ));
    }
    if value.is_empty() || actual_utf16_byte_length > MAX_LOADER_BASENAME_BYTES {
        return Err(format!(
            "native API-set {description} length is outside its bound"
        ));
    }
    if !value.is_ascii()
        || value.contains(['/', '\\', '.'])
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || value.split('-').any(str::is_empty)
    {
        return Err(format!(
            "native API-set {description} is not a safe alphanumeric-and-dash namespace identifier"
        ));
    }
    Ok(value.to_ascii_uppercase())
}

fn normalize_api_set_hash_prefix(
    value: &str,
    utf16_byte_length: u32,
    description: &str,
) -> Result<String, String> {
    let actual_utf16_byte_length = value
        .encode_utf16()
        .count()
        .checked_mul(2)
        .ok_or_else(|| format!("native API-set {description} UTF-16 length overflowed"))?;
    if actual_utf16_byte_length != utf16_byte_length as usize {
        return Err(format!(
            "native API-set {description} UTF-16 length does not match its declared byte length"
        ));
    }
    if value.is_empty() || actual_utf16_byte_length > MAX_LOADER_BASENAME_BYTES {
        return Err(format!(
            "native API-set {description} length is outside its bound"
        ));
    }
    if !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(format!(
            "native API-set {description} is not a safe exact namespace-name prefix"
        ));
    }
    Ok(value.to_ascii_uppercase())
}

fn is_schema_extension_namespace_name(value: &str) -> bool {
    let components = value.split('-').collect::<Vec<_>>();
    components.len() >= 5
        && components[0] == "SCHEMAEXT"
        && components[1] == "WIN3"
        && components[2] == "PRODUCT"
        && components[3] == "EXTENSION"
        && components[4..].iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn parse_api_set_full_name(value: &str) -> Result<ApiSetRequestName, String> {
    if value.is_empty()
        || value.len() > MAX_LOADER_BASENAME_BYTES
        || !value.is_ascii()
        || value.contains(['/', '\\'])
    {
        return Err("API-set contract is not a bounded ASCII basename".to_owned());
    }
    let full_name = value.to_ascii_uppercase();
    if !(full_name.starts_with("API-") || full_name.starts_with("EXT-")) {
        return Err("API-set contract does not begin with api- or ext-".to_owned());
    }
    if !full_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || full_name.split('-').any(str::is_empty)
    {
        return Err("API-set contract body is not alphanumeric-and-dash grammar".to_owned());
    }
    let components = full_name.split('-').collect::<Vec<_>>();
    if components.len() < 5 {
        return Err("API-set contract lacks terminal l<n>-<n>-<n> grammar".to_owned());
    }
    let level = components[components.len() - 3];
    let major = components[components.len() - 2];
    let revision = components[components.len() - 1];
    if !level.starts_with('L')
        || level.len() == 1
        || !level[1..].bytes().all(|byte| byte.is_ascii_digit())
        || major.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || revision.is_empty()
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("API-set contract lacks terminal l<n>-<n>-<n> grammar".to_owned());
    }
    let (revision_key, _) = full_name
        .rsplit_once('-')
        .expect("validated API-set contract contains its revision separator");
    let revision_key = revision_key.to_owned();
    Ok(ApiSetRequestName {
        full_name,
        revision_key,
    })
}

fn parse_api_set_request(value: &str) -> Result<ApiSetRequestName, String> {
    validate_graph_name(value).map_err(|detail| {
        format!(
            "requested API-set contract {:?} is invalid: {detail}",
            bounded(value, MAX_LOADER_BASENAME_BYTES)
        )
    })?;
    let normalized = value.to_ascii_uppercase();
    let without_extension = normalized.strip_suffix(".DLL").unwrap_or(&normalized);
    parse_api_set_full_name(without_extension).map_err(|detail| {
        format!("requested API-set contract {without_extension:?} is invalid: {detail}")
    })
}

fn api_set_hash(lookup_key: &str, hash_factor: u32) -> u32 {
    debug_assert!(lookup_key.is_ascii());
    lookup_key.encode_utf16().fold(0_u32, |hash, unit| {
        let unit = if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
            unit + u16::from(b'a' - b'A')
        } else {
            unit
        };
        hash.wrapping_mul(hash_factor).wrapping_add(u32::from(unit))
    })
}

fn normalize_api_set_parent(value: &str) -> Result<String, String> {
    validate_graph_name(value)
        .map_err(|detail| format!("API-set parent alias is invalid: {detail}"))?;
    Ok(value.to_ascii_uppercase())
}

fn normalize_api_set_host(value: &str) -> Result<String, String> {
    let mut host = value.to_ascii_uppercase();
    if host == "." || host == ".." || is_api_set_name(&host) {
        return Err("native API-set host is not a physical loader basename".to_owned());
    }
    if !host.ends_with(".DLL") {
        host.push_str(".DLL");
    }
    validate_graph_name(&host)?;
    Ok(host)
}

fn api_set_table_end(
    offset: usize,
    count: usize,
    record_size: usize,
    mapped_size: usize,
    description: &str,
) -> Result<usize, String> {
    let length = count
        .checked_mul(record_size)
        .ok_or_else(|| format!("native API-set schema {description} length overflowed"))?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format!("native API-set schema {description} range overflowed"))?;
    if end > mapped_size {
        return Err(format!(
            "native API-set schema {description} exceeds its bound"
        ));
    }
    Ok(end)
}

fn parse_api_set_schema_v6(bytes: &[u8]) -> Result<ApiSetSchemaV6, String> {
    if !(28..=16 * 1024 * 1024).contains(&bytes.len()) {
        return Err("native API-set schema size is outside its bound".to_owned());
    }
    if api_set_u32(&bytes, 0)? != 6 || api_set_u32(&bytes, 4)? as usize != bytes.len() {
        return Err("native API-set schema is not canonical version 6".to_owned());
    }
    let count = api_set_u32(&bytes, 12)? as usize;
    let entry_offset = api_set_u32(&bytes, 16)? as usize;
    if count == 0 || count > 65_536 {
        return Err(format!(
            "native API-set schema contract count {count} is outside its bound"
        ));
    }
    api_set_table_end(entry_offset, count, 24, bytes.len(), "entry table")?;
    let hash_offset = api_set_u32(&bytes, 20)? as usize;
    api_set_table_end(hash_offset, count, 8, bytes.len(), "hash table")?;
    let hash_factor = api_set_u32(bytes, 24)?;
    let mut hashes = Vec::with_capacity(count);
    let mut namespace_indices = vec![false; count];
    for hash_index in 0..count {
        let hash = hash_offset + hash_index * 8;
        let value = api_set_u32(bytes, hash)?;
        let contract_index = api_set_u32(bytes, hash + 4)? as usize;
        if contract_index >= count {
            return Err(format!(
                "native API-set schema hash entry {hash_index} references contract index {contract_index} outside count {count}"
            ));
        }
        if namespace_indices[contract_index] {
            return Err(format!(
                "native API-set schema hash entry {hash_index} duplicates namespace index {contract_index}"
            ));
        }
        namespace_indices[contract_index] = true;
        hashes.push(ApiSetHashEntryV6 {
            hash: value,
            namespace_index: contract_index,
        });
    }
    if let Some(missing_index) = namespace_indices.iter().position(|present| !present) {
        return Err(format!(
            "native API-set schema hash table omits namespace index {missing_index}"
        ));
    }
    let mut entries = Vec::with_capacity(count);
    let mut namespace_names = BTreeSet::new();
    let mut hash_keys = BTreeMap::<String, String>::new();
    for index in 0..count {
        let entry = entry_offset + index * 24;
        let name_length = api_set_u32(bytes, entry + 8)?;
        let hashed_length = api_set_u32(bytes, entry + 12)?;
        if name_length == 0 || name_length % 2 != 0 {
            return Err(format!(
                "native API-set contract entry {index} name length {name_length} is empty or odd"
            ));
        }
        let name_offset = api_set_u32(bytes, entry + 4)?;
        let name = api_set_utf16(bytes, name_offset, name_length)?;
        if hashed_length == 0 || hashed_length % 2 != 0 || hashed_length > name_length {
            return Err(format!(
                "native API-set contract entry {index} name {:?} hashed length {hashed_length} is zero, odd, or exceeds name length {name_length}",
                bounded(&name, MAX_LOADER_BASENAME_BYTES)
            ));
        }
        let namespace_name = normalize_api_set_namespace_identifier(
            &name,
            name_length,
            &format!("namespace entry {index} name"),
        )
        .map_err(|detail| {
            format!(
                "native API-set namespace entry {index} name {:?} is invalid (name_length={name_length} hashed_length={hashed_length}): {detail}",
                bounded(&name, MAX_LOADER_BASENAME_BYTES)
            )
        })?;
        let raw_hash_key = api_set_utf16(bytes, name_offset, hashed_length)?;
        let hash_key = normalize_api_set_hash_prefix(
            &raw_hash_key,
            hashed_length,
            &format!("namespace entry {index} hash key"),
        )?;
        let hash_span = if hashed_length == name_length {
            ApiSetHashSpanV6::WholeName
        } else {
            ApiSetHashSpanV6::ProperPrefix
        };
        let parsed_request_name = parse_api_set_full_name(&namespace_name).ok();
        let request_name = parsed_request_name.filter(|request| {
            hash_span == ApiSetHashSpanV6::ProperPrefix && hash_key == request.revision_key
        });
        let namespace_kind = if request_name.is_some() {
            ApiSetNamespaceKindV6::PublicContract
        } else if hash_span == ApiSetHashSpanV6::WholeName
            && is_schema_extension_namespace_name(&namespace_name)
        {
            ApiSetNamespaceKindV6::SchemaComposition
        } else {
            ApiSetNamespaceKindV6::Opaque
        };
        if !namespace_names.insert(namespace_name.clone()) {
            return Err(format!(
                "native API-set schema contains duplicate namespace name {namespace_name}"
            ));
        }
        if let Some(prior) = hash_keys.insert(hash_key.clone(), namespace_name.clone()) {
            return Err(format!(
                "native API-set schema contains duplicate hash key {hash_key} for namespace names {prior} and {namespace_name}"
            ));
        }
        let value_offset = api_set_u32(bytes, entry + 16)? as usize;
        let value_count = api_set_u32(bytes, entry + 20)? as usize;
        if value_count > 64 {
            return Err(format!(
                "native API-set contract entry {index} value count {value_count} exceeds its bound"
            ));
        }
        if value_count != 0 {
            api_set_table_end(
                value_offset,
                value_count,
                20,
                bytes.len(),
                &format!("contract entry {index} value table"),
            )?;
        }
        let mut values = Vec::with_capacity(value_count);
        for value_index in 0..value_count {
            let value = value_offset + value_index * 20;
            let alias_length = api_set_u32(bytes, value + 8)?;
            let alias = api_set_utf16(bytes, api_set_u32(bytes, value + 4)?, alias_length)?;
            let parent_alias = if alias_length == 0 {
                None
            } else {
                Some(normalize_api_set_parent(&alias).map_err(|detail| {
                    format!(
                        "native API-set namespace {namespace_name} value {value_index} parent alias is invalid: {detail}"
                    )
                })?)
            };
            if value_index == 0 && parent_alias.is_some() {
                return Err(format!(
                    "native API-set namespace {namespace_name} value 0 is not the default mapping"
                ));
            }
            if value_index != 0 && parent_alias.is_none() {
                return Err(format!(
                    "native API-set namespace {namespace_name} value {value_index} has no parent alias"
                ));
            }
            if parent_alias.as_ref().is_some_and(String::is_empty) {
                return Err(format!(
                    "native API-set namespace {namespace_name} value {value_index} has an empty parent alias"
                ));
            }
            if let Some(parent_alias) = parent_alias.as_deref() {
                if values.iter().any(|prior: &ApiSetValueV6| {
                    prior.parent_alias.as_deref() == Some(parent_alias)
                }) {
                    return Err(format!(
                        "native API-set namespace {namespace_name} contains duplicate parent alias {parent_alias}"
                    ));
                }
            }
            let host_length = api_set_u32(bytes, value + 16)?;
            let host = if host_length == 0 {
                api_set_utf16(bytes, api_set_u32(bytes, value + 12)?, host_length)?;
                ApiSetHostV6::Unhosted
            } else {
                let host = api_set_utf16(bytes, api_set_u32(bytes, value + 12)?, host_length)?;
                let host = normalize_api_set_host(&host).map_err(|detail| {
                    format!(
                        "native API-set namespace {namespace_name} value {value_index} host is invalid: {detail}"
                    )
                })?;
                ApiSetHostV6::Hosted(host)
            };
            values.push(ApiSetValueV6 { parent_alias, host });
        }
        let mapping = if values.is_empty() {
            ApiSetMappingV6::Unhosted
        } else {
            ApiSetMappingV6::Mapped(values)
        };
        entries.push(ApiSetContractV6 {
            namespace_name,
            hash_key,
            hashed_length,
            hash_span,
            namespace_kind,
            request_name,
            mapping,
        });
    }
    for hash_index in 1..hashes.len() {
        if hashes[hash_index - 1].hash >= hashes[hash_index].hash {
            return Err(format!(
                "native API-set schema hash entry {hash_index} value {:#010x} is not strictly increasing",
                hashes[hash_index].hash
            ));
        }
    }
    for (hash_index, hash_entry) in hashes.iter().enumerate() {
        let entry = &entries[hash_entry.namespace_index];
        let expected = api_set_hash(&entry.hash_key, hash_factor);
        if hash_entry.hash != expected {
            return Err(format!(
                "native API-set schema hash entry {hash_index} value {:#010x} does not match namespace index {} name {} family={} hash_span={} hash_key={} expected hash {expected:#010x}",
                hash_entry.hash,
                hash_entry.namespace_index,
                entry.namespace_name,
                entry.namespace_kind.diagnostic(),
                entry.hash_span.diagnostic(),
                entry.hash_key,
            ));
        }
    }
    Ok(ApiSetSchemaV6 {
        sha256: sha256_bytes(bytes),
        hash_factor,
        entries,
        hashes,
    })
}

fn current_api_set_schema() -> Result<ApiSetSchemaV6, String> {
    type RtlGetCurrentPebFn = unsafe extern "system" fn() -> *const u8;

    let ntdll = super::pipe::wide_null("ntdll.dll");
    let module = unsafe { GetModuleHandleW(ntdll.as_ptr()) };
    if module.is_null() {
        return Err(format!(
            "already-loaded ntdll.dll is unavailable for API-set schema: {}",
            io::Error::last_os_error()
        ));
    }
    let procedure = unsafe { GetProcAddress(module, b"RtlGetCurrentPeb\0".as_ptr()) }
        .ok_or_else(|| "ntdll!RtlGetCurrentPeb is absent".to_owned())?;
    let rtl_get_current_peb = unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, RtlGetCurrentPebFn>(procedure)
    };
    let peb = unsafe { rtl_get_current_peb() };
    if peb.is_null() {
        return Err("RtlGetCurrentPeb returned null".to_owned());
    }
    #[cfg(target_pointer_width = "64")]
    const API_SET_MAP_OFFSET: usize = 0x68;
    #[cfg(target_pointer_width = "32")]
    const API_SET_MAP_OFFSET: usize = 0x38;
    let map = unsafe { ptr::read_unaligned(peb.add(API_SET_MAP_OFFSET).cast::<*const u8>()) };
    if map.is_null() {
        return Err("PEB API-set schema pointer is null".to_owned());
    }
    let size = unsafe { ptr::read_unaligned(map.add(4).cast::<u32>()) } as usize;
    if !(28..=16 * 1024 * 1024).contains(&size) {
        return Err("PEB API-set schema size is outside its bound".to_owned());
    }
    let bytes = unsafe { std::slice::from_raw_parts(map, size) }.to_vec();
    parse_api_set_schema_v6(&bytes)
}

fn select_api_set_value<'a>(
    values: &'a [ApiSetValueV6],
    parent_key: &str,
) -> Option<ApiSetSelectionV6<'a>> {
    values
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, value)| value.parent_alias.as_deref() == Some(parent_key))
        .map(|(value_index, value)| ApiSetSelectionV6 {
            value_index,
            kind: ApiSetSelectionKindV6::ParentAlias,
            value,
        })
        .or_else(|| {
            values.first().map(|value| ApiSetSelectionV6 {
                value_index: 0,
                kind: ApiSetSelectionKindV6::Default,
                value,
            })
        })
}

#[derive(Clone, Copy, Debug)]
struct ApiSetContractSelectionV6<'a> {
    contract: &'a ApiSetContractV6,
    namespace_index: usize,
    hash_row_index: usize,
    lookup_hash: u32,
}

#[derive(Clone, Copy, Debug)]
struct ApiSetResolvedHostV6<'a> {
    selection: ApiSetContractSelectionV6<'a>,
    host: &'a str,
}

fn probe_api_set_contract<'a>(
    schema: &'a ApiSetSchemaV6,
    key: &str,
) -> Result<ApiSetContractSelectionV6<'a>, String> {
    let lookup_hash = api_set_hash(key, schema.hash_factor);
    let hash_row_index = schema
        .hashes
        .binary_search_by_key(&lookup_hash, |entry| entry.hash)
        .map_err(|_| format!("key={key} lookup_hash={lookup_hash:#010x}: hash not found"))?;
    let hash_entry = &schema.hashes[hash_row_index];
    let contract = &schema.entries[hash_entry.namespace_index];
    if contract.hash_key != key {
        return Err(format!(
            "key={key} lookup_hash={lookup_hash:#010x}: hash collision at hash_row={hash_row_index} namespace_index={} namespace_name={} namespace_family={} schema_key={} hash_span={}",
            hash_entry.namespace_index,
            contract.namespace_name,
            contract.namespace_kind.diagnostic(),
            contract.hash_key,
            contract.hash_span.diagnostic(),
        ));
    }
    let request_name = contract.request_name.as_ref().ok_or_else(|| {
        format!(
            "key={key} lookup_hash={lookup_hash:#010x}: exact key names nonselectable namespace at hash_row={hash_row_index} namespace_index={} namespace_name={} namespace_family={} hash_span={}",
            hash_entry.namespace_index,
            contract.namespace_name,
            contract.namespace_kind.diagnostic(),
            contract.hash_span.diagnostic(),
        )
    })?;
    if contract.namespace_kind != ApiSetNamespaceKindV6::PublicContract
        || contract.hash_span != ApiSetHashSpanV6::ProperPrefix
        || request_name.revision_key != key
    {
        return Err(format!(
            "key={key} lookup_hash={lookup_hash:#010x}: exact key is not a public revision-prefix row at hash_row={hash_row_index} namespace_index={} namespace_name={} namespace_family={} hash_span={} request_revision_key={}",
            hash_entry.namespace_index,
            contract.namespace_name,
            contract.namespace_kind.diagnostic(),
            contract.hash_span.diagnostic(),
            request_name.revision_key,
        ));
    }
    Ok(ApiSetContractSelectionV6 {
        contract,
        namespace_index: hash_entry.namespace_index,
        hash_row_index,
        lookup_hash,
    })
}

fn select_api_set_contract<'a>(
    schema: &'a ApiSetSchemaV6,
    request: &ApiSetRequestName,
    parent_key: &str,
) -> Result<ApiSetContractSelectionV6<'a>, String> {
    probe_api_set_contract(schema, &request.revision_key).map_err(|detail| {
        format!(
            "API-set requested_contract={} lookup_key={} parent={} is absent: schema_sha256={} selection=absent revision_probe=({detail}) namespace_name=none schema_hashed_length=none value_index=none",
            request.full_name, request.revision_key, parent_key, schema.sha256,
        )
    })
}

fn selected_api_set_host<'a>(
    schema: &'a ApiSetSchemaV6,
    request: &ApiSetRequestName,
    parent_key: &str,
) -> Result<ApiSetResolvedHostV6<'a>, String> {
    let contract_selection = select_api_set_contract(schema, request, parent_key)?;
    let contract = contract_selection.contract;
    let hash_key = &contract.hash_key;
    let lookup_hash = contract_selection.lookup_hash;
    let values = match &contract.mapping {
        ApiSetMappingV6::Mapped(values) => values,
        ApiSetMappingV6::Unhosted => {
            return Err(format!(
                "API-set requested_contract={} hash_key={} lookup_hash={lookup_hash:#010x} hash_factor={} parent={} is present but unhosted: schema_sha256={} selection=inactive hash_row={} namespace_index={} namespace_name={} namespace_family={} schema_hashed_length={} value_index=none",
                request.full_name,
                hash_key,
                schema.hash_factor,
                parent_key,
                schema.sha256,
                contract_selection.hash_row_index,
                contract_selection.namespace_index,
                contract.namespace_name,
                contract.namespace_kind.diagnostic(),
                contract.hashed_length,
            ));
        }
    };
    let Some(selection) = select_api_set_value(values, parent_key) else {
        return Err(format!(
            "API-set requested_contract={} hash_key={} lookup_hash={lookup_hash:#010x} hash_factor={} parent={} has an invalid empty mapping set: schema_sha256={} selection=invalid hash_row={} namespace_index={} namespace_name={} namespace_family={} schema_hashed_length={} value_index=none",
            request.full_name,
            hash_key,
            schema.hash_factor,
            parent_key,
            schema.sha256,
            contract_selection.hash_row_index,
            contract_selection.namespace_index,
            contract.namespace_name,
            contract.namespace_kind.diagnostic(),
            contract.hashed_length,
        ));
    };
    match &selection.value.host {
        ApiSetHostV6::Hosted(host) => Ok(ApiSetResolvedHostV6 {
            selection: contract_selection,
            host,
        }),
        ApiSetHostV6::Unhosted => Err(format!(
            "API-set requested_contract={} hash_key={} lookup_hash={lookup_hash:#010x} hash_factor={} parent={} is present but unhosted: schema_sha256={} selection={} hash_row={} namespace_index={} namespace_name={} namespace_family={} schema_hashed_length={} value_index={}",
            request.full_name,
            hash_key,
            schema.hash_factor,
            parent_key,
            schema.sha256,
            selection.kind.diagnostic(),
            contract_selection.hash_row_index,
            contract_selection.namespace_index,
            contract.namespace_name,
            contract.namespace_kind.diagnostic(),
            contract.hashed_length,
            selection.value_index,
        )),
    }
}

fn resolve_api_set(
    schema: &ApiSetSchemaV6,
    contract: &str,
    parent_host: &str,
    system_directory: &Path,
) -> Result<ApiSetResolutionV6, String> {
    let request = parse_api_set_request(contract)?;
    let parent_key = normalize_api_set_parent(parent_host)?;
    let selected = selected_api_set_host(schema, &request, &parent_key)?;
    let path = system_directory.join(selected.host);
    if path
        .parent()
        .is_none_or(|parent| !same_path(parent, system_directory))
    {
        return Err(format!(
            "API-set host for {} (hash key {}) and parent {parent_key} escaped native System32",
            request.full_name, selected.selection.contract.hash_key,
        ));
    }
    Ok(ApiSetResolutionV6 {
        path,
        selection: ApiSetSelectionIdentityV6 {
            hash_key: selected.selection.contract.hash_key.clone(),
        },
    })
}

fn resolve_native_object_api() -> Result<NativeObjectApi, String> {
    let ntdll = super::pipe::wide_null("ntdll.dll");
    let module = unsafe { GetModuleHandleW(ntdll.as_ptr()) };
    if module.is_null() {
        return Err(format!(
            "already-loaded ntdll.dll is unavailable: {}",
            io::Error::last_os_error()
        ));
    }
    let directory = unsafe { GetProcAddress(module, b"NtOpenDirectoryObject\0".as_ptr()) }
        .ok_or_else(|| "ntdll!NtOpenDirectoryObject is absent".to_owned())?;
    let section = unsafe { GetProcAddress(module, b"NtOpenSection\0".as_ptr()) }
        .ok_or_else(|| "ntdll!NtOpenSection is absent".to_owned())?;
    let query_section = unsafe { GetProcAddress(module, b"NtQuerySection\0".as_ptr()) }
        .ok_or_else(|| "ntdll!NtQuerySection is absent".to_owned())?;
    Ok(NativeObjectApi {
        nt_open_directory_object: unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, NtOpenDirectoryObjectFn>(
                directory,
            )
        },
        nt_open_section: unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, NtOpenSectionFn>(section)
        },
        nt_query_section: unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, NtQuerySectionFn>(
                query_section,
            )
        },
    })
}

fn unicode_string(storage: &mut [u16]) -> Result<UNICODE_STRING, String> {
    let bytes = storage
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| "native object name exceeds UNICODE_STRING capacity".to_owned())?;
    Ok(UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: storage.as_mut_ptr(),
    })
}

fn system_directory() -> Result<PathBuf, String> {
    let required = unsafe { GetSystemDirectoryW(ptr::null_mut(), 0) };
    if required == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut buffer = vec![0_u16; required as usize];
    let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), required) };
    if written == 0 || written >= required {
        return Err(io::Error::last_os_error().to_string());
    }
    buffer.truncate(written as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

fn final_path_by_handle(handle: HANDLE, flags: u32) -> Result<PathBuf, String> {
    let mut buffer = vec![0_u16; 32_768];
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, flags)
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(io::Error::last_os_error().to_string());
    }
    buffer.truncate(written as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

fn ancestors_of_file(path: &Path) -> Vec<PathBuf> {
    let mut ancestors = path
        .ancestors()
        .skip(1)
        .map(Path::to_owned)
        .collect::<Vec<_>>();
    ancestors.reverse();
    ancestors
}

fn ancestors_including(path: &Path) -> Vec<PathBuf> {
    let mut ancestors = path.ancestors().map(Path::to_owned).collect::<Vec<_>>();
    ancestors.reverse();
    ancestors
}

fn native_machine() -> Result<u16, String> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(memcordon_core::WINDOWS_PE_MACHINE_AMD64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(memcordon_core::WINDOWS_PE_MACHINE_ARM64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err("native loader preflight does not admit this architecture".to_owned())
    }
}

fn is_api_set_name(name: &str) -> bool {
    parse_api_set_request(name).is_ok()
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn path_digest(path: &Path) -> String {
    super::record::digest(path.to_string_lossy().as_bytes())
}

fn normalized_path_digest(path: &Path) -> String {
    super::record::digest(path.to_string_lossy().to_ascii_lowercase().as_bytes())
}

fn safe_basename(path: &Path) -> String {
    bounded(
        &path
            .file_name()
            .unwrap_or_else(|| path.as_os_str())
            .to_string_lossy(),
        MAX_LOADER_BASENAME_BYTES,
    )
}

fn bounded(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut boundary = max;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].to_owned()
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn contract_failure(
    resource_class: &'static str,
    path: &Path,
    api: &'static str,
    detail: impl Into<String>,
) -> NativeLoaderAccessFailureV1 {
    let repair_scope = if matches!(
        resource_class,
        "memcordon-install-root" | "memcordon-bootstrap-image"
    ) {
        "memcordon-owned"
    } else {
        "external-never-repair"
    };
    NativeLoaderAccessFailureV1 {
        object_domain: NativeLoaderObjectDomainV1::File,
        resource_class,
        resource_sha256: path_digest(path),
        resource_basename: safe_basename(path),
        api,
        requested: 0,
        granted: None,
        native_code: None,
        native_status: None,
        repair_scope,
        detail: detail.into(),
    }
}

fn file_failure(
    role: LoaderPathRoleV1,
    path: &Path,
    api: &'static str,
    requested: u32,
    granted: Option<u32>,
    error: io::Error,
) -> NativeLoaderAccessFailureV1 {
    NativeLoaderAccessFailureV1 {
        object_domain: NativeLoaderObjectDomainV1::File,
        resource_class: role.diagnostic(),
        resource_sha256: path_digest(path),
        resource_basename: safe_basename(path),
        api,
        requested,
        granted,
        native_code: error.raw_os_error(),
        native_status: None,
        repair_scope: role.repair_scope(),
        detail: error.to_string(),
    }
}

fn object_failure(
    resource_class: &'static str,
    name: &str,
    api: &'static str,
    requested: u32,
    granted: Option<u32>,
    native_status: Option<i32>,
    detail: impl Into<String>,
) -> NativeLoaderAccessFailureV1 {
    NativeLoaderAccessFailureV1 {
        object_domain: NativeLoaderObjectDomainV1::ObjectManager,
        resource_class,
        resource_sha256: super::record::digest(name.as_bytes()),
        resource_basename: bounded(
            name.rsplit('\\').next().unwrap_or(name),
            MAX_LOADER_BASENAME_BYTES,
        ),
        api,
        requested,
        granted,
        native_code: native_status.or_else(|| i32::try_from(unsafe { GetLastError() }).ok()),
        native_status,
        repair_scope: "external-never-repair",
        detail: detail.into(),
    }
}

#[cfg(test)]
pub(crate) fn validate_loader_access_for_test(requested: u32, granted: u32) -> Result<(), String> {
    require_access(requested, granted, "test")
}

#[cfg(test)]
pub(crate) fn capture_source_ancestor_identity_for_test(
    path: &Path,
) -> Result<LoaderPathAccessEvidenceV1, NativeLoaderAccessFailureV1> {
    capture_source_ancestor(path, LoaderPathRoleV1::ExternalInstallAncestor)
        .map(|identity| identity.evidence)
}

#[cfg(test)]
pub(crate) fn validate_same_final_identity_for_test(
    source_final_path: &Path,
    source: &LoaderPathAccessEvidenceV1,
    source_file_id: u64,
    target_final_path: &Path,
    target: &LoaderPathAccessEvidenceV1,
    target_file_id: u64,
) -> Result<(), String> {
    validate_same_final_identity(
        source_final_path,
        source,
        source_file_id,
        target_final_path,
        target,
        target_file_id,
    )
}

#[cfg(test)]
pub(crate) fn known_dll_disposition_for_test(status: i32) -> Result<KnownDllDispositionV1, String> {
    if status >= 0 {
        Ok(KnownDllDispositionV1::Section {
            requested_access: KNOWN_DLL_SECTION_ACCESS,
            granted_access: KNOWN_DLL_SECTION_ACCESS,
        })
    } else if status == STATUS_OBJECT_NAME_NOT_FOUND {
        Ok(KnownDllDispositionV1::FileBacked {
            not_found_status: status,
        })
    } else {
        Err(format!(
            "KnownDll section failed with NTSTATUS 0x{:08x}",
            status as u32
        ))
    }
}

#[cfg(test)]
pub(crate) fn native_known_dll_namespace_for_test(machine: u16) -> Result<&'static str, String> {
    match machine {
        memcordon_core::WINDOWS_PE_MACHINE_AMD64 | memcordon_core::WINDOWS_PE_MACHINE_ARM64 => {
            Ok(r"\KnownDlls")
        }
        _ => Err("non-native machine has no admitted loader namespace".to_owned()),
    }
}

pub(crate) fn loader_export_matches_for_test(
    contract: &memcordon_core::WindowsPeLoaderContract,
    symbol: &memcordon_core::WindowsPeImportSymbol,
) -> bool {
    find_export(contract, symbol).is_some()
}

pub(crate) fn forwarder_path_result_for_test(
    nodes: &[(String, memcordon_core::WindowsPeImportSymbol)],
) -> Result<usize, &'static str> {
    let mut active = BTreeMap::new();
    let mut hops = 0;
    for (host, symbol) in nodes {
        advance_forwarder_chain(&mut active, host, "synthetic-contract", symbol, &mut hops)
            .map_err(|failure| match failure {
                ForwarderStepFailure::Cycle { .. } => "export-forwarder-cycle",
                ForwarderStepFailure::HopBound { .. } => "export-forwarder-hop-bound",
            })?;
    }
    Ok(hops)
}

pub(crate) fn api_set_parent_selection_for_test(
    values: &[(Option<&str>, &str)],
    parent: &str,
) -> Option<String> {
    let values = values
        .iter()
        .map(|(alias, host)| ApiSetValueV6 {
            parent_alias: alias.map(|alias| {
                normalize_api_set_parent(alias).expect("synthetic API-set parent is valid")
            }),
            host: if host.is_empty() {
                ApiSetHostV6::Unhosted
            } else {
                ApiSetHostV6::Hosted((*host).to_owned())
            },
        })
        .collect::<Vec<_>>();
    let parent = normalize_api_set_parent(parent).expect("synthetic API-set parent is valid");
    select_api_set_value(&values, &parent).and_then(|selection| match &selection.value.host {
        ApiSetHostV6::Hosted(host) => Some(host.clone()),
        ApiSetHostV6::Unhosted => None,
    })
}

pub(crate) fn is_api_set_name_for_test(name: &str) -> bool {
    is_api_set_name(name)
}

pub(crate) fn api_set_schema_summary_for_test(
    bytes: &[u8],
) -> Result<(String, usize, usize, usize), String> {
    let schema = parse_api_set_schema_v6(bytes)?;
    let inactive_contract_count = schema
        .entries
        .iter()
        .filter(|contract| matches!(contract.mapping, ApiSetMappingV6::Unhosted))
        .count();
    let unhosted_value_count = schema
        .entries
        .iter()
        .filter_map(|contract| match &contract.mapping {
            ApiSetMappingV6::Mapped(values) => Some(values),
            ApiSetMappingV6::Unhosted => None,
        })
        .flatten()
        .filter(|value| matches!(value.host, ApiSetHostV6::Unhosted))
        .count();
    Ok((
        schema.sha256,
        schema.entries.len(),
        inactive_contract_count,
        unhosted_value_count,
    ))
}

pub(crate) fn api_set_namespace_summary_for_test(
    bytes: &[u8],
) -> Result<(usize, usize, usize, usize, usize), String> {
    let schema = parse_api_set_schema_v6(bytes)?;
    api_set_namespace_summary(&schema)
}

pub(crate) fn api_set_namespace_entry_for_test(
    bytes: &[u8],
    name: &str,
) -> Result<Option<(String, u32, String, String)>, String> {
    let schema = parse_api_set_schema_v6(bytes)?;
    let name = name.to_ascii_uppercase();
    Ok(schema
        .entries
        .iter()
        .find(|entry| entry.namespace_name == name)
        .map(|entry| {
            (
                entry.hash_key.clone(),
                entry.hashed_length,
                entry.namespace_kind.diagnostic().to_owned(),
                entry.hash_span.diagnostic().to_owned(),
            )
        }))
}

pub(crate) fn api_set_schema_resolution_for_test(
    bytes: &[u8],
    contract: &str,
    parent: &str,
) -> Result<String, String> {
    let schema = parse_api_set_schema_v6(bytes)?;
    let request = parse_api_set_request(contract)?;
    let parent_key = normalize_api_set_parent(parent)?;
    selected_api_set_host(&schema, &request, &parent_key).map(|selected| selected.host.to_owned())
}

pub(crate) fn api_set_selection_cache_key_for_test(
    bytes: &[u8],
    contract: &str,
    parent: &str,
) -> Result<(String, String, String), String> {
    let schema = parse_api_set_schema_v6(bytes)?;
    let request = parse_api_set_request(contract)?;
    let parent = normalize_api_set_parent(parent)?;
    let selection = select_api_set_contract(&schema, &request, &parent)?;
    let hash_key = selection.contract.hash_key.clone();
    Ok((schema.sha256, parent, hash_key))
}

pub(crate) fn current_api_set_schema_for_test() -> Result<(String, usize, usize, usize), String> {
    let schema = current_api_set_schema()?;
    let inactive_contract_count = schema
        .entries
        .iter()
        .filter(|contract| matches!(contract.mapping, ApiSetMappingV6::Unhosted))
        .count();
    let unhosted_value_count = schema
        .entries
        .iter()
        .filter_map(|contract| match &contract.mapping {
            ApiSetMappingV6::Mapped(values) => Some(values),
            ApiSetMappingV6::Unhosted => None,
        })
        .flatten()
        .filter(|value| matches!(value.host, ApiSetHostV6::Unhosted))
        .count();
    Ok((
        schema.sha256,
        schema.entries.len(),
        inactive_contract_count,
        unhosted_value_count,
    ))
}

fn api_set_namespace_summary(
    schema: &ApiSetSchemaV6,
) -> Result<(usize, usize, usize, usize, usize), String> {
    let mut whole_name_count = 0;
    let mut proper_prefix_count = 0;
    let mut public_contract_count = 0;
    let mut schema_composition_count = 0;
    let mut opaque_count = 0;
    for (namespace_index, contract) in schema.entries.iter().enumerate() {
        match contract.hash_span {
            ApiSetHashSpanV6::WholeName => whole_name_count += 1,
            ApiSetHashSpanV6::ProperPrefix => proper_prefix_count += 1,
        }
        match contract.namespace_kind {
            ApiSetNamespaceKindV6::PublicContract => {
                public_contract_count += 1;
                let selection = probe_api_set_contract(&schema, &contract.hash_key)?;
                if selection.namespace_index != namespace_index {
                    return Err(format!(
                        "native public API-set namespace {} resolved namespace index {} instead of {namespace_index}",
                        contract.namespace_name, selection.namespace_index
                    ));
                }
            }
            ApiSetNamespaceKindV6::SchemaComposition => schema_composition_count += 1,
            ApiSetNamespaceKindV6::Opaque => opaque_count += 1,
        }
    }
    Ok((
        whole_name_count,
        proper_prefix_count,
        public_contract_count,
        schema_composition_count,
        opaque_count,
    ))
}

pub(crate) fn current_api_set_namespace_summary_for_test()
-> Result<(usize, usize, usize, usize, usize), String> {
    let schema = current_api_set_schema()?;
    api_set_namespace_summary(&schema)
}

pub(crate) fn current_api_set_namespace_entry_for_test(
    name: &str,
) -> Result<Option<(String, u32, u32, String, String)>, String> {
    let schema = current_api_set_schema()?;
    let name = name.to_ascii_uppercase();
    Ok(schema
        .entries
        .iter()
        .find(|entry| entry.namespace_name == name)
        .map(|entry| {
            (
                schema.sha256.clone(),
                u32::try_from(entry.namespace_name.encode_utf16().count() * 2)
                    .expect("bounded namespace name length fits u32"),
                entry.hashed_length,
                entry.namespace_kind.diagnostic().to_owned(),
                entry.hash_span.diagnostic().to_owned(),
            )
        }))
}

pub(crate) fn current_api_set_resolution_for_test(
    contract: &str,
    parent: &str,
) -> Result<String, String> {
    let schema = current_api_set_schema()?;
    let request = parse_api_set_request(contract)?;
    let parent_key = normalize_api_set_parent(parent)?;
    selected_api_set_host(&schema, &request, &parent_key).map(|selected| selected.host.to_owned())
}

pub(crate) fn loader_graph_shortest_depths_for_test(
    roots: &[LoaderRootEvidenceV2],
    edges: &[LoaderImportEdgeEvidenceV2],
) -> BTreeMap<(LoaderRootPhaseV2, String), usize> {
    loader_graph_shortest_depths(roots, edges)
}
