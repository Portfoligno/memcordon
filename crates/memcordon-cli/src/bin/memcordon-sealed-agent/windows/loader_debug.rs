use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsString, c_void};
use std::fmt::Write as _;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_SEM_TIMEOUT, EXCEPTION_BREAKPOINT, GetLastError,
    HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT,
    DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
    ReadProcessMemory, UNLOAD_DLL_DEBUG_EVENT, WaitForDebugEventEx,
};
use windows_sys::Win32::System::ProcessStatus::K32GetMappedFileNameW;
use windows_sys::Win32::System::Threading::{
    GetCurrentThreadId, GetExitCodeProcess, WaitForSingleObject,
};

use super::pipe::{OwnedHandle, PendingTargetDesktopBootstrapAccept};

const DEBUG_EVENT_SLICE_MILLIS: u32 = 20;
pub(crate) const MODULE_TAIL_CAPACITY: usize = 8;
pub(crate) const EXCEPTION_TAIL_CAPACITY: usize = 4;
pub(crate) const UNLOAD_TAIL_CAPACITY: usize = 4;
pub(crate) const UNKNOWN_EVENT_TAIL_CAPACITY: usize = 4;
const OBSERVED_HOST_CAPACITY: usize = 32;
pub(crate) const MODULE_BASENAME_MAX_BYTES: usize = 96;
const MODULE_PATH_BUFFER_WCHARS: usize = 32_768;
const REMOTE_IMAGE_NAME_MAX_UNITS: usize = 512;
const HOST_SET_DIAGNOSTIC_MAX_BYTES: usize = 160;
const ROOT_FRONTIER_DIAGNOSTIC_MAX_BYTES: usize = 2_048;
const LOADER_TRACE_DIAGNOSTIC_MAX_BYTES: usize = 8_192;
const EXCEPTION_PARAMETER_CAPACITY: usize = 15;
const LOADER_SNAP_EVENT_MAX_BYTES: usize = 1_024;
pub(crate) const LOADER_SNAP_TOTAL_MAX_BYTES: usize = 8_192;
pub(crate) const LOADER_SNAP_TAIL_CAPACITY: usize = 4;
const LOADER_SNAP_RENDER_MAX_BYTES: usize = 256;
pub(crate) const LOADER_TRACE_EVENT_ADMISSION_MAX: u64 = 65_536;

pub(crate) fn candidate_modules_tail_digest(serialized: &str) -> String {
    let mut material = b"memcordon-loader-candidate-modules-tail-v1\0".to_vec();
    material.extend_from_slice(serialized.as_bytes());
    super::record::digest(&material)
}

pub(super) fn enabled(role: super::process::TargetDesktopBootstrapRoleV1) -> bool {
    super::package::ephemeral_ci_enabled()
        && role == super::process::TargetDesktopBootstrapRoleV1::LoaderControl
}

pub(crate) enum LoaderDebugAcceptOutcome {
    Connected(OwnedHandle),
    Exited(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoaderDebugObserverV5 {
    MandatoryPump,
    FullObserver,
}

impl LoaderDebugObserverV5 {
    pub(crate) const fn diagnostic(self) -> &'static str {
        match self {
            Self::MandatoryPump => "minimal-mandatory-pump",
            Self::FullObserver => "full-observer-v4",
        }
    }
}

#[derive(Clone, Debug)]
struct LoaderModuleTailV2 {
    ordinal: u64,
    base: usize,
    basename: String,
    path_source: String,
    path_sha256: String,
    path_error: Option<i32>,
    path_provenance: String,
}

#[derive(Clone, Debug)]
struct LoaderUnloadTailV2 {
    ordinal: u64,
    base: usize,
    matched_load_ordinal: Option<u64>,
    matched_basename: Option<String>,
}

#[derive(Clone, Debug)]
struct LoaderExceptionTailV2 {
    ordinal: u64,
    first_chance: bool,
    code: u32,
    address: usize,
    flags: u32,
    parameters: Vec<usize>,
    nearest_module_basename: Option<String>,
    nearest_module_base: Option<usize>,
}

#[derive(Clone, Debug)]
struct LoaderSnapTailV4 {
    ordinal: u64,
    unicode: bool,
    declared_bytes: usize,
    captured_bytes: usize,
    raw_sha256: String,
    status: String,
    sanitized: String,
}

#[derive(Clone)]
pub(crate) struct LoaderDebugTraceV4 {
    event_count: u64,
    module_count: u64,
    load_dll_count: u64,
    unload_count: u64,
    exception_count: u64,
    thread_count: u64,
    exit_thread_count: u64,
    output_debug_string_count: u64,
    output_debug_string_bytes: usize,
    output_debug_string_overflow: u64,
    rip_count: u64,
    unknown_event_count: u64,
    create_event: bool,
    initial_breakpoint: bool,
    exit_event: bool,
    drained: bool,
    exit_code: Option<u32>,
    modules: VecDeque<LoaderModuleTailV2>,
    unloads: VecDeque<LoaderUnloadTailV2>,
    unknown_events: VecDeque<u32>,
    exceptions: VecDeque<LoaderExceptionTailV2>,
    loader_snaps: VecDeque<LoaderSnapTailV4>,
    expected_hosts: BTreeSet<String>,
    observed_hosts: BTreeSet<String>,
    active_modules: BTreeMap<usize, String>,
    observed_host_order: Vec<String>,
    observed_host_overflow: u64,
    ordered_root_sha256: String,
    loader_graph_sha256: String,
    graph_roots: Vec<LoaderGraphTraceRootV4>,
    graph_edges: Vec<LoaderGraphTraceEdgeV4>,
    exact_target_import_tier_canary_attested: bool,
    launch_evidence: Option<LoaderLaunchEvidenceV4>,
    canonical: Sha256,
}

#[derive(Clone, Debug)]
struct LoaderGraphTraceRootV4 {
    descriptor_ordinal: u32,
    import_contract: String,
    concrete_host: String,
    expected_resolution: String,
    physical_selection: String,
    preflight_nt_status: i32,
    object_name_sha256: String,
    source_target_object_attested: bool,
    read_map_attested: bool,
    execute_map_attested: bool,
    path_sha256: String,
    volume_serial: u64,
    file_id_sha256: String,
    image_sha256: String,
    loader_contract_sha256: String,
}

#[derive(Clone, Debug)]
pub(crate) struct LoaderLaunchEvidenceV4 {
    pub(crate) matrix_cell: &'static str,
    pub(crate) debug_mode: bool,
    pub(crate) environment_classification: &'static str,
    pub(crate) environment_sha256: String,
    pub(crate) environment_keys: Vec<String>,
    pub(crate) environment_keys_sha256: String,
    pub(crate) environment_units: usize,
    pub(crate) environment_entries: usize,
    pub(crate) environment_profile_loaded: bool,
    pub(crate) missing_required_environment: Vec<String>,
    pub(crate) source_token_sha256: String,
    pub(crate) child_token_sha256: String,
    pub(crate) source_token_id: u64,
    pub(crate) child_token_id: u64,
    pub(crate) source_modified_id: u64,
    pub(crate) child_modified_id: u64,
    pub(crate) source_authentication_id: u64,
    pub(crate) child_authentication_id: u64,
    pub(crate) source_session_id: u32,
    pub(crate) child_session_id: u32,
    pub(crate) assigned_authority_attested: bool,
    pub(crate) mitigation_diagnostic: String,
    pub(crate) job_membership_attested: bool,
    pub(crate) desktop_sha256: String,
    pub(crate) binary_sha256: String,
    pub(crate) current_directory_sha256: String,
    pub(crate) command_semantics_sha256: String,
    pub(crate) creation_flags: u32,
}

impl LoaderLaunchEvidenceV4 {
    pub(crate) fn diagnostic(&self) -> String {
        format!(
            "loader_launch=v4 matrix_cell={} debug_mode={} environment_classification={} environment_sha256={} environment_keys=[{}] environment_keys_sha256={} environment_units={} environment_entries={} environment_profile_loaded={} missing_required_environment=[{}] source_token_sha256={} child_token_sha256={} source_token_id={:016x} child_token_id={:016x} source_modified_id={:016x} child_modified_id={:016x} source_authentication_id={:016x} child_authentication_id={:016x} source_session_id={} child_session_id={} assigned_authority_attested={} mitigations=[{}] job_membership_attested={} desktop_sha256={} binary_sha256={} current_directory_sha256={} command_semantics_sha256={} command_dynamic_fields=authenticated-private-pipe,authenticated-nonce creation_flags=0x{:08x} holder_resources=identity-access-attestation-and-mutation-pin child_inherited_resources=false child_loader_consumption=unproven",
            self.matrix_cell,
            self.debug_mode,
            self.environment_classification,
            self.environment_sha256,
            self.environment_keys.join(","),
            self.environment_keys_sha256,
            self.environment_units,
            self.environment_entries,
            self.environment_profile_loaded,
            self.missing_required_environment.join(","),
            self.source_token_sha256,
            self.child_token_sha256,
            self.source_token_id,
            self.child_token_id,
            self.source_modified_id,
            self.child_modified_id,
            self.source_authentication_id,
            self.child_authentication_id,
            self.source_session_id,
            self.child_session_id,
            self.assigned_authority_attested,
            self.mitigation_diagnostic,
            self.job_membership_attested,
            self.desktop_sha256,
            self.binary_sha256,
            self.current_directory_sha256,
            self.command_semantics_sha256,
            self.creation_flags,
        )
    }
}

#[derive(Clone)]
struct LoaderGraphTraceEdgeV4 {
    parent_host: String,
    import_contract: String,
    concrete_host: String,
    descriptor_ordinal: Option<u32>,
    requested_symbol: Option<String>,
    forwarder: bool,
}

impl LoaderDebugTraceV4 {
    fn new(expected_hosts: impl IntoIterator<Item = String>) -> Self {
        let mut canonical = Sha256::new();
        canonical.update(b"memcordon-loader-debug-trace-v4\0");
        let expected_hosts = expected_hosts
            .into_iter()
            .map(|host| normalized_basename(&host))
            .collect::<BTreeSet<_>>();
        canonical.update(host_set_digest_bytes(&expected_hosts));
        let expected_digest = host_set_digest(&expected_hosts);
        Self {
            event_count: 0,
            module_count: 0,
            load_dll_count: 0,
            unload_count: 0,
            exception_count: 0,
            thread_count: 0,
            exit_thread_count: 0,
            output_debug_string_count: 0,
            output_debug_string_bytes: 0,
            output_debug_string_overflow: 0,
            rip_count: 0,
            unknown_event_count: 0,
            create_event: false,
            initial_breakpoint: false,
            exit_event: false,
            drained: false,
            exit_code: None,
            modules: VecDeque::with_capacity(MODULE_TAIL_CAPACITY),
            unloads: VecDeque::with_capacity(UNLOAD_TAIL_CAPACITY),
            unknown_events: VecDeque::with_capacity(UNKNOWN_EVENT_TAIL_CAPACITY),
            exceptions: VecDeque::with_capacity(EXCEPTION_TAIL_CAPACITY),
            loader_snaps: VecDeque::with_capacity(LOADER_SNAP_TAIL_CAPACITY),
            expected_hosts,
            observed_hosts: BTreeSet::new(),
            active_modules: BTreeMap::new(),
            observed_host_order: Vec::new(),
            observed_host_overflow: 0,
            ordered_root_sha256: expected_digest.clone(),
            loader_graph_sha256: expected_digest,
            graph_roots: Vec::new(),
            graph_edges: Vec::new(),
            exact_target_import_tier_canary_attested: false,
            launch_evidence: None,
            canonical,
        }
    }

    fn from_loader_evidence(evidence: &super::loader_access::NativeLoaderAccessEvidenceV2) -> Self {
        let expected_hosts = evidence
            .loader_roots
            .iter()
            .filter(|root| root.phase == super::loader_access::LoaderRootPhaseV2::StaticKernel)
            .map(|root| root.concrete_host.clone())
            .chain(
                evidence
                    .loader_edges
                    .iter()
                    .filter(|edge| {
                        edge.phase == super::loader_access::LoaderRootPhaseV2::StaticKernel
                    })
                    .map(|edge| edge.concrete_host.clone()),
            )
            .collect::<BTreeSet<_>>();
        let graph_roots = evidence
            .loader_roots
            .iter()
            .filter(|root| root.phase == super::loader_access::LoaderRootPhaseV2::StaticKernel)
            .map(|root| {
                let concrete_host = normalized_basename(&root.concrete_host);
                let module = evidence
                    .system_modules
                    .iter()
                    .find(|module| module.concrete_host.eq_ignore_ascii_case(&concrete_host))
                    .expect("sealed loader evidence relates every root to one physical module");
                let section = evidence
                    .known_dll_sections
                    .iter()
                    .find(|section| section.concrete_host.eq_ignore_ascii_case(&concrete_host))
                    .expect(
                        "sealed loader evidence relates every root to one KnownDll disposition",
                    );
                let (physical_selection, preflight_nt_status, object_attested) =
                    match section.disposition {
                        super::loader_access::KnownDllDispositionV1::Section { .. } => {
                            ("known-dll-section", 0, true)
                        }
                        super::loader_access::KnownDllDispositionV1::FileBacked {
                            not_found_status,
                        } => ("system32-file-fallback", not_found_status, false),
                    };
                LoaderGraphTraceRootV4 {
                    descriptor_ordinal: root
                        .descriptor_ordinal
                        .expect("static loader roots have descriptor ordinals"),
                    import_contract: normalized_basename(&root.import_contract),
                    concrete_host: concrete_host.clone(),
                    expected_resolution: if root
                        .import_contract
                        .eq_ignore_ascii_case(&root.concrete_host)
                    {
                        "physical-direct".to_owned()
                    } else {
                        "api-set-to-physical".to_owned()
                    },
                    physical_selection: physical_selection.to_owned(),
                    preflight_nt_status,
                    object_name_sha256: super::record::digest(
                        format!(r"\KnownDlls\{concrete_host}").as_bytes(),
                    ),
                    source_target_object_attested: object_attested,
                    read_map_attested: section.read_map_attested,
                    execute_map_attested: section.execute_map_attested,
                    path_sha256: module.file.path_sha256.clone(),
                    volume_serial: module.file.volume_serial,
                    file_id_sha256: module.file.file_id_sha256.clone(),
                    image_sha256: module.image_sha256.clone(),
                    loader_contract_sha256: module.loader_contract_sha256.clone(),
                }
            })
            .collect::<Vec<_>>();
        let graph_edges = evidence
            .loader_edges
            .iter()
            .filter(|edge| edge.phase == super::loader_access::LoaderRootPhaseV2::StaticKernel)
            .map(|edge| LoaderGraphTraceEdgeV4 {
                parent_host: normalized_basename(&edge.parent_host),
                import_contract: normalized_basename(&edge.import_contract),
                concrete_host: normalized_basename(&edge.concrete_host),
                descriptor_ordinal: edge.descriptor_ordinal,
                requested_symbol: edge.requested_symbol.clone(),
                forwarder: edge.forwarder,
            })
            .collect();
        let mut trace = Self::new(expected_hosts);
        trace.ordered_root_sha256 = evidence.ordered_root_sha256.clone();
        trace.loader_graph_sha256 = evidence.loader_graph_sha256.clone();
        trace.graph_roots = graph_roots;
        trace.graph_edges = graph_edges;
        trace.exact_target_import_tier_canary_attested =
            evidence.exact_target_import_tier_canary_attested;
        trace.canonical.update(trace.ordered_root_sha256.as_bytes());
        trace.canonical.update(trace.loader_graph_sha256.as_bytes());
        trace
            .canonical
            .update([trace.exact_target_import_tier_canary_attested as u8]);
        for root in &trace.graph_roots {
            trace
                .canonical
                .update(root.descriptor_ordinal.to_le_bytes());
            trace.canonical.update(root.import_contract.as_bytes());
            trace.canonical.update(root.concrete_host.as_bytes());
            trace.canonical.update(root.expected_resolution.as_bytes());
            trace.canonical.update(root.physical_selection.as_bytes());
            trace
                .canonical
                .update(root.preflight_nt_status.to_le_bytes());
            trace.canonical.update(root.object_name_sha256.as_bytes());
            trace.canonical.update([root.read_map_attested as u8]);
            trace.canonical.update([root.execute_map_attested as u8]);
            trace.canonical.update(root.path_sha256.as_bytes());
            trace.canonical.update(root.file_id_sha256.as_bytes());
        }
        trace
    }

    fn bind_launch_evidence(&mut self, evidence: LoaderLaunchEvidenceV4) {
        self.canonical.update(evidence.diagnostic().as_bytes());
        self.launch_evidence = Some(evidence);
    }

    fn canonical_field(&mut self, kind: u32, values: &[u64]) {
        self.canonical.update(kind.to_le_bytes());
        for value in values {
            self.canonical.update(value.to_le_bytes());
        }
    }

    fn record_module(
        &mut self,
        process: HANDLE,
        base: usize,
        main_image: bool,
        file: HANDLE,
        remote_image_name: *mut c_void,
        unicode: u16,
    ) {
        self.module_count += 1;
        if !main_image {
            self.load_dll_count += 1;
        }
        let ordinal = self.module_count;
        let resolved = debug_module_path(process, base, file, remote_image_name, unicode != 0);
        self.canonical_field(
            if main_image {
                CREATE_PROCESS_DEBUG_EVENT
            } else {
                LOAD_DLL_DEBUG_EVENT
            },
            &[
                ordinal,
                base as u64,
                main_image as u64,
                resolved.path_error.unwrap_or_default() as u32 as u64,
            ],
        );
        self.canonical.update(resolved.path_source.as_bytes());
        self.canonical.update(resolved.path_sha256.as_bytes());
        self.canonical.update(resolved.path_provenance.as_bytes());
        if !main_image && resolved.path_source != "unavailable" {
            self.record_observed_host(&resolved.basename);
            self.active_modules
                .insert(base, normalized_basename(&resolved.basename));
        }
        if self.modules.len() == MODULE_TAIL_CAPACITY {
            self.modules.pop_front();
        }
        self.modules.push_back(LoaderModuleTailV2 {
            ordinal,
            base,
            basename: resolved.basename,
            path_source: resolved.path_source,
            path_sha256: resolved.path_sha256,
            path_error: resolved.path_error,
            path_provenance: resolved.path_provenance,
        });
    }

    fn record_module_minimal(&mut self, base: usize, main_image: bool, file: HANDLE) {
        self.module_count += 1;
        if !main_image {
            self.load_dll_count += 1;
        }
        let ordinal = self.module_count;
        self.canonical_field(
            if main_image {
                CREATE_PROCESS_DEBUG_EVENT
            } else {
                LOAD_DLL_DEBUG_EVENT
            },
            &[ordinal, base as u64, main_image as u64],
        );
        self.canonical.update(b"minimal-pump-no-observation");
        if !file.is_null() {
            // The debug event transfers only hFile close responsibility. The
            // minimal mandatory pump intentionally performs no path or remote
            // memory query while still closing every transferred capability.
            let _ = OwnedHandle::new(file);
        }
        if self.modules.len() == MODULE_TAIL_CAPACITY {
            self.modules.pop_front();
        }
        self.modules.push_back(LoaderModuleTailV2 {
            ordinal,
            base,
            basename: "unobserved".to_owned(),
            path_source: "minimal-pump".to_owned(),
            path_sha256: super::record::digest(b"minimal-pump-no-observation"),
            path_error: None,
            path_provenance: "debug-event-hfile-close-only".to_owned(),
        });
    }

    fn record_debug_string_minimal(&mut self, declared_bytes: usize, unicode: bool) {
        self.output_debug_string_count += 1;
        self.canonical_field(
            OUTPUT_DEBUG_STRING_EVENT,
            &[
                self.output_debug_string_count,
                unicode as u64,
                declared_bytes as u64,
            ],
        );
        self.canonical.update(b"minimal-pump-no-remote-read");
    }

    fn record_observed_host(&mut self, basename: &str) {
        let host = normalized_basename(basename);
        if self.observed_hosts.contains(&host) {
            return;
        }
        if self.observed_hosts.len() == OBSERVED_HOST_CAPACITY {
            self.observed_host_overflow += 1;
        } else {
            self.observed_host_order.push(host.clone());
            self.observed_hosts.insert(host);
        }
    }

    fn record_unload(&mut self, base: usize) {
        self.unload_count += 1;
        let ordinal = self.unload_count;
        let matched = self.modules.iter().rev().find(|module| module.base == base);
        let (matched_load_ordinal, matched_basename) = matched.map_or((None, None), |module| {
            (Some(module.ordinal), Some(module.basename.clone()))
        });
        self.canonical_field(
            UNLOAD_DLL_DEBUG_EVENT,
            &[
                ordinal,
                base as u64,
                matched_load_ordinal.unwrap_or_default(),
            ],
        );
        if let Some(basename) = &matched_basename {
            self.canonical.update(basename.as_bytes());
        }
        self.active_modules.remove(&base);
        if self.unloads.len() == UNLOAD_TAIL_CAPACITY {
            self.unloads.pop_front();
        }
        self.unloads.push_back(LoaderUnloadTailV2 {
            ordinal,
            base,
            matched_load_ordinal,
            matched_basename,
        });
    }

    fn record_unknown_event(&mut self, code: u32) {
        self.unknown_event_count += 1;
        self.canonical_field(code, &[self.unknown_event_count]);
        if self.unknown_events.len() == UNKNOWN_EVENT_TAIL_CAPACITY {
            self.unknown_events.pop_front();
        }
        self.unknown_events.push_back(code);
    }

    fn record_exception(
        &mut self,
        code: u32,
        first_chance: bool,
        address: usize,
        flags: u32,
        parameters: &[usize],
    ) {
        self.exception_count += 1;
        let ordinal = self.exception_count;
        let nearest = self
            .modules
            .iter()
            .filter(|module| module.base <= address)
            .max_by_key(|module| module.base);
        let (nearest_module_basename, nearest_module_base) = nearest
            .map_or((None, None), |module| {
                (Some(module.basename.clone()), Some(module.base))
            });
        self.canonical_field(
            EXCEPTION_DEBUG_EVENT,
            &[
                ordinal,
                code as u64,
                first_chance as u64,
                address as u64,
                flags as u64,
            ],
        );
        for parameter in parameters {
            self.canonical.update(parameter.to_le_bytes());
        }
        if self.exceptions.len() == EXCEPTION_TAIL_CAPACITY {
            self.exceptions.pop_front();
        }
        self.exceptions.push_back(LoaderExceptionTailV2 {
            ordinal,
            first_chance,
            code,
            address,
            flags,
            parameters: parameters.to_vec(),
            nearest_module_basename,
            nearest_module_base,
        });
    }

    fn record_debug_string(
        &mut self,
        process: HANDLE,
        remote: *const u8,
        declared_bytes: usize,
        unicode: bool,
    ) {
        self.output_debug_string_count += 1;
        let ordinal = self.output_debug_string_count;
        let remaining = LOADER_SNAP_TOTAL_MAX_BYTES.saturating_sub(self.output_debug_string_bytes);
        let capture_bytes = declared_bytes
            .min(LOADER_SNAP_EVENT_MAX_BYTES)
            .min(remaining);
        let (captured, status) = if remote.is_null() {
            (Vec::new(), "null-pointer".to_owned())
        } else if declared_bytes == 0 {
            (Vec::new(), "zero-length".to_owned())
        } else if unicode && declared_bytes % 2 != 0 {
            (Vec::new(), "odd-unicode-byte-length".to_owned())
        } else if capture_bytes == 0 {
            self.output_debug_string_overflow += 1;
            (Vec::new(), "total-bound-exhausted".to_owned())
        } else {
            let mut bytes = vec![0_u8; capture_bytes];
            let mut bytes_read = 0_usize;
            // SAFETY: process is the exact debugged child, remote comes from the current debug
            // event, and the local buffer is writable for the bounded requested byte count.
            if unsafe {
                ReadProcessMemory(
                    process,
                    remote.cast(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    &raw mut bytes_read,
                )
            } == 0
            {
                let code = io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_default();
                (Vec::new(), format!("read-native-{code}"))
            } else if bytes_read != bytes.len() {
                bytes.truncate(bytes_read.min(bytes.len()));
                (
                    bytes,
                    format!("partial-read-{bytes_read}-of-{capture_bytes}"),
                )
            } else if declared_bytes > capture_bytes {
                self.output_debug_string_overflow += 1;
                (bytes, "captured-prefix-overflow".to_owned())
            } else {
                (bytes, "complete".to_owned())
            }
        };
        self.output_debug_string_bytes = self
            .output_debug_string_bytes
            .saturating_add(captured.len());
        let raw_sha256 = super::record::digest(&captured);
        let decoded = if unicode && captured.len() % 2 == 0 {
            let units = captured
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>();
            String::from_utf16(&units).unwrap_or_else(|_| "invalid-unicode".to_owned())
        } else if unicode {
            "invalid-unicode-byte-count".to_owned()
        } else {
            String::from_utf8_lossy(captured.split(|byte| *byte == 0).next().unwrap_or_default())
                .into_owned()
        };
        let sanitized = bounded(
            &decoded
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric()
                        || matches!(character, ' ' | '.' | '-' | '_' | '/' | '\\')
                    {
                        character
                    } else {
                        '?'
                    }
                })
                .collect::<String>(),
            LOADER_SNAP_RENDER_MAX_BYTES,
        );
        self.canonical_field(
            OUTPUT_DEBUG_STRING_EVENT,
            &[
                ordinal,
                unicode as u64,
                declared_bytes as u64,
                captured.len() as u64,
            ],
        );
        self.canonical.update(raw_sha256.as_bytes());
        self.canonical.update(status.as_bytes());
        if self.loader_snaps.len() == LOADER_SNAP_TAIL_CAPACITY {
            self.loader_snaps.pop_front();
        }
        self.loader_snaps.push_back(LoaderSnapTailV4 {
            ordinal,
            unicode,
            declared_bytes,
            captured_bytes: captured.len(),
            raw_sha256,
            status,
            sanitized,
        });
    }

    pub(crate) fn diagnostic(&self) -> String {
        let observed_admitted = self
            .observed_hosts
            .intersection(&self.expected_hosts)
            .cloned()
            .collect::<BTreeSet<_>>();
        let missing_hosts = self
            .expected_hosts
            .difference(&self.observed_hosts)
            .cloned()
            .collect::<BTreeSet<_>>();
        let extra_hosts = self
            .observed_hosts
            .difference(&self.expected_hosts)
            .cloned()
            .collect::<BTreeSet<_>>();
        let active_at_exit = self
            .active_modules
            .values()
            .filter(|host| self.expected_hosts.contains(*host))
            .cloned()
            .collect::<BTreeSet<_>>();
        let missing_direct_roots = self
            .graph_roots
            .iter()
            .filter(|root| missing_hosts.contains(&root.concrete_host))
            .collect::<Vec<_>>();
        let missing_root_hosts = missing_direct_roots
            .iter()
            .map(|root| root.concrete_host.clone())
            .collect::<BTreeSet<_>>();
        let mut blocked_hosts = missing_root_hosts.clone();
        loop {
            let before = blocked_hosts.len();
            for edge in &self.graph_edges {
                if blocked_hosts.contains(&edge.parent_host)
                    && missing_hosts.contains(&edge.concrete_host)
                {
                    blocked_hosts.insert(edge.concrete_host.clone());
                }
            }
            if blocked_hosts.len() == before {
                break;
            }
        }
        let blocked_descendants = blocked_hosts
            .difference(&missing_root_hosts)
            .cloned()
            .collect::<BTreeSet<_>>();
        let root_frontier = missing_direct_roots
            .iter()
            .map(|root| {
                format!(
                    "{}:{}>{}:resolution={}:selection={}:preflight_nt_status=0x{:08x}:loader_native_status=unavailable:object_name_sha256={}:source_target_object_attested={}:read_map_attested={}:execute_map_attested={}:path_sha256={}:volume_serial={:016x}:file_id_sha256={}:image_sha256={}:loader_contract_sha256={}",
                    root.descriptor_ordinal,
                    root.import_contract,
                    root.concrete_host,
                    root.expected_resolution,
                    root.physical_selection,
                    root.preflight_nt_status as u32,
                    root.object_name_sha256,
                    root.source_target_object_attested,
                    root.read_map_attested,
                    root.execute_map_attested,
                    root.path_sha256,
                    root.volume_serial,
                    root.file_id_sha256,
                    root.image_sha256,
                    root.loader_contract_sha256,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let frontier_edges = self
            .graph_edges
            .iter()
            .filter(|edge| {
                missing_hosts.contains(&edge.concrete_host)
                    && self.observed_hosts.contains(&edge.parent_host)
            })
            .collect::<Vec<_>>();
        let edge_frontier = if frontier_edges.len() == 1 {
            let edge = frontier_edges[0];
            format!(
                "unique:{}>{}:contract={}:descriptor={}:symbol={}:forwarder={}",
                edge.parent_host,
                edge.concrete_host,
                edge.import_contract,
                edge.descriptor_ordinal
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                edge.requested_symbol.as_deref().unwrap_or("none"),
                edge.forwarder,
            )
        } else if frontier_edges.is_empty() {
            "none".to_owned()
        } else {
            format!("ambiguous:{}", frontier_edges.len())
        };
        let resolution = if missing_hosts.is_empty() && self.observed_host_overflow == 0 {
            "closure-hosts-all-observed:initialization-unresolved"
        } else {
            "closure-incomplete"
        };
        let observed_order = bounded(
            &self.observed_host_order.join(","),
            HOST_SET_DIAGNOSTIC_MAX_BYTES,
        );
        let modules = self
            .modules
            .iter()
            .map(|module| {
                format!(
                    "{}@0x{:x}:{}:{}:{}:{}:{}",
                    module.ordinal,
                    module.base,
                    module.basename,
                    module.path_source,
                    module.path_sha256,
                    module
                        .path_error
                        .map_or_else(|| "ok".to_owned(), |code| format!("os-{code}")),
                    module.path_provenance,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let unloads = self
            .unloads
            .iter()
            .map(|unload| {
                format!(
                    "{}@0x{:x}:load={}({})",
                    unload.ordinal,
                    unload.base,
                    unload
                        .matched_load_ordinal
                        .map_or_else(|| "none".to_owned(), |ordinal| ordinal.to_string()),
                    unload.matched_basename.as_deref().unwrap_or("none"),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let unknown_events = self
            .unknown_events
            .iter()
            .map(|code| format!("0x{code:08x}"))
            .collect::<Vec<_>>()
            .join(",");
        let exceptions = self
            .exceptions
            .iter()
            .map(|exception| {
                format!(
                    "{}:{}:0x{:08x}@0x{:x}:flags=0x{:x}:params={}:nearest-candidate={}@{}",
                    exception.ordinal,
                    if exception.first_chance {
                        "first"
                    } else {
                        "second"
                    },
                    exception.code,
                    exception.address,
                    exception.flags,
                    exception.parameters.len(),
                    exception
                        .nearest_module_basename
                        .as_deref()
                        .unwrap_or("none"),
                    exception
                        .nearest_module_base
                        .map_or_else(|| "none".to_owned(), |base| format!("0x{base:x}")),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let loader_snaps = self
            .loader_snaps
            .iter()
            .map(|snap| {
                format!(
                    "{}:{}:declared={}:captured={}:sha256={}:status={}:text={}",
                    snap.ordinal,
                    if snap.unicode { "unicode" } else { "ansi" },
                    snap.declared_bytes,
                    snap.captured_bytes,
                    snap.raw_sha256,
                    snap.status,
                    snap.sanitized,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let trace_sha256 = hex_digest(&self.canonical.clone().finalize());
        let accounted_events = u64::from(self.create_event)
            + self.load_dll_count
            + self.unload_count
            + self.exception_count
            + self.thread_count
            + self.exit_thread_count
            + self.output_debug_string_count
            + self.rip_count
            + u64::from(self.exit_event)
            + self.unknown_event_count;
        let failure_phase = if self.exit_event && !self.initial_breakpoint {
            "pre-initial-breakpoint-static-loader"
        } else if self.exit_event {
            "post-initial-breakpoint"
        } else {
            "not-exited"
        };
        let exit_status_symbol = self.exit_code.map_or("unavailable", loader_status_symbol);
        let launch_evidence = self.launch_evidence.as_ref().map_or_else(
            || "loader_launch=v4 unavailable=true".to_owned(),
            LoaderLaunchEvidenceV4::diagnostic,
        );
        let header = format!(
            "loader_trace=v4 gate=ephemeral-ci trace_sha256={} drained={} debug_cleanup={} events={} accounted_events={} modules={} dll_loads={} unloads={} exceptions={} threads={} exit_threads={} debug_strings={} debug_string_bytes={} debug_string_overflow={} rip_events={} unknown_events={} create_event={} initial_breakpoint={} exit_event={} exit={} exit_status_symbol={} pre_initial_breakpoint={} static_closure_complete={} application_entry_possible={} failure_phase={} resolution_vs_initialization={}",
            trace_sha256,
            self.drained,
            if self.drained {
                "exit-process-event-continued"
            } else {
                "pending"
            },
            self.event_count,
            accounted_events,
            self.module_count,
            self.load_dll_count,
            self.unload_count,
            self.exception_count,
            self.thread_count,
            self.exit_thread_count,
            self.output_debug_string_count,
            self.output_debug_string_bytes,
            self.output_debug_string_overflow,
            self.rip_count,
            self.unknown_event_count,
            self.create_event,
            self.initial_breakpoint,
            self.exit_event,
            self.exit_code
                .map_or_else(|| "unavailable".to_owned(), |code| format!("0x{code:08x}")),
            exit_status_symbol,
            self.exit_event && !self.initial_breakpoint,
            missing_hosts.is_empty() && self.observed_host_overflow == 0,
            !self.exit_event || self.initial_breakpoint,
            failure_phase,
            resolution,
        );
        let causal_frontier = format!(
            "candidate_modules_count={} candidate_modules_retained={} candidate_modules_overflow={} candidate_modules_sha256={} candidate_modules=[{}] unload_tail_count={} unload_tail_retained={} unload_tail_overflow={} unload_tail_sha256={} unload_tail=[{}] loader_snap_tail_count={} loader_snap_tail_retained={} loader_snap_tail_overflow={} loader_snap_tail_sha256={} loader_snap_tail=[{}] unknown_event_tail_count={} unknown_event_tail_retained={} unknown_event_tail_overflow={} unknown_event_tail_sha256={} unknown_event_tail=[{}] exception_tail_count={} exception_tail_retained={} exception_tail_overflow={} exception_tail_sha256={} exception_tail=[{}]",
            self.module_count,
            self.modules.len(),
            self.module_count.saturating_sub(self.modules.len() as u64),
            candidate_modules_tail_digest(&modules),
            modules,
            self.unload_count,
            self.unloads.len(),
            self.unload_count.saturating_sub(self.unloads.len() as u64),
            super::record::digest(unloads.as_bytes()),
            unloads,
            self.output_debug_string_count,
            self.loader_snaps.len(),
            self.output_debug_string_count
                .saturating_sub(self.loader_snaps.len() as u64),
            super::record::digest(loader_snaps.as_bytes()),
            loader_snaps,
            self.unknown_event_count,
            self.unknown_events.len(),
            self.unknown_event_count
                .saturating_sub(self.unknown_events.len() as u64),
            super::record::digest(unknown_events.as_bytes()),
            unknown_events,
            self.exception_count,
            self.exceptions.len(),
            self.exception_count
                .saturating_sub(self.exceptions.len() as u64),
            super::record::digest(exceptions.as_bytes()),
            exceptions,
        );
        let bounded_root_frontier = bounded(&root_frontier, ROOT_FRONTIER_DIAGNOSTIC_MAX_BYTES);
        let root_detail = format!(
            "observed_host_overflow={} ordered_root_sha256={} loader_graph_sha256={} expected_hosts_sha256={} ever_mapped_sha256={} active_at_exit_sha256={} missing_hosts_sha256={} extra_hosts_sha256={} missing_direct_roots_count={} missing_direct_roots_retained_bytes={} missing_direct_roots_overflow_bytes={} missing_direct_roots_sha256={} missing_direct_roots=[{}] edge_frontier=[{}] blocked_descendants=[{}] expected_hosts=[{}] observed_order=[{}] ever_mapped=[{}] active_at_exit=[{}] missing_hosts=[{}] extra_hosts=[{}]",
            self.observed_host_overflow,
            self.ordered_root_sha256,
            self.loader_graph_sha256,
            host_set_digest(&self.expected_hosts),
            host_set_digest(&observed_admitted),
            host_set_digest(&active_at_exit),
            host_set_digest(&missing_hosts),
            host_set_digest(&extra_hosts),
            missing_direct_roots.len(),
            bounded_root_frontier.len(),
            root_frontier
                .len()
                .saturating_sub(bounded_root_frontier.len()),
            super::record::digest(root_frontier.as_bytes()),
            bounded_root_frontier,
            edge_frontier,
            host_set_diagnostic(&blocked_descendants),
            host_set_diagnostic(&self.expected_hosts),
            observed_order,
            host_set_diagnostic(&observed_admitted),
            host_set_diagnostic(&active_at_exit),
            host_set_diagnostic(&missing_hosts),
            host_set_diagnostic(&extra_hosts),
        );
        bounded(
            &format!(
                "{header} {causal_frontier} exact_token_import_tier_canary=core-ntdll-kernel32:read-execute-map-attested,advapi32:read-execute-map-attested canary_attested={} canary_execution_scope=holder-effective-thread-under-exact-target-impersonation canary_child_startup=unproven {launch_evidence} {root_detail}",
                self.exact_target_import_tier_canary_attested,
            ),
            LOADER_TRACE_DIAGNOSTIC_MAX_BYTES,
        )
    }
}

pub(crate) struct LoaderDebugSession {
    creator_thread_id: u32,
    process: HANDLE,
    observer: LoaderDebugObserverV5,
    trace: LoaderDebugTraceV4,
}

impl LoaderDebugSession {
    pub(crate) fn attach(
        process: HANDLE,
        native_loader_access: &super::loader_access::NativeLoaderAccessEvidenceV2,
        observer: LoaderDebugObserverV5,
    ) -> Self {
        Self {
            creator_thread_id: unsafe { GetCurrentThreadId() },
            process,
            observer,
            trace: LoaderDebugTraceV4::from_loader_evidence(native_loader_access),
        }
    }

    pub(crate) fn assert_kill_on_exit(&self) -> Result<(), String> {
        if unsafe { GetCurrentThreadId() } != self.creator_thread_id {
            return Err("loader debug setup moved off the process-creation thread".to_owned());
        }
        if unsafe { DebugSetProcessKillOnExit(1) } == 0 {
            return Err(format!(
                "DebugSetProcessKillOnExit(TRUE) failed: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(crate) fn trace(&self) -> &LoaderDebugTraceV4 {
        &self.trace
    }

    pub(crate) fn bind_launch_evidence(&mut self, evidence: LoaderLaunchEvidenceV4) {
        self.trace.bind_launch_evidence(evidence);
    }

    pub(crate) fn accept_pipe(
        &mut self,
        mut pending: PendingTargetDesktopBootstrapAccept,
        process: HANDLE,
        deadline: Instant,
    ) -> Result<LoaderDebugAcceptOutcome, String> {
        loop {
            if pending.poll().map_err(|error| error.to_string())? {
                return pending
                    .finish()
                    .map(LoaderDebugAcceptOutcome::Connected)
                    .map_err(|error| error.to_string());
            }
            if self.trace.drained {
                pending
                    .cancel_and_drain()
                    .map_err(|error| error.to_string())?;
                return Ok(LoaderDebugAcceptOutcome::Exited(
                    self.trace.exit_code.unwrap_or_default(),
                ));
            }
            if Instant::now() >= deadline {
                pending
                    .cancel_and_drain()
                    .map_err(|error| error.to_string())?;
                return Err("loader debug accept reached its fixed deadline".to_owned());
            }
            self.wait_and_continue(DEBUG_EVENT_SLICE_MILLIS)?;
            if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 && self.trace.drained {
                pending
                    .cancel_and_drain()
                    .map_err(|error| error.to_string())?;
                return Ok(LoaderDebugAcceptOutcome::Exited(
                    self.trace.exit_code.unwrap_or_default(),
                ));
            }
        }
    }

    pub(crate) fn drain_until_exit(
        &mut self,
        process: HANDLE,
        deadline: Instant,
    ) -> Result<u32, String> {
        while !self.trace.drained {
            if Instant::now() >= deadline {
                return Err("loader debug-event drain reached its fixed deadline".to_owned());
            }
            self.wait_and_continue(DEBUG_EVENT_SLICE_MILLIS)?;
        }
        if unsafe { WaitForSingleObject(process, 30_000) } != WAIT_OBJECT_0 {
            return Err(
                "debugged loader-control did not signal after EXIT_PROCESS continuation".to_owned(),
            );
        }
        let mut observed = 0_u32;
        if unsafe { GetExitCodeProcess(process, &raw mut observed) } == 0 {
            return Err(format!(
                "GetExitCodeProcess failed after debug drain: {}",
                io::Error::last_os_error()
            ));
        }
        let event_code = self.trace.exit_code.unwrap_or_default();
        if event_code != observed {
            return Err(format!(
                "loader debug exit mismatch event=0x{event_code:08x} process=0x{observed:08x}"
            ));
        }
        Ok(observed)
    }

    pub(crate) fn terminate_and_drain(
        &mut self,
        job: &super::job::Job,
        process: HANDLE,
    ) -> Result<(), String> {
        job.terminate(super::process::target_desktop_bootstrap_failure_status() as u32)?;
        self.drain_until_exit(process, Instant::now() + Duration::from_secs(5))
            .map(|_| ())
    }

    fn wait_and_continue(&mut self, timeout_millis: u32) -> Result<bool, String> {
        if unsafe { GetCurrentThreadId() } != self.creator_thread_id {
            return Err("loader debug events moved off the process-creation thread".to_owned());
        }
        let mut event = DEBUG_EVENT::default();
        if unsafe { WaitForDebugEventEx(&raw mut event, timeout_millis) } == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_SEM_TIMEOUT {
                return Ok(false);
            }
            return Err(format!(
                "WaitForDebugEvent failed with native code {code}: {}",
                io::Error::from_raw_os_error(code as i32)
            ));
        }
        let continuation = self.observe_event(&event);
        if unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation) } == 0 {
            return Err(format!(
                "ContinueDebugEvent failed for event {}: {}",
                event.dwDebugEventCode,
                io::Error::last_os_error()
            ));
        }
        if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
            self.trace.drained = true;
        }
        Ok(true)
    }

    fn observe_event(&mut self, event: &DEBUG_EVENT) -> i32 {
        self.trace.event_count += 1;
        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                self.trace.create_event = true;
                let info = unsafe { event.u.CreateProcessInfo };
                self.trace.canonical_field(
                    CREATE_PROCESS_DEBUG_EVENT,
                    &[info.lpBaseOfImage as usize as u64],
                );
                // The event's hProcess/hThread are debugger-owned.  Only hFile
                // transfers close responsibility to the debugger.
                match self.observer {
                    LoaderDebugObserverV5::MandatoryPump => self.trace.record_module_minimal(
                        info.lpBaseOfImage as usize,
                        true,
                        info.hFile,
                    ),
                    LoaderDebugObserverV5::FullObserver => self.trace.record_module(
                        self.process,
                        info.lpBaseOfImage as usize,
                        true,
                        info.hFile,
                        info.lpImageName,
                        info.fUnicode,
                    ),
                }
                DBG_CONTINUE
            }
            CREATE_THREAD_DEBUG_EVENT => {
                self.trace.thread_count += 1;
                self.trace
                    .canonical_field(CREATE_THREAD_DEBUG_EVENT, &[event.dwThreadId as u64]);
                DBG_CONTINUE
            }
            EXIT_THREAD_DEBUG_EVENT => {
                self.trace.exit_thread_count += 1;
                self.trace
                    .canonical_field(EXIT_THREAD_DEBUG_EVENT, &[event.dwThreadId as u64]);
                DBG_CONTINUE
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { event.u.LoadDll };
                match self.observer {
                    LoaderDebugObserverV5::MandatoryPump => self.trace.record_module_minimal(
                        info.lpBaseOfDll as usize,
                        false,
                        info.hFile,
                    ),
                    LoaderDebugObserverV5::FullObserver => self.trace.record_module(
                        self.process,
                        info.lpBaseOfDll as usize,
                        false,
                        info.hFile,
                        info.lpImageName,
                        info.fUnicode,
                    ),
                }
                DBG_CONTINUE
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { event.u.UnloadDll };
                self.trace.record_unload(info.lpBaseOfDll as usize);
                DBG_CONTINUE
            }
            EXCEPTION_DEBUG_EVENT => {
                let info = unsafe { event.u.Exception };
                let record = info.ExceptionRecord;
                let count = (record.NumberParameters as usize).min(EXCEPTION_PARAMETER_CAPACITY);
                let parameters = &record.ExceptionInformation[..count];
                let code = record.ExceptionCode as u32;
                let initial_breakpoint =
                    code == EXCEPTION_BREAKPOINT as u32 && !self.trace.initial_breakpoint;
                if initial_breakpoint {
                    self.trace.initial_breakpoint = true;
                }
                self.trace.record_exception(
                    code,
                    info.dwFirstChance != 0,
                    record.ExceptionAddress as usize,
                    record.ExceptionFlags,
                    parameters,
                );
                if initial_breakpoint {
                    DBG_CONTINUE
                } else {
                    DBG_EXCEPTION_NOT_HANDLED
                }
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                let info = unsafe { event.u.DebugString };
                match self.observer {
                    LoaderDebugObserverV5::MandatoryPump => self.trace.record_debug_string_minimal(
                        info.nDebugStringLength as usize,
                        info.fUnicode != 0,
                    ),
                    LoaderDebugObserverV5::FullObserver => self.trace.record_debug_string(
                        self.process,
                        info.lpDebugStringData,
                        info.nDebugStringLength as usize,
                        info.fUnicode != 0,
                    ),
                }
                DBG_CONTINUE
            }
            RIP_EVENT => {
                let info = unsafe { event.u.RipInfo };
                self.trace.rip_count += 1;
                self.trace
                    .canonical_field(RIP_EVENT, &[info.dwError as u64, info.dwType as u64]);
                DBG_CONTINUE
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                let info = unsafe { event.u.ExitProcess };
                self.trace.exit_event = true;
                self.trace.exit_code = Some(info.dwExitCode);
                self.trace
                    .canonical_field(EXIT_PROCESS_DEBUG_EVENT, &[info.dwExitCode as u64]);
                DBG_CONTINUE
            }
            other => {
                self.trace.record_unknown_event(other);
                DBG_CONTINUE
            }
        }
    }
}

struct ModulePathResolution {
    basename: String,
    path_source: String,
    path_sha256: String,
    path_error: Option<i32>,
    path_provenance: String,
}

fn debug_module_path(
    process: HANDLE,
    base: usize,
    file: HANDLE,
    remote_image_name: *mut c_void,
    unicode: bool,
) -> ModulePathResolution {
    let (file_path, file_status, file_error) = debug_file_handle_path(file);
    if let Some(path) = file_path {
        return resolved_module_path(path, "file-handle", file_status, file_error);
    }

    let (mapped_path, mapped_status, mapped_error) = debug_mapped_file_path(process, base);
    let mapped_provenance = format!("{file_status}>{mapped_status}");
    if let Some(path) = mapped_path {
        return resolved_module_path(path, "mapped-file", mapped_provenance, None);
    }

    let (event_path, event_status, event_error) =
        debug_event_image_name(process, remote_image_name, unicode);
    let provenance = bounded(
        &format!("{file_status}>{mapped_status}>{event_status}"),
        192,
    );
    if let Some(path) = event_path {
        return resolved_module_path(path, "event-image-name-untrusted", provenance, None);
    }

    ModulePathResolution {
        basename: "unavailable".to_owned(),
        path_source: "unavailable".to_owned(),
        path_sha256: super::record::digest(provenance.as_bytes()),
        path_error: event_error.or(mapped_error).or(file_error),
        path_provenance: provenance,
    }
}

fn resolved_module_path(
    path: PathBuf,
    source: &str,
    provenance: String,
    path_error: Option<i32>,
) -> ModulePathResolution {
    let basename = bounded_module_basename(
        &path
            .file_name()
            .unwrap_or_else(|| path.as_os_str())
            .to_string_lossy(),
    );
    ModulePathResolution {
        basename,
        path_source: source.to_owned(),
        path_sha256: super::record::digest(path.to_string_lossy().to_ascii_lowercase().as_bytes()),
        path_error,
        path_provenance: bounded(&provenance, 192),
    }
}

fn debug_file_handle_path(file: HANDLE) -> (Option<PathBuf>, String, Option<i32>) {
    if file.is_null() {
        return (None, "file-null".to_owned(), None);
    }
    let file = match OwnedHandle::new(file) {
        Ok(file) => file,
        Err(_) => return (None, "file-invalid".to_owned(), Some(6)),
    };
    let mut buffer = vec![0_u16; MODULE_PATH_BUFFER_WCHARS];
    let written = unsafe {
        GetFinalPathNameByHandleW(file.raw(), buffer.as_mut_ptr(), buffer.len() as u32, 0)
    };
    if written == 0 {
        let code = io::Error::last_os_error().raw_os_error();
        return (None, format!("file-os-{}", code.unwrap_or_default()), code);
    }
    if written as usize >= buffer.len() {
        return (None, "file-overflow".to_owned(), None);
    }
    buffer.truncate(written as usize);
    (
        Some(PathBuf::from(OsString::from_wide(&buffer))),
        "file-ok".to_owned(),
        None,
    )
}

fn debug_mapped_file_path(process: HANDLE, base: usize) -> (Option<PathBuf>, String, Option<i32>) {
    if base == 0 {
        return (None, "mapped-null-base".to_owned(), None);
    }
    let mut buffer = vec![0_u16; MODULE_PATH_BUFFER_WCHARS];
    let written = unsafe {
        K32GetMappedFileNameW(
            process,
            base as *const c_void,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    if written == 0 {
        let code = io::Error::last_os_error().raw_os_error();
        return (
            None,
            format!("mapped-os-{}", code.unwrap_or_default()),
            code,
        );
    }
    if written as usize >= buffer.len() {
        return (None, "mapped-overflow".to_owned(), None);
    }
    buffer.truncate(written as usize);
    (
        Some(PathBuf::from(OsString::from_wide(&buffer))),
        "mapped-ok".to_owned(),
        None,
    )
}

fn debug_event_image_name(
    process: HANDLE,
    remote_image_name: *mut c_void,
    unicode: bool,
) -> (Option<PathBuf>, String, Option<i32>) {
    if remote_image_name.is_null() {
        return (None, "event-pointer-null".to_owned(), None);
    }
    let mut remote_string = 0_usize;
    let mut pointer_bytes = 0_usize;
    let pointer_ok = unsafe {
        ReadProcessMemory(
            process,
            remote_image_name.cast_const(),
            (&raw mut remote_string).cast(),
            std::mem::size_of::<usize>(),
            &raw mut pointer_bytes,
        )
    };
    if pointer_ok == 0 || pointer_bytes != std::mem::size_of::<usize>() {
        let code = io::Error::last_os_error().raw_os_error();
        let status = if pointer_ok == 0 {
            format!("event-pointer-os-{}", code.unwrap_or_default())
        } else {
            format!("event-pointer-partial-{pointer_bytes}")
        };
        return (None, status, code);
    }
    if remote_string == 0 {
        return (None, "event-string-null".to_owned(), None);
    }
    if unicode {
        let mut buffer = vec![0_u16; REMOTE_IMAGE_NAME_MAX_UNITS];
        let mut bytes_read = 0_usize;
        let read_ok = unsafe {
            ReadProcessMemory(
                process,
                remote_string as *const c_void,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(buffer.as_slice()),
                &raw mut bytes_read,
            )
        };
        if read_ok == 0 || bytes_read != std::mem::size_of_val(buffer.as_slice()) {
            let code = io::Error::last_os_error().raw_os_error();
            let status = if read_ok == 0 {
                format!("event-wide-os-{}", code.unwrap_or_default())
            } else {
                format!("event-wide-partial-{bytes_read}")
            };
            return (None, status, code);
        }
        let Some(nul) = buffer.iter().position(|unit| *unit == 0) else {
            return (None, "event-wide-unterminated".to_owned(), None);
        };
        let value = match String::from_utf16(&buffer[..nul]) {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => return (None, "event-wide-empty".to_owned(), None),
            Err(_) => return (None, "event-wide-invalid".to_owned(), None),
        };
        return (Some(PathBuf::from(value)), "event-wide-ok".to_owned(), None);
    }

    let mut buffer = vec![0_u8; REMOTE_IMAGE_NAME_MAX_UNITS];
    let mut bytes_read = 0_usize;
    let read_ok = unsafe {
        ReadProcessMemory(
            process,
            remote_string as *const c_void,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut bytes_read,
        )
    };
    if read_ok == 0 || bytes_read != buffer.len() {
        let code = io::Error::last_os_error().raw_os_error();
        let status = if read_ok == 0 {
            format!("event-ansi-os-{}", code.unwrap_or_default())
        } else {
            format!("event-ansi-partial-{bytes_read}")
        };
        return (None, status, code);
    }
    let Some(nul) = buffer.iter().position(|byte| *byte == 0) else {
        return (None, "event-ansi-unterminated".to_owned(), None);
    };
    let value = match std::str::from_utf8(&buffer[..nul]) {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => return (None, "event-ansi-empty".to_owned(), None),
        Err(_) => return (None, "event-ansi-invalid".to_owned(), None),
    };
    (Some(PathBuf::from(value)), "event-ansi-ok".to_owned(), None)
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

fn bounded_module_basename(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '?'
            }
        })
        .collect::<String>();
    bounded(&sanitized, MODULE_BASENAME_MAX_BYTES)
}

fn normalized_basename(value: &str) -> String {
    PathBuf::from(value)
        .file_name()
        .unwrap_or_else(|| value.as_ref())
        .to_string_lossy()
        .to_ascii_uppercase()
}

fn loader_status_symbol(status: u32) -> &'static str {
    match status {
        0xC000_0142 => "STATUS_DLL_INIT_FAILED",
        0 => "STATUS_SUCCESS",
        _ => "UNKNOWN_NT_OR_NATIVE_STATUS",
    }
}

fn host_set_digest_bytes(hosts: &BTreeSet<String>) -> Vec<u8> {
    let mut canonical = b"memcordon-loader-debug-host-set-v1\0".to_vec();
    for host in hosts {
        canonical.extend_from_slice(&(host.len() as u64).to_le_bytes());
        canonical.extend_from_slice(host.as_bytes());
    }
    canonical
}

fn host_set_digest(hosts: &BTreeSet<String>) -> String {
    super::record::digest(&host_set_digest_bytes(hosts))
}

fn host_set_diagnostic(hosts: &BTreeSet<String>) -> String {
    bounded(
        &hosts.iter().cloned().collect::<Vec<_>>().join(","),
        HOST_SET_DIAGNOSTIC_MAX_BYTES,
    )
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
pub(crate) fn reduce_loader_trace_for_test(
    expected_hosts: &[&str],
    loads: &[(usize, &str, &str, bool)],
    unloads: &[usize],
    unknown_events: &[u32],
    exceptions: &[(bool, u32, usize)],
    exit: u32,
) -> String {
    let mut trace = LoaderDebugTraceV4::new(expected_hosts.iter().map(|host| (*host).to_owned()));
    for (base, name, source, main_image) in loads {
        trace.event_count += 1;
        if *main_image {
            trace.create_event = true;
        } else {
            trace.load_dll_count += 1;
        }
        trace.module_count += 1;
        let ordinal = trace.module_count;
        trace.canonical_field(
            if *main_image {
                CREATE_PROCESS_DEBUG_EVENT
            } else {
                LOAD_DLL_DEBUG_EVENT
            },
            &[ordinal, *base as u64, *main_image as u64],
        );
        trace.canonical.update(name.as_bytes());
        trace.canonical.update(source.as_bytes());
        if !*main_image && *source != "unavailable" {
            trace.record_observed_host(name);
            trace
                .active_modules
                .insert(*base, normalized_basename(name));
        }
        if trace.modules.len() == MODULE_TAIL_CAPACITY {
            trace.modules.pop_front();
        }
        trace.modules.push_back(LoaderModuleTailV2 {
            ordinal,
            base: *base,
            basename: bounded_module_basename(name),
            path_source: (*source).to_owned(),
            path_sha256: super::record::digest(name.as_bytes()),
            path_error: None,
            path_provenance: "test-ok".to_owned(),
        });
    }
    for base in unloads {
        trace.event_count += 1;
        trace.record_unload(*base);
    }
    for code in unknown_events {
        trace.event_count += 1;
        trace.record_unknown_event(*code);
    }
    for (first, code, address) in exceptions {
        trace.event_count += 1;
        if *code == EXCEPTION_BREAKPOINT as u32 && !trace.initial_breakpoint {
            trace.initial_breakpoint = true;
        }
        trace.record_exception(*code, *first, *address, 0, &[]);
    }
    trace.event_count += 1;
    trace.exit_event = true;
    trace.drained = true;
    trace.exit_code = Some(exit);
    trace.canonical_field(EXIT_PROCESS_DEBUG_EVENT, &[exit as u64]);
    trace.diagnostic()
}

#[cfg(test)]
pub(crate) fn reduce_loader_root_frontier_for_test(
    roots: &[(u32, &str, &str)],
    edges: &[(&str, &str, &str)],
    observed_hosts: &[&str],
) -> String {
    let expected_hosts = roots
        .iter()
        .map(|(_, _, concrete)| (*concrete).to_owned())
        .chain(edges.iter().map(|(_, _, concrete)| (*concrete).to_owned()));
    let mut trace = LoaderDebugTraceV4::new(expected_hosts);
    trace.graph_roots = roots
        .iter()
        .map(
            |(descriptor_ordinal, import_contract, concrete_host)| LoaderGraphTraceRootV4 {
                descriptor_ordinal: *descriptor_ordinal,
                import_contract: normalized_basename(import_contract),
                concrete_host: normalized_basename(concrete_host),
                expected_resolution: if import_contract.eq_ignore_ascii_case(concrete_host) {
                    "physical-direct".to_owned()
                } else {
                    "api-set-to-physical".to_owned()
                },
                physical_selection: "known-dll-section".to_owned(),
                preflight_nt_status: 0,
                object_name_sha256: super::record::digest(
                    format!(r"\KnownDlls\{concrete_host}").as_bytes(),
                ),
                source_target_object_attested: true,
                read_map_attested: true,
                execute_map_attested: true,
                path_sha256: "11".repeat(32),
                volume_serial: 1,
                file_id_sha256: "22".repeat(32),
                image_sha256: "33".repeat(32),
                loader_contract_sha256: "44".repeat(32),
            },
        )
        .collect();
    trace.graph_edges = edges
        .iter()
        .map(|(parent, contract, concrete)| LoaderGraphTraceEdgeV4 {
            parent_host: normalized_basename(parent),
            import_contract: normalized_basename(contract),
            concrete_host: normalized_basename(concrete),
            descriptor_ordinal: Some(0),
            requested_symbol: None,
            forwarder: false,
        })
        .collect();
    for host in observed_hosts {
        trace.record_observed_host(host);
    }
    trace.diagnostic()
}

#[cfg(test)]
pub(crate) fn reduce_loader_causal_frontier_for_test(root_count: usize) -> String {
    let expected_hosts = (0..root_count)
        .map(|index| format!("ROOT{index:04}.DLL"))
        .collect::<Vec<_>>();
    let mut trace = LoaderDebugTraceV4::new(expected_hosts.iter().cloned());
    trace.graph_roots = expected_hosts
        .iter()
        .enumerate()
        .map(|(index, host)| LoaderGraphTraceRootV4 {
            descriptor_ordinal: index as u32,
            import_contract: host.clone(),
            concrete_host: host.clone(),
            expected_resolution: "physical-direct".to_owned(),
            physical_selection: "known-dll-section".to_owned(),
            preflight_nt_status: 0,
            object_name_sha256: super::record::digest(format!(r"\KnownDlls\{host}").as_bytes()),
            source_target_object_attested: true,
            read_map_attested: true,
            execute_map_attested: true,
            path_sha256: "11".repeat(32),
            volume_serial: 1,
            file_id_sha256: "22".repeat(32),
            image_sha256: "33".repeat(32),
            loader_contract_sha256: "44".repeat(32),
        })
        .collect();
    for (base, name, main_image) in [
        (0x1000, "bootstrap.exe", true),
        (0x2000, "NTDLL.DLL", false),
        (0x3000, "KERNELBASE.DLL", false),
        (0x4000, "FAILING-INITIALIZER.DLL", false),
    ] {
        trace.event_count += 1;
        if main_image {
            trace.create_event = true;
        } else {
            trace.load_dll_count += 1;
            trace.active_modules.insert(base, name.to_owned());
        }
        trace.module_count += 1;
        trace.modules.push_back(LoaderModuleTailV2 {
            ordinal: trace.module_count,
            base,
            basename: name.to_owned(),
            path_source: "mapped-file".to_owned(),
            path_sha256: super::record::digest(name.as_bytes()),
            path_error: None,
            path_provenance: "test-ok".to_owned(),
        });
    }
    for base in [0x3000, 0x4000] {
        trace.event_count += 1;
        trace.record_unload(base);
    }
    let snap = "LdrpCallInitRoutine returned STATUS_DLL_INIT_FAILED";
    trace.event_count += 1;
    trace.output_debug_string_count = 1;
    trace.output_debug_string_bytes = snap.len();
    trace.loader_snaps.push_back(LoaderSnapTailV4 {
        ordinal: 1,
        unicode: true,
        declared_bytes: snap.len(),
        captured_bytes: snap.len(),
        raw_sha256: super::record::digest(snap.as_bytes()),
        status: "captured".to_owned(),
        sanitized: snap.to_owned(),
    });
    trace.event_count += 1;
    trace.exit_event = true;
    trace.drained = true;
    trace.exit_code = Some(0xc000_0142);
    trace.canonical_field(EXIT_PROCESS_DEBUG_EVENT, &[0xc000_0142]);
    trace.diagnostic()
}

#[cfg(test)]
pub(crate) fn loader_path_resolution_precedence_for_test(
    file: Option<&str>,
    mapped: Option<&str>,
    event: Option<&str>,
) -> (String, String) {
    if let Some(path) = file {
        let resolution = resolved_module_path(
            PathBuf::from(path),
            "file-handle",
            "file-ok".to_owned(),
            None,
        );
        return (resolution.path_source, resolution.basename);
    }
    if let Some(path) = mapped {
        let resolution = resolved_module_path(
            PathBuf::from(path),
            "mapped-file",
            "file-null>mapped-ok".to_owned(),
            None,
        );
        return (resolution.path_source, resolution.basename);
    }
    if let Some(path) = event {
        let resolution = resolved_module_path(
            PathBuf::from(path),
            "event-image-name-untrusted",
            "file-null>mapped-os-5>event-wide-ok".to_owned(),
            None,
        );
        return (resolution.path_source, resolution.basename);
    }
    ("unavailable".to_owned(), "unavailable".to_owned())
}
