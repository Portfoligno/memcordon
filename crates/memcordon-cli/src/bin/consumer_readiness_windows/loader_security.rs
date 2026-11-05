//! Later same-caller security observations, never a replay of the loader check.
use super::{loader_security_record as record, winsock_trace::Context};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_TOKEN, LocalFree},
    Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
    Security::{
        AccessCheck, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GENERIC_MAPPING,
        GROUP_SECURITY_INFORMATION, GetSecurityDescriptorLength, IsValidSecurityDescriptor,
        OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, SecurityImpersonation, TOKEN_DUPLICATE,
        TOKEN_QUERY, TokenImpersonation,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_EXECUTE, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, READ_CONTROL,
    },
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, OpenProcessToken, OpenThreadToken,
    },
};

fn checked<T>(
    context: &Context<'_>,
    operation: impl FnOnce() -> io::Result<T>,
) -> Result<T, Value> {
    super::listener_trace::live(context.clock).map_err(|error|json!({"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind()),"original_cutoff_unavailable":true}))?;
    let value = operation();
    let ended = super::listener_trace::live(context.clock);
    match (value, ended) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), ended) => Err(
            json!({"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind()),"cutoff_error":ended.err().map(|error|json!({"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind())}))}),
        ),
        (Ok(_), Err(error)) => Err(
            json!({"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind()),"original_cutoff_unavailable":true}),
        ),
    }
}

fn identity(file: &File, directory: bool) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    identity_observed(file, directory, None)
}

fn identity_observed(
    file: &File,
    directory: bool,
    mut row: Option<&mut record::AncestorRow>,
) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    if let Some(row) = row.as_deref_mut() {
        row.phase = record::AncestorPhase::Query;
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: exact held file handle and complete fixed writable output.
    let queried = if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(info)
    };
    if let Some(row) = row.as_deref_mut() {
        row.query = record::CallOutcome::from_result(&queried);
    }
    let info = queried?;
    if let Some(row) = row.as_deref_mut() {
        row.phase = record::AncestorPhase::ValidateAttributes;
        row.observed_directory = Some(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0);
        row.observed_reparse = Some(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0);
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        if let Some(row) = row.as_deref_mut() {
            row.validation = record::CallState::Failed;
            row.validation_reason = Some(
                if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    record::ValidationReason::ReparsePoint
                } else {
                    record::ValidationReason::NotDirectory
                },
            );
        }
        return Err(io::Error::other(
            "selected path type or reparse attribute differs",
        ));
    }
    if let Some(row) = row {
        row.validation = record::CallState::Succeeded;
    }
    Ok(info)
}

fn ancestors(
    context: &Context<'_>,
    path: &Path,
    selected_path: &[u16],
    progress: &mut record::AncestryProgress,
) -> io::Result<Vec<File>> {
    if path
        .components()
        .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(io::Error::other("selected ancestry is not normalized"));
    }
    let mut held = Vec::new();
    for (index, parent) in path
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .filter(|parent| !parent.as_os_str().is_empty())
        .enumerate()
    {
        let prefix = parent.as_os_str().encode_wide().collect::<Vec<_>>();
        let mut row = record::AncestorRow::new(
            index as u32,
            prefix.len() as u32,
            if parent.parent().is_none() {
                record::AncestorRole::Root
            } else {
                record::AncestorRole::Ancestor
            },
        );
        let result = (|| -> io::Result<File> {
            row.phase = record::AncestorPhase::BeforeOpen;
            if !selected_path.starts_with(&prefix) {
                return Err(io::Error::other("selected ancestry prefix differs"));
            }
            let before = super::listener_trace::live(context.clock);
            row.before_open = record::CallOutcome::from_result(&before);
            before?;
            row.phase = record::AncestorPhase::Open;
            let opened = OpenOptions::new()
                .access_mode(0)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(parent);
            row.open = record::CallOutcome::from_result(&opened);
            let file = opened?;
            row.phase = record::AncestorPhase::AfterOpenBeforeQuery;
            let after = super::listener_trace::live(context.clock);
            row.after_open = record::CallOutcome::from_result(&after);
            after?;
            identity_observed(&file, true, Some(&mut row))?;
            row.phase = record::AncestorPhase::AfterValidationBeforeRetain;
            let after = super::listener_trace::live(context.clock);
            row.after_validation = record::CallOutcome::from_result(&after);
            after?;
            Ok(file)
        })();
        match result {
            Ok(file) => {
                held.push(file);
                row.retained = true;
                row.phase = record::AncestorPhase::Retained;
                progress.record(row);
            }
            Err(error) => {
                progress.record(row);
                progress.failed = true;
                return Err(error);
            }
        }
    }
    Ok(held)
}

fn checked_ancestors(
    context: &Context<'_>,
    path: &Path,
    selected_path: &[u16],
    progress: &mut record::AncestryProgress,
) -> Result<Vec<File>, Value> {
    // Exactly the original checked() precondition, ancestry call and postcondition.
    // Progress recording itself makes no native or clock queries.
    let before = super::listener_trace::live(context.clock);
    progress.outer_before = record::CallOutcome::from_result(&before);
    if let Err(error) = before {
        progress.failed = true;
        progress.terminal_phase = Some(record::AncestorPhase::OuterBefore);
        return Err(
            json!({"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind()),"original_cutoff_unavailable":true}),
        );
    }
    let value = path
        .parent()
        .ok_or_else(|| io::Error::other("selected path parent absent"))
        .and_then(|parent| ancestors(context, parent, selected_path, progress));
    let ended = super::listener_trace::live(context.clock);
    progress.outer_after = record::CallOutcome::from_result(&ended);
    if value.is_err() {
        progress.failed = true;
        if progress.terminal_phase.is_none() {
            progress.terminal_phase = Some(record::AncestorPhase::BeforeOpen);
        }
    }
    if ended.is_err() {
        progress.failed = true;
        if value.is_ok() {
            progress.terminal_phase = Some(record::AncestorPhase::OuterAfter);
        }
    }
    if value.is_ok() && ended.is_ok() {
        progress.terminal_phase = Some(record::AncestorPhase::Complete);
    }
    match (value, ended) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), ended) => Err(
            json!({"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind()),"cutoff_error":ended.err().map(|error|json!({"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind())}))}),
        ),
        (Ok(_), Err(error)) => Err(
            json!({"native_error":error.raw_os_error(),"kind":format!("{:?}",error.kind()),"original_cutoff_unavailable":true}),
        ),
    }
}

struct Descriptor(*mut std::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo transferred this LocalFree allocation once.
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub fn observe(
    context: &Context<'_>,
    packet: &super::listener_trace_record::Packet,
    before: &Value,
) -> Value {
    let mut output = json!({"format":"memcordon.post-original-loader-security","revision":1,"diagnostic_only":true,"acceptance_authority":false,"denied_object_proved":false,
        "original_desired_access":null,"original_desired_access_unavailable":true,"continuous_token_equality_proved":false,"original_file_identity_proved":false,
        "observation_timing":"same-caller-after-original-collectors-disarmed","file_observation_timing":"later-path-open-not-original-file-object","checks_are_hypotheses":true,
        "access_check_scope":"later-leaf-owner-group-dacl-only","unmodeled_inputs":["original-desired-access","original-file-object","mandatory-integrity-policy","parent-traversal","image-mapping","sharing","other-kernel-policy"],
        "later_file_open_request":{"desired_access":READ_CONTROL|FILE_READ_ATTRIBUTES,"share_access":FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,"flags":FILE_FLAG_OPEN_REPARSE_POINT,"original_request":false},
        "later_ancestor_open_request":{"desired_access":0,"share_access":FILE_SHARE_READ|FILE_SHARE_WRITE,"flags":FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,"original_request":false},
        "token_source_requested_access":TOKEN_QUERY|TOKEN_DUPLICATE,"access_check_duplicate_requested_access":TOKEN_QUERY});
    let selected = match record::select(packet) {
        Ok(value) => value,
        Err(reason) => {
            output["state"] = json!("unavailable");
            output["stage"] = json!("select-original-loader-path");
            output["reason"] = json!(reason);
            return record::bounded(output);
        }
    };
    output["selection"] = json!({"path_utf16":selected.path,"path_sha256":super::descriptor::controller_start::descriptor_digest(&selected.path.iter().flat_map(|unit|unit.to_le_bytes()).collect::<Vec<_>>()),"thread_id":selected.thread_id,
        "dependency_sequence":selected.dependency_sequence,"loader_dependency_sequence":selected.loader_dependency_sequence,"parent_listener_sequence":selected.parent_listener_sequence});
    let mut stage = "same-original-process-and-thread";
    let result = (|| -> Result<(), Value> {
        checked(context, || {
            let current = super::native::current_identity()?;
            // SAFETY: query the current thread id without acquiring authority.
            if current.process_id != context.binding.pid
                || current.creation_time_100ns != context.binding.birth
                || unsafe { GetCurrentThreadId() } != selected.thread_id
            {
                return Err(io::Error::other("post-original caller identity differs"));
            }
            Ok(())
        })?;
        stage = "query-post-original-effective-token-endpoint";
        let post_endpoint = checked(context, super::native::effective_token_observation);
        let post_endpoint_digest = post_endpoint.as_ref().ok().map(|bytes| {
            json!(super::descriptor::controller_start::descriptor_digest(
                bytes
            ))
        });
        output["effective_token_endpoint"] = match post_endpoint {
            Ok(_) => {
                json!({"post_return_sha256":post_endpoint_digest,"before_call_sha256":before.get("sha256"),
                "endpoint_digest_equal":post_endpoint_digest.as_ref().is_some_and(|digest|before.get("sha256").is_some_and(|prior|!prior.is_null()&&prior==digest)),
                "endpoint_comparison_only":true,"query_only_pseudo_handle":true,"held_source_identity_proved":false})
            }
            Err(error) => {
                json!({"observation_unavailable":error,"query_only_pseudo_handle":true,"held_source_identity_proved":false})
            }
        };
        stage = "capture-post-original-effective-token";
        let mut token_origin = "thread-token";
        let source = checked(context, || {
            let mut raw = std::ptr::null_mut();
            // SAFETY: same-caller token query/duplication only; OpenAsSelf does
            // not impersonate, revert, adjust privileges or replace any token.
            if unsafe {
                OpenThreadToken(
                    GetCurrentThread(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    1,
                    &mut raw,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
                    return Err(error);
                }
                token_origin = "process-token-after-no-thread-token";
                super::listener_trace::live(context.clock)?;
                // SAFETY: only documented ERROR_NO_TOKEN permits this fallback.
                if unsafe {
                    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw)
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            if raw.is_null() {
                return Err(io::Error::other(
                    "native token query succeeded without a handle",
                ));
            }
            // SAFETY: successful Open*Token transferred this owned native handle.
            Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
        });
        let impersonation = match source {
            Ok(source) => {
                let queried = checked(context, || {
                    super::native::token_observation_from(source.as_raw_handle())
                });
                match queried {
                    Ok(bytes) => {
                        let digest = json!(super::descriptor::controller_start::descriptor_digest(
                            &bytes
                        ));
                        let agrees = post_endpoint_digest.as_ref() == Some(&digest)
                            && before
                                .get("sha256")
                                .is_some_and(|prior| !prior.is_null() && *prior == digest);
                        output["token"] = json!({"origin":token_origin,"post_return_sha256":digest,"before_call_sha256":before.get("sha256"),"endpoint_digest_equal":agrees,"endpoint_comparison_only":true});
                        if agrees {
                            let duplicated = checked(context, || {
                                let mut raw = std::ptr::null_mut();
                                // SAFETY: same held effective source, query-only
                                // noninheritable impersonation token for AccessCheck.
                                if unsafe {
                                    DuplicateTokenEx(
                                        source.as_raw_handle(),
                                        TOKEN_QUERY,
                                        std::ptr::null(),
                                        SecurityImpersonation,
                                        TokenImpersonation,
                                        &mut raw,
                                    )
                                } == 0
                                {
                                    return Err(io::Error::last_os_error());
                                }
                                if raw.is_null() {
                                    return Err(io::Error::other(
                                        "native token duplication succeeded without a handle",
                                    ));
                                }
                                // SAFETY: successful duplication transfers one reference.
                                Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
                            });
                            match duplicated {
                                Ok(token) => Some(token),
                                Err(error) => {
                                    output["token"]["access_check_token_unavailable"] = error;
                                    None
                                }
                            }
                        } else {
                            output["token"]["access_check_token_unavailable"] = json!({"reason":"before-after-effective-token-endpoints-differ-or-unavailable"});
                            None
                        }
                    }
                    Err(error) => {
                        output["token"] =
                            json!({"origin":token_origin,"observation_unavailable":error});
                        None
                    }
                }
            }
            Err(error) => {
                output["token"] = json!({"origin":token_origin,"observation_unavailable":error});
                None
            }
        };
        stage = "validate-selected-native-system-directory-leaf";
        let path = PathBuf::from(std::ffi::OsString::from_wide(&selected.path));
        checked(context, || {
            let mut directory = [0u16; 256];
            // SAFETY: fixed bounded writable directory buffer.
            let count = unsafe {
                windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
                    directory.as_mut_ptr(),
                    directory.len() as u32,
                )
            };
            if count == 0 {
                return Err(io::Error::last_os_error());
            }
            if count as usize >= directory.len() {
                return Err(io::Error::other(
                    "native system directory exceeds path bound",
                ));
            }
            let parent = path
                .parent()
                .ok_or_else(|| io::Error::other("selected path has no parent"))?;
            let parent = parent.as_os_str().encode_wide().collect::<Vec<_>>();
            let leaf = path
                .file_name()
                .ok_or_else(|| io::Error::other("selected path has no leaf"))?
                .encode_wide()
                .collect::<Vec<_>>();
            if leaf.is_empty()
                || leaf
                    .iter()
                    .any(|unit| matches!(*unit, 0 | 47 | 58 | 92 | 42 | 63))
                || matches!(leaf.last(), Some(32 | 46))
            {
                return Err(io::Error::other(
                    "selected leaf is not a single canonical file component",
                ));
            }
            // SAFETY: complete explicit bounded UTF16 slices; native ordinal
            // comparison handles Windows case equivalence without normalizing.
            let compared = unsafe {
                windows_sys::Win32::Globalization::CompareStringOrdinal(
                    parent.as_ptr(),
                    parent.len() as i32,
                    directory.as_ptr(),
                    count as i32,
                    1,
                )
            };
            if compared == 0 {
                return Err(io::Error::last_os_error());
            }
            if compared != 2 {
                return Err(io::Error::other(
                    "selected loader path is outside native system directory",
                ));
            }
            Ok(())
        })?;
        stage = "hold-no-reparse-selected-ancestry";
        let mut progress = record::AncestryProgress::default();
        let ancestry = checked_ancestors(context, &path, &selected.path, &mut progress);
        output["ancestry"] = progress.diagnostic(&selected.path);
        let _ancestors = ancestry?;
        stage = "open-selected-leaf-read-control-and-attributes";
        let file = checked(context, || {
            OpenOptions::new()
                .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
        })?;
        stage = "query-held-later-file-identity";
        let info = checked(context, || identity(&file, false))?;
        output["later_file_identity"] = json!({"volume":info.dwVolumeSerialNumber,"file_index":(u64::from(info.nFileIndexHigh)<<32)|u64::from(info.nFileIndexLow),"attributes":info.dwFileAttributes,"original_object_identity_proved":false});
        stage = "query-held-owner-group-dacl";
        let descriptor = checked(context, || {
            let mut raw = std::ptr::null_mut();
            // SAFETY: same held read-control file; no SACL or privilege query.
            let status = unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut raw,
                )
            };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            if raw.is_null() {
                return Err(io::Error::other("native security descriptor is null"));
            }
            Ok(Descriptor(raw))
        })?;
        stage = "validate-and-hash-bounded-held-security-descriptor";
        checked(context, || {
            // SAFETY: GetSecurityInfo-owned descriptor remains live until all checks finish.
            if unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0 {
                return Err(io::Error::other("invalid returned security descriptor"));
            }
            let bytes = unsafe { GetSecurityDescriptorLength(descriptor.0) };
            if bytes == 0 || bytes > 64 * 1024 {
                return Err(io::Error::other(
                    "selected security descriptor exceeds bound",
                ));
            }
            let bytes =
                unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), bytes as usize) };
            output["security_descriptor"] = json!({"bytes":bytes.len(),"sha256":super::descriptor::controller_start::descriptor_digest(bytes),"sections":"owner-group-dacl-only","raw_bytes_exported":false});
            Ok(())
        })?;
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        output["generic_mapping"] = json!({"read":mapping.GenericRead,"write":mapping.GenericWrite,"execute":mapping.GenericExecute,"all":mapping.GenericAll});
        let mut checks = Vec::new();
        if let Some(token) = impersonation {
            for desired in [FILE_READ_DATA, FILE_EXECUTE, FILE_READ_DATA | FILE_EXECUTE] {
                stage = "hypothetical-leaf-dacl-access-check";
                let mut api_return = None;
                let check = checked(context, || {
                    let mut privileges = [0usize; 64];
                    let mut length = std::mem::size_of_val(&privileges) as u32;
                    let mut granted = 0;
                    let mut allowed = 0;
                    // SAFETY: retained descriptor/token and fixed aligned writable outputs.
                    let returned = unsafe {
                        AccessCheck(
                            descriptor.0,
                            token.as_raw_handle(),
                            desired,
                            &mapping,
                            privileges.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                            &mut length,
                            &mut granted,
                            &mut allowed,
                        )
                    };
                    let error = (returned == 0).then(io::Error::last_os_error);
                    api_return = Some(returned != 0);
                    if let Some(error) = error {
                        return Err(error);
                    }
                    if length as usize > std::mem::size_of_val(&privileges) {
                        return Err(io::Error::other(
                            "AccessCheck privilege extent exceeds supplied buffer",
                        ));
                    }
                    Ok(
                        json!({"desired_hypothesis":desired,"api_succeeded":true,"access_status":allowed!=0,"granted_access":granted,"api_native_error":null,"original_desired_access":false}),
                    )
                });
                checks.push(match check {Ok(value)=>value,Err(error)=>json!({"desired_hypothesis":desired,"api_succeeded":api_return,"access_status":null,"granted_access":null,"unavailable":error,"original_desired_access":false})});
            }
        } else {
            output["hypothetical_checks_unavailable"] =
                json!("no-bound-query-only-impersonation-token");
        }
        output["hypothetical_checks"] = json!(checks);
        stage = "final-original-cutoff";
        checked(context, || Ok(()))?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            output["state"] = json!("observed-later-readback");
        }
        Err(error) => {
            output["state"] = json!("unavailable");
            output["stage"] = json!(stage);
            output["unavailable"] = error;
        }
    }
    record::bounded(output)
}
