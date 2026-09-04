use crate::{
    PreparedCurrentDirectoryV1, PreparedLoaderCommandV1, PreparedLoaderEnvironmentV1,
    ProductionLoaderPlanV1,
};
use sha2::{Digest, Sha256};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::c_void;
use std::io;
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetKernelObjectSecurity,
    GetSecurityDescriptorLength, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::System::IO::CreateIoCompletionPort;
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW,
    STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

const PROCESS_HANDLE_INFORMATION_CLASS: u32 = 51;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xc000_0004_u32 as i32;
const MAX_PROCESS_HANDLE_SNAPSHOT_BYTES: usize = 1024 * 1024;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// The single raw Windows process-creation boundary shared by every shipped
/// launcher role. Callers retain ownership of every pointer for the duration
/// of this one native call.
///
/// # Safety
///
/// Every handle and pointer must satisfy `CreateProcessAsUserW`'s validity,
/// access, alignment, initialization, aliasing, and lifetime requirements for
/// the duration of the call. Output storage must be writable.
#[allow(clippy::too_many_arguments)]
pub unsafe fn create_process_as_user_native(
    token: HANDLE,
    application: *const u16,
    command_line: *mut u16,
    process_attributes: *const SECURITY_ATTRIBUTES,
    thread_attributes: *const SECURITY_ATTRIBUTES,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u16,
    startup: *const STARTUPINFOW,
    process: *mut PROCESS_INFORMATION,
) -> i32 {
    // SAFETY: this function is the raw boundary; its safety contract requires
    // every pointer and handle to remain valid throughout the native call.
    unsafe {
        CreateProcessAsUserW(
            token,
            application,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            creation_flags,
            environment,
            current_directory,
            startup,
            process,
        )
    }
}

/// Current-token counterpart to [`create_process_as_user_native`].
///
/// # Safety
///
/// Every pointer must satisfy `CreateProcessW`'s validity, alignment,
/// initialization, aliasing, and lifetime requirements for the duration of
/// the call. Output storage must be writable.
#[allow(clippy::too_many_arguments)]
pub unsafe fn create_process_native(
    application: *const u16,
    command_line: *mut u16,
    process_attributes: *const SECURITY_ATTRIBUTES,
    thread_attributes: *const SECURITY_ATTRIBUTES,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u16,
    startup: *const STARTUPINFOW,
    process: *mut PROCESS_INFORMATION,
) -> i32 {
    // SAFETY: this function is the raw boundary; its safety contract requires
    // every pointer and handle to remain valid throughout the native call.
    unsafe {
        CreateProcessW(
            application,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            creation_flags,
            environment,
            current_directory,
            startup,
            process,
        )
    }
}

pub struct NativeSecurityDescriptorV1 {
    raw: *mut c_void,
    sddl_sha256: String,
}

impl NativeSecurityDescriptorV1 {
    pub fn from_sddl(sddl: &str) -> Result<Self, NativeCreateErrorV1> {
        if sddl.is_empty() || sddl.contains('\0') {
            return Err(contract_error(
                "security-descriptor-shape",
                "security descriptor SDDL must be nonempty and NUL-free",
            ));
        }
        let mut wide = sddl.encode_utf16().collect::<Vec<_>>();
        wide.push(0);
        let mut raw = ptr::null_mut();
        // SAFETY: wide is a live NUL-terminated SDDL string and raw receives
        // the LocalAlloc-owned absolute descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_error("security-descriptor-parse"));
        }
        Ok(Self {
            raw,
            sddl_sha256: hex::encode(Sha256::digest(sddl.as_bytes())),
        })
    }

    /// Returns non-inheritable native attributes borrowing this descriptor.
    /// The caller must keep `self` alive for every FFI call using the pointer.
    pub fn security_attributes(&self) -> Result<SECURITY_ATTRIBUTES, NativeCreateErrorV1> {
        Ok(SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
                contract_error(
                    "security-attributes-size",
                    "SECURITY_ATTRIBUTES size overflow",
                )
            })?,
            lpSecurityDescriptor: self.raw,
            bInheritHandle: 0,
        })
    }

    pub fn binary_sha256(&self) -> Result<String, NativeCreateErrorV1> {
        let length = unsafe { GetSecurityDescriptorLength(self.raw.cast()) };
        if length == 0 {
            return Err(last_error("security-descriptor-length"));
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self.raw.cast::<u8>(),
                usize::try_from(length).map_err(|_| {
                    contract_error(
                        "security-descriptor-size",
                        "security descriptor size overflow",
                    )
                })?,
            )
        };
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

impl Drop for NativeSecurityDescriptorV1 {
    fn drop(&mut self) {
        // SAFETY: raw is the exact LocalAlloc result and is freed once.
        unsafe { LocalFree(self.raw as HLOCAL) };
    }
}

pub struct ProductionNativeCreateRequestV1<'a> {
    pub plan: &'a ProductionLoaderPlanV1,
    pub target_token: HANDLE,
    pub job: HANDLE,
    pub application: &'a [u16],
    pub command: &'a mut PreparedLoaderCommandV1,
    pub environment: &'a mut PreparedLoaderEnvironmentV1,
    pub current_directory: &'a PreparedCurrentDirectoryV1,
    pub desktop: &'a mut [u16],
    /// `None` asks Windows to apply its default process-object descriptor.
    pub process_security: Option<&'a NativeSecurityDescriptorV1>,
    /// `None` asks Windows to apply its default thread-object descriptor.
    pub thread_security: Option<&'a NativeSecurityDescriptorV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCreateErrorV1 {
    pub stable_code: &'static str,
    pub win32_error: Option<u32>,
    pub detail: String,
}

pub struct SuspendedNativeProcessV1 {
    process: OwnedHandle,
    thread: OwnedHandle,
    process_id: u32,
    thread_id: u32,
    resumed: std::cell::Cell<bool>,
}

pub struct ProductionJobV1 {
    handle: OwnedHandle,
    _completion_port: OwnedHandle,
}

impl ProductionJobV1 {
    pub fn create(sddl: &str) -> Result<Self, NativeCreateErrorV1> {
        let security = NativeSecurityDescriptorV1::from_sddl(sddl)?;
        let attributes = security.security_attributes()?;
        // SAFETY: the exact production descriptor remains live for this call.
        let handle =
            OwnedHandle::new(unsafe { CreateJobObjectW(&raw const attributes, ptr::null()) })?;
        // SAFETY: INVALID_HANDLE_VALUE requests an independently owned port.
        let completion_port = OwnedHandle::new(unsafe {
            CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1)
        })?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: handle.raw(),
            CompletionPort: completion_port.raw(),
        };
        // SAFETY: association and size match the selected information class.
        if unsafe {
            SetInformationJobObject(
                handle.raw(),
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                u32::try_from(std::mem::size_of_val(&association)).map_err(|_| {
                    contract_error("job-port-size", "Job completion-port size overflow")
                })?,
            )
        } == 0
        {
            return Err(last_error("job-completion-port-association"));
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: structure and byte size match the requested information class.
        if unsafe {
            SetInformationJobObject(
                handle.raw(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                u32::try_from(std::mem::size_of_val(&limits)).map_err(|_| {
                    contract_error("job-limit-size", "Job limit structure size overflow")
                })?,
            )
        } == 0
        {
            return Err(last_error("job-limit-configuration"));
        }
        let job = Self {
            handle,
            _completion_port: completion_port,
        };
        verify_kernel_object_security(job.handle(), &security)?;
        let configured = job.query_limits()?;
        let flags = configured.BasicLimitInformation.LimitFlags;
        if flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0
            || flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0
        {
            return Err(contract_error(
                "job-limit-readback",
                "Job limit readback did not prove kill-on-close and breakaway denial",
            ));
        }
        Ok(job)
    }

    #[must_use]
    pub const fn handle(&self) -> HANDLE {
        self.handle.raw()
    }

    pub fn terminate(&self, status: u32) -> Result<(), NativeCreateErrorV1> {
        // SAFETY: this object owns the live Job handle.
        if unsafe { TerminateJobObject(self.handle.raw(), status) } == 0 {
            Err(last_error("job-terminate"))
        } else {
            Ok(())
        }
    }

    pub fn wait_empty(&self, deadline: std::time::Instant) -> Result<bool, NativeCreateErrorV1> {
        loop {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            let mut returned = 0_u32;
            // SAFETY: accounting and returned are live writable output buffers.
            if unsafe {
                QueryInformationJobObject(
                    self.handle(),
                    JobObjectBasicAccountingInformation,
                    (&raw mut accounting).cast(),
                    u32::try_from(std::mem::size_of_val(&accounting)).map_err(|_| {
                        contract_error("job-accounting-size", "Job accounting size overflow")
                    })?,
                    &raw mut returned,
                )
            } == 0
            {
                return Err(last_error("job-accounting-readback"));
            }
            if accounting.ActiveProcesses == 0 {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn query_limits(&self) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION, NativeCreateErrorV1> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut returned = 0_u32;
        // SAFETY: limits and returned are live writable output buffers.
        if unsafe {
            QueryInformationJobObject(
                self.handle(),
                JobObjectExtendedLimitInformation,
                (&raw mut limits).cast(),
                u32::try_from(std::mem::size_of_val(&limits)).map_err(|_| {
                    contract_error("job-limit-size", "Job limit structure size overflow")
                })?,
                &raw mut returned,
            )
        } == 0
        {
            Err(last_error("job-limit-readback"))
        } else {
            Ok(limits)
        }
    }
}

fn verify_kernel_object_security(
    handle: HANDLE,
    expected: &NativeSecurityDescriptorV1,
) -> Result<(), NativeCreateErrorV1> {
    let information =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut required = 0_u32;
    unsafe { GetKernelObjectSecurity(handle, information, ptr::null_mut(), 0, &raw mut required) };
    if required == 0 {
        return Err(last_error("job-security-size-readback"));
    }
    let mut observed =
        vec![
            0_u8;
            usize::try_from(required)
                .map_err(|_| contract_error("job-security-size", "Job security size overflow"))?
        ];
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            information,
            observed.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(last_error("job-security-readback"));
    }
    let expected_length = unsafe { GetSecurityDescriptorLength(expected.raw.cast()) };
    let expected_bytes = unsafe {
        std::slice::from_raw_parts(
            expected.raw.cast::<u8>(),
            usize::try_from(expected_length).map_err(|_| {
                contract_error("job-security-size", "Job security descriptor size overflow")
            })?,
        )
    };
    observed.truncate(
        usize::try_from(required)
            .map_err(|_| contract_error("job-security-size", "Job security size overflow"))?,
    );
    if observed != expected_bytes {
        return Err(contract_error(
            "job-security-mismatch",
            "Job security descriptor readback differs from the production plan",
        ));
    }
    Ok(())
}

impl SuspendedNativeProcessV1 {
    #[must_use]
    pub const fn process_handle(&self) -> HANDLE {
        self.process.raw()
    }

    #[must_use]
    pub const fn thread_handle(&self) -> HANDLE {
        self.thread.raw()
    }

    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    #[must_use]
    pub const fn thread_id(&self) -> u32 {
        self.thread_id
    }

    pub fn resume_once(&self) -> Result<(), NativeCreateErrorV1> {
        if self.resumed.replace(true) {
            return Err(contract_error(
                "thread-already-resumed",
                "production primary thread was already resumed",
            ));
        }
        // SAFETY: the thread handle is owned and the production contract calls
        // this exactly once after suspended-process attestation.
        if unsafe { ResumeThread(self.thread.raw()) } == 1 {
            Ok(())
        } else {
            Err(last_error("resume-thread"))
        }
    }
}

/// Reads the suspended child's live handle-table cardinality.
///
/// The production loader plan currently permits only an empty inherited-handle
/// list. This readback distinguishes that native postcondition from merely
/// trusting the inputs passed to process creation.
pub fn query_process_handle_count(
    process: &SuspendedNativeProcessV1,
) -> Result<usize, NativeCreateErrorV1> {
    let word_bytes = std::mem::size_of::<usize>();
    let initial_words = 512_usize;
    let mut buffer = vec![0_usize; initial_words];
    loop {
        let byte_len = buffer.len().checked_mul(word_bytes).ok_or_else(|| {
            contract_error(
                "process-handle-snapshot-size",
                "process handle snapshot buffer size overflow",
            )
        })?;
        let information_length = u32::try_from(byte_len).map_err(|_| {
            contract_error(
                "process-handle-snapshot-size",
                "process handle snapshot buffer exceeds the native range",
            )
        })?;
        let mut required = 0_u32;
        // SAFETY: the process handle is live, buffer is writable/aligned, and
        // its exact byte extent is supplied to the native query.
        let status = unsafe {
            NtQueryInformationProcess(
                process.process.raw(),
                PROCESS_HANDLE_INFORMATION_CLASS,
                buffer.as_mut_ptr().cast(),
                information_length,
                &raw mut required,
            )
        };
        if status >= 0 {
            return Ok(buffer[0]);
        }
        if status != STATUS_INFO_LENGTH_MISMATCH {
            return Err(contract_error(
                "process-handle-snapshot-query",
                &format!("NtQueryInformationProcess failed with NTSTATUS {status:#010x}"),
            ));
        }
        let required = usize::try_from(required).map_err(|_| {
            contract_error(
                "process-handle-snapshot-size",
                "process handle snapshot size exceeds the platform range",
            )
        })?;
        if required > MAX_PROCESS_HANDLE_SNAPSHOT_BYTES {
            return Err(contract_error(
                "process-handle-snapshot-size",
                "process handle snapshot exceeds the bounded evidence limit",
            ));
        }
        let words = required
            .checked_add(word_bytes - 1)
            .and_then(|bytes| bytes.checked_div(word_bytes))
            .ok_or_else(|| {
                contract_error(
                    "process-handle-snapshot-size",
                    "process handle snapshot allocation size overflow",
                )
            })?;
        if words <= buffer.len() {
            return Err(contract_error(
                "process-handle-snapshot-size",
                "native process handle snapshot size did not grow after retry",
            ));
        }
        buffer.resize(words, 0);
    }
}

pub fn create_suspended_in_job(
    request: ProductionNativeCreateRequestV1<'_>,
) -> Result<SuspendedNativeProcessV1, NativeCreateErrorV1> {
    create_suspended_in_job_inner(request)
}

fn create_suspended_in_job_inner(
    request: ProductionNativeCreateRequestV1<'_>,
) -> Result<SuspendedNativeProcessV1, NativeCreateErrorV1> {
    validate_request(&request)?;
    let jobs = [request.job];
    let attributes = AttributeList::new(&jobs)?;
    let process_attributes = request
        .process_security
        .map(NativeSecurityDescriptorV1::security_attributes)
        .transpose()?;
    let thread_attributes = request
        .thread_security
        .map(NativeSecurityDescriptorV1::security_attributes)
        .transpose()?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
        .map_err(|_| contract_error("startup-info-size", "STARTUPINFOEXW size overflow"))?;
    startup.StartupInfo.lpDesktop = request.desktop.as_mut_ptr();
    startup.lpAttributeList = attributes.raw();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: validation proves every buffer is NUL-terminated, the mutable
    // buffers remain live for the call, the token and Job are caller-owned live
    // handles, security descriptors outlive the call, and inheritance is off.
    if unsafe {
        create_process_as_user_native(
            request.target_token,
            request.application.as_ptr(),
            request.command.units_mut().as_mut_ptr(),
            process_attributes
                .as_ref()
                .map_or(ptr::null(), |value| value as *const SECURITY_ATTRIBUTES),
            thread_attributes
                .as_ref()
                .map_or(ptr::null(), |value| value as *const SECURITY_ATTRIBUTES),
            0,
            request.plan.creation_flags(),
            request.environment.units_mut().as_mut_ptr().cast(),
            request.current_directory.units().as_ptr(),
            &raw const startup.StartupInfo,
            &raw mut process,
        )
    } == 0
    {
        return Err(last_error("create-process-as-user"));
    }
    let process_handle = OwnedHandle::new(process.hProcess)?;
    let thread_handle = OwnedHandle::new(process.hThread)?;
    for (handle, descriptor, stable_code) in [
        (
            process_handle.raw(),
            request.process_security,
            "process-security-readback",
        ),
        (
            thread_handle.raw(),
            request.thread_security,
            "thread-security-readback",
        ),
    ] {
        if let Some(descriptor) = descriptor {
            if let Err(error) = verify_kernel_object_security(handle, descriptor) {
                terminate_created_process(process_handle.raw());
                return Err(NativeCreateErrorV1 {
                    stable_code,
                    win32_error: error.win32_error,
                    detail: error.detail,
                });
            }
        }
    }
    let mut contained = 0_i32;
    // SAFETY: both handles remain live and owned for this readback.
    if unsafe { IsProcessInJob(process_handle.raw(), jobs[0], &raw mut contained) } == 0 {
        let primary = last_error("job-membership-readback");
        terminate_created_process(process_handle.raw());
        return Err(primary);
    }
    if contained == 0 {
        let primary = contract_error(
            "job-membership-mismatch",
            "created process is absent from the creation-time Job",
        );
        terminate_created_process(process_handle.raw());
        return Err(primary);
    }
    Ok(SuspendedNativeProcessV1 {
        process: process_handle,
        thread: thread_handle,
        process_id: process.dwProcessId,
        thread_id: process.dwThreadId,
        resumed: std::cell::Cell::new(false),
    })
}

fn validate_request(
    request: &ProductionNativeCreateRequestV1<'_>,
) -> Result<(), NativeCreateErrorV1> {
    for (name, value) in [
        ("application", request.application),
        ("command-line", &*request.command.units),
        ("environment", &*request.environment.units),
        ("current-directory", request.current_directory.units()),
        ("desktop", &*request.desktop),
    ] {
        if value.last() != Some(&0) {
            return Err(contract_error(
                "unterminated-native-buffer",
                &format!("{name} is not NUL terminated"),
            ));
        }
    }
    let application = request.application.strip_suffix(&[0]).ok_or_else(|| {
        contract_error(
            "unterminated-native-buffer",
            "application is not NUL terminated",
        )
    })?;
    let desktop = request.desktop.strip_suffix(&[0]).ok_or_else(|| {
        contract_error(
            "unterminated-native-buffer",
            "desktop is not NUL terminated",
        )
    })?;
    if application != request.plan.executable_path_utf16() {
        return Err(contract_error(
            "application-plan-mismatch",
            "native application path differs from the production plan",
        ));
    }
    if request.command.semantic_sha256() != request.plan.command_line_sha256()
        || request.current_directory.sha256() != request.plan.current_directory_sha256()
        || request.environment.identity() != request.plan.environment()
        || desktop
            != request
                .plan
                .desktop()
                .exact_name
                .encode_utf16()
                .collect::<Vec<_>>()
        || security_identity(request.process_security)
            != request.plan.process_security_descriptor_sha256()
        || security_identity(request.thread_security)
            != request.plan.thread_security_descriptor_sha256()
    {
        return Err(contract_error(
            "concrete-plan-mismatch",
            "native creation material differs from the attested production plan",
        ));
    }
    if request.target_token.is_null()
        || request.target_token == INVALID_HANDLE_VALUE
        || request.job.is_null()
        || request.job == INVALID_HANDLE_VALUE
    {
        return Err(contract_error(
            "invalid-authority-handle",
            "production token or Job handle is invalid",
        ));
    }
    let envelope = crate::query_token_envelope(request.target_token)
        .map_err(|detail| contract_error("target-token-envelope-readback", &detail))?;
    let envelope_sha256 = crate::token_envelope_sha256(&envelope)
        .map_err(|detail| contract_error("target-token-envelope-digest", &detail))?;
    if envelope.authentication_id != request.plan.target_token().authentication_id
        || envelope.session_id != request.plan.target_token().session_id
        || envelope_sha256 != request.plan.target_token().envelope_sha256
    {
        return Err(contract_error(
            "target-token-identity-mismatch",
            "live target token identity differs from the attested production plan",
        ));
    }
    if !request.plan.debugger_is_unrepresentable()
        || !request.plan.inherited_handles().roles().is_empty()
        || !request.plan.job_at_creation()
    {
        return Err(contract_error(
            "invalid-production-plan",
            "production plan can express diagnostic or post-create authority",
        ));
    }
    Ok(())
}

fn security_identity(descriptor: Option<&NativeSecurityDescriptorV1>) -> String {
    descriptor.map_or_else(
        || {
            hex::encode(Sha256::digest(
                crate::WINDOWS_DEFAULT_SECURITY_DESCRIPTOR_V1.as_bytes(),
            ))
        },
        |descriptor| descriptor.sddl_sha256.clone(),
    )
}

struct AttributeList {
    raw: LPPROC_THREAD_ATTRIBUTE_LIST,
    layout: Layout,
}

impl AttributeList {
    fn new(jobs: &[HANDLE; 1]) -> Result<Self, NativeCreateErrorV1> {
        let mut size = 0_usize;
        let attribute_count = 1;
        // SAFETY: documented size-query form.
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), attribute_count, 0, &raw mut size)
        };
        let layout =
            Layout::from_size_align(size, std::mem::align_of::<usize>()).map_err(|_| {
                contract_error(
                    "attribute-list-layout",
                    "invalid native attribute-list layout",
                )
            })?;
        // SAFETY: layout is API supplied.
        let allocation = unsafe { alloc_zeroed(layout) };
        if allocation.is_null() {
            return Err(contract_error(
                "attribute-list-allocation",
                "cannot allocate process attribute list",
            ));
        }
        let raw = allocation.cast();
        // SAFETY: allocation has the queried size.
        if unsafe { InitializeProcThreadAttributeList(raw, attribute_count, 0, &raw mut size) } == 0
        {
            // SAFETY: this is the exact allocation/layout pair.
            unsafe { dealloc(allocation, layout) };
            return Err(last_error("attribute-list-initialize"));
        }
        let list = Self { raw, layout };
        // SAFETY: the initialized list and one-element Job array remain live
        // through the subsequent CreateProcessAsUserW call.
        if unsafe {
            UpdateProcThreadAttribute(
                list.raw,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast_mut().cast::<c_void>(),
                std::mem::size_of_val(jobs),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(last_error("job-list-attribute"));
        }
        Ok(list)
    }

    const fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.raw
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: raw is initialized and the allocation/layout pair is exact.
        unsafe {
            DeleteProcThreadAttributeList(self.raw);
            dealloc(self.raw.cast(), self.layout);
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Result<Self, NativeCreateErrorV1> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(last_error("process-handle-adoption"))
        } else {
            Ok(Self(handle))
        }
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this type owns one live native handle and closes it once.
        unsafe { CloseHandle(self.0) };
    }
}

fn last_error(stable_code: &'static str) -> NativeCreateErrorV1 {
    let error = io::Error::last_os_error();
    NativeCreateErrorV1 {
        stable_code,
        win32_error: error
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok()),
        detail: error.to_string(),
    }
}

fn contract_error(stable_code: &'static str, detail: &str) -> NativeCreateErrorV1 {
    NativeCreateErrorV1 {
        stable_code,
        win32_error: None,
        detail: detail.to_owned(),
    }
}

fn terminate_created_process(process: HANDLE) {
    // SAFETY: process is the just-created suspended child. Termination is a
    // best-effort secondary cleanup and never replaces the captured primary.
    unsafe {
        TerminateProcess(process, 0xc000_0142_u32);
        let _ = WaitForSingleObject(process, 5_000);
    }
}
