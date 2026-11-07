//! Native owners for the additional matched-control measurement only.
//! No owner is constructed by reopening a numeric process identifier.
use std::{
    ffi::OsString,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    sync::Arc,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::TOKEN_QUERY,
    System::{JobObjects::*, Threading::*},
};

pub(super) fn live(cutoff: Instant) -> io::Result<()> {
    if Instant::now() >= cutoff {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "matched-control original cutoff expired",
        ))
    } else {
        Ok(())
    }
}
fn last() -> io::Error {
    io::Error::last_os_error()
}
#[derive(Debug)]
struct SettlementFailure {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for SettlementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; matched settlement: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for SettlementFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
pub(super) fn combine(primary: io::Error, secondary: io::Result<()>) -> io::Error {
    match secondary {
        Ok(()) => primary,
        Err(secondary) => io::Error::new(primary.kind(), SettlementFailure { primary, secondary }),
    }
}

pub(super) struct Caller {
    _inputs: Vec<std::fs::File>,
    source: OwnedHandle,
    derived: OwnedHandle,
    restricted: bool,
    source_before: super::native_fixture_default_dacl::Snapshot,
    selected_before: super::native_fixture_default_dacl::Snapshot,
}
#[derive(Clone, Copy)]
pub(super) enum Image {
    Fixture,
    Frontend,
}
impl Caller {
    pub fn select(
        restricted: bool,
        inputs: Vec<std::fs::File>,
        cutoff: Instant,
    ) -> io::Result<Arc<Self>> {
        live(cutoff)?;
        let (source, derived) = super::native::select_frontend_caller(restricted)?;
        let source_before = super::native_fixture_default_dacl::snapshot(source.as_raw_handle())?;
        live(cutoff)?;
        let selected_before = super::native_fixture_default_dacl::snapshot(if restricted {
            derived.as_raw_handle()
        } else {
            source.as_raw_handle()
        })?;
        live(cutoff)?;
        Ok(Arc::new(Self {
            _inputs: inputs,
            source,
            derived,
            restricted,
            source_before,
            selected_before,
        }))
    }
    pub fn token(&self) -> HANDLE {
        if self.restricted {
            self.derived.as_raw_handle()
        } else {
            self.source.as_raw_handle()
        }
    }
    pub fn default_acl(&self) -> io::Result<&[u8]> {
        self.selected_before
            .default_acl()
            .ok_or_else(|| io::Error::other("selected caller default ACL absent"))
    }
    pub fn token_hash(&self, cutoff: Instant) -> io::Result<[u8; 32]> {
        live(cutoff)?;
        let bytes =
            serde_json::to_vec(self.selected_before.envelope()).map_err(io::Error::other)?;
        live(cutoff)?;
        Ok(super::descriptor::controller_start::descriptor_digest(
            &bytes,
        ))
    }
    pub fn measurement(&self) -> serde_json::Value {
        serde_json::json!({"source":self.source_before.measurement(),"selected":self.selected_before.measurement()})
    }
    pub fn retain_inputs(owner: &mut Arc<Self>, files: Vec<std::fs::File>) -> io::Result<()> {
        Arc::get_mut(owner)
            .ok_or_else(|| {
                io::Error::other("matched inputs must freeze before any child creation")
            })?
            ._inputs
            .extend(files);
        Ok(())
    }
    fn verify_image(&self, process: HANDLE, image: Image, cutoff: Instant) -> io::Result<()> {
        use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        let expected = self
            ._inputs
            .get(match image {
                Image::Fixture => 0,
                Image::Frontend => 1,
            })
            .ok_or_else(|| io::Error::other("matched original image owner missing"))?;
        let mut name = vec![0u16; 32768];
        let mut length = name.len() as u32;
        live(cutoff)?;
        if unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut length) } == 0 {
            return Err(last());
        }
        live(cutoff)?;
        if length == 0 || length as usize >= name.len() {
            return Err(io::Error::other(
                "matched actual image name unavailable or oversize",
            ));
        }
        name.truncate(length as usize);
        let named = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(OsString::from_wide(&name))?;
        let actual = memcordon_platform::test_support::windows_held_file_metadata(&named)?;
        live(cutoff)?;
        let original = memcordon_platform::test_support::windows_held_file_metadata(expected)?;
        live(cutoff)?;
        if actual.volume_serial != original.volume_serial
            || actual.file_index != original.file_index
            || actual.length != original.length
            || actual.links != 1
            || actual.attributes & (0x400 | 0x10 | 0x40) != 0
        {
            return Err(io::Error::other(
                "matched actual suspended image differs from same held immutable input",
            ));
        }
        Ok(())
    }
    pub fn verify_unchanged(&self, cutoff: Instant) -> io::Result<()> {
        live(cutoff)?;
        let source = super::native_fixture_default_dacl::snapshot(self.source.as_raw_handle())?;
        live(cutoff)?;
        let selected = super::native_fixture_default_dacl::snapshot(self.token())?;
        live(cutoff)?;
        if !source.stable_eq(&self.source_before) || !selected.stable_eq(&self.selected_before) {
            return Err(io::Error::other(
                "held matched source/selected token changed",
            ));
        }
        Ok(())
    }
    fn verify_child(&self, process: HANDLE, cutoff: Instant) -> io::Result<()> {
        live(cutoff)?;
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(last());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let observed = super::native_fixture_default_dacl::snapshot(token.as_raw_handle())?;
        live(cutoff)?;
        if !observed.same_input(&self.selected_before) {
            return Err(io::Error::other(
                "suspended matched child token/default ACL differs from same held caller",
            ));
        }
        Ok(())
    }
}

pub(super) struct Job {
    handle: OwnedHandle,
}
impl Job {
    pub fn create(cutoff: Instant) -> io::Result<Arc<Self>> {
        live(cutoff)?;
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(last());
        }
        let owned = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        live(cutoff)?;
        if unsafe {
            SetInformationJobObject(
                owned.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(last());
        }
        live(cutoff)?;
        let job = Arc::new(Self { handle: owned });
        job.verify_policy(cutoff)?;
        Ok(job)
    }
    fn verify_policy(&self, cutoff: Instant) -> io::Result<()> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut returned = 0;
        live(cutoff)?;
        if unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(last());
        }
        live(cutoff)?;
        if returned as usize != std::mem::size_of_val(&limits)
            || limits.BasicLimitInformation.LimitFlags != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        {
            return Err(io::Error::other(
                "direct Job policy differs from kill-on-close/nonbreakaway-only declaration",
            ));
        }
        Ok(())
    }
    pub fn active(&self, cutoff: Instant) -> io::Result<u32> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut returned = 0;
        live(cutoff)?;
        if unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(last());
        }
        live(cutoff)?;
        if returned as usize != std::mem::size_of_val(&accounting) {
            return Err(io::Error::other("direct Job accounting extent differs"));
        }
        Ok(accounting.ActiveProcesses)
    }
    pub fn terminate(&self, cutoff: Instant) -> io::Result<()> {
        live(cutoff)?;
        if unsafe { TerminateJobObject(self.handle.as_raw_handle(), 2) } == 0 {
            return Err(last());
        }
        live(cutoff)
    }
}

struct ProcessReferences {
    process: OwnedHandle,
    thread: OwnedHandle,
    _caller: Arc<Caller>,
    job: Option<Arc<Job>>,
}
/// Drop retains an unsettled exact native owner for this controller lifetime.
/// It never treats kill-on-close or a parent exit as physical retirement proof.
pub(super) struct Process {
    references: Option<ProcessReferences>,
    pub pid: u32,
    pub birth: u64,
}
pub(super) struct Launch<'a> {
    pub image_role: Image,
    pub image: &'a Path,
    pub argv: &'a [OsString],
    pub environment: &'a [memcordon_core::WindowsEnvironmentEntryV1],
    pub cwd: &'a Path,
    pub stdio: [HANDLE; 3],
    pub job: Option<Arc<Job>>,
    pub work: Instant,
    pub cleanup: Instant,
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(references) = self.references.take() {
            let _retained = Box::leak(Box::new(references));
        }
    }
}
impl Process {
    pub fn needs_settlement(&self) -> bool {
        self.references.is_some()
    }
    pub fn create(caller: Arc<Caller>, launch: Launch<'_>) -> io::Result<Self> {
        let Launch {
            image_role,
            image,
            argv,
            environment,
            cwd,
            stdio,
            job,
            work,
            cleanup,
        } = launch;
        use std::os::windows::ffi::OsStrExt;
        if !image.is_absolute()
            || !cwd.is_absolute()
            || argv.is_empty()
            || argv.len() > 128
            || Path::new(&argv[0]) != image
        {
            return Err(io::Error::other(
                "matched process argv/image/cwd declaration differs",
            ));
        }
        let native_argv: Vec<Vec<u16>> =
            argv.iter().map(|arg| arg.encode_wide().collect()).collect();
        if native_argv.iter().any(|arg| arg.contains(&0)) {
            return Err(io::Error::other("matched native argv contains NUL"));
        }
        let mut command = memcordon_core::encode_windows_command_line(&native_argv);
        command.push(0);
        let image: Vec<u16> = image.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut cwd: Vec<u16> = cwd.as_os_str().encode_wide().collect();
        if cwd.contains(&0) {
            return Err(io::Error::other("matched cwd contains NUL"));
        }
        cwd.push(0);
        for handle in stdio {
            use windows_sys::Win32::Foundation::{
                GetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
            };
            let mut flags = 0;
            live(work)?;
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::other("matched stdio handle missing"));
            }
            if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
                return Err(last());
            }
            live(work)?;
            if flags & HANDLE_FLAG_INHERIT == 0 {
                return Err(io::Error::other(
                    "matched explicit stdio handle is not inheritable",
                ));
            }
        }
        let environment = memcordon_core::encode_windows_environment_block(environment)
            .map_err(io::Error::other)?;
        let count = 1 + u32::from(job.is_some());
        let mut size = 0;
        live(work)?;
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size) };
        if size == 0 || size > 64 * 1024 {
            return Err(io::Error::other(
                "matched process attribute allocation invalid",
            ));
        }
        let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let attributes = storage.as_mut_ptr().cast();
        live(work)?;
        if unsafe { InitializeProcThreadAttributeList(attributes, count, 0, &mut size) } == 0 {
            return Err(last());
        }
        // Both value arrays outlive the initialized attribute list, including
        // its destruction after the call/validation closure returns.
        let jobs = [job
            .as_ref()
            .map_or(std::ptr::null_mut(), |job| job.handle.as_raw_handle())];
        let result = (|| {
            live(work)?;
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    stdio.as_ptr().cast_mut().cast(),
                    std::mem::size_of_val(&stdio),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(last());
            }
            if job.is_some() {
                live(work)?;
                if unsafe {
                    UpdateProcThreadAttribute(
                        attributes,
                        0,
                        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                        jobs.as_ptr().cast_mut().cast(),
                        std::mem::size_of_val(&jobs),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(last());
                }
            }
            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = std::mem::size_of_val(&startup) as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = stdio[0];
            startup.StartupInfo.hStdOutput = stdio[1];
            startup.StartupInfo.hStdError = stdio[2];
            startup.lpAttributeList = attributes;
            let mut created = PROCESS_INFORMATION::default();
            live(work)?;
            if unsafe {
                CreateProcessAsUserW(
                    caller.token(),
                    image.as_ptr(),
                    command.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                    environment.as_ptr().cast(),
                    cwd.as_ptr(),
                    &startup.StartupInfo,
                    &mut created,
                )
            } == 0
            {
                return Err(last());
            }
            let mut owned = Self {
                references: Some(ProcessReferences {
                    process: unsafe { OwnedHandle::from_raw_handle(created.hProcess) },
                    thread: unsafe { OwnedHandle::from_raw_handle(created.hThread) },
                    _caller: Arc::clone(&caller),
                    job: job.clone(),
                }),
                pid: created.dwProcessId,
                birth: 0,
            };
            let validate = (|| {
                let held = owned.references.as_ref().expect("created native owners");
                let mut birth = FILETIME::default();
                let mut exit = FILETIME::default();
                let mut kernel = FILETIME::default();
                let mut user = FILETIME::default();
                live(work)?;
                if unsafe {
                    GetProcessTimes(
                        held.process.as_raw_handle(),
                        &mut birth,
                        &mut exit,
                        &mut kernel,
                        &mut user,
                    )
                } == 0
                {
                    return Err(last());
                }
                owned.birth =
                    (u64::from(birth.dwHighDateTime) << 32) | u64::from(birth.dwLowDateTime);
                caller.verify_child(held.process.as_raw_handle(), work)?;
                caller.verify_image(held.process.as_raw_handle(), image_role, work)?;
                if let Some(job) = &job {
                    let mut member = 0;
                    live(work)?;
                    if unsafe {
                        IsProcessInJob(
                            held.process.as_raw_handle(),
                            job.handle.as_raw_handle(),
                            &mut member,
                        )
                    } == 0
                    {
                        return Err(last());
                    }
                    live(work)?;
                    if member == 0 || job.active(work)? != 1 {
                        return Err(io::Error::other(
                            "direct suspended process lacks exact creation-time Job membership",
                        ));
                    }
                }
                Ok(())
            })();
            if let Err(primary) = validate {
                return Err(owned.fail(primary, cleanup));
            }
            Ok(owned)
        })();
        unsafe { DeleteProcThreadAttributeList(attributes) };
        result
    }
    pub fn resume(&self, cutoff: Instant) -> io::Result<()> {
        live(cutoff)?;
        let previous = unsafe {
            ResumeThread(
                self.references
                    .as_ref()
                    .expect("held initial thread")
                    .thread
                    .as_raw_handle(),
            )
        };
        if previous == u32::MAX {
            return Err(last());
        }
        if previous != 1 {
            return Err(io::Error::other(
                "matched initial thread suspend count differs",
            ));
        }
        live(cutoff)
    }
    pub fn status(&self, cutoff: Instant) -> io::Result<Option<u32>> {
        live(cutoff)?;
        let process = self
            .references
            .as_ref()
            .expect("held process")
            .process
            .as_raw_handle();
        match unsafe { WaitForSingleObject(process, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut status = 0;
                if unsafe { GetExitCodeProcess(process, &mut status) } == 0 {
                    return Err(last());
                }
                live(cutoff)?;
                Ok(Some(status))
            }
            _ => Err(last()),
        }
    }
    pub fn settle(&mut self, cutoff: Instant) -> io::Result<u32> {
        loop {
            if let Some(status) = self.status(cutoff)? {
                if let Some(job) = &self.references.as_ref().expect("held references").job {
                    if job.active(cutoff)? != 0 {
                        live(cutoff)?;
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                }
                self.references.take();
                return Ok(status);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    pub fn fail(&mut self, primary: io::Error, cutoff: Instant) -> io::Error {
        let killed = (|| {
            let held = self.references.as_ref().expect("held unsettled references");
            if let Some(job) = &held.job {
                job.terminate(cutoff)?;
            } else {
                live(cutoff)?;
                if unsafe { TerminateProcess(held.process.as_raw_handle(), 2) } == 0 {
                    return Err(last());
                }
            }
            self.settle(cutoff).map(|_| ())
        })();
        combine(primary, killed)
    }
}
