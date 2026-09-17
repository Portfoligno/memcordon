//! Std-only Windows child-tree containment for the bootstrap executable.
use super::Process;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
type Handle = *mut c_void;
#[repr(C)]
#[derive(Default)]
struct BasicLimits {
    process_time: i64,
    job_time: i64,
    flags: u32,
    min_working: usize,
    max_working: usize,
    active: u32,
    affinity: usize,
    priority: u32,
    scheduling: u32,
}
#[repr(C)]
#[derive(Default)]
struct ExtendedLimits {
    basic: BasicLimits,
    io: [u64; 6],
    process_memory: usize,
    job_memory: usize,
    peak_process: usize,
    peak_job: usize,
}
#[repr(C)]
#[derive(Default)]
struct Accounting {
    times: [i64; 4],
    faults: u32,
    total: u32,
    active: u32,
    terminated: u32,
}
#[repr(C)]
#[derive(Default)]
struct ThreadEntry {
    size: u32,
    usage: u32,
    id: u32,
    process: u32,
    priority: i32,
    delta: i32,
    flags: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
    fn SetInformationJobObject(job: Handle, class: i32, info: *const c_void, length: u32) -> i32;
    fn QueryInformationJobObject(
        job: Handle,
        class: i32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    fn TerminateJobObject(job: Handle, code: u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry) -> i32;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry) -> i32;
    fn OpenThread(access: u32, inherit: i32, id: u32) -> Handle;
    fn ResumeThread(thread: Handle) -> u32;
}
struct Owned(Handle);
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub struct Contained {
    child: Child,
    job: Owned,
}
impl Process for Contained {
    fn status(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_none() {
            return Ok(None);
        }
        let mut info = Accounting::default();
        if unsafe {
            QueryInformationJobObject(
                self.job.0,
                1,
                (&raw mut info).cast(),
                size_of::<Accounting>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(if info.active == 0 { status } else { None })
    }
    fn terminate(&mut self) -> io::Result<()> {
        if unsafe { TerminateJobObject(self.job.0, 124) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
pub fn spawn(command: &mut Command) -> io::Result<Contained> {
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let job = Owned(raw);
    let mut limits = ExtendedLimits::default();
    limits.basic.flags = 0x2000; // KILL_ON_JOB_CLOSE; no breakaway.
    if unsafe {
        SetInformationJobObject(
            job.0,
            9,
            (&raw const limits).cast(),
            size_of::<ExtendedLimits>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    command.creation_flags(0x4); // CREATE_SUSPENDED: no descendant can escape assignment.
    let mut child = command.spawn()?;
    if unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) } == 0 {
        let error = io::Error::last_os_error();
        return Err(super::abort_spawn(
            &mut child,
            &mut super::WallClock(std::time::Instant::now()),
            &error,
        ));
    }
    let mut contained = Contained { child, job };
    if let Err(error) = resume(&contained.child) {
        return Err(super::abort_spawn(
            &mut contained,
            &mut super::WallClock(std::time::Instant::now()),
            &error,
        ));
    }
    Ok(contained)
}
fn resume(child: &Child) -> io::Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(0x4, 0) }; // TH32CS_SNAPTHREAD.
    if snapshot as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    let snapshot = Owned(snapshot);
    let mut entry = ThreadEntry {
        size: size_of::<ThreadEntry>() as u32,
        ..ThreadEntry::default()
    };
    let mut next = unsafe { Thread32First(snapshot.0, &raw mut entry) };
    while next != 0 {
        if entry.process == child.id() {
            let thread = unsafe { OpenThread(0x2, 0, entry.id) }; // THREAD_SUSPEND_RESUME.
            if thread.is_null() {
                return Err(io::Error::last_os_error());
            }
            let thread = Owned(thread);
            if unsafe { ResumeThread(thread.0) } == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            return Ok(());
        }
        next = unsafe { Thread32Next(snapshot.0, &raw mut entry) };
    }
    Err(io::Error::other(
        "suspended bootstrap primary thread was not found",
    ))
}
