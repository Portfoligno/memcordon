use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub struct NamespaceInit {
    pub host_pid: libc::pid_t,
    pub pidfd: OwnedFd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceInitPhase {
    MountIsolation,
    CgroupViewIsolation,
    ProcMount,
    ChildSubreaper,
    TargetFork,
}

impl NamespaceInitPhase {
    pub const fn code(self) -> u8 {
        match self {
            Self::MountIsolation => 1,
            Self::CgroupViewIsolation => 2,
            Self::ProcMount => 3,
            Self::ChildSubreaper => 4,
            Self::TargetFork => 5,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::MountIsolation),
            2 => Some(Self::CgroupViewIsolation),
            3 => Some(Self::ProcMount),
            4 => Some(Self::ChildSubreaper),
            5 => Some(Self::TargetFork),
            _ => None,
        }
    }

    pub const fn rejection_code(self) -> &'static str {
        match self {
            Self::MountIsolation => "MCSEALED-NAMESPACE-INIT-MOUNT-ISOLATION",
            Self::CgroupViewIsolation => "MCSEALED-NAMESPACE-INIT-CGROUP-VIEW",
            Self::ProcMount => "MCSEALED-NAMESPACE-INIT-PROC-MOUNT",
            Self::ChildSubreaper => "MCSEALED-NAMESPACE-INIT-SUBREAPER",
            Self::TargetFork => "MCSEALED-NAMESPACE-INIT-TARGET-FORK",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceInitError {
    pub phase: NamespaceInitPhase,
    pub os_code: i32,
}

impl NamespaceInitError {
    pub(super) fn last(phase: NamespaceInitPhase) -> Self {
        let error = std::io::Error::last_os_error();
        let os_code = error
            .raw_os_error()
            .unwrap_or_else(|| panic!("failed namespace-init syscall omitted native errno"));
        if os_code <= 0 {
            panic!("failed namespace-init syscall returned invalid native errno {os_code}");
        }
        Self { phase, os_code }
    }
}

impl std::fmt::Display for NamespaceInitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {}",
            self.phase.rejection_code(),
            std::io::Error::from_raw_os_error(self.os_code)
        )
    }
}

/// Creates a trusted PID-namespace init directly in the already-open attempt
/// cgroup. The child begins in `child_entry` and never returns to provider code.
pub fn clone_into_cgroup<F>(cgroup: &std::fs::File, child_entry: F) -> Result<NamespaceInit, String>
where
    F: FnOnce() -> i32,
{
    let mut pidfd = -1_i32;
    let arguments = CloneArgs {
        flags: (libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP | libc::CLONE_PIDFD)
            as u64
            | (1_u64 << 33),
        pidfd: (&raw mut pidfd).addr() as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup.as_raw_fd() as u64,
        ..CloneArgs::default()
    };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw const arguments,
            size_of::<CloneArgs>(),
        )
    };
    if result == -1 {
        return Err(format!(
            "MCSEALED-CLONE3: {}",
            std::io::Error::last_os_error()
        ));
    }
    if result == 0 {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::_exit(child_entry()) };
    }
    if pidfd < 0 {
        return Err("MCSEALED-CLONE3: kernel omitted pidfd".to_owned());
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok(NamespaceInit {
        host_pid: result as libc::pid_t,
        pidfd,
    })
}

pub fn prepare_namespace_init() -> Result<(), NamespaceInitError> {
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } == -1
    {
        return Err(NamespaceInitError::last(NamespaceInitPhase::MountIsolation));
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::umount2(c"/sys/fs/cgroup".as_ptr(), libc::MNT_DETACH) } == -1 {
        return Err(NamespaceInitError::last(
            NamespaceInitPhase::CgroupViewIsolation,
        ));
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let _ = unsafe { libc::umount2(c"/proc".as_ptr(), libc::MNT_DETACH) };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    } == -1
    {
        return Err(NamespaceInitError::last(NamespaceInitPhase::ProcMount));
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(NamespaceInitError::last(NamespaceInitPhase::ChildSubreaper));
    }
    Ok(())
}
