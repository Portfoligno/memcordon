//! Checked cBPF compiler for the disabled private TCP profile.
//!
//! This is intentionally **not** an installable or qualified profile filter.
//! Native execution, exact digest binding, and the full prelaunch descriptor
//! and lifecycle checks must exist before a target can be released.

use libc::sock_filter;
use sha2::{Digest, Sha256};

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_JMP_JA: u16 = 0x05;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const KERNEL_FILTER_INSTRUCTION_LIMIT: usize = 4096;

const NR_OFFSET: u32 = 0;
const ARCH_OFFSET: u32 = 4;
const ARG0_LOW: u32 = 16;
const ARG0_HIGH: u32 = 20;
const ARG1_LOW: u32 = 24;
const ARG1_HIGH: u32 = 28;
const ARG2_LOW: u32 = 32;
const ARG2_HIGH: u32 = 36;
const ARG3_LOW: u32 = 40;
const ARG3_HIGH: u32 = 44;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAbi {
    X86_64,
    Aarch64,
}

#[derive(Clone, Copy)]
struct Syscalls {
    socket: u32,
    socketpair: u32,
    clone: u32,
    clone3: u32,
    fcntl: u32,
    ioctl: u32,
    getsockopt: u32,
    setsockopt: u32,
    prctl: u32,
    prlimit64: u32,
    arch_prctl: Option<u32>,
    accept4: u32,
    pipe2: u32,
    dup3: u32,
    eventfd2: u32,
    epoll_create1: u32,
    signalfd4: u32,
    timerfd_create: u32,
}

// Reviewed Linux UAPI syscall_64.tbl and asm-generic/unistd.h mappings.
// The seven scalar-restricted descriptor/event calls are deliberately absent.
// ARM64 omits legacy names not allocated by its native ABI.
const X64_UNCONDITIONAL: &[(&str, u32)] = &[
    ("read", 0),
    ("write", 1),
    ("readv", 19),
    ("writev", 20),
    ("pread64", 17),
    ("pwrite64", 18),
    ("preadv", 295),
    ("pwritev", 296),
    ("preadv2", 327),
    ("pwritev2", 328),
    ("lseek", 8),
    ("close", 3),
    ("close_range", 436),
    ("dup", 32),
    ("dup2", 33),
    ("pipe", 22),
    ("sendfile", 40),
    ("copy_file_range", 326),
    ("splice", 275),
    ("tee", 276),
    ("vmsplice", 278),
    ("open", 2),
    ("openat", 257),
    ("openat2", 437),
    ("creat", 85),
    ("stat", 4),
    ("lstat", 6),
    ("fstat", 5),
    ("newfstatat", 262),
    ("statx", 332),
    ("statfs", 137),
    ("fstatfs", 138),
    ("access", 21),
    ("faccessat", 269),
    ("faccessat2", 439),
    ("getdents", 78),
    ("getdents64", 217),
    ("readlink", 89),
    ("readlinkat", 267),
    ("getcwd", 79),
    ("chdir", 80),
    ("fchdir", 81),
    ("mkdir", 83),
    ("mkdirat", 258),
    ("rmdir", 84),
    ("unlink", 87),
    ("unlinkat", 263),
    ("rename", 82),
    ("renameat", 264),
    ("renameat2", 316),
    ("link", 86),
    ("linkat", 265),
    ("symlink", 88),
    ("symlinkat", 266),
    ("chmod", 90),
    ("fchmod", 91),
    ("fchmodat", 268),
    ("fchmodat2", 452),
    ("chown", 92),
    ("fchown", 93),
    ("lchown", 94),
    ("fchownat", 260),
    ("umask", 95),
    ("truncate", 76),
    ("ftruncate", 77),
    ("fallocate", 285),
    ("fsync", 74),
    ("fdatasync", 75),
    ("utime", 132),
    ("utimes", 235),
    ("futimesat", 261),
    ("utimensat", 280),
    ("flock", 73),
    ("getxattr", 191),
    ("lgetxattr", 192),
    ("fgetxattr", 193),
    ("listxattr", 194),
    ("llistxattr", 195),
    ("flistxattr", 196),
    ("setxattr", 188),
    ("lsetxattr", 189),
    ("fsetxattr", 190),
    ("removexattr", 197),
    ("lremovexattr", 198),
    ("fremovexattr", 199),
    ("brk", 12),
    ("mmap", 9),
    ("mprotect", 10),
    ("munmap", 11),
    ("mremap", 25),
    ("madvise", 28),
    ("mincore", 27),
    ("membarrier", 324),
    ("msync", 26),
    ("futex", 202),
    ("futex_waitv", 449),
    ("set_robust_list", 273),
    ("get_robust_list", 274),
    ("rseq", 334),
    ("set_tid_address", 218),
    ("sched_yield", 24),
    ("sched_getaffinity", 204),
    ("sched_getscheduler", 145),
    ("sched_getparam", 143),
    ("getcpu", 309),
    ("restart_syscall", 219),
    ("clock_gettime", 228),
    ("clock_getres", 229),
    ("clock_nanosleep", 230),
    ("gettimeofday", 96),
    ("time", 201),
    ("nanosleep", 35),
    ("poll", 7),
    ("ppoll", 271),
    ("select", 23),
    ("pselect6", 270),
    ("epoll_create", 213),
    ("epoll_ctl", 233),
    ("epoll_wait", 232),
    ("epoll_pwait", 281),
    ("epoll_pwait2", 441),
    ("eventfd", 284),
    ("timerfd_settime", 286),
    ("timerfd_gettime", 287),
    ("rt_sigaction", 13),
    ("rt_sigprocmask", 14),
    ("rt_sigpending", 127),
    ("rt_sigtimedwait", 128),
    ("rt_sigsuspend", 130),
    ("rt_sigreturn", 15),
    ("sigaltstack", 131),
    ("kill", 62),
    ("tkill", 200),
    ("tgkill", 234),
    ("rt_sigqueueinfo", 129),
    ("rt_tgsigqueueinfo", 297),
    ("signalfd", 282),
    ("alarm", 37),
    ("getitimer", 36),
    ("setitimer", 38),
    ("pause", 34),
    ("getpid", 39),
    ("getppid", 110),
    ("gettid", 186),
    ("getuid", 102),
    ("geteuid", 107),
    ("getgid", 104),
    ("getegid", 108),
    ("getresuid", 118),
    ("getresgid", 120),
    ("getgroups", 115),
    ("capget", 125),
    ("getpgid", 121),
    ("getpgrp", 111),
    ("getsid", 124),
    ("getrlimit", 97),
    ("getrusage", 98),
    ("uname", 63),
    ("sysinfo", 99),
    ("getrandom", 318),
    ("fork", 57),
    ("vfork", 58),
    ("execve", 59),
    ("execveat", 322),
    ("wait4", 61),
    ("waitid", 247),
    ("exit", 60),
    ("exit_group", 231),
    ("setpgid", 109),
    ("setsid", 112),
    ("bind", 49),
    ("listen", 50),
    ("accept", 43),
    ("connect", 42),
    ("getsockname", 51),
    ("getpeername", 52),
    ("shutdown", 48),
    ("sendto", 44),
    ("recvfrom", 45),
];

const ARM64_UNCONDITIONAL: &[(&str, u32)] = &[
    ("read", 63),
    ("write", 64),
    ("readv", 65),
    ("writev", 66),
    ("pread64", 67),
    ("pwrite64", 68),
    ("preadv", 69),
    ("pwritev", 70),
    ("preadv2", 286),
    ("pwritev2", 287),
    ("lseek", 62),
    ("close", 57),
    ("close_range", 436),
    ("dup", 23),
    ("sendfile", 71),
    ("copy_file_range", 285),
    ("splice", 76),
    ("tee", 77),
    ("vmsplice", 75),
    ("openat", 56),
    ("openat2", 437),
    ("fstat", 80),
    ("newfstatat", 79),
    ("statx", 291),
    ("statfs", 43),
    ("fstatfs", 44),
    ("faccessat", 48),
    ("faccessat2", 439),
    ("getdents64", 61),
    ("readlinkat", 78),
    ("getcwd", 17),
    ("chdir", 49),
    ("fchdir", 50),
    ("mkdirat", 34),
    ("unlinkat", 35),
    ("renameat", 38),
    ("renameat2", 276),
    ("linkat", 37),
    ("symlinkat", 36),
    ("fchmod", 52),
    ("fchmodat", 53),
    ("fchmodat2", 452),
    ("fchown", 55),
    ("fchownat", 54),
    ("umask", 166),
    ("truncate", 45),
    ("ftruncate", 46),
    ("fallocate", 47),
    ("fsync", 82),
    ("fdatasync", 83),
    ("utimensat", 88),
    ("flock", 32),
    ("getxattr", 8),
    ("lgetxattr", 9),
    ("fgetxattr", 10),
    ("listxattr", 11),
    ("llistxattr", 12),
    ("flistxattr", 13),
    ("setxattr", 5),
    ("lsetxattr", 6),
    ("fsetxattr", 7),
    ("removexattr", 14),
    ("lremovexattr", 15),
    ("fremovexattr", 16),
    ("brk", 214),
    ("mmap", 222),
    ("mprotect", 226),
    ("munmap", 215),
    ("mremap", 216),
    ("madvise", 233),
    ("mincore", 232),
    ("membarrier", 283),
    ("msync", 227),
    ("futex", 98),
    ("futex_waitv", 449),
    ("set_robust_list", 99),
    ("get_robust_list", 100),
    ("rseq", 293),
    ("set_tid_address", 96),
    ("sched_yield", 124),
    ("sched_getaffinity", 123),
    ("sched_getscheduler", 120),
    ("sched_getparam", 121),
    ("getcpu", 168),
    ("restart_syscall", 128),
    ("clock_gettime", 113),
    ("clock_getres", 114),
    ("clock_nanosleep", 115),
    ("gettimeofday", 169),
    ("nanosleep", 101),
    ("ppoll", 73),
    ("pselect6", 72),
    ("epoll_ctl", 21),
    ("epoll_pwait", 22),
    ("epoll_pwait2", 441),
    ("timerfd_settime", 86),
    ("timerfd_gettime", 87),
    ("rt_sigaction", 134),
    ("rt_sigprocmask", 135),
    ("rt_sigpending", 136),
    ("rt_sigtimedwait", 137),
    ("rt_sigsuspend", 133),
    ("rt_sigreturn", 139),
    ("sigaltstack", 132),
    ("kill", 129),
    ("tkill", 130),
    ("tgkill", 131),
    ("rt_sigqueueinfo", 138),
    ("rt_tgsigqueueinfo", 240),
    ("getitimer", 102),
    ("setitimer", 103),
    ("getpid", 172),
    ("getppid", 173),
    ("gettid", 178),
    ("getuid", 174),
    ("geteuid", 175),
    ("getgid", 176),
    ("getegid", 177),
    ("getresuid", 148),
    ("getresgid", 150),
    ("getgroups", 158),
    ("capget", 90),
    ("getpgid", 155),
    ("getsid", 156),
    ("getrlimit", 163),
    ("getrusage", 165),
    ("uname", 160),
    ("sysinfo", 179),
    ("getrandom", 278),
    ("execve", 221),
    ("execveat", 281),
    ("wait4", 260),
    ("waitid", 95),
    ("exit", 93),
    ("exit_group", 94),
    ("setpgid", 154),
    ("setsid", 157),
    ("bind", 200),
    ("listen", 201),
    ("accept", 202),
    ("connect", 203),
    ("getsockname", 204),
    ("getpeername", 205),
    ("shutdown", 210),
    ("sendto", 206),
    ("recvfrom", 207),
];

pub fn unconditional_catalogue(abi: NativeAbi) -> &'static [(&'static str, u32)] {
    match abi {
        NativeAbi::X86_64 => X64_UNCONDITIONAL,
        NativeAbi::Aarch64 => ARM64_UNCONDITIONAL,
    }
}

impl NativeAbi {
    const fn audit_arch(self) -> u32 {
        match self {
            Self::X86_64 => 0xc000_003e,
            Self::Aarch64 => 0xc000_00b7,
        }
    }

    const fn syscalls(self) -> Syscalls {
        match self {
            Self::X86_64 => Syscalls {
                socket: 41,
                socketpair: 53,
                clone: 56,
                clone3: 435,
                fcntl: 72,
                ioctl: 16,
                getsockopt: 55,
                setsockopt: 54,
                prctl: 157,
                prlimit64: 302,
                arch_prctl: Some(158),
                accept4: 288,
                pipe2: 293,
                dup3: 292,
                eventfd2: 290,
                epoll_create1: 291,
                signalfd4: 289,
                timerfd_create: 283,
            },
            Self::Aarch64 => Syscalls {
                socket: 198,
                socketpair: 199,
                clone: 220,
                clone3: 435,
                fcntl: 25,
                ioctl: 29,
                getsockopt: 209,
                setsockopt: 208,
                prctl: 167,
                prlimit64: 261,
                arch_prctl: None,
                accept4: 242,
                pipe2: 59,
                dup3: 24,
                eventfd2: 19,
                epoll_create1: 20,
                signalfd4: 74,
                timerfd_create: 85,
            },
        }
    }
}

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

fn load(offset: u32) -> sock_filter {
    instruction(BPF_LD_W_ABS, 0, 0, offset)
}

fn jump_equal(value: u32, on_equal: u8, on_other: u8) -> sock_filter {
    instruction(BPF_JMP_JEQ_K, on_equal, on_other, value)
}

fn return_action(value: u32) -> sock_filter {
    instruction(BPF_RET_K, 0, 0, value)
}

fn errno(value: i32) -> u32 {
    SECCOMP_RET_ERRNO | value as u32
}

/// Compile the reviewed closed catalogue for structural tests. This function
/// is not exposed to a native installer and cannot qualify the private profile
/// without executed target-specific tests and authenticated setup evidence.
pub fn compile_initial_closed_filter(abi: NativeAbi) -> Vec<sock_filter> {
    let numbers = abi.syscalls();
    let mut program = vec![
        load(ARCH_OFFSET),
        jump_equal(abi.audit_arch(), 1, 0),
        return_action(SECCOMP_RET_KILL_PROCESS),
        load(NR_OFFSET),
    ];
    if abi == NativeAbi::X86_64 {
        program.push(instruction(BPF_JMP_JSET_K, 0, 1, 0x4000_0000));
        program.push(return_action(SECCOMP_RET_KILL_PROCESS));
    }
    for (number, result) in [
        (numbers.clone3, errno(libc::ENOSYS)),
        (numbers.socketpair, errno(libc::EPERM)),
    ] {
        program.push(jump_equal(number, 0, 1));
        program.push(return_action(result));
    }

    let clone_checks = clone_checks();
    program.push(jump_equal(numbers.clone, 1, 0));
    program.push(instruction(
        BPF_JMP_JA,
        0,
        0,
        u32::try_from(clone_checks.len()).expect("fixed clone rule block fits"),
    ));
    program.extend(clone_checks);
    program.push(load(NR_OFFSET));

    for (number, checks) in [
        (numbers.fcntl, fcntl_checks()),
        (numbers.ioctl, ioctl_checks()),
        (numbers.getsockopt, socket_option_checks(true)),
        (numbers.setsockopt, socket_option_checks(false)),
        (numbers.prctl, prctl_checks()),
        (numbers.prlimit64, first_argument_zero_checks()),
        (
            numbers.accept4,
            scalar_flags_checks(
                ARG3_LOW,
                ARG3_HIGH,
                (libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32,
            ),
        ),
        (
            numbers.pipe2,
            scalar_flags_checks(
                ARG1_LOW,
                ARG1_HIGH,
                (libc::O_CLOEXEC | libc::O_NONBLOCK) as u32,
            ),
        ),
        (
            numbers.dup3,
            scalar_flags_checks(ARG2_LOW, ARG2_HIGH, libc::O_CLOEXEC as u32),
        ),
        (
            numbers.eventfd2,
            scalar_flags_checks(
                ARG1_LOW,
                ARG1_HIGH,
                (libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) as u32,
            ),
        ),
        (
            numbers.epoll_create1,
            scalar_flags_checks(ARG0_LOW, ARG0_HIGH, libc::EPOLL_CLOEXEC as u32),
        ),
        (
            numbers.signalfd4,
            scalar_flags_checks(
                ARG3_LOW,
                ARG3_HIGH,
                (libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) as u32,
            ),
        ),
        (
            numbers.timerfd_create,
            scalar_flags_checks(
                ARG1_LOW,
                ARG1_HIGH,
                (libc::TFD_CLOEXEC | libc::TFD_NONBLOCK) as u32,
            ),
        ),
    ] {
        program.push(jump_equal(number, 1, 0));
        program.push(instruction(
            BPF_JMP_JA,
            0,
            0,
            u32::try_from(checks.len()).expect("fixed scalar rule block fits"),
        ));
        program.extend(checks);
        program.push(load(NR_OFFSET));
    }
    if let Some(number) = numbers.arch_prctl {
        let checks = arch_prctl_checks();
        program.push(jump_equal(number, 1, 0));
        program.push(instruction(
            BPF_JMP_JA,
            0,
            0,
            u32::try_from(checks.len()).expect("fixed arch_prctl rule block fits"),
        ));
        program.extend(checks);
        program.push(load(NR_OFFSET));
    }

    let socket_checks = socket_checks();
    program.push(jump_equal(numbers.socket, 1, 0));
    program.push(instruction(
        BPF_JMP_JA,
        0,
        0,
        u32::try_from(socket_checks.len()).expect("fixed socket rule block fits"),
    ));
    program.extend(socket_checks);
    program.push(load(NR_OFFSET));
    for (_, number) in unconditional_catalogue(abi) {
        program.push(jump_equal(*number, 0, 1));
        program.push(return_action(SECCOMP_RET_ALLOW));
    }
    program.push(return_action(errno(libc::EPERM)));
    validate_program(&program).expect("fixed initial filter must have valid forward jumps");
    program
}

pub fn validate_program(program: &[sock_filter]) -> Result<(), &'static str> {
    if program.is_empty() || program.len() > KERNEL_FILTER_INSTRUCTION_LIMIT {
        return Err("invalid cBPF instruction count");
    }
    for (position, instruction) in program.iter().enumerate() {
        let check_target = |delta: usize| {
            position
                .checked_add(1)
                .and_then(|next| next.checked_add(delta))
                .filter(|target| *target < program.len())
                .ok_or("cBPF jump escapes instruction array")
        };
        match instruction.code {
            BPF_RET_K => {}
            BPF_LD_W_ABS | BPF_ALU_AND_K => {
                check_target(0)?;
            }
            BPF_JMP_JEQ_K | BPF_JMP_JSET_K => {
                check_target(usize::from(instruction.jt))?;
                check_target(usize::from(instruction.jf))?;
            }
            BPF_JMP_JA => {
                check_target(
                    usize::try_from(instruction.k).map_err(|_| "cBPF jump offset overflow")?,
                )?;
            }
            _ => return Err("unknown cBPF instruction"),
        }
    }
    Ok(())
}

/// Hash the exact instruction words in native little-endian cBPF layout for
/// the two supported GNU ABIs. This is an artifact input, not qualification.
pub fn filter_instruction_digest(program: &[sock_filter]) -> Result<[u8; 32], &'static str> {
    validate_program(program)?;
    let mut digest = Sha256::new();
    for instruction in program {
        digest.update(instruction.code.to_le_bytes());
        digest.update([instruction.jt, instruction.jf]);
        digest.update(instruction.k.to_le_bytes());
    }
    Ok(digest.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledFilterProof {
    pub abi: NativeAbi,
    pub instruction_digest: [u8; 32],
    pub instruction_count: u16,
}

/// This native operation is only for the trusted, single-threaded gated target
/// stub after exact identity/descriptor checks and before release. It is not
/// called by the disabled private path yet. The successful seccomp result binds
/// the compiled instruction bytes; `PR_GET_SECCOMP` alone cannot identify the
/// installed program.
pub fn install_gated_private_filter(
    abi: NativeAbi,
    expected_digest: [u8; 32],
) -> Result<InstalledFilterProof, String> {
    let native_abi = native_abi()?;
    if abi != native_abi {
        return Err("MCSEALED-PRIVATE-FILTER: requested ABI is not native".into());
    }
    let mut program = compile_initial_closed_filter(abi);
    let digest = filter_instruction_digest(&program)
        .map_err(|reason| format!("MCSEALED-PRIVATE-FILTER: invalid program: {reason}"))?;
    if digest != expected_digest {
        return Err("MCSEALED-PRIVATE-FILTER: expected instruction digest mismatch".into());
    }
    require_single_threaded_stub()?;
    let length = u16::try_from(program.len())
        .map_err(|_| "MCSEALED-PRIVATE-FILTER: program length overflow")?;
    // SAFETY: PR_GET_NO_NEW_PRIVS takes only scalar arguments.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err("MCSEALED-PRIVATE-FILTER: target no_new_privs is not set".into());
    }
    let mut native_program = libc::sock_fprog {
        len: length,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: the validated instruction vector and sock_fprog remain live
    // across this call; NNP was checked immediately before attachment. TSYNC
    // prevents a concurrent-thread race from leaving an unfiltered sibling.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &raw mut native_program,
        )
    };
    if result == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-FILTER: native install: {}",
            std::io::Error::last_os_error()
        ));
    }
    if result != 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-FILTER: thread synchronization rejected {result}"
        ));
    }
    // SAFETY: both readbacks take only scalar arguments and are allowed by
    // the filter's exact prctl command rule.
    if unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }
        != i32::try_from(libc::SECCOMP_MODE_FILTER).expect("filter mode fits i32")
        || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
    {
        return Err("MCSEALED-PRIVATE-FILTER: native readback mismatch".into());
    }
    Ok(InstalledFilterProof {
        abi,
        instruction_digest: digest,
        instruction_count: length,
    })
}

fn require_single_threaded_stub() -> Result<(), String> {
    let tasks = std::fs::read_dir("/proc/self/task")
        .map_err(|error| format!("MCSEALED-PRIVATE-FILTER: task inventory: {error}"))?;
    let mut count = 0_u8;
    for task in tasks {
        task.map_err(|error| format!("MCSEALED-PRIVATE-FILTER: task inventory: {error}"))?;
        count = count.saturating_add(1);
        if count > 1 {
            return Err("MCSEALED-PRIVATE-FILTER: setup stub is multithreaded".into());
        }
    }
    if count != 1 {
        return Err("MCSEALED-PRIVATE-FILTER: setup stub task is absent".into());
    }
    Ok(())
}

fn native_abi() -> Result<NativeAbi, String> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(NativeAbi::X86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(NativeAbi::Aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err("MCSEALED-PRIVATE-FILTER: unsupported native architecture".into())
    }
}

fn socket_checks() -> Vec<sock_filter> {
    let family_error = errno(libc::EAFNOSUPPORT);
    let protocol_error = errno(libc::EPROTONOSUPPORT);
    let socket_flags = (libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u32;
    vec![
        load(ARG0_HIGH),
        jump_equal(0, 1, 0),
        return_action(family_error),
        load(ARG0_LOW),
        jump_equal(libc::AF_INET as u32, 1, 0),
        return_action(family_error),
        load(ARG1_HIGH),
        jump_equal(0, 1, 0),
        return_action(protocol_error),
        load(ARG1_LOW),
        instruction(BPF_JMP_JSET_K, 0, 1, !socket_flags),
        return_action(protocol_error),
        instruction(BPF_ALU_AND_K, 0, 0, 0xf),
        jump_equal(libc::SOCK_STREAM as u32, 1, 0),
        return_action(protocol_error),
        load(ARG2_HIGH),
        jump_equal(0, 1, 0),
        return_action(protocol_error),
        load(ARG2_LOW),
        jump_equal(0, 2, 0),
        jump_equal(libc::IPPROTO_TCP as u32, 1, 0),
        return_action(protocol_error),
        return_action(SECCOMP_RET_ALLOW),
    ]
}

fn clone_checks() -> Vec<sock_filter> {
    let allowed_flags = (libc::CLONE_VM
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SIGHAND
        | libc::CLONE_THREAD
        | libc::CLONE_SYSVSEM
        | libc::CLONE_SETTLS
        | libc::CLONE_PARENT_SETTID
        | libc::CLONE_CHILD_SETTID
        | libc::CLONE_CHILD_CLEARTID
        | libc::CLONE_VFORK) as u32;
    let required_thread_flags = (libc::CLONE_VM | libc::CLONE_SIGHAND) as u32;
    let denied = errno(libc::EPERM);
    vec![
        load(ARG0_HIGH),
        jump_equal(0, 1, 0),
        return_action(denied),
        load(ARG0_LOW),
        instruction(BPF_JMP_JSET_K, 0, 1, !(allowed_flags | 0xff)),
        return_action(denied),
        load(ARG0_LOW),
        instruction(BPF_ALU_AND_K, 0, 0, 0xff),
        jump_equal(0, 2, 0),
        jump_equal(libc::SIGCHLD as u32, 1, 0),
        return_action(denied),
        load(ARG0_LOW),
        instruction(BPF_JMP_JSET_K, 0, 8, libc::CLONE_THREAD as u32),
        load(ARG0_LOW),
        instruction(BPF_ALU_AND_K, 0, 0, required_thread_flags),
        jump_equal(required_thread_flags, 1, 0),
        return_action(denied),
        load(ARG0_LOW),
        instruction(BPF_ALU_AND_K, 0, 0, 0xff),
        jump_equal(0, 1, 0),
        return_action(denied),
        return_action(SECCOMP_RET_ALLOW),
    ]
}

fn fcntl_checks() -> Vec<sock_filter> {
    let denied = errno(libc::EPERM);
    let mut checks = vec![
        load(ARG1_HIGH),
        jump_equal(0, 1, 0),
        return_action(denied),
        load(ARG1_LOW),
    ];
    for command in [
        libc::F_GETFD,
        libc::F_GETFL,
        libc::F_DUPFD,
        libc::F_DUPFD_CLOEXEC,
        libc::F_GETLK,
        libc::F_SETLK,
        libc::F_SETLKW,
        libc::F_OFD_GETLK,
        libc::F_OFD_SETLK,
        libc::F_OFD_SETLKW,
    ] {
        checks.push(jump_equal(command as u32, 0, 1));
        checks.push(return_action(SECCOMP_RET_ALLOW));
    }
    for (command, allowed_argument_bits) in [
        (libc::F_SETFD, libc::FD_CLOEXEC as u32),
        (
            libc::F_SETFL,
            (libc::O_ACCMODE | libc::O_APPEND | libc::O_NONBLOCK | libc::O_LARGEFILE) as u32,
        ),
    ] {
        let argument_checks = [
            load(ARG2_HIGH),
            jump_equal(0, 1, 0),
            return_action(denied),
            load(ARG2_LOW),
            instruction(BPF_JMP_JSET_K, 0, 1, !allowed_argument_bits),
            return_action(denied),
            return_action(SECCOMP_RET_ALLOW),
        ];
        checks.push(jump_equal(command as u32, 1, 0));
        checks.push(instruction(
            BPF_JMP_JA,
            0,
            0,
            u32::try_from(argument_checks.len()).expect("fixed fcntl argument block fits"),
        ));
        checks.extend(argument_checks);
        checks.push(load(ARG1_LOW));
    }
    checks.push(return_action(denied));
    checks
}

fn ioctl_checks() -> Vec<sock_filter> {
    let denied = errno(libc::EPERM);
    let mut checks = vec![
        load(ARG1_HIGH),
        jump_equal(0, 1, 0),
        return_action(denied),
        load(ARG1_LOW),
    ];
    for command in [
        libc::FIONBIO,
        libc::FIONREAD,
        libc::TCGETS,
        libc::TIOCGWINSZ,
    ] {
        checks.push(jump_equal(command as u32, 0, 1));
        checks.push(return_action(SECCOMP_RET_ALLOW));
    }
    checks.push(return_action(denied));
    checks
}

fn socket_option_checks(read: bool) -> Vec<sock_filter> {
    let denied = errno(libc::EPERM);
    let mut socket_options = vec![
        libc::SO_REUSEADDR,
        libc::SO_KEEPALIVE,
        libc::SO_RCVBUF,
        libc::SO_SNDBUF,
        libc::SO_RCVTIMEO,
        libc::SO_SNDTIMEO,
        libc::SO_LINGER,
    ];
    if read {
        socket_options.extend([
            libc::SO_ERROR,
            libc::SO_TYPE,
            libc::SO_DOMAIN,
            libc::SO_PROTOCOL,
            libc::SO_ACCEPTCONN,
        ]);
    }
    let tcp_options = [
        libc::TCP_NODELAY,
        libc::TCP_KEEPIDLE,
        libc::TCP_KEEPINTVL,
        libc::TCP_KEEPCNT,
    ];
    let mut checks = vec![
        load(ARG1_HIGH),
        jump_equal(0, 1, 0),
        return_action(denied),
        load(ARG2_HIGH),
        jump_equal(0, 1, 0),
        return_action(denied),
        load(ARG1_LOW),
    ];
    for (level, options) in [
        (libc::SOL_SOCKET, socket_options.as_slice()),
        (libc::IPPROTO_TCP, tcp_options.as_slice()),
    ] {
        let mut options_checks = vec![load(ARG2_LOW)];
        for option in options {
            options_checks.push(jump_equal(*option as u32, 0, 1));
            options_checks.push(return_action(SECCOMP_RET_ALLOW));
        }
        options_checks.push(return_action(denied));
        checks.push(jump_equal(level as u32, 1, 0));
        checks.push(instruction(
            BPF_JMP_JA,
            0,
            0,
            u32::try_from(options_checks.len()).expect("fixed socket option block fits"),
        ));
        checks.extend(options_checks);
        checks.push(load(ARG1_LOW));
    }
    checks.push(return_action(denied));
    checks
}

fn first_argument_zero_checks() -> Vec<sock_filter> {
    let denied = errno(libc::EPERM);
    vec![
        load(ARG0_HIGH),
        jump_equal(0, 1, 0),
        return_action(denied),
        load(ARG0_LOW),
        jump_equal(0, 1, 0),
        return_action(denied),
        return_action(SECCOMP_RET_ALLOW),
    ]
}

fn first_argument_command_checks(commands: &[u32]) -> Vec<sock_filter> {
    let denied = errno(libc::EPERM);
    let mut checks = vec![
        load(ARG0_HIGH),
        jump_equal(0, 1, 0),
        return_action(denied),
        load(ARG0_LOW),
    ];
    for command in commands {
        checks.push(jump_equal(*command, 0, 1));
        checks.push(return_action(SECCOMP_RET_ALLOW));
    }
    checks.push(return_action(denied));
    checks
}

fn prctl_checks() -> Vec<sock_filter> {
    first_argument_command_checks(&[
        libc::PR_GET_NO_NEW_PRIVS as u32,
        libc::PR_GET_DUMPABLE as u32,
        libc::PR_GET_NAME as u32,
        libc::PR_SET_NAME as u32,
        libc::PR_GET_SECCOMP as u32,
        libc::PR_GET_TIMERSLACK as u32,
    ])
}

fn arch_prctl_checks() -> Vec<sock_filter> {
    // Linux x86 UAPI asm/prctl.h; there is no corresponding ARM64 allowance.
    const ARCH_SET_FS: u32 = 0x1002;
    const ARCH_GET_FS: u32 = 0x1003;
    first_argument_command_checks(&[ARCH_SET_FS, ARCH_GET_FS])
}

fn scalar_flags_checks(low_offset: u32, high_offset: u32, allowed_bits: u32) -> Vec<sock_filter> {
    let denied = errno(libc::EPERM);
    vec![
        load(high_offset),
        jump_equal(0, 1, 0),
        return_action(denied),
        load(low_offset),
        instruction(BPF_JMP_JSET_K, 0, 1, !allowed_bits),
        return_action(denied),
        return_action(SECCOMP_RET_ALLOW),
    ]
}
