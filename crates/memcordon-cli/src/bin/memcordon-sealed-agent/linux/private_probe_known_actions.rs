//! Fixed probe-coverage control, run only from the installed B-bound agent.
//! Its child exit reports are diagnostic; CI must join actual BPF seccomp
//! ALLOW, ERRNO and KILL decisions from the pinned kernel probe bundle.

use super::network_filter::{
    NativeAbi, compile_initial_closed_filter, filter_instruction_digest,
    install_gated_private_filter,
};

fn native_abi() -> NativeAbi {
    #[cfg(target_arch = "x86_64")]
    {
        NativeAbi::X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        NativeAbi::Aarch64
    }
}

fn filtered_child(kill: bool, digest: [u8; 32]) -> i32 {
    // SAFETY: child owns a single thread and these arguments are scalars.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || install_gated_private_filter(native_abi(), digest).is_err()
    {
        return 121;
    }
    if kill {
        #[cfg(target_arch = "x86_64")]
        {
            // The reviewed filter kills the x32-numbered native entry.
            unsafe { libc::syscall(libc::SYS_getpid | 0x4000_0000) };
        }
        #[cfg(target_arch = "aarch64")]
        {
            // The B-inventoried AArch32 helper issues a compat syscall.
            // A kernel without compat execution fails this control closed.
            let image = b"/usr/libexec/memcordon-arm32-abi-helper\0";
            let name = b"memcordon-arm32-abi-helper\0";
            let argv = [name.as_ptr().cast(), std::ptr::null()];
            let envp = [std::ptr::null()];
            unsafe { libc::execve(image.as_ptr().cast(), argv.as_ptr(), envp.as_ptr()) };
        }
        return 122;
    }
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    let mut sockets = [-1_i32; 2];
    let denied =
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()) };
    if denied == 0 {
        unsafe {
            libc::close(sockets[0]);
            libc::close(sockets[1]);
        }
    }
    if pid <= 0
        || denied != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
    {
        return 123;
    }
    0
}

fn fork_control(kill: bool, digest: [u8; 32]) -> Result<u32, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE-CONTROL: fork: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        let code = filtered_child(kill, digest);
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &raw mut status, 0) } != pid {
        return Err("MCSEALED-PRIVATE-PROBE-CONTROL: child wait differs".into());
    }
    if kill {
        if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGSYS {
            return Err("MCSEALED-PRIVATE-PROBE-CONTROL: kill path did not SIGSYS".into());
        }
    } else if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err("MCSEALED-PRIVATE-PROBE-CONTROL: allow/ERRNO path differs".into());
    }
    Ok(pid as u32)
}

pub(crate) fn run() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-PROBE-CONTROL: root required".into());
    }
    crate::package::verify()?;
    let abi = native_abi();
    let digest = filter_instruction_digest(&compile_initial_closed_filter(abi))
        .map_err(|error| error.to_string())?;
    super::private_observer_hooks::mc_private_request_enter_v1();
    let ordinary = fork_control(false, digest)?;
    let killed = fork_control(true, digest)?;
    super::private_observer_hooks::mc_private_request_exit_v1();
    println!("{{\"schema_version\":1,\"ordinary_pid\":{ordinary},\"killed_pid\":{killed}}}");
    Ok(())
}
