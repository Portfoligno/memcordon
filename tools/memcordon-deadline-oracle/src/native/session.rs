use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub(super) const SESSION_EXEC_MODE: &str = "--session-exec";
pub(super) const CONFIRMED_SESSION_EXEC_MODE: &str = "--session-exec-confirmed";

pub(super) fn exec_in_new_session(arguments: &[OsString]) -> super::Result<()> {
    exec_session(arguments, false)
}

pub(super) fn exec_confirmed_session(arguments: &[OsString]) -> super::Result<()> {
    exec_session(arguments, true)
}

fn exec_session(arguments: &[OsString], confirmed: bool) -> super::Result<()> {
    let (executable, arguments) = arguments
        .split_first()
        .ok_or("session launcher requires an executable")?;
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // Preserve the native scope until the parent confirms it, even for a
    // zero-budget frontend. Product timing still starts after exec.
    if confirmed && unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Err(Command::new(executable).args(arguments).exec().into())
}
