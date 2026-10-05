use super::*;
use std::os::unix::process::CommandExt;

fn observe_natural_exit(child: &Child, deadline: Instant) -> Result<(), String> {
    loop {
        if let Some(status) = child.observe().map_err(|error| error.to_string())? {
            if !status.success() {
                return Err(format!("inspector did not exit naturally: {status}"));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("inspector EOF exit exceeded its original retirement reserve".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

pub fn inspector_eof_retirement(image: &Path) -> Result<(), String> {
    let runtime = LaunchRuntime::new(2).map_err(|error| error.to_string())?;
    let lane = InventoryLane::start_in(&runtime, image, 1, Instant::now() + STARTUP)
        .map_err(|error| format!("create real inspector: {error}"))?;
    let retirement_deadline = Instant::now() + crate::macos_watchdog::CLEANUP_DEADLINE;
    lane.stream
        .shutdown(std::net::Shutdown::Both)
        .map_err(|error| error.to_string())?;
    // WNOWAIT observes genuine EOF exit without consuming the native identity.
    observe_natural_exit(&lane.child, retirement_deadline)?;
    drop(lane);
    if !runtime.settled_until(retirement_deadline) {
        return Err(format!(
            "actual inspector drop did not settle: {:#?}",
            runtime.startup_cleanup_observation(true, true)
        ));
    }
    if Instant::now() > retirement_deadline || runtime.outstanding() != 0 {
        return Err("inspector retirement missed its original reserve".into());
    }

    // A general process-group ticket must still charge a genuine signalling
    // error. Exact-PID inspector cancellation must not suppress group errors.
    let group_runtime = LaunchRuntime::new(1).map_err(|error| error.to_string())?;
    let ticket = group_runtime.reserve().map_err(|error| error.to_string())?;
    ticket.begin().map_err(|error| error.to_string())?;
    let deadline = Instant::now() + crate::macos_watchdog::CLEANUP_DEADLINE;
    let mut command = std::process::Command::new("/usr/bin/true");
    command.process_group(0);
    let child = command.spawn().map_err(|error| error.to_string())?;
    let pid = child.id() as i32;
    ticket.publish(pid);
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        if unsafe {
            libc::waitid(
                libc::P_PID,
                pid as _,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err(format!(
                "observe group child: {}",
                io::Error::last_os_error()
            ));
        }
        let info = unsafe { info.assume_init() };
        if info.si_pid == pid {
            if info.si_code != libc::CLD_EXITED {
                return Err("group child was not a natural exit".into());
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err("group child exceeded its original reserve".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(ticket);
    loop {
        let snapshot = group_runtime.startup_cleanup_observation(true, false);
        let value = serde_json::to_value(&snapshot).map_err(|error| error.to_string())?;
        if value["slots"][0]["state_after"] == "OwnershipLost" && value["slots"][0]["pid"] == 0 {
            if value["slots"][0]["cleanup_errno"] != libc::EPERM || group_runtime.outstanding() != 1
            {
                return Err(format!(
                    "group signalling error was not retained: {snapshot:#?}"
                ));
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "group control did not actually reap while retaining its error: {snapshot:#?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(child);
    Ok(())
}
