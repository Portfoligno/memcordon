//! Native CI regression on the initial thread of the actual RC fixture launcher.
use std::{
    io,
    io::Write,
    os::windows::io::{AsRawHandle, FromRawHandle},
    sync::mpsc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::ERROR_OPERATION_ABORTED,
    Storage::FileSystem::ReadFile,
    System::{Pipes::CreatePipe, Threading::GetCurrentThreadId},
};

#[derive(Debug)]
struct Failures {
    original: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; independent cleanup: {}",
            self.original, self.secondary
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
fn settled<T>(original: io::Result<T>, secondary: io::Result<()>) -> io::Result<T> {
    match (original, secondary) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(original), Err(secondary)) => Err(io::Error::new(
            original.kind(),
            Failures {
                original,
                secondary,
            },
        )),
    }
}
fn pipe() -> io::Result<(std::fs::File, std::fs::File)> {
    let (mut reader, mut writer) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: private non-inheritable pipe outputs transfer ownership once.
    if unsafe { CreatePipe(&mut reader, &mut writer, std::ptr::null(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            std::fs::File::from_raw_handle(reader),
            std::fs::File::from_raw_handle(writer),
        )
    })
}
fn byte(reader: &std::fs::File) -> io::Result<u8> {
    let (mut value, mut count) = (0_u8, 0_u32);
    // SAFETY: one writable byte, exact original private pipe; no buffered EOF conversion.
    if unsafe {
        ReadFile(
            reader.as_raw_handle(),
            &mut value,
            1,
            &mut count,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if count != 1 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "owned pipe ended before one byte",
        ));
    }
    Ok(value)
}
fn successful_io(cutoff: Instant) -> io::Result<()> {
    let (reader, mut writer) = pipe()?;
    let guard = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)
        .map_err(io::Error::other)?;
    let producer = std::thread::Builder::new()
        .name("deadline-independent-writer".into())
        .spawn(move || {
            // Keep a real subsequent I/O pending beyond the old watcher's retry interval.
            std::thread::sleep(Duration::from_millis(20));
            writer.write_all(&[0, 255, 128])
        })?;
    let read = (|| {
        for expected in [0, 255, 128] {
            if byte(&reader)? != expected {
                return Err(io::Error::other("original pipe bytes differ"));
            }
        }
        Ok(())
    })();
    let stopped = guard.finish().map_err(io::Error::other);
    drop(reader);
    let joined = producer
        .join()
        .map_err(|_| io::Error::other("owned pipe producer panicked"))
        .and_then(|result| result);
    settled(settled(read, stopped), joined)
}
fn cancellation(cutoff: Instant) -> io::Result<()> {
    let (reader, writer) = pipe()?;
    let work = (Instant::now() + Duration::from_millis(100)).min(cutoff);
    let guard =
        memcordon_platform::WindowsSynchronousIoDeadline::start(work).map_err(io::Error::other)?;
    let original = unsafe { GetCurrentThreadId() };
    let (ready, receiver) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let rescue = std::thread::Builder::new()
        .name("deadline-owned-writer-rescue".into())
        .spawn(move || {
            // This different thread never receives a pseudo thread handle.
            let _ = ready.send(unsafe { GetCurrentThreadId() });
            let _ = released.recv_timeout(cutoff.saturating_duration_since(Instant::now()));
            drop(writer); // Fixed cleanup cutoff unblocks the read even if cancellation regresses.
        })?;
    let read = match receiver.recv_timeout(cutoff.saturating_duration_since(Instant::now())) {
        Ok(other) if other != original => byte(&reader),
        Ok(_) => Err(io::Error::other(
            "rescue did not execute on a different original thread",
        )),
        Err(error) => Err(io::Error::other(error)),
    };
    let stopped = guard.finish();
    let _ = release.send(());
    drop(reader);
    let joined = rescue
        .join()
        .map_err(|_| io::Error::other("owned pipe rescue panicked"));
    let observed = match read {
        Err(error) if error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other(
            "original blocked I/O completed without cutoff cancellation",
        )),
    };
    let retirement = match stopped {
        Err(reason) if reason == "original terminal transport session cutoff expired" => Ok(()),
        Err(reason) => Err(io::Error::other(reason)),
        Ok(()) => Err(io::Error::other(
            "expired original deadline reported success",
        )),
    };
    settled(settled(observed, retirement), joined)
}
fn two_phase_io(cutoff: Instant) -> io::Result<()> {
    use super::descriptor::controller_start::{self, Binding, Phase, Receiver, Sender};
    let identity = super::native::current_identity()?;
    let binding = Binding {
        challenge: vec![0, 255, 128, b'R'],
        descriptor_sha256: controller_start::descriptor_digest(
            b"owned two-phase fixture descriptor",
        ),
        pid: identity.process_id,
        birth: identity.creation_time_100ns,
    };
    let producer_binding = binding.clone();
    let (mut reader, mut writer) = pipe()?;
    let producer = std::thread::Builder::new()
        .name("owned-control-frame-writer".into())
        .spawn(move || -> io::Result<()> {
            let mut session = Sender::joint();
            for phase in [Phase::Start, Phase::ToolchainObserverRelease] {
                let guard = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)
                    .map_err(io::Error::other)?;
                let sent = session.send(&mut writer, &producer_binding, phase, || {
                    if Instant::now() >= cutoff {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "original control test cutoff",
                        ))
                    } else {
                        Ok(())
                    }
                });
                settled(sent, guard.finish().map_err(io::Error::other))?;
            }
            drop(writer);
            Ok(())
        })?;
    let received = (|| -> io::Result<()> {
        let mut session = Receiver::joint();
        for phase in [Phase::Start, Phase::ToolchainObserverRelease] {
            let guard = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)
                .map_err(io::Error::other)?;
            let result = session.receive_phase(&mut reader, &binding, phase, || {
                if Instant::now() >= cutoff {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "original control test cutoff",
                    ))
                } else {
                    Ok(())
                }
            });
            settled(result, guard.finish().map_err(io::Error::other))?;
        }
        let guard = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)
            .map_err(io::Error::other)?;
        let eof = match byte(&reader) {
            Err(error) if error.raw_os_error() == Some(109) => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::other(
                "control session consumed or fabricated application data",
            )),
        };
        settled(eof, guard.finish().map_err(io::Error::other))
    })();
    drop(reader);
    let joined = producer
        .join()
        .map_err(|_| io::Error::other("owned control writer panicked"))
        .and_then(|result| result);
    settled(received, joined)
}
pub(super) fn run() -> io::Result<i32> {
    let cutoff = Instant::now() + Duration::from_secs(5);
    let token: super::descriptor::gate_precondition::TokenObservation =
        serde_json::from_slice(&super::native::token_observation()?).map_err(io::Error::other)?;
    if !token.restricted
        || token.restricting_sids != [super::fixture_default_dacl::RESTRICTED_CODE_SID.to_vec()]
    {
        return Err(io::Error::other(
            "deadline regression requires the actual RC-only fixture token",
        ));
    }
    let before = super::native_fixture_default_dacl::snapshot(-4_isize as _)?;
    successful_io(cutoff)?;
    cancellation(cutoff)?;
    successful_io(cutoff)?; // No previous watcher may cancel this subsequent I/O.
    two_phase_io(cutoff)?;
    let (reader, writer) = pipe()?;
    let guard = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)
        .map_err(io::Error::other)?;
    drop(writer);
    let ended = byte(&reader);
    let stopped = guard.finish().map_err(io::Error::other);
    let observed = match ended {
        Err(error) if error.raw_os_error() == Some(109) => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other("closed input fabricated a byte")),
    };
    settled(observed, stopped)?;
    let after = super::native_fixture_default_dacl::snapshot(-4_isize as _)?;
    if !after.stable_eq(&before) {
        return Err(io::Error::other(
            "deadline operations changed original token security",
        ));
    }
    Ok(0)
}
