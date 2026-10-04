//! An authenticated cancellation request is distinct from native frontend death.
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateCancellation {
    Controlled,
    FrontendLost,
}

/// Observe the original held frontend only after its exchange requests cancel.
/// Closing the exchange does not itself prove that the frontend process died.
pub fn observe_cancellation(
    stream: &UnixStream,
    mut frontend_exited: impl FnMut() -> Result<bool, String>,
) -> Result<Option<PrivateCancellation>, String> {
    if !cancellation_requested(stream)? {
        return Ok(None);
    }
    Ok(Some(if frontend_exited()? {
        PrivateCancellation::FrontendLost
    } else {
        PrivateCancellation::Controlled
    }))
}

/// Only the authenticated exchange's cancellation byte or EOF requests cancel.
/// Neither event asserts cleanup or process death.
pub fn cancellation_requested(stream: &UnixStream) -> Result<bool, String> {
    let mut byte = [0_u8];
    // SAFETY: the held stream and writable byte are live; peek does not consume
    // the sole allowed follow-up input or extend the original exchange.
    let count = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            byte.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if count == 0 {
        return Ok(true);
    }
    if count < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Ok(false);
        }
        return Err(error.to_string());
    }
    if byte != [1] {
        return Err("MCSEALED-PRIVATE-CANCEL: invalid exchange byte".into());
    }
    Ok(true)
}
