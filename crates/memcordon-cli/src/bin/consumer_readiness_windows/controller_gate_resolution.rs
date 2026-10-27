//! Limited named-open observations, never synchronization or fixture identity proof.
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Context {
    Controller,
    FailedFixture,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub context: Context,
    pub diagnostic_only: bool,
    pub desired_access: u32,
    pub attempted: bool,
    pub open_succeeded: Option<bool>,
    pub raw_os_error: Option<i32>,
    pub same_original_event: Option<bool>,
    pub original_work_live: bool,
    pub unavailable: Option<&'static str>,
    pub interpretation: &'static str,
}

impl Observation {
    pub fn unavailable(context: Context, reason: &'static str) -> Self {
        Self {
            context,
            diagnostic_only: true,
            desired_access: match context {
                Context::Controller => 0x0010_0000,
                Context::FailedFixture => 0,
            },
            attempted: false,
            open_succeeded: None,
            raw_os_error: None,
            same_original_event: None,
            original_work_live: false,
            unavailable: Some(reason),
            interpretation: match context {
                Context::Controller => {
                    "controller-context only; equality does not prove fixture resolution"
                }
                Context::FailedFixture => {
                    "zero-rights reference only; original identity and synchronization unproved"
                }
            },
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // One diagnostic open and optional same-process original-handle comparison.
pub fn query(
    terminated_name: &[u16],
    original: Option<&std::os::windows::io::OwnedHandle>,
    live: impl Fn() -> std::io::Result<()>,
) -> Observation {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{Foundation::CompareObjectHandles, System::Threading::OpenEventW};
    let context = if original.is_some() {
        Context::Controller
    } else {
        Context::FailedFixture
    };
    let mut observation =
        Observation::unavailable(context, "original-bound-clock-or-name-unavailable");
    let Some(name) = terminated_name.strip_suffix(&[0]) else {
        return observation;
    };
    if name.is_empty()
        || name.contains(&0)
        || terminated_name
            .len()
            .checked_mul(size_of::<u16>())
            .is_none_or(|bytes| bytes > 64 * 1024)
        || live().is_err()
    {
        return observation;
    }
    observation.attempted = true;
    let raw = unsafe { OpenEventW(observation.desired_access, 0, terminated_name.as_ptr()) };
    let error = if raw.is_null() {
        Some(std::io::Error::last_os_error().raw_os_error())
    } else {
        None
    };
    // Adopt before the next clock check or comparison, including expired/error routes.
    let owned = if raw.is_null() {
        None
    } else {
        Some(unsafe { OwnedHandle::from_raw_handle(raw.cast()) })
    };
    observation.open_succeeded = Some(owned.is_some());
    observation.raw_os_error = error.flatten();
    observation.unavailable = None;
    if live().is_err() {
        observation.unavailable = Some("original-bound-clock-refused-after-open");
        return observation;
    }
    if let (Some(original), Some(reopened)) = (original, owned.as_ref()) {
        observation.same_original_event = Some(
            unsafe { CompareObjectHandles(original.as_raw_handle(), reopened.as_raw_handle()) }
                != 0,
        );
        if live().is_err() {
            observation.unavailable = Some("original-bound-clock-refused-after-comparison");
            return observation;
        }
    }
    observation.original_work_live = true;
    observation
}
