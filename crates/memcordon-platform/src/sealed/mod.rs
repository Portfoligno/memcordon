#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
mod linux_runtime;
#[cfg(target_os = "windows")]
pub mod windows;

pub(crate) fn current_profile_installed() -> bool {
    #[cfg(target_os = "linux")]
    {
        return linux_runtime::installed_current_binding().is_ok();
    }
    #[cfg(target_os = "windows")]
    {
        return windows::current_installed();
    }
    #[allow(unreachable_code)]
    false
}
