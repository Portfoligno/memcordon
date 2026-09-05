pub mod control_service;
pub mod guardian;
pub mod guardian_service;
pub mod job;
pub mod launcher_service;
pub(crate) mod loader_access;
pub mod package;
pub mod pipe;
pub mod process;
mod process_impl;
pub mod qualification;
pub mod record;
pub mod security;
pub mod service;
pub mod service_manager;
pub mod session_broker;
mod settlement;
pub mod token;
pub mod user_api;

pub fn control() -> Result<(), String> {
    control_service::run()
}

pub fn launcher() -> Result<(), String> {
    launcher_service::run()
}

pub fn guardian_service(slot: &std::ffi::OsString) -> Result<(), String> {
    guardian_service::run(slot)
}

pub fn guardian(arguments: &[std::ffi::OsString]) -> Result<(), guardian::GuardianFailure> {
    guardian::run(arguments)
}

pub fn target_desktop_holder(
    pipe_name: &std::ffi::OsStr,
    nonce: &std::ffi::OsStr,
) -> Result<(), String> {
    process::target_desktop_bootstrap(
        pipe_name,
        nonce,
        process::TargetDesktopBootstrapRole::Holder,
        None,
    )
}

pub fn target_desktop_loader_control(
    pipe_name: &std::ffi::OsStr,
    nonce: &std::ffi::OsStr,
    desktop: &std::ffi::OsStr,
) -> Result<(), String> {
    process::target_desktop_bootstrap(
        pipe_name,
        nonce,
        process::TargetDesktopBootstrapRole::LoaderControl,
        Some(desktop),
    )
}

pub fn target_desktop_probe(
    pipe_name: &std::ffi::OsStr,
    nonce: &std::ffi::OsStr,
    desktop: &std::ffi::OsStr,
) -> Result<(), String> {
    process::target_desktop_bootstrap(
        pipe_name,
        nonce,
        process::TargetDesktopBootstrapRole::Probe,
        Some(desktop),
    )
}

pub const fn target_desktop_bootstrap_failure_status() -> i32 {
    process::target_desktop_bootstrap_failure_status()
}
