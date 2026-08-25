pub mod control_service;
pub mod guardian;
pub mod job;
pub mod launcher_service;
pub mod package;
pub mod pipe;
pub mod process;
pub mod qualification;
pub mod record;
pub mod security;
pub mod service;
pub mod service_manager;
pub mod token;

pub fn control() -> Result<(), String> {
    control_service::run()
}

pub fn launcher() -> Result<(), String> {
    launcher_service::run()
}

pub fn guardian(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    guardian::run(arguments)
}
