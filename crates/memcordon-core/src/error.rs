use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCategory {
    Usage,
    Unsupported,
    Setup,
    Spawn,
    Monitor,
    Wait,
    Termination,
    Cleanup,
    Report,
}

#[derive(Clone, Debug, Error)]
#[error("{message} ({code})")]
pub struct Error {
    pub category: ErrorCategory,
    pub code: &'static str,
    pub message: String,
    pub backend: Option<String>,
    pub os_code: Option<i32>,
    pub target_released: bool,
    pub workload_may_be_alive: bool,
}

impl Error {
    pub fn new(category: ErrorCategory, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            category,
            code,
            message: message.into(),
            backend: None,
            os_code: None,
            target_released: false,
            workload_may_be_alive: false,
        }
    }

    pub fn with_os_error(mut self, error: &std::io::Error) -> Self {
        self.os_code = error.raw_os_error();
        self
    }
}
