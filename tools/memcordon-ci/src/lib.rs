#![forbid(unsafe_code)]

pub mod capability;
pub mod command;
pub mod config;
pub mod line_evidence;
pub mod policy;
pub mod release_archive;
pub mod release_evidence;
pub mod runtime_manifest;
pub mod scenario_diagnostic;
pub mod sealed_identity;
pub mod sealed_selector;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CiError {
    #[error("{0}")]
    Message(String),
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML operation failed: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("YAML operation failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Cargo metadata failed: {0}")]
    Metadata(#[from] cargo_metadata::Error),
    #[error("semantic version is invalid: {0}")]
    Semver(#[from] semver::Error),
    #[error("HTTP operation failed: {0}")]
    Http(#[from] Box<ureq::Error>),
    #[error("process operation failed: {0}")]
    Process(#[from] memcordon_testkit::ProcessTestError),
    #[error("ZIP operation failed: {0}")]
    Zip(#[from] zip::result::ZipError),
}

pub type Result<T> = std::result::Result<T, CiError>;
