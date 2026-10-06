// Unsafe Windows calls are confined to file identity and owned-guardian adapters.
// All other CI orchestration remains safe Rust.
#![deny(unsafe_code)]

pub mod bootstrap_profile;
pub mod cache;
pub mod capability;
pub mod command;
pub mod config;
pub mod fuzz_targets;
pub mod line_evidence;
pub mod miri_targets;
pub mod native_channel;
pub mod native_results;
pub mod native_test_plan;
pub mod policy;
pub mod preparation;
pub mod public_reads;
pub mod rehearsal_support;
pub mod release;
pub mod reparse_diagnostic;
pub mod runtime_manifest;
pub mod scenario_diagnostic;
pub mod sealed_identity;
pub mod sealed_selector;
pub mod standard_contract;
pub mod standard_runner;
pub mod stress;
pub mod target_shard;
pub mod windows_causal_acceptance;
pub mod windows_channel_identity;
pub mod windows_execution_acceptance;
pub mod windows_installed_cases;
pub mod windows_owned_guardian;
pub mod windows_package_cleanup;
pub mod windows_package_staging;
pub mod workflow_output;
pub mod workflow_scope;

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
    #[error("GitHub {method} {endpoint} failed: {source}{details}")]
    GithubHttp {
        method: String,
        endpoint: String,
        source: Box<CiError>,
        details: String,
        retry_after: Option<std::time::Duration>,
    },
    #[error("process operation failed: {0}")]
    Process(#[from] memcordon_testkit::ProcessTestError),
    #[error("ZIP operation failed: {0}")]
    Zip(#[from] zip::result::ZipError),
}

pub type Result<T> = std::result::Result<T, CiError>;
pub mod arm32_abi_helper;
pub mod exact_harness;
pub mod external_consumer;
pub mod macos_performance;
pub mod native_acceptance_catalogue;
pub mod performance_plan;
