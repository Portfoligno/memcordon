// Unsafe Windows calls are confined to file identity and owned-guardian adapters.
// All other CI orchestration remains safe Rust.
#![deny(unsafe_code)]

pub mod bootstrap_profile;
pub mod cache;
pub mod cache_inputs;
pub mod cache_restore;
pub mod cache_snapshot;
pub mod caller_observation;
pub mod capability;
pub mod ci_operation_time;
pub mod command;
pub mod config;
pub mod consumer_readiness_ledger;
pub mod download_cache;
pub mod driver_cache;
pub mod failure_mode;
pub mod fuzz_targets;
pub mod line_evidence;
#[cfg(target_os = "linux")]
pub mod linux_consumer_readiness;
pub mod miri_cache;
pub mod miri_targets;
pub mod native_channel;
pub mod native_results;
pub mod native_test_plan;
pub mod policy;
pub mod preparation;
pub mod preparation_tools;
pub mod public_install_capture;
pub mod public_reads;
pub mod rehearsal_support;
pub mod release;
pub mod reparse_diagnostic;
pub mod retained_build_source;
pub mod runtime_manifest;
pub mod scenario_diagnostic;
pub mod sealed_identity;
pub mod sealed_selector;
pub mod segment_cache;
pub mod standard_contract;
pub mod standard_runner;
pub mod stress;
pub mod support_loader_producer;
pub mod target_shard;
#[cfg(windows)]
pub mod windows_cache_identity;
#[cfg(windows)]
mod windows_caller_snapshot_diagnostic;
pub mod windows_causal_acceptance;
pub mod windows_channel_identity;
pub mod windows_component_failed_recovery;
pub mod windows_component_query_evidence;
pub mod windows_consumer_readiness;
pub mod windows_execution_acceptance;
pub mod windows_installed_cases;
pub mod windows_owned_guardian;
pub mod windows_package_cleanup;
pub mod windows_package_staging;
pub mod windows_policy_activation;
#[cfg(windows)]
mod windows_readiness_acl;
pub mod windows_readiness_adapter;
pub mod windows_readiness_capacity;
pub mod windows_readiness_components;
pub mod windows_readiness_faults;
pub mod windows_readiness_native_tests;
pub mod windows_readiness_refusals;
#[cfg(windows)]
mod windows_receipt_identity;
#[doc(hidden)]
pub mod work_outcome;
pub mod workflow_definitions;
pub mod workflow_output;
pub mod workflow_scope;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CiError {
    #[error("{0}")]
    CacheSafety(Box<CiError>),
    #[error("{source}")]
    OwnedWork {
        source: Box<CiError>,
        writers: work_outcome::WriterSettlement,
        facts: work_outcome::CompilationFacts,
    },
    #[error("{0}")]
    Message(String),
    #[error("subprocess cancelled by peer: {0}")]
    Cancelled(String),
    #[error("subprocess cancelled by peer after settlement: {0}")]
    SettledCancellation(String),
    #[error("{0}")]
    SettledCommandFailure(String),
    #[error("primary lane: {primary}; secondary lane: {secondary}")]
    LaneFailures {
        primary: Box<CiError>,
        secondary: Box<CiError>,
    },
    #[error("not-run-after-failure")]
    NotStartedAfterFailure,
    #[error("subprocess could not be started: {0}")]
    CommandSpawnFailure(std::io::Error),
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
pub mod mixed_collection_diagnostics;
pub mod native_acceptance_catalogue;
pub mod performance_plan;
