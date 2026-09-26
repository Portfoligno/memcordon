#![forbid(unsafe_code)]

pub mod build_context;
pub mod capability;
pub mod certification_context;
pub mod command;
pub mod config;
pub mod fuzz_targets;
pub mod inventory_benchmark;
pub mod inventory_pipeline;
pub mod inventory_profile;
pub mod inventory_progress;
pub mod inventory_reader;
pub mod inventory_workers;
pub mod line_evidence;
pub mod managed_workflow;
pub mod miri_targets;
pub mod native_file_digest;
pub mod native_profile;
pub mod native_test_plan;
pub mod policy;
pub(crate) mod private_abi_composite;
pub(crate) mod private_abi_raw_readback;
pub mod private_actions_readback;
pub mod private_agent_path;
pub(crate) mod private_archive_certificate;
pub mod private_candidate_abi_facts;
pub mod private_candidate_c_v3;
pub(crate) mod private_candidate_caller_facts;
pub(crate) mod private_candidate_caller_frames;
pub(crate) mod private_candidate_causal_facts;
pub(crate) mod private_candidate_facility_live;
pub mod private_candidate_facility_replay;
pub mod private_candidate_filter_facility_facts;
pub mod private_candidate_host_facts;
pub(crate) mod private_candidate_network_facts;
pub mod private_candidate_producer;
pub mod private_candidate_replay;
pub mod private_candidate_reuse_facts;
pub(crate) mod private_candidate_reuse_live;
pub mod private_candidate_unix_facts;
pub mod private_case_semantics;
pub mod private_child_live;
pub mod private_completed_run;
pub mod private_dual_live;
pub mod private_final_install;
pub mod private_host_state;
pub mod private_installed_h0;
pub(crate) mod private_kernel_observer;
pub(crate) mod private_kernel_replay;
pub(crate) mod private_live_fact_recording;
pub mod private_native;
pub mod private_native_verify;
pub mod private_observer_session;
pub(crate) mod private_origin_replay;
pub(crate) mod private_policy_intervals;
mod private_policy_provision;
pub(crate) mod private_policy_request_join;
pub(crate) mod private_policy_semantics;
pub(crate) mod private_probe_bundle;
pub(crate) mod private_probe_controls;
pub(crate) mod private_process_clock;
pub mod private_protected_readback;
pub mod private_public_abi_filtered;
pub(crate) mod private_public_abi_live;
pub mod private_public_abi_outer;
pub(crate) mod private_public_caller_replay;
pub mod private_public_case_readback;
pub mod private_public_completion;
pub mod private_public_dispatch;
pub(crate) mod private_public_driver;
pub mod private_public_epoch_join;
pub(crate) mod private_public_fault;
pub(crate) mod private_public_fault_dual_replay;
mod private_public_kernel_join;
pub mod private_public_live;
pub(crate) mod private_public_ordinary_replay;
pub mod private_public_plan;
pub(crate) mod private_public_policy_live;
pub(crate) mod private_public_policy_replay;
pub mod private_public_preparation;
pub(crate) mod private_public_producer;
pub mod private_public_raw;
pub mod private_public_reuse_join;
pub(crate) mod private_public_reuse_live;
pub mod private_public_source_facts;
pub(crate) mod private_public_specialist_replay;
pub mod private_public_v2;
pub mod private_public_verify;
pub mod private_release_gate;
pub mod private_socket_live;
pub mod private_source_carrier;
pub mod private_suite;
pub mod private_supervisor;
pub mod private_terminal_live;
pub mod private_unix_live;
pub mod producer_metadata;
pub mod release_archive;
pub mod release_evidence;
pub mod release_private;
pub mod reparse_diagnostic;
pub mod runtime_manifest;
pub mod scenario_diagnostic;
pub mod sealed_identity;
pub mod sealed_selector;
pub mod standard_contract;
pub mod standard_runner;
pub mod windows_causal_acceptance;
pub mod windows_channel_identity;
pub mod windows_package_cleanup;
pub mod windows_package_staging;
pub mod windows_qualification_artifacts;
pub mod workload_qualification;

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
