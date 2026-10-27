//! Observer-free Windows loader launch contracts.
//!
//! This crate deliberately contains no Windows debugging, ETW, loader-snap,
//! service-recovery, or package-rollback APIs.  Production and the standalone
//! laboratory share these typed plan and outcome boundaries.

/// Canonical plan marker for a Windows-selected default kernel-object DACL.
pub const WINDOWS_DEFAULT_SECURITY_DESCRIPTOR_V1: &str = "<windows-default-security-descriptor>";

mod artifact;
mod attributes;
mod create;
mod desktop;
mod environment;
mod evidence;
mod handshake;
#[cfg(windows)]
mod native;
mod plan;
mod prepared;
#[cfg(feature = "test-support")]
mod support_diagnostic;
#[cfg(windows)]
mod token;
mod token_observation;
mod token_snapshot;

#[cfg(all(windows, feature = "test-support"))]
pub use native::create_support_detached_console;
#[cfg(feature = "test-support")]
pub use support_diagnostic::SupportDetachedConsolePlanV1;

pub use artifact::{ArtifactRefError, ArtifactRefV1, RedactionClassV1};
pub use attributes::{ExactHandleListV1, HandleRoleV1};
pub use create::{
    LoaderReadyChannel, PackageLoaderProbeError, ProcessCreateFailure,
    ProductionQualificationDriver, SuspendedProcessAttestor, SuspendedProcessEvidenceV1,
    SuspendedProcessFactory, create_package_loader_probe,
};
pub use desktop::DesktopBindingV1;
pub use environment::PreparedEnvironmentIdentityV1;
pub use evidence::{
    CleanupOutcomeV1, CleanupStatusV1, LoaderReadyEvidenceV1, MAX_FAILURE_DETAIL_BYTES,
    NativeCallOutcomeV1, NativeStatusV1, WindowsLoaderQualificationFailureV2,
    WindowsLoaderQualificationOutcomeV2, WindowsLoaderQualificationStageV2,
};
pub use handshake::{
    HandshakeOutcomeV1, LoaderReadyEndpointV1, PRODUCTION_LOADER_READY_SCHEMA_VERSION,
};
#[cfg(windows)]
pub use native::{
    NativeCreateErrorV1, NativeKernelObjectKindV1, NativeSecurityDescriptorV1, ProductionJobV1,
    ProductionNativeCreateRequest, ProductionNativeCreateRequestV1,
    ProductionNativeCreateRequestV2, SuspendedNativeProcessV1, create_process_as_user_native,
    create_process_native, create_suspended_in_job, query_process_handle_count,
};
pub use plan::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    ProductionLoaderPlan, ProductionLoaderPlanInputV1, ProductionLoaderPlanV1,
    ProductionLoaderPlanV2, ProductionPlanError, build_package_loader_plan,
    build_package_loader_plan_v2,
};
pub use prepared::{
    PreparedCurrentDirectoryV1, PreparedLoaderCommandV1, PreparedLoaderEnvironmentV1,
};
#[cfg(windows)]
pub use token::{
    query_token_envelope, query_token_envelope_bounded, query_token_envelope_with_observation,
};
pub use token_observation::{
    ObservationUnavailable, PrivilegeAttributesV1, SidAttributesV1, TOKEN_OBSERVATION_BYTE_BOUND,
    TOKEN_OBSERVATION_ENTRY_BOUND, TokenObservationV1, TokenStatisticsObservationV1,
    privilege_attributes_digest, sid_attributes_digest,
};
pub use token_snapshot::{TargetTokenIdentityV1, token_envelope_sha256};
