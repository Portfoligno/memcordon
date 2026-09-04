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
#[cfg(windows)]
mod token;
mod token_snapshot;

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
    ProductionNativeCreateRequestV1, SuspendedNativeProcessV1, create_process_as_user_native,
    create_process_native, create_suspended_in_job, query_process_handle_count,
};
pub use plan::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    ProductionLoaderPlanInputV1, ProductionLoaderPlanV1, ProductionPlanError,
    build_package_loader_plan,
};
pub use prepared::{
    PreparedCurrentDirectoryV1, PreparedLoaderCommandV1, PreparedLoaderEnvironmentV1,
};
#[cfg(windows)]
pub use token::query_token_envelope;
pub use token_snapshot::{TargetTokenIdentityV1, token_envelope_sha256};
