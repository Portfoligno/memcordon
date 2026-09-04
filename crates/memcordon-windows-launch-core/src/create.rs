use crate::{
    CleanupOutcomeV1, HandshakeOutcomeV1, LoaderReadyEvidenceV1, NativeStatusV1,
    ProductionLoaderPlanV1, WindowsLoaderQualificationFailureV2,
    WindowsLoaderQualificationOutcomeV2, WindowsLoaderQualificationStageV2,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessCreateFailure {
    pub stable_code: String,
    pub native_status: Option<NativeStatusV1>,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendedProcessEvidenceV1 {
    pub image_sha256: String,
    pub token_envelope_sha256: String,
    pub job_membership_attested: bool,
    pub desktop_binding_attested: bool,
    pub exact_handle_list_attested: bool,
}

pub trait SuspendedProcessFactory {
    type Process;

    fn desktop_preflight(&self, plan: &ProductionLoaderPlanV1) -> Result<(), ProcessCreateFailure>;

    fn create(&self, plan: &ProductionLoaderPlanV1) -> Result<Self::Process, ProcessCreateFailure>;

    fn cleanup(&self, process: &mut Self::Process) -> CleanupOutcomeV1;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageLoaderProbeError {
    DesktopPreflight(ProcessCreateFailure),
    ProcessCreate(ProcessCreateFailure),
}

/// Runs the shipped package qualification's single process-factory boundary.
///
/// Production and semantic tests both enter through this function. The
/// factory is borrowed only for this call, so retry policy cannot be hidden
/// inside the orchestration boundary.
pub fn create_package_loader_probe<Factory>(
    factory: &Factory,
    plan: &ProductionLoaderPlanV1,
) -> Result<Factory::Process, PackageLoaderProbeError>
where
    Factory: SuspendedProcessFactory,
{
    factory
        .desktop_preflight(plan)
        .map_err(PackageLoaderProbeError::DesktopPreflight)?;
    factory
        .create(plan)
        .map_err(PackageLoaderProbeError::ProcessCreate)
}

pub trait SuspendedProcessAttestor<Process> {
    fn attest(
        &self,
        process: &Process,
        plan: &ProductionLoaderPlanV1,
    ) -> Result<SuspendedProcessEvidenceV1, ProcessCreateFailure>;
}

pub trait LoaderReadyChannel<Process> {
    fn resume(
        &self,
        process: &mut Process,
        plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure>;

    fn await_ready(
        &self,
        process: &mut Process,
        plan: &ProductionLoaderPlanV1,
    ) -> Result<HandshakeOutcomeV1, ProcessCreateFailure>;

    fn attest_containment(
        &self,
        process: &Process,
        plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure>;

    fn drain_exit(
        &self,
        process: &mut Process,
        plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure>;
}

pub struct ProductionQualificationDriver<Factory, Attestor, Channel> {
    factory: Factory,
    attestor: Attestor,
    channel: Channel,
}

impl<Factory, Attestor, Channel> ProductionQualificationDriver<Factory, Attestor, Channel> {
    #[must_use]
    pub const fn new(factory: Factory, attestor: Attestor, channel: Channel) -> Self {
        Self {
            factory,
            attestor,
            channel,
        }
    }
}

impl<Factory, Attestor, Channel> ProductionQualificationDriver<Factory, Attestor, Channel>
where
    Factory: SuspendedProcessFactory,
    Attestor: SuspendedProcessAttestor<Factory::Process>,
    Channel: LoaderReadyChannel<Factory::Process>,
{
    pub fn qualify(
        &self,
        plan: &ProductionLoaderPlanV1,
        qualification_id: &str,
    ) -> WindowsLoaderQualificationOutcomeV2 {
        let started = Instant::now();
        let mut process = match create_package_loader_probe(&self.factory, plan) {
            Ok(process) => process,
            Err(error) => {
                let (stage, failure) = match error {
                    PackageLoaderProbeError::DesktopPreflight(failure) => {
                        (WindowsLoaderQualificationStageV2::DesktopPreflight, failure)
                    }
                    PackageLoaderProbeError::ProcessCreate(failure) => {
                        (WindowsLoaderQualificationStageV2::ProcessCreate, failure)
                    }
                };
                return WindowsLoaderQualificationOutcomeV2::Failed(map_failure(
                    plan,
                    qualification_id,
                    started,
                    stage,
                    failure,
                    CleanupOutcomeV1::not_started(),
                ));
            }
        };

        match self.attestor.attest(&process, plan) {
            Ok(evidence)
                if evidence.image_sha256 == plan.executable_sha256()
                    && evidence.token_envelope_sha256 == plan.target_token().envelope_sha256
                    && evidence.job_membership_attested
                    && evidence.desktop_binding_attested
                    && evidence.exact_handle_list_attested => {}
            Ok(_) => {
                let cleanup = self.factory.cleanup(&mut process);
                return WindowsLoaderQualificationOutcomeV2::Failed(map_failure(
                    plan,
                    qualification_id,
                    started,
                    WindowsLoaderQualificationStageV2::SuspendedAttestation,
                    ProcessCreateFailure {
                        stable_code: String::from("suspended-attestation-mismatch"),
                        native_status: None,
                        detail: String::from(
                            "suspended process evidence does not match the validated launch plan",
                        ),
                    },
                    cleanup,
                ));
            }
            Err(failure) => {
                let cleanup = self.factory.cleanup(&mut process);
                return WindowsLoaderQualificationOutcomeV2::Failed(map_failure(
                    plan,
                    qualification_id,
                    started,
                    WindowsLoaderQualificationStageV2::SuspendedAttestation,
                    failure,
                    cleanup,
                ));
            }
        }

        if let Err(failure) = self.channel.resume(&mut process, plan) {
            return failed_after_create(
                &self.factory,
                &mut process,
                plan,
                qualification_id,
                started,
                WindowsLoaderQualificationStageV2::Resume,
                failure,
            );
        }
        match self.channel.await_ready(&mut process, plan) {
            Ok(HandshakeOutcomeV1::Authenticated {
                protocol_version: crate::PRODUCTION_LOADER_READY_SCHEMA_VERSION,
            }) => {}
            Ok(_) => {
                return failed_after_create(
                    &self.factory,
                    &mut process,
                    plan,
                    qualification_id,
                    started,
                    WindowsLoaderQualificationStageV2::LoaderReadyHandshake,
                    ProcessCreateFailure {
                        stable_code: String::from("loader-ready-not-authenticated"),
                        native_status: None,
                        detail: String::from(
                            "loader-ready channel returned success without an authenticated version-1 frame",
                        ),
                    },
                );
            }
            Err(failure) => {
                return failed_after_create(
                    &self.factory,
                    &mut process,
                    plan,
                    qualification_id,
                    started,
                    WindowsLoaderQualificationStageV2::LoaderReadyHandshake,
                    failure,
                );
            }
        };
        if let Err(failure) = self.channel.attest_containment(&process, plan) {
            return failed_after_create(
                &self.factory,
                &mut process,
                plan,
                qualification_id,
                started,
                WindowsLoaderQualificationStageV2::ContainmentReadback,
                failure,
            );
        }
        if let Err(failure) = self.channel.drain_exit(&mut process, plan) {
            return failed_after_create(
                &self.factory,
                &mut process,
                plan,
                qualification_id,
                started,
                WindowsLoaderQualificationStageV2::ExitDrain,
                failure,
            );
        }
        let cleanup = self.factory.cleanup(&mut process);
        if cleanup.status() != crate::CleanupStatusV1::Complete {
            return WindowsLoaderQualificationOutcomeV2::Failed(
                WindowsLoaderQualificationFailureV2::new(
                    "loader-cleanup-incomplete",
                    WindowsLoaderQualificationStageV2::ExitDrain,
                    None,
                    elapsed_millis(started),
                    plan,
                    qualification_id,
                    "loader process completed but cleanup did not converge",
                )
                .with_cleanup(cleanup),
            );
        }
        WindowsLoaderQualificationOutcomeV2::Ready(LoaderReadyEvidenceV1::authenticated(
            plan,
            elapsed_millis(started),
        ))
    }
}

fn map_failure(
    plan: &ProductionLoaderPlanV1,
    qualification_id: &str,
    started: Instant,
    stage: WindowsLoaderQualificationStageV2,
    failure: ProcessCreateFailure,
    cleanup: CleanupOutcomeV1,
) -> WindowsLoaderQualificationFailureV2 {
    WindowsLoaderQualificationFailureV2::new(
        failure.stable_code,
        stage,
        failure.native_status,
        elapsed_millis(started),
        plan,
        qualification_id,
        failure.detail,
    )
    .with_cleanup(cleanup)
}

fn failed_after_create<Factory>(
    factory: &Factory,
    process: &mut Factory::Process,
    plan: &ProductionLoaderPlanV1,
    qualification_id: &str,
    started: Instant,
    stage: WindowsLoaderQualificationStageV2,
    failure: ProcessCreateFailure,
) -> WindowsLoaderQualificationOutcomeV2
where
    Factory: SuspendedProcessFactory,
{
    let cleanup = factory.cleanup(process);
    WindowsLoaderQualificationOutcomeV2::Failed(map_failure(
        plan,
        qualification_id,
        started,
        stage,
        failure,
        cleanup,
    ))
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
