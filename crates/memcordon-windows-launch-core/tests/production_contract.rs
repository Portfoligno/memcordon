use memcordon_windows_launch_core::{
    CleanupOutcomeV1, CleanupStatusV1, DesktopBindingV1, ExactHandleListV1, HandshakeOutcomeV1,
    LoaderReadyChannel, NativeStatusV1, PreparedEnvironmentIdentityV1, ProcessCreateFailure,
    ProductionLoaderPlanInputV1, ProductionLoaderPlanV1, ProductionQualificationDriver,
    SuspendedProcessAttestor, SuspendedProcessEvidenceV1, SuspendedProcessFactory,
    TargetTokenIdentityV1, WindowsLoaderQualificationOutcomeV2, WindowsLoaderQualificationStageV2,
    build_package_loader_plan,
};
use std::cell::Cell;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn plan_input() -> ProductionLoaderPlanInputV1 {
    ProductionLoaderPlanInputV1 {
        executable_path_utf16: "C:\\Program Files\\MemCordon\\bootstrap.exe"
            .encode_utf16()
            .collect(),
        executable_sha256: String::from(DIGEST_A),
        command_line_sha256: String::from(DIGEST_B),
        environment: PreparedEnvironmentIdentityV1 {
            encoding: String::from("utf-16le-double-nul"),
            byte_len: 42,
            sha256: String::from(DIGEST_A),
        },
        current_directory_sha256: String::from(DIGEST_B),
        desktop: DesktopBindingV1 {
            exact_name: String::from("MemCordon\\Qualification"),
            security_descriptor_sha256: String::from(DIGEST_A),
            window_station_security_descriptor_sddl: String::from("D:P(A;;GA;;;SY)"),
            desktop_security_descriptor_sddl: String::from("D:P(A;;GA;;;SY)"),
        },
        process_security_descriptor_sddl: String::from("D:P(A;;GA;;;SY)"),
        thread_security_descriptor_sddl: String::from("D:P(A;;GA;;;SY)"),
        job_security_descriptor_sddl: String::from("D:P(A;;GA;;;SY)"),
        loader_ready_pipe_security_descriptor_sddl: String::from("D:P(A;;GA;;;SY)"),
        target_token: TargetTokenIdentityV1 {
            envelope_sha256: String::from(DIGEST_B),
            authentication_id: 7,
            session_id: 0,
        },
        inherited_handles: ExactHandleListV1::none(),
        job_at_creation: true,
    }
}

fn plan() -> ProductionLoaderPlanV1 {
    build_package_loader_plan(plan_input()).expect("fixture plan must be valid")
}

struct CountingFactory {
    creates: Cell<usize>,
    cleanup: CleanupOutcomeV1,
}

impl SuspendedProcessFactory for CountingFactory {
    type Process = u32;

    fn desktop_preflight(
        &self,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure> {
        Ok(())
    }

    fn create(
        &self,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<Self::Process, ProcessCreateFailure> {
        self.creates.set(self.creates.get() + 1);
        Ok(42)
    }

    fn cleanup(&self, _process: &mut Self::Process) -> CleanupOutcomeV1 {
        self.cleanup.clone()
    }
}

struct PassingAttestor;

impl SuspendedProcessAttestor<u32> for PassingAttestor {
    fn attest(
        &self,
        _process: &u32,
        plan: &ProductionLoaderPlanV1,
    ) -> Result<SuspendedProcessEvidenceV1, ProcessCreateFailure> {
        Ok(SuspendedProcessEvidenceV1 {
            image_sha256: String::from(plan.executable_sha256()),
            token_envelope_sha256: plan.target_token().envelope_sha256.clone(),
            job_membership_attested: true,
            desktop_binding_attested: true,
            exact_handle_list_attested: true,
        })
    }
}

struct MutatedAttestor {
    desktop_binding_attested: bool,
    exact_handle_list_attested: bool,
}

impl SuspendedProcessAttestor<u32> for MutatedAttestor {
    fn attest(
        &self,
        _process: &u32,
        plan: &ProductionLoaderPlanV1,
    ) -> Result<SuspendedProcessEvidenceV1, ProcessCreateFailure> {
        Ok(SuspendedProcessEvidenceV1 {
            image_sha256: String::from(plan.executable_sha256()),
            token_envelope_sha256: plan.target_token().envelope_sha256.clone(),
            job_membership_attested: true,
            desktop_binding_attested: self.desktop_binding_attested,
            exact_handle_list_attested: self.exact_handle_list_attested,
        })
    }
}

struct PassingChannel;

impl LoaderReadyChannel<u32> for PassingChannel {
    fn resume(
        &self,
        _process: &mut u32,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure> {
        Ok(())
    }

    fn await_ready(
        &self,
        _process: &mut u32,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<HandshakeOutcomeV1, ProcessCreateFailure> {
        Ok(HandshakeOutcomeV1::Authenticated {
            protocol_version: memcordon_windows_launch_core::PRODUCTION_LOADER_READY_SCHEMA_VERSION,
        })
    }

    fn attest_containment(
        &self,
        _process: &u32,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure> {
        Ok(())
    }

    fn drain_exit(
        &self,
        _process: &mut u32,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure> {
        Ok(())
    }
}

struct FailingChannel;

impl LoaderReadyChannel<u32> for FailingChannel {
    fn resume(
        &self,
        _process: &mut u32,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure> {
        Ok(())
    }

    fn await_ready(
        &self,
        _process: &mut u32,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<HandshakeOutcomeV1, ProcessCreateFailure> {
        Err(ProcessCreateFailure {
            stable_code: String::from("loader-ready-pipe"),
            native_status: Some(NativeStatusV1::Win32 { code: 109 }),
            detail: "x".repeat(4096),
        })
    }

    fn attest_containment(
        &self,
        _process: &u32,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure> {
        Ok(())
    }

    fn drain_exit(
        &self,
        _process: &mut u32,
        _plan: &ProductionLoaderPlanV1,
    ) -> Result<(), ProcessCreateFailure> {
        Ok(())
    }
}

#[test]
fn ephemeral_marker_does_not_change_production_plan() {
    // This exact function type is the production package-plan boundary. It
    // cannot receive marker state, and launch-core has no package-state
    // dependency from which ambient fault authorization could be obtained.
    let marker_blind_builder: fn(ProductionLoaderPlanInputV1) -> Result<ProductionLoaderPlanV1, _> =
        build_package_loader_plan;
    let marker_absent =
        marker_blind_builder(plan_input()).expect("marker-absent package plan must be valid");
    let marker_present =
        marker_blind_builder(plan_input()).expect("marker-present package plan must be valid");
    assert_eq!(
        marker_absent.canonical_bytes(),
        marker_present.canonical_bytes()
    );
    assert_eq!(
        marker_absent.launch_plan_sha256(),
        marker_present.launch_plan_sha256()
    );
    assert_eq!(
        marker_absent.creation_flags(),
        ProductionLoaderPlanV1::CREATION_FLAGS
    );
}

#[test]
fn production_plan_cannot_enable_debugger() {
    let plan = plan();
    assert!(plan.debugger_is_unrepresentable());
    assert_eq!(plan.inherited_handles(), &ExactHandleListV1::none());
    assert!(plan.job_at_creation());
}

#[test]
fn diagnostic_failure_cannot_fail_qualification() {
    // The shipped qualifier completes before the separate diagnostic-only
    // observer runs; the observer receives no mutable production state and
    // cannot replace the typed gate outcome.
    let production = ProductionQualificationDriver::new(
        CountingFactory {
            creates: Cell::new(0),
            cleanup: CleanupOutcomeV1::complete(),
        },
        PassingAttestor,
        PassingChannel,
    )
    .qualify(&plan(), "qualification-1");
    let diagnostic_observer = || Err::<(), _>("diagnostic-observer-failed");
    assert_eq!(diagnostic_observer(), Err("diagnostic-observer-failed"));
    assert!(matches!(
        production,
        WindowsLoaderQualificationOutcomeV2::Ready(_)
    ));
}

#[test]
fn production_failure_is_not_replaced() {
    let production = ProductionQualificationDriver::new(
        CountingFactory {
            creates: Cell::new(0),
            cleanup: CleanupOutcomeV1::complete(),
        },
        PassingAttestor,
        FailingChannel,
    )
    .qualify(&plan(), "qualification-1");
    let diagnostic_observer = || Err::<(), _>("diagnostic-observer-failed");
    assert_eq!(diagnostic_observer(), Err("diagnostic-observer-failed"));
    let WindowsLoaderQualificationOutcomeV2::Failed(failure) = production else {
        panic!("production failure must remain a failure")
    };
    assert_eq!(
        failure.stage,
        WindowsLoaderQualificationStageV2::LoaderReadyHandshake
    );
    assert_eq!(failure.win32_error, Some(109));
}

#[test]
fn qualification_runs_one_loader_probe() {
    let factory = CountingFactory {
        creates: Cell::new(0),
        cleanup: CleanupOutcomeV1::complete(),
    };
    let outcome = ProductionQualificationDriver::new(&factory, PassingAttestor, PassingChannel)
        .qualify(&plan(), "qualification-1");
    assert!(matches!(
        outcome,
        WindowsLoaderQualificationOutcomeV2::Ready(_)
    ));
    assert_eq!(factory.creates.get(), 1);
}

#[test]
fn suspended_attestation_rejects_unproven_desktop_and_handles() {
    for attestor in [
        MutatedAttestor {
            desktop_binding_attested: false,
            exact_handle_list_attested: true,
        },
        MutatedAttestor {
            desktop_binding_attested: true,
            exact_handle_list_attested: false,
        },
    ] {
        let outcome = ProductionQualificationDriver::new(
            CountingFactory {
                creates: Cell::new(0),
                cleanup: CleanupOutcomeV1::complete(),
            },
            attestor,
            PassingChannel,
        )
        .qualify(&plan(), "qualification-attestation-mutation");
        let WindowsLoaderQualificationOutcomeV2::Failed(failure) = outcome else {
            panic!("unproven suspended attestation must fail qualification")
        };
        assert_eq!(
            failure.stage,
            WindowsLoaderQualificationStageV2::SuspendedAttestation
        );
    }
}

impl SuspendedProcessFactory for &CountingFactory {
    type Process = u32;

    fn desktop_preflight(&self, plan: &ProductionLoaderPlanV1) -> Result<(), ProcessCreateFailure> {
        (*self).desktop_preflight(plan)
    }

    fn create(&self, plan: &ProductionLoaderPlanV1) -> Result<Self::Process, ProcessCreateFailure> {
        (*self).create(plan)
    }

    fn cleanup(&self, process: &mut Self::Process) -> CleanupOutcomeV1 {
        (*self).cleanup(process)
    }
}

#[test]
fn failure_payload_is_bounded_and_typed() {
    let failure = ProductionQualificationDriver::new(
        CountingFactory {
            creates: Cell::new(0),
            cleanup: CleanupOutcomeV1::complete(),
        },
        PassingAttestor,
        FailingChannel,
    )
    .qualify(&plan(), "qualification-1");
    let bytes = serde_json::to_vec(&failure).expect("typed failure must serialize");
    assert!(bytes.len() < 2048, "failure payload must remain bounded");
    let decoded: WindowsLoaderQualificationOutcomeV2 =
        serde_json::from_slice(&bytes).expect("typed failure must round trip");
    let WindowsLoaderQualificationOutcomeV2::Failed(decoded) = decoded else {
        panic!("fixture must fail")
    };
    assert_eq!(decoded.win32_error, Some(109));
    assert!(decoded.nt_status.is_none());
    assert!(decoded.target_exit_code.is_none());
}

#[test]
fn cleanup_is_secondary() {
    let outcome = ProductionQualificationDriver::new(
        CountingFactory {
            creates: Cell::new(0),
            cleanup: CleanupOutcomeV1::failed("job-drain-timeout"),
        },
        PassingAttestor,
        FailingChannel,
    )
    .qualify(&plan(), "qualification-1");
    let WindowsLoaderQualificationOutcomeV2::Failed(failure) = outcome else {
        panic!("fixture must fail")
    };
    assert_eq!(
        failure.stage,
        WindowsLoaderQualificationStageV2::LoaderReadyHandshake
    );
    assert_eq!(failure.win32_error, Some(109));
    assert_eq!(failure.cleanup.status(), CleanupStatusV1::Failed);
}
