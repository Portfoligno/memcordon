use super::*;

fn plan() -> ProductionLoaderPlan {
    build_package_loader_plan(ProductionLoaderPlanInputV1 {
        executable_path_utf16: r"C:\Program Files\MemCordon\bootstrap.exe"
            .encode_utf16()
            .collect(),
        executable_sha256: "ab".repeat(32),
        command_line_sha256: "cd".repeat(32),
        environment: memcordon_windows_launch_core::PreparedEnvironmentIdentityV1 {
            encoding: "utf-16le-double-nul".into(),
            byte_len: 42,
            sha256: "ab".repeat(32),
        },
        current_directory_sha256: "cd".repeat(32),
        desktop: DesktopBindingV1 {
            exact_name: r"MemCordon\Qualification".into(),
            security_descriptor_sha256: "ab".repeat(32),
            window_station_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
            desktop_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        },
        process_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        thread_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        job_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        loader_ready_pipe_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        target_token: TargetTokenIdentityV1 {
            envelope_sha256: "cd".repeat(32),
            authentication_id: 7,
            session_id: 0,
        },
        inherited_handles: ExactHandleListV1::none(),
        job_at_creation: true,
    })
    .unwrap()
}

fn peer_exit(code: u32) -> super::super::super::pipe::TargetDesktopBootstrapPipeError {
    super::super::super::pipe::target_desktop_bootstrap_peer_exit_error(
        super::super::super::pipe::TargetDesktopBootstrapPipeOperation::Accept,
        "connect",
        0,
        code,
    )
}

#[test]
fn contextual_and_generic_pipe_conversions_preserve_target_exit() {
    let context = TargetDesktopBootstrapLaunchContext {
        policy_role: super::super::super::security::TargetUserObjectPolicyRoleV1::DirectTarget,
        scenario: "restricted",
        target_token_restricted: true,
        target_token_write_restricted: false,
        target_integrity: "S-1-16-12288".into(),
        target_restricting_sid_sha256: "ab".repeat(32),
    };
    let error = context.accept_error(
        TargetDesktopBootstrapRoleV1::LoaderControl,
        3028,
        &"cd".repeat(32),
        "private",
        &"evidence".repeat(200),
        peer_exit(0xc000_0142),
    );
    assert_eq!(error.os_code, None);
    assert_eq!(
        error.native_status,
        Some(NativeStatusV1::TargetExit { code: 0xc000_0142 })
    );
    let projected = memcordon_windows_launch_core::WindowsLoaderQualificationFailureV2::new(
        "loader-control-pipe-accept",
        LaunchQualificationStageV2::LoaderReadyHandshake,
        error.native_status.clone(),
        69,
        &plan(),
        "qualification-1",
        &error.detail,
    );
    let public = &projected.detail;
    assert_eq!(
        public.len(),
        memcordon_windows_launch_core::MAX_FAILURE_DETAIL_BYTES
    );
    assert!(public.contains("operation=accept"));
    assert!(public.contains("origin=held-peer-exit"));
    assert!(public.contains("child_exit_code_decimal=3221225794"));
    assert!(public.contains("child_exit_code_hex=0xC0000142"));
    let generic = TargetDesktopLeaseCreateError::from(peer_exit(0xc000_0142));
    assert_eq!(generic.os_code, None);
    assert_eq!(generic.native_status, error.native_status);
    let api = context.accept_error(
        TargetDesktopBootstrapRoleV1::LoaderControl,
        3028,
        &"cd".repeat(32),
        "private",
        "bound evidence",
        super::super::super::pipe::target_desktop_bootstrap_api_error_for_test(5),
    );
    assert_eq!(api.os_code, Some(5));
    assert_eq!(api.native_status, Some(NativeStatusV1::Win32 { code: 5 }));
    let generic_api = TargetDesktopLeaseCreateError::from(
        super::super::super::pipe::target_desktop_bootstrap_api_error_for_test(5),
    );
    assert_eq!(generic_api.os_code, api.os_code);
    assert_eq!(generic_api.native_status, api.native_status);
}

#[test]
fn qualification_native_domain_is_independent_of_stage_and_exclusive() {
    use memcordon_windows_launch_core::WindowsLoaderQualificationFailureV2;
    for stage in [
        LaunchQualificationStageV2::ProcessCreate,
        LaunchQualificationStageV2::SuspendedAttestation,
        LaunchQualificationStageV2::LoaderReadyHandshake,
        LaunchQualificationStageV2::ExitDrain,
    ] {
        for (win32, nt_status, target_exit, expected) in [
            (Some(5), None, None, NativeStatusV1::Win32 { code: 5 }),
            (
                None,
                Some(0xc000_0022),
                None,
                NativeStatusV1::NtStatus { code: 0xc000_0022 },
            ),
            (
                None,
                None,
                Some(0xc000_0142),
                NativeStatusV1::TargetExit { code: 0xc000_0142 },
            ),
        ] {
            let mut failure = WindowsLoaderQualificationFailureV2::new(
                "loader-control-pipe-accept",
                stage,
                Some(expected.clone()),
                69,
                &plan(),
                "qualification-1",
                "actual primitive",
            );
            failure.cleanup = CleanupOutcomeV1::complete();
            assert_eq!(
                (
                    failure.win32_error,
                    failure.nt_status,
                    failure.target_exit_code
                ),
                (win32, nt_status, target_exit)
            );
            let projected = lease_error_from_qualification(&failure)
                .unwrap_or_else(|error| panic!("{}", error.detail));
            assert_eq!(projected.native_status, Some(expected));
            assert_eq!(projected.os_code, win32.map(|code| code as i32));
            assert_eq!(
                projected.loader_phase,
                match stage {
                    LaunchQualificationStageV2::ProcessCreate =>
                        LoaderLaunchFailurePhaseV1::CreateProcessReturn,
                    LaunchQualificationStageV2::SuspendedAttestation =>
                        LoaderLaunchFailurePhaseV1::PreResumeAttestation,
                    LaunchQualificationStageV2::LoaderReadyHandshake =>
                        LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
                    LaunchQualificationStageV2::ExitDrain => LoaderLaunchFailurePhaseV1::ExitDrain,
                    _ => unreachable!(),
                }
            );
            let wire = LaunchQualificationOutcomeV2::Failed(failure).to_wire();
            assert!(wire.is_consistent());
            let decoded: memcordon_core::WindowsLoaderQualificationOutcomeV2 =
                serde_json::from_slice(&serde_json::to_vec(&wire).unwrap()).unwrap();
            assert_eq!(decoded, wire);
        }
    }
    assert!(qualification_failure_native_status(Some(5), None, Some(5)).is_err());
}
