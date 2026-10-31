use memcordon_core::*;

fn report() -> WindowsLauncherStartupDiagnosticV1 {
    WindowsLauncherStartupDiagnosticV1 {
        schema_version: 1,
        provider: PublicProviderBindingV1 {
            generation: BoundedText::new("installed-generation").unwrap(),
            source_commit: BoundedText::new(&"12".repeat(20)).unwrap(),
            runtime_manifest_sha256: DiagnosticSha256::from_bytes([3; 32]),
        },
        startup_process: WindowsProcessIdentityV1 {
            process_id: 42,
            creation_time_100ns: 73,
        },
        boot_identity: "134366600000000000".into(),
        recorded_tick_millis: 1000,
        service_exit: 0x4d43_0202,
        stage: WindowsLauncherStartupStageV1::RecordAuthentication,
        reason: WindowsLauncherStartupReasonV1::InvalidRecord,
        native_code: None,
    }
}

fn validate(value: &WindowsLauncherStartupDiagnosticV1) -> Result<(), &'static str> {
    let expected = report();
    value.validate_for(
        &expected.provider,
        &expected.boot_identity,
        1001,
        expected.service_exit,
        Some(&expected.startup_process),
    )
}

#[test]
fn startup_failure_codec_preserves_only_bound_typed_diagnostics() {
    let report = report();
    let bytes = report.to_bounded_json().unwrap();
    assert!(bytes.len() <= WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES);
    let restored = WindowsLauncherStartupDiagnosticV1::from_json_for(
        &bytes,
        &report.provider,
        &report.boot_identity,
        1001,
        report.service_exit,
        Some(&report.startup_process),
    )
    .unwrap();
    assert_eq!(restored, report);
    report.validate_since(report.recorded_tick_millis).unwrap();
    assert!(
        report
            .validate_since(report.recorded_tick_millis + 1)
            .is_err(),
        "accepted earlier same-provider failure within freshness window"
    );
    // SCM has no live process identity after STOPPED. The remaining exact
    // joins still qualify this as a diagnostic, never as terminal authority.
    report
        .validate_for(
            &report.provider,
            &report.boot_identity,
            1001,
            report.service_exit,
            None,
        )
        .unwrap();
}

#[test]
fn every_startup_gate_keeps_its_native_service_failure_namespace() {
    use WindowsLauncherStartupStageV1::*;
    for (stage, exit) in [
        (ProcessProtection, 0x4d43_0201),
        (TokenPolicy, 0x4d43_0210),
        (GuardianSlots, 0x4d43_0202),
        (WriterQuarantine, 0x4d43_0202),
        (WriterRegistry, 0x4d43_0202),
        (AttemptsDirectory, 0x4d43_0202),
        (QuarantineDirectory, 0x4d43_0202),
        (ReplayDirectory, 0x4d43_0202),
        (AdmissionDirectory, 0x4d43_0202),
        (GuardianReceiptDirectory, 0x4d43_0202),
        (QuarantineOpen, 0x4d43_0202),
        (QuarantineEntry, 0x4d43_0202),
        (StagedAck, 0x4d43_0202),
        (GuardianDirectory, 0x4d43_0202),
        (ReaderAdmission, 0x4d43_0202),
        (WriterAdmission, 0x4d43_0202),
        (OwnedAdmission, 0x4d43_0202),
        (RecordRead, 0x4d43_0202),
        (RecordAuthentication, 0x4d43_0202),
        (PendingOutbox, 0x4d43_0202),
        (GuardianReceiptBinding, 0x4d43_0202),
        (UnresolvedContract, 0x4d43_0202),
        (NativeOwnerClosure, 0x4d43_0202),
        (FinalAmbiguity, 0x4d43_0202),
        (PipePreparation, 0x4d43_0203),
        (RunningAnnouncement, 0x4d43_0204),
        (ServiceLoop, 0x4d43_0205),
    ] {
        let mut value = report();
        value.stage = stage;
        value.reason = WindowsLauncherStartupReasonV1::OperationFailed;
        value.native_code = Some(32);
        value.service_exit = exit;
        let bytes = value.to_bounded_json().unwrap();
        let restored = WindowsLauncherStartupDiagnosticV1::from_json_for(
            &bytes,
            &value.provider,
            &value.boot_identity,
            1001,
            exit,
            Some(&value.startup_process),
        )
        .unwrap();
        assert_eq!(restored, value);
        value.service_exit = 1067;
        assert!(
            value.to_bounded_json().is_err(),
            "accepted generic SCM exit for {stage:?}"
        );
    }
}

#[test]
fn registry_failure_reasons_round_trip_without_a_native_code() {
    for reason in [
        WindowsLauncherStartupReasonV1::WriterRegistryUnavailable,
        WindowsLauncherStartupReasonV1::UnconfirmedWriter,
    ] {
        let mut value = report();
        value.stage = WindowsLauncherStartupStageV1::WriterRegistry;
        value.reason = reason;
        let bytes = value.to_bounded_json().unwrap();
        assert!(bytes.len() <= WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES);
        let restored = WindowsLauncherStartupDiagnosticV1::from_json_for(
            &bytes,
            &value.provider,
            &value.boot_identity,
            1001,
            value.service_exit,
            Some(&value.startup_process),
        )
        .unwrap();
        assert_eq!(restored, value);
        assert_eq!(restored.native_code, None);
    }
}

#[test]
fn startup_diagnostic_rejects_stale_future_and_cross_identity_reports() {
    let original = report();
    for change in 0..8 {
        let mut value = original.clone();
        match change {
            0 => value.provider.generation = BoundedText::new("other-generation").unwrap(),
            1 => value.provider.source_commit = BoundedText::new(&"34".repeat(20)).unwrap(),
            2 => value.provider.runtime_manifest_sha256 = DiagnosticSha256::from_bytes([9; 32]),
            3 => value.boot_identity = "134366500000000000".into(),
            4 => value.startup_process.process_id += 1,
            5 => value.startup_process.creation_time_100ns += 1,
            6 => value.recorded_tick_millis = 1002,
            _ => value.service_exit = 0x4d43_0203,
        }
        assert!(
            validate(&value).is_err(),
            "accepted unjoined diagnostic {change}"
        );
    }
    original
        .validate_for(
            &original.provider,
            &original.boot_identity,
            1000 + WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS,
            original.service_exit,
            None,
        )
        .unwrap();
    assert!(
        original
            .validate_for(
                &original.provider,
                &original.boot_identity,
                1001 + WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS,
                original.service_exit,
                None
            )
            .is_err()
    );
}

#[test]
fn startup_diagnostic_decoder_rejects_unknown_truncated_duplicate_and_oversized_input() {
    let report = report();
    let decode = |bytes: &[u8]| {
        WindowsLauncherStartupDiagnosticV1::from_json_for(
            bytes,
            &report.provider,
            &report.boot_identity,
            1001,
            report.service_exit,
            None,
        )
    };
    let original = serde_json::to_value(&report).unwrap();
    for (field, value) in [
        ("schema_version", serde_json::json!(2)),
        ("stage", serde_json::json!("unverified-recovery")),
        ("reason", serde_json::json!("arbitrary-secret-detail")),
        ("raw_error", serde_json::json!("private-input")),
        ("boot_identity", serde_json::json!("not-a-native-boot")),
        (
            "startup_process",
            serde_json::json!({"process_id":0,"creation_time_100ns":73}),
        ),
    ] {
        let mut hostile = original.clone();
        hostile[field] = value;
        assert!(
            decode(&serde_json::to_vec(&hostile).unwrap()).is_err(),
            "accepted {field}"
        );
    }
    let bytes = report.to_bounded_json().unwrap();
    assert!(decode(&bytes[..bytes.len() / 2]).is_err());
    let rest = std::str::from_utf8(&bytes)
        .unwrap()
        .strip_prefix('{')
        .unwrap();
    let duplicate = format!("{{\"schema_version\":1,{rest}");
    assert!(decode(duplicate.as_bytes()).is_err());
    assert!(decode(&vec![b' '; WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES + 1]).is_err());
}
