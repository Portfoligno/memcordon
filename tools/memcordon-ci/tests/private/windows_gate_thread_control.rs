use super::*;

fn request_input(name: &str, deadline: Instant) -> descriptor::gate_access::Input {
    let gate = super::super::super::native::event_create(name).unwrap();
    let snapshot = crate::windows_consumer_readiness::workload_diagnostic::gate_security_snapshot(
        &gate, deadline,
    )
    .unwrap();
    let (work_cutoff_qpc, qpc_frequency) =
        memcordon_testkit::windows_native_work_cutoff(deadline).unwrap();
    descriptor::gate_access::Input {
        revision: 1,
        descriptor: hex::decode(snapshot.descriptor_bytes_hex).unwrap(),
        descriptor_sha256: snapshot.descriptor_sha256,
        name_utf16_sha256: descriptor::gate_access::name_sha256(
            &name.encode_utf16().collect::<Vec<_>>(),
        ),
        challenge_sha256: descriptor::gate_access::sha256(b"original-thread-control"),
        work_cutoff_qpc,
        qpc_frequency,
        namespace: None,
    }
}

fn permit() -> controller_gate_control_publication::Permit {
    controller_gate_control_publication::publish(
        &std::io::Error::from_raw_os_error(5),
        &serde_json::json!({"test":"original-thread-control"}),
        &mut Vec::new(),
    )
    .unwrap()
}

#[test]
fn original_primary_control_matches_independent_explicit_context_and_restores() {
    let deadline = Instant::now() + Duration::from_secs(30);
    assert!(
        thread_identity().is_none(),
        "primary-context fixture requires no ambient thread token"
    );
    let source = source();
    let before =
        memcordon_windows_launch_core::query_token_envelope(source.as_raw_handle()).unwrap();
    let name = super::super::name();
    let gate = super::super::super::native::event_create(&name).unwrap();
    let snapshot = crate::windows_consumer_readiness::workload_diagnostic::gate_security_snapshot(
        &gate, deadline,
    )
    .unwrap();
    let (work_cutoff_qpc, qpc_frequency) =
        memcordon_testkit::windows_native_work_cutoff(deadline).unwrap();
    let units = name.encode_utf16().collect::<Vec<_>>();
    let input = descriptor::gate_access::Input {
        revision: 1,
        descriptor: hex::decode(&snapshot.descriptor_bytes_hex).unwrap(),
        descriptor_sha256: snapshot.descriptor_sha256.clone(),
        name_utf16_sha256: descriptor::gate_access::name_sha256(&units),
        challenge_sha256: descriptor::gate_access::sha256(b"original-thread-control"),
        work_cutoff_qpc,
        qpc_frequency,
        namespace: None,
    };
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            if unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    assert!(Instant::now() < deadline);
    assert_ne!(
        unsafe { windows_sys::Win32::Security::ImpersonateLoggedOnUser(source.as_raw_handle()) },
        0
    );
    let revert = Revert;
    let terminated = units.iter().copied().chain(Some(0)).collect::<Vec<_>>();
    assert!(Instant::now() < deadline);
    let raw = unsafe {
        windows_sys::Win32::System::Threading::OpenEventW(0x0010_0000, 0, terminated.as_ptr())
    };
    let expected = if raw.is_null() {
        (false, Some(unsafe { GetLastError() }))
    } else {
        drop(unsafe { OwnedHandle::from_raw_handle(raw.cast()) });
        (true, None)
    };
    drop(revert);
    assert!(thread_identity().is_none());
    let observed = controller_gate_token::capture_with_control(
        Some(controller_gate_token::AccessRequest {
            input: &input,
            name: &units,
            challenge: b"original-thread-control",
        }),
        Some(permit()),
    );
    let control = &observed["access_check"]["thread_context_control"];
    assert_eq!(control["impersonation_succeeded"], true, "{observed}");
    assert_eq!(control["control_open_succeeded"], expected.0, "{observed}");
    assert_eq!(
        control["control_raw_os_error"],
        serde_json::json!(expected.1),
        "{observed}"
    );
    assert_eq!(control["restoration_verified"], true, "{observed}");
    assert_eq!(control["same_original_event_identity_proved"], false);
    assert_eq!(control["acceptance_authority"], false);
    assert!(thread_identity().is_none());
    let missing_name = super::super::name();
    let missing_units = missing_name.encode_utf16().collect::<Vec<_>>();
    let mut missing_input = input.clone();
    missing_input.name_utf16_sha256 = descriptor::gate_access::name_sha256(&missing_units);
    assert!(Instant::now() < deadline);
    assert_ne!(
        unsafe { windows_sys::Win32::Security::ImpersonateLoggedOnUser(source.as_raw_handle()) },
        0
    );
    let revert = Revert;
    let terminated = missing_units
        .iter()
        .copied()
        .chain(Some(0))
        .collect::<Vec<_>>();
    assert!(Instant::now() < deadline);
    let raw = unsafe {
        windows_sys::Win32::System::Threading::OpenEventW(0x0010_0000, 0, terminated.as_ptr())
    };
    let missing_expected = if raw.is_null() {
        (false, Some(unsafe { GetLastError() }))
    } else {
        drop(unsafe { OwnedHandle::from_raw_handle(raw.cast()) });
        (true, None)
    };
    drop(revert);
    let observed = controller_gate_token::capture_with_control(
        Some(controller_gate_token::AccessRequest {
            input: &missing_input,
            name: &missing_units,
            challenge: b"original-thread-control",
        }),
        Some(permit()),
    );
    let control = &observed["access_check"]["thread_context_control"];
    assert_eq!(
        control["control_open_succeeded"], missing_expected.0,
        "{observed}"
    );
    assert_eq!(
        control["control_raw_os_error"],
        serde_json::json!(missing_expected.1),
        "{observed}"
    );
    assert_eq!(control["restoration_verified"], true, "{observed}");
    assert!(thread_identity().is_none());
    assert_eq!(
        memcordon_windows_launch_core::query_token_envelope(source.as_raw_handle()).unwrap(),
        before
    );
    assert_eq!(
        crate::windows_consumer_readiness::workload_diagnostic::gate_security_snapshot(
            &gate, deadline
        )
        .unwrap()
        .descriptor_sha256,
        snapshot.descriptor_sha256
    );
}

#[test]
fn restricted_thread_missing_publication_and_expiry_cannot_mutate_context() {
    let deadline = Instant::now() + Duration::from_secs(30);
    let source = source();
    let restricted = restricted(&source);
    let name = super::super::name();
    let mut input = request_input(&name, deadline);
    let units = name.encode_utf16().collect::<Vec<_>>();
    let invoke = |input: &descriptor::gate_access::Input, permit| {
        controller_gate_token::capture_with_control(
            Some(controller_gate_token::AccessRequest {
                input,
                name: &units,
                challenge: b"original-thread-control",
            }),
            permit,
        )
    };
    {
        let _restore = Restore::install(restricted.as_raw_handle());
        let original = thread_identity();
        let observed = invoke(&input, Some(permit()));
        assert_eq!(
            observed["thread_context_control_eligibility"]["eligible"], false,
            "{observed}"
        );
        assert_eq!(thread_identity(), original);
    }
    let original = thread_identity();
    let observed = invoke(&input, None);
    assert_eq!(
        observed["access_check"]["thread_context_control"]["observed"], false,
        "{observed}"
    );
    assert_eq!(thread_identity(), original);
    input.work_cutoff_qpc = 1;
    let observed = invoke(&input, Some(permit()));
    assert_eq!(observed["observed"], false, "{observed}");
    assert_eq!(thread_identity(), original);
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(
        controller_gate_control_publication::publish(
            &std::io::Error::from_raw_os_error(5),
            &serde_json::json!({}),
            &mut Broken
        )
        .is_err()
    );
    assert_eq!(thread_identity(), original);
}
