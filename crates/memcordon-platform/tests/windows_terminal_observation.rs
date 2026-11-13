#![cfg(windows)]

#[path = "../src/sealed/windows_client_input_observation.rs"]
mod client_input;
#[path = "../src/sealed/windows_client_input_observation_native.rs"]
mod client_input_native;
#[path = "../src/sealed/windows_terminal_observation.rs"]
mod observation;

pub use memcordon_platform::WindowsSynchronousIoDeadline;
use observation::WindowsTerminalObservationScope;

#[test]
fn client_capture_preserves_calling_thread_error_without_claiming_token_success() {
    use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    // SAFETY: last-error is local to this test's issuing thread.
    unsafe { SetLastError(233) };
    let mut sample = None;
    let original: Result<(), std::io::Error> = Err(std::io::Error::from_raw_os_error(233));
    let result = client_input::after_io(original, |state| {
        assert_eq!(state, client_input::FrameResult::ReturnedError);
        sample = Some(client_input_native::capture(
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        ));
    });
    assert_eq!(result.unwrap_err().raw_os_error(), Some(233));
    assert_eq!(unsafe { GetLastError() }, 233);
    if let Some(client_input::Sample::Observed { thread_id, .. }) = sample {
        assert_eq!(thread_id, unsafe { GetCurrentThreadId() });
    }
    let expired = client_input_native::capture(std::time::Instant::now());
    assert!(matches!(
        expired,
        client_input::Sample::Unavailable {
            stage: client_input::Stage::Cutoff,
            ..
        }
    ));
    assert_eq!(unsafe { GetLastError() }, 233);
}

#[test]
fn client_publication_is_scope_owned_one_shot_unbound_and_uses_original_cutoff() {
    let provider: memcordon_core::PublicProviderBindingV1 = serde_json::from_value(serde_json::json!({
        "generation":"provider", "source_commit":"ab".repeat(20), "runtime_manifest_sha256":"cd".repeat(32)
    })).unwrap();
    let cutoff = || std::time::Instant::now() + std::time::Duration::from_secs(2);
    observation::client_begin(&provider, cutoff());
    assert!(!observation::client_enabled());
    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::client_begin(&provider, cutoff());
    assert!(!observation::client_enabled());
    drop(scope);

    for mode in ["write-error", "finish", "drop", "expired"] {
        let directory = tempfile::tempdir().unwrap();
        let terminal = directory.path().join("result.terminal-observation.json");
        std::fs::write(&terminal, []).unwrap();
        let scope = WindowsTerminalObservationScope::begin_with_terminal_path(&terminal).unwrap();
        let path = terminal.with_extension("client-input-observation.json");
        observation::client_begin(
            &provider,
            if mode == "expired" {
                std::time::Instant::now()
            } else {
                cutoff()
            },
        );
        if mode == "write-error" {
            let original: Result<(), &str> = Err("original WriteFile failure");
            assert_eq!(
                client_input::after_io(original, |state| {
                    observation::client_after_write(
                        state,
                        client_input::Sample::Unavailable {
                            stage: client_input::Stage::PrivilegesQuery,
                            native_win32_error: Some(5),
                        },
                    );
                }),
                Err("original WriteFile failure")
            );
            let first = std::fs::read(&path).unwrap();
            observation::client_after_write(
                client_input::FrameResult::ReturnedOk,
                client_input::Sample::Missing {},
            );
            assert_eq!(std::fs::read(&path).unwrap(), first);
        }
        if mode == "finish" {
            assert!(scope.finish().is_err());
        } else {
            drop(scope);
        }
        let bytes = std::fs::read(&path).unwrap();
        if mode == "expired" {
            assert!(bytes.is_empty());
        } else {
            let record: client_input::Record = serde_json::from_slice(&bytes).unwrap();
            record.validate().unwrap();
            assert_eq!(record.binding, client_input::Binding::RequestMissing);
            assert!(record.accepted.is_none());
            assert_eq!(
                record.frame_result,
                if mode == "write-error" {
                    client_input::FrameResult::ReturnedError
                } else {
                    client_input::FrameResult::NotReached
                }
            );
        }
        assert!(!observation::client_enabled());
    }
}

#[test]
fn local_probe_failure_does_not_supply_terminal_or_request_authority() {
    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::retain_probe_failure("OpenProcess(provider): raw-os-error=Some(5)");
    observation::retain_probe_failure("later failure must not replace original");
    let error = scope.finish().unwrap_err();
    assert!(error.contains("unavailable"));
    assert!(error.contains("OpenProcess(provider): raw-os-error=Some(5)"));
    assert!(!error.contains("later failure"));

    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::retain_probe_failure("CreateFileW(control pipe): raw-os-error=Some(5)");
    let error = scope.finish_request().unwrap_err();
    assert!(error.contains("unavailable"));
    assert!(error.contains("CreateFileW(control pipe)"));
}

#[test]
fn local_probe_failure_is_bounded_and_cannot_escape_its_scope() {
    observation::retain_probe_failure("outside explicit observation scope");
    let scope = WindowsTerminalObservationScope::begin().unwrap();
    let error = scope.finish().unwrap_err();
    assert!(!error.contains("probe failure"));

    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::retain_probe_failure(&"界".repeat(4096));
    let error = scope.finish().unwrap_err();
    let detail = error
        .split_once("first local provider probe failure: ")
        .unwrap()
        .1;
    assert!(detail.len() <= 2048);
    assert!(!detail.is_empty());
    assert!(detail.chars().all(|character| character == '界'));

    let scope = WindowsTerminalObservationScope::begin().unwrap();
    observation::retain_probe_failure("dropped scope failure");
    drop(scope);
    let scope = WindowsTerminalObservationScope::begin().unwrap();
    assert!(!scope.finish().unwrap_err().contains("probe failure"));
}

#[test]
fn accepted_receipt_is_durable_before_terminal_and_has_no_external_ack_dependency() {
    use memcordon_core::*;
    let directory = tempfile::tempdir().unwrap();
    let terminal = directory
        .path()
        .join("frontend-result.terminal-observation.json");
    // This models the independently pre-reserved terminal file owned by main.
    std::fs::write(&terminal, []).unwrap();
    let scope = WindowsTerminalObservationScope::begin_with_terminal_path(&terminal).unwrap();
    let request: WindowsLaunchRequestV2 = serde_json::from_value(serde_json::json!({
        "schema_version":4,"restart_attempt":0,
        "expected_provider_binding":{"generation":"provider","source_commit":"ab".repeat(20),"runtime_manifest_sha256":"cd".repeat(32)},
        "nonce":"original","command":{"program":[120],"arguments":[]},"environment":[],"current_directory":[67,58,92],
        "policy":{"memory_limit_bytes":null,"absolute_deadline_millis":null,"lifetime":"command","poll_interval_millis":10,"signal_grace_millis":10,"command_exit_grace_millis":10,"limit_grace_millis":10}
    })).unwrap();
    let bytes = serde_json::to_vec(&request).unwrap();
    observation::retain_request(&bytes).unwrap();
    observation::client_begin(
        &request.expected_provider_binding,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    );
    assert!(observation::client_enabled());
    observation::client_request(&request.nonce, &String::from(hash_bytes(&bytes)));
    observation::client_before_write(client_input::Sample::Unavailable {
        stage: client_input::Stage::ThreadTokenOpen,
        native_win32_error: Some(5),
    });
    observation::client_after_write(
        client_input::FrameResult::ReturnedOk,
        client_input::Sample::Missing {},
    );
    let frontend = WindowsProcessIdentityV1 {
        process_id: 4,
        creation_time_100ns: 5,
    };
    let accepted = WindowsWorkloadAcceptedV1 {
        format: "memcordon.windows-workload-accepted".into(),
        revision: 1,
        provider: request.expected_provider_binding.clone(),
        frontend: frontend.clone(),
        attempt_id: "ef".repeat(32),
        nonce: request.nonce,
        request_sha256: hash_bytes(&bytes).into(),
        setup_deadline_millis: 10,
    };
    observation::retain_accepted(&accepted, &bytes, &accepted.provider, &frontend).unwrap();
    let client_path = terminal.with_extension("client-input-observation.json");
    let client_bytes = std::fs::read(&client_path).unwrap();
    let client: client_input::Record = serde_json::from_slice(&client_bytes).unwrap();
    client.validate().unwrap();
    assert_eq!(client.binding, client_input::Binding::AcceptedReceipt);
    assert_eq!(client.accepted.as_ref(), Some(&accepted));
    assert!(client_bytes.len() <= client_input::MAX_BYTES);
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&client_path)
            .is_err()
    );
    let path = terminal.with_extension("accepted-observation.json");
    let retained = std::fs::read(&path).unwrap();
    assert_eq!(
        serde_json::from_slice::<WindowsWorkloadAcceptedV1>(&retained).unwrap(),
        accepted
    );
    assert!(std::fs::read(&terminal).unwrap().is_empty());
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    assert!(
        observation::retain_accepted(&accepted, &bytes, &accepted.provider, &frontend).is_err()
    );
    assert!(scope.finish().unwrap_err().contains("unavailable"));
    assert_eq!(std::fs::read(path).unwrap(), retained);
    assert_eq!(std::fs::read(client_path).unwrap(), client_bytes);
}
