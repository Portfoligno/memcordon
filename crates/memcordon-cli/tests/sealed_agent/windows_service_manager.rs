use std::os::windows::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows_sys::Win32::System::Services::{
    SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS,
};

use crate::windows::package::remove_installed_binary_with_convergence;
use crate::windows::pipe::OwnedHandle;
use crate::windows::service_manager::{
    DependencyIntent, PinnedServiceProcess, ServiceBaseSnapshot, ServiceConfig, ServiceSidType,
    base_configuration_mismatches, dependency_multistring, service_start_argument_values,
    wait_service_process_exit,
};

const DEPENDENCIES: &[&str] = &["MemCordonSealedLauncher"];
const PRIVILEGES: &[&str] = &[];
type SnapshotMutation = (&'static str, fn(&mut ServiceBaseSnapshot));

fn config() -> ServiceConfig<'static> {
    ServiceConfig {
        name: "MemCordonSealedControl",
        display_name: "MemCordon sealed local control provider",
        binary_command: r#"C:\Program Files\MemCordon\memcordon-sealed-agent.exe windows-control"#,
        account: Some(r"NT AUTHORITY\LocalService"),
        dependencies: DEPENDENCIES,
        required_privileges: PRIVILEGES,
        sid_type: ServiceSidType::Restricted,
    }
}

fn expected_snapshot() -> ServiceBaseSnapshot {
    let config = config();
    ServiceBaseSnapshot {
        service_type: SERVICE_WIN32_OWN_PROCESS,
        start_type: SERVICE_AUTO_START,
        error_control: SERVICE_ERROR_NORMAL,
        binary_path: config.binary_command.to_owned(),
        load_order_group: String::new(),
        tag_id: 0,
        dependencies: DEPENDENCIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        service_start_name: config.account.unwrap().to_owned(),
        display_name: config.display_name.to_owned(),
    }
}

fn decode_start_arguments(values: &[Vec<u16>]) -> Vec<String> {
    values
        .iter()
        .map(|value| {
            assert_eq!(value.last(), Some(&0), "SCM argument must be terminated");
            assert!(
                !value[..value.len() - 1].contains(&0),
                "SCM argument must not truncate before its terminator"
            );
            String::from_utf16(&value[..value.len() - 1]).expect("SCM argument must be Unicode")
        })
        .collect()
}

fn scm_service_main_arguments(name: &str, native_input: &[Vec<u16>]) -> Vec<String> {
    std::iter::once(name.to_owned())
        .chain(decode_start_arguments(native_input))
        .collect()
}

#[test]
fn demand_start_builder_passes_only_extras_and_scm_binds_argv_zero() {
    let broker_name = memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME;
    assert_eq!(
        crate::windows::session_broker::SESSION_BROKER_SCHEMA_VERSION,
        5
    );
    let broker_payload = vec![
        crate::windows::session_broker::SESSION_BROKER_SCHEMA_VERSION.to_string(),
        "22".repeat(32),
    ];
    let broker_native = service_start_argument_values(broker_name, &broker_payload).unwrap();
    assert_eq!(decode_start_arguments(&broker_native), broker_payload);
    let broker = scm_service_main_arguments(broker_name, &broker_native);
    assert_eq!(broker.len(), 3);
    assert_eq!(broker[0], broker_name);
    assert_eq!(&broker[1..], broker_payload);
    crate::windows::session_broker::validate_broker_service_arguments(&broker).unwrap();

    let guardian_name = crate::windows::security::guardian_slot_name(0).unwrap();
    let guardian_nonce = "33".repeat(32);
    let guardian_payload = vec![
        crate::windows::guardian_service::SERVICE_BINDING_SCHEMA_VERSION.to_string(),
        guardian_name.clone(),
        "44".repeat(32),
        guardian_nonce.clone(),
        format!(
            "{}{}",
            memcordon_core::WINDOWS_GUARDIAN_PIPE_PREFIX,
            guardian_nonce
        ),
        "42".to_owned(),
        "123456789".to_owned(),
        "30000".to_owned(),
        "0".to_owned(),
    ];
    let guardian_native = service_start_argument_values(&guardian_name, &guardian_payload).unwrap();
    assert_eq!(decode_start_arguments(&guardian_native), guardian_payload);
    let guardian = scm_service_main_arguments(&guardian_name, &guardian_native);
    assert_eq!(guardian.len(), 10);
    assert_eq!(guardian[0], guardian_name);
    assert_eq!(&guardian[1..], guardian_payload);
    crate::windows::guardian_service::validate_service_arguments_for_test(
        &guardian_name,
        &guardian,
    )
    .unwrap();
}

#[test]
fn demand_start_builder_and_broker_parser_reject_ambiguous_name_vectors() {
    assert!(service_start_argument_values("", &[]).is_err());
    assert!(service_start_argument_values("Bad\0Service", &[]).is_err());
    assert!(service_start_argument_values("GoodService", &["bad\0value".to_owned()]).is_err());
    assert!(
        service_start_argument_values("GoodService", &[])
            .unwrap()
            .is_empty()
    );

    let name = memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME.to_owned();
    let schema = crate::windows::session_broker::SESSION_BROKER_SCHEMA_VERSION.to_string();
    let nonce = "55".repeat(32);
    let duplicated_native =
        service_start_argument_values(&name, &[name.clone(), schema.clone(), nonce.clone()])
            .unwrap();
    let duplicated_callback = scm_service_main_arguments(&name, &duplicated_native);
    assert_eq!(
        duplicated_callback,
        [name.clone(), name.clone(), schema.clone(), nonce.clone()]
    );
    assert!(
        crate::windows::session_broker::validate_broker_service_arguments(&duplicated_callback)
            .is_err()
    );
    let guardian_name = crate::windows::security::guardian_slot_name(0).unwrap();
    let guardian_payload = vec![
        guardian_name.clone(),
        crate::windows::guardian_service::SERVICE_BINDING_SCHEMA_VERSION.to_string(),
        guardian_name.clone(),
        "66".repeat(32),
        "77".repeat(32),
        format!(
            "{}{}",
            memcordon_core::WINDOWS_GUARDIAN_PIPE_PREFIX,
            "77".repeat(32)
        ),
        "42".to_owned(),
        "123456789".to_owned(),
        "30000".to_owned(),
        "0".to_owned(),
    ];
    let guardian_native = service_start_argument_values(&guardian_name, &guardian_payload).unwrap();
    let guardian_callback = scm_service_main_arguments(&guardian_name, &guardian_native);
    assert_eq!(guardian_callback[0], guardian_callback[1]);
    assert!(
        crate::windows::guardian_service::validate_service_arguments_for_test(
            &guardian_name,
            &guardian_callback,
        )
        .is_err()
    );
    for invalid in [
        vec![schema.clone(), nonce.clone()],
        vec![name.clone(), name.clone(), schema.clone(), nonce.clone()],
        vec![schema.clone(), name.clone(), nonce.clone()],
        vec!["WrongService".to_owned(), schema.clone(), nonce.clone()],
        vec![name.clone(), "1".to_owned(), nonce.clone()],
        vec![name.clone(), "999".to_owned(), nonce.clone()],
    ] {
        assert!(
            crate::windows::session_broker::validate_broker_service_arguments(&invalid).is_err(),
            "ambiguous broker argument vector was accepted: {invalid:?}"
        );
    }
    assert!(crate::windows::session_broker::validate_broker_start_nonce("invalid").is_err());
}

#[test]
fn demand_start_stopped_diagnostic_preserves_typed_scm_evidence() {
    let status = SERVICE_STATUS_PROCESS {
        dwCurrentState: SERVICE_STOPPED,
        dwWin32ExitCode: windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR,
        dwServiceSpecificExitCode: crate::windows::session_broker::BROKER_FAILURE_ARGUMENTS,
        ..SERVICE_STATUS_PROCESS::default()
    };
    let diagnostic = crate::windows::service_manager::demand_start_stopped_diagnostic_for_test(
        memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME,
        &status,
        7,
    );
    assert!(diagnostic.contains("operation=state-convergence phase=demand-start"));
    assert!(diagnostic.contains("service=MemCordonSealedSessionBroker"));
    assert!(diagnostic.contains("last_state=1 process_id=0"));
    assert!(diagnostic.contains("win32_exit=1066"));
    assert!(diagnostic.contains("service_exit=1296238353"));
    assert!(diagnostic.contains("elapsed_ms=7"));
    assert!(diagnostic.contains("role=session-broker operation=startup stage=arguments"));
    assert!(!diagnostic.contains("target desktop bootstrap"));
}

#[test]
fn session_broker_protection_failures_preserve_exact_subphases() {
    for (exit, subphase) in [
        (
            crate::windows::session_broker::BROKER_FAILURE_PROCESS_DESCRIPTOR,
            "process-descriptor",
        ),
        (
            crate::windows::session_broker::BROKER_FAILURE_PROCESS_APPLY,
            "process-apply",
        ),
        (
            crate::windows::session_broker::BROKER_FAILURE_PROCESS_READBACK,
            "process-readback",
        ),
        (
            crate::windows::session_broker::BROKER_FAILURE_TOKEN_OPEN,
            "token-open",
        ),
        (
            crate::windows::session_broker::BROKER_FAILURE_TOKEN_DESCRIPTOR,
            "token-descriptor",
        ),
        (
            crate::windows::session_broker::BROKER_FAILURE_TOKEN_DACL_APPLY,
            "token-dacl-apply",
        ),
        (
            crate::windows::session_broker::BROKER_FAILURE_TOKEN_READBACK,
            "token-readback",
        ),
    ] {
        assert_eq!(
            crate::windows::session_broker::startup_diagnostic_from_exit(exit),
            Some(("process-protection", Some(subphase)))
        );
        let status = SERVICE_STATUS_PROCESS {
            dwCurrentState: SERVICE_STOPPED,
            dwWin32ExitCode: windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR,
            dwServiceSpecificExitCode: exit,
            ..SERVICE_STATUS_PROCESS::default()
        };
        let diagnostic = crate::windows::service_manager::demand_start_stopped_diagnostic_for_test(
            memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME,
            &status,
            9,
        );
        assert!(diagnostic.contains(&format!(
            "role=session-broker operation=startup stage=process-protection subphase={subphase}"
        )));
    }
    assert_eq!(
        crate::windows::session_broker::startup_diagnostic_from_exit(0x4d43_0712),
        Some(("process-protection", None))
    );
}

#[test]
fn guardian_argument_failure_preserves_typed_scm_evidence() {
    let status = SERVICE_STATUS_PROCESS {
        dwCurrentState: SERVICE_STOPPED,
        dwWin32ExitCode: windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR,
        dwServiceSpecificExitCode: 0x4d43_0401,
        ..SERVICE_STATUS_PROCESS::default()
    };
    let diagnostic = crate::windows::service_manager::demand_start_stopped_diagnostic_for_test(
        "MemCordonSealedGuardian0",
        &status,
        11,
    );
    assert!(diagnostic.contains("role=guardian operation=startup stage=arguments"));
    assert!(diagnostic.contains("service_exit=1296237569"));
}

#[test]
fn dependency_intents_distinguish_preserve_clear_and_replace() {
    assert_eq!(dependency_multistring(DependencyIntent::Preserve), None);
    assert_eq!(
        dependency_multistring(DependencyIntent::Clear),
        Some(vec![0, 0])
    );

    let replacement = dependency_multistring(DependencyIntent::Replace(&["Alpha", "Beta"]))
        .expect("replacement should carry a multistring");
    let expected = "Alpha\0Beta\0\0".encode_utf16().collect::<Vec<_>>();
    assert_eq!(replacement, expected);
}

#[test]
fn matching_base_configuration_has_no_diagnostics() {
    assert!(base_configuration_mismatches(&expected_snapshot(), &config()).is_empty());
}

#[test]
fn base_configuration_diagnostics_name_every_checked_field() {
    let mutations: &[SnapshotMutation] = &[
        ("service_type", |value| value.service_type = 0),
        ("start_type", |value| value.start_type = 0),
        ("error_control", |value| value.error_control = 0),
        ("binary_path", |value| {
            value.binary_path = "wrong".to_owned()
        }),
        ("service_start_name", |value| {
            value.service_start_name = "wrong".to_owned();
        }),
        ("dependencies", |value| value.dependencies.clear()),
        ("load_order_group", |value| {
            value.load_order_group = "wrong".to_owned();
        }),
        ("tag_id", |value| value.tag_id = 17),
        ("display_name", |value| {
            value.display_name = "wrong".to_owned();
        }),
    ];

    for (field, mutate) in mutations {
        let mut actual = expected_snapshot();
        mutate(&mut actual);
        let mismatches = base_configuration_mismatches(&actual, &config());
        assert_eq!(mismatches.len(), 1, "unexpected diagnostics for {field}");
        assert!(
            mismatches[0].starts_with(field),
            "diagnostic does not identify {field}: {}",
            mismatches[0]
        );
        assert!(mismatches[0].contains("expected="));
        assert!(mismatches[0].contains("actual="));
    }
}

fn open_without_delete_share(path: &std::path::Path) -> OwnedHandle {
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: path is NUL-terminated and the returned handle is immediately
    // adopted. Omitting FILE_SHARE_DELETE deliberately models a mapped image.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    OwnedHandle::new(raw).expect("test image should open without delete sharing")
}

#[test]
fn installed_image_delete_converges_after_transient_native_sharing() {
    let directory = tempfile::tempdir().unwrap();
    for iteration in 0..32 {
        let image = directory.path().join(format!("agent-{iteration}.exe"));
        std::fs::write(&image, b"native image\n").unwrap();
        let image_owner = open_without_delete_share(&image);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            drop(image_owner);
        });
        let started = Instant::now();
        remove_installed_binary_with_convergence(
            &image,
            Duration::from_secs(2),
            Duration::from_millis(2),
        )
        .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(2));
        assert!(!image.exists());
        release.join().unwrap();
    }
}

#[test]
fn installed_image_delete_timeout_names_phase_path_attempt_and_native_error() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("agent.exe");
    std::fs::write(&image, b"native image\n").unwrap();
    let _image_owner = open_without_delete_share(&image);
    let error =
        remove_installed_binary_with_convergence(&image, Duration::ZERO, Duration::from_millis(1))
            .unwrap_err();
    assert!(error.contains("MCSEALED-WINDOWS-REMOVE: phase=delete-image"));
    assert!(error.contains(&format!("path={}", image.display())));
    assert!(error.contains("attempts=1"));
    assert!(error.contains("elapsed_ms="));
    assert!(error.contains("native_code=Some("));
}

#[test]
fn exact_process_wait_holds_until_the_pinned_process_object_signals() {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
    let mut child = Command::new("ping.exe")
        .args(["-n", "2", "-w", "1000", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("native delayed process should start");
    // SAFETY: PID comes from the retained child and the handle is immediately
    // adopted with only the rights used by service shutdown.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            child.id(),
        )
    };
    let handle = OwnedHandle::new(raw).expect("delayed process should be pinnable");
    let identity = crate::windows::process::process_identity(handle.raw()).unwrap();
    let process = PinnedServiceProcess { handle, identity };
    let started = Instant::now();
    wait_service_process_exit(
        &process,
        "MemCordonDelayedStopFixture",
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(child.wait().unwrap().success());
}
