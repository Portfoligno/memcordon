#![allow(dead_code)]

#[path = "../src/bin/memcordon-sealed-agent/inspection_schema.rs"]
mod schema;

use schema::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn platform(windows: bool) -> ProviderPackageMetadataV5 {
    if !windows {
        return ProviderPackageMetadataV5::LinuxSystemd {
            control_service_sha256: "a".repeat(64),
            control_socket_sha256: "b".repeat(64),
            launcher_service_sha256: "c".repeat(64),
            launcher_socket_sha256: "d".repeat(64),
            tmpfiles_sha256: "e".repeat(64),
        };
    }
    ProviderPackageMetadataV5::WindowsService {
        control_service_name: "control".into(),
        launcher_service_name: "launcher".into(),
        session_broker_service_name: "broker".into(),
        guardian_slot_count: 4,
        control_service_config_sha256: "a".repeat(64),
        launcher_service_config_sha256: "a".repeat(64),
        session_broker_service_config_sha256: "a".repeat(64),
        guardian_slot_config_sha256: "a".repeat(64),
        control_pipe: "control".into(),
        launcher_pipe: "launcher".into(),
        session_broker_pipe: "broker".into(),
        guardian_pipe_prefix: "guardian".into(),
        binary_install_path: "C:\\Program Files\\Memcordon\\agent.exe".into(),
        target_desktop_bootstrap_install_path: "C:\\Program Files\\Memcordon\\bootstrap.exe".into(),
        target_desktop_bootstrap_sha256: "a".repeat(64),
        target_desktop_bootstrap_runtime: TargetDesktopBootstrapRuntimeV4::StaticVcRuntimeOsUcrt,
        target_desktop_bootstrap_normal_imports: vec!["kernel32.dll".into()],
        target_desktop_bootstrap_delayed_imports: vec![],
        target_desktop_bootstrap_loader_contract_sha256: "a".repeat(64),
        session_broker_install_path: "C:\\Program Files\\Memcordon\\broker.exe".into(),
        session_broker_sha256: "a".repeat(64),
        state_root: "C:\\ProgramData\\Memcordon".into(),
        diagnostics_root: "C:\\ProgramData\\diagnostics".into(),
        control_service_sid_type: "unrestricted".into(),
        launcher_service_sid_type: "unrestricted".into(),
        session_broker_service_sid_type: "unrestricted".into(),
        guardian_slot_service_sid_type: "unrestricted".into(),
        control_required_privileges: vec![],
        launcher_required_privileges: vec![],
        session_broker_required_privileges: vec![],
        guardian_slot_required_privileges: vec![],
        control_pipe_security_sha256: "a".repeat(64),
        launcher_pipe_security_sha256: "a".repeat(64),
        session_broker_service_security_sha256: "a".repeat(64),
        session_broker_pipe_security_sha256: "a".repeat(64),
        guardian_pipe_security_contract_sha256: "a".repeat(64),
        install_directory_security_sha256: "a".repeat(64),
        state_directory_security_sha256: "a".repeat(64),
    }
}

fn agent(windows: bool) -> AgentPackageInspectionV2 {
    let mut value = current_inspection();
    if windows {
        for key in serde_json::to_value(platform(false))
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
        {
            value.as_object_mut().unwrap().remove(key);
        }
        value.as_object_mut().unwrap().extend(
            serde_json::to_value(platform(true))
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
        );
        value["provider_protocol"] = json!(4);
        value["native_protocols"] =
            json!({"platform":"windows","provider_contract":4,"public_wire":4,"private_wire":4});
        value["runtime_profile"] = json!("windows-sealed-current-token-v1");
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn current_inspection_strictly_preserves_both_platforms_and_rejects_unknown_revision() {
    for windows in [false, true] {
        let current = agent(windows);
        check(&current, windows);
        let mut unsupported = serde_json::to_value(current).unwrap();
        unsupported["revision"] = json!(29);
        assert!(serde_json::from_value::<AgentPackageInspectionV2>(unsupported).is_err());
    }
}

fn check<T: Serialize + DeserializeOwned + std::fmt::Debug>(value: &T, windows: bool) {
    let bytes = serde_json::to_vec(value).unwrap();
    let decoded: T = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(decoded).unwrap(),
        serde_json::to_value(value).unwrap()
    );
    let original: Value = serde_json::from_slice(&bytes).unwrap();
    let mut unknown_platform = original.clone();
    unknown_platform["platform"] = json!("unknown-platform");
    assert!(serde_json::from_value::<T>(unknown_platform).is_err());
    for (key, value) in [
        ("unknown", json!(true)),
        (
            if windows {
                "tmpfiles_sha256"
            } else {
                "control_pipe"
            },
            json!("unexpected"),
        ),
    ] {
        let mut invalid = original.clone();
        invalid[key] = value;
        assert!(
            serde_json::from_value::<T>(invalid).is_err(),
            "accepted {key}"
        );
    }
    for key in [
        if original.get("format").is_some() {
            "format"
        } else {
            "schema_version"
        },
        "platform",
        if windows {
            "control_pipe"
        } else {
            "tmpfiles_sha256"
        },
    ] {
        let text = std::str::from_utf8(&bytes).unwrap();
        let duplicate = format!(
            "{{{}:{},{}",
            serde_json::to_string(key).unwrap(),
            original[key],
            text.strip_prefix('{').unwrap()
        );
        assert!(
            serde_json::from_str::<T>(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate field")
        );
    }
    for key in [
        "version",
        "platform",
        if windows {
            "control_pipe"
        } else {
            "tmpfiles_sha256"
        },
    ] {
        let mut invalid = original.clone();
        invalid.as_object_mut().unwrap().remove(key).unwrap();
        assert!(
            serde_json::from_value::<T>(invalid).is_err(),
            "accepted missing {key}"
        );
    }
}

#[test]
fn nested_protocol_duplicate_fields_are_not_lost_to_buffering() {
    let wire = serde_json::to_string(&agent(false)).unwrap();
    let original = "\"launch_wire\":5";
    assert!(wire.contains(original));
    let duplicate = wire.replace(original, "\"launch_wire\":5,\"launch_wire\":5");
    assert!(
        serde_json::from_str::<AgentPackageInspectionV2>(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate field")
    );
}

fn current_inspection() -> Value {
    json!({
        "format": "memcordon.agent-package-inspection", "revision": 2,
        "version": "0.5.8-dev", "source_commit": "a".repeat(40),
        "executable_sha256": "b".repeat(64), "provider_protocol": 3,
        "native_protocols": {"platform":"linux", "provider_contract":3,"launch_wire":5},
        "runtime_manifest_revision":2,
        "workload_request":{"format":"memcordon.workload-request","revision":1},
        "result":{"format":"memcordon.result","revision":3},
        "capabilities":{"format":"memcordon.capabilities","revision":3},
        "plan":{"format":"memcordon.plan","revision":3},
        "runtime_profile":"linux-private-workload-v1", "profile_revision":1,
        "profile_supported":false,
        "mechanism":"linux-pid-namespace-cgroup-v2", "compiled_metadata_valid":true,
        "platform":"linux-systemd",
        "control_service_sha256":"a".repeat(64),
        "control_socket_sha256":"b".repeat(64),
        "launcher_service_sha256":"c".repeat(64),
        "launcher_socket_sha256":"d".repeat(64),
        "tmpfiles_sha256":"e".repeat(64)
    })
}

#[test]
fn current_installed_inspection_rejects_fabricated_policy_observation() {
    let mut installed = json!({
        "format":"memcordon.installed-provider-inspection", "revision":2,
        "agent": current_inspection(),
        "installed_executable_sha256":"b".repeat(64),
        "installed_artifacts_valid":true,
        "provider_identity":null,"provider_reachable":false
    });
    assert!(serde_json::from_value::<InstalledProviderInspectionV2>(installed.clone()).is_ok());
    installed["policy"] = json!({"state":"active"});
    assert!(serde_json::from_value::<InstalledProviderInspectionV2>(installed).is_err());
}
