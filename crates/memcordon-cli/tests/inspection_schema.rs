#![allow(dead_code)]

#[path = "../src/bin/memcordon-sealed-agent/inspection_schema.rs"]
mod schema;

use memcordon_core::runtime_manifest::{
    InstalledPolicyObservationV1, NativeProviderProtocols, QualificationArtifactReferenceV1,
};
use schema::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn platform(windows: bool) -> ProviderPackageMetadataV4 {
    if !windows {
        return ProviderPackageMetadataV4::LinuxSystemd {
            control_service_sha256: "a".repeat(64),
            control_socket_sha256: "b".repeat(64),
            launcher_service_sha256: "c".repeat(64),
            launcher_socket_sha256: "d".repeat(64),
            tmpfiles_sha256: "e".repeat(64),
        };
    }
    ProviderPackageMetadataV4::WindowsService {
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

fn agent(windows: bool) -> AgentPackageInspectionV5 {
    AgentPackageInspectionV5 {
        schema_version: 5,
        version: env!("CARGO_PKG_VERSION").into(),
        source_commit: "a".repeat(40),
        executable_sha256: "b".repeat(64),
        provider_protocol: if windows { 2 } else { 3 },
        native_protocols: if windows {
            NativeProviderProtocols::Windows {
                provider_contract: 3,
                public_wire: 2,
                private_wire: 2,
            }
        } else {
            NativeProviderProtocols::Linux {
                provider_contract: 3,
                launch_wire: 3,
            }
        },
        runtime_manifest_schema: 2,
        workload_contract_schema: 1,
        profile_catalog_sha256: "c".repeat(64),
        mechanism: "sealed-v2".into(),
        execution_report_schema: 4,
        plan_report_schema: 1,
        doctor_report_schema: 1,
        platform: platform(windows),
        compiled_metadata_valid: true,
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
        "schema_version",
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
fn flattened_inspections_preserve_all_versions_and_platforms_strictly() {
    for windows in [false, true] {
        let current = agent(windows);
        check(&current, windows);
        let previous = AgentPackageInspectionV4 {
            schema_version: 4,
            version: current.version.clone(),
            source_commit: current.source_commit.clone(),
            executable_sha256: current.executable_sha256.clone(),
            provider_protocol: 2,
            mechanism: current.mechanism.clone(),
            execution_report_schema: current.execution_report_schema,
            plan_report_schema: current.plan_report_schema,
            doctor_report_schema: current.doctor_report_schema,
            platform: current.platform.clone(),
            compiled_metadata_valid: true,
        };
        check(&previous, windows);
        let mut historical_platform = serde_json::to_value(&current.platform).unwrap();
        if windows {
            historical_platform
                .as_object_mut()
                .unwrap()
                .remove("target_desktop_bootstrap_runtime")
                .unwrap();
            historical_platform["target_desktop_bootstrap_crt_static"] = json!(true);
        }
        let historical = AgentPackageInspectionV3 {
            schema_version: 3,
            version: previous.version,
            source_commit: previous.source_commit,
            executable_sha256: previous.executable_sha256,
            provider_protocol: previous.provider_protocol,
            mechanism: previous.mechanism,
            execution_report_schema: previous.execution_report_schema,
            plan_report_schema: previous.plan_report_schema,
            doctor_report_schema: previous.doctor_report_schema,
            platform: serde_json::from_value(historical_platform).unwrap(),
            compiled_metadata_valid: true,
        };
        check(&historical, windows);
        let installed = InstalledProviderInspectionV5 {
            schema_version: 5,
            agent: current,
            installed_executable_sha256: "b".repeat(64),
            installed_artifacts_valid: true,
            provider_identity: Some("provider".into()),
            provider_reachable: true,
            qualification_complete: true,
            policy: InstalledPolicyObservationV1::Unconfigured,
            profile_qualification: QualificationArtifactReferenceV1 {
                schema_version: 1,
                artifact: "qualification.json".into(),
                qualified_target: "native-target".into(),
                qualifies_package_target: true,
            },
            diagnostic_qualification: None,
        };
        let wire = serde_json::to_value(&installed).unwrap();
        let decoded: InstalledProviderInspectionV5 = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
        let mut invalid = wire;
        invalid["unexpected"] = json!(true);
        assert!(serde_json::from_value::<InstalledProviderInspectionV5>(invalid).is_err());
    }
}

#[test]
fn nested_protocol_duplicate_fields_are_not_lost_to_buffering() {
    let wire = serde_json::to_string(&agent(false)).unwrap();
    let original = "\"launch_wire\":3";
    assert!(wire.contains(original));
    let duplicate = wire.replace(original, "\"launch_wire\":3,\"launch_wire\":3");
    assert!(
        serde_json::from_str::<AgentPackageInspectionV5>(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate field")
    );
}
