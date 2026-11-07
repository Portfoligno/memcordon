#![cfg(feature = "test-fixtures")]

#[path = "../src/bin/consumer_readiness_windows/descriptor.rs"]
pub mod descriptor;
use descriptor::{
    matched::{Binding, Lane, Scope},
    matched_plan::{Directory, DirectoryRole, Plan},
};

fn pair(restricted: bool, scope: Scope) -> (Plan, descriptor::Descriptor, descriptor::Descriptor) {
    let root = std::env::temp_dir().join("memcordon-matched-plan-model");
    let clock = descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 1000,
        qpc_frequency: 100,
    };
    let protected = restricted && scope == Scope::Envelope;
    let mut direct = descriptor::Descriptor {
        matched_control: Some(Binding {
            pair_sha256: [1; 32],
            lane: Lane::Direct,
            scope,
            input_sha256: [0; 32],
        }),
        provider_input_experiment: false,
        provider_input_paths: vec![],
        provider_input_binding: None,
        format: "memcordon.fixture-workload".into(),
        revision: descriptor::DESCRIPTOR_REVISION,
        case: if scope == Scope::BinaryFiles {
            descriptor::Case::BinaryFiles
        } else {
            descriptor::Case::Envelope
        },
        output_root: root.join("direct"),
        transcript: root.join("direct/events.bin"),
        challenge: vec![0, 255, 1],
        stdout: vec![],
        stderr: vec![],
        arguments: vec!["argument with space".into()],
        application_status: 0,
        churn_creations: descriptor::CHURN_CREATIONS,
        churn_live: descriptor::CHURN_LIVE,
        denied_write_paths: if protected {
            vec![
                root.join("driver/probe.bin"),
                root.join("provider/probe.bin"),
            ]
        } else {
            vec![]
        },
        sentinel_handles: vec![],
        descendant_gate: None,
        start_gate: Some("Local\\matched-model".into()),
        start_transport: descriptor::StartTransport::ControllerStdin {
            version: descriptor::controller_start::VERSION,
        },
        control_clock: Some(clock.clone()),
        winsock_registry: None,
        gate_access_diagnostic: None,
        gate_precondition: None,
        completion_gate: None,
        cohort_gate: None,
        generation_gate: None,
        toolchain: None,
    };
    let mut installed = direct.clone();
    installed.output_root = root.join("installed");
    installed.transcript = installed.output_root.join("events.bin");
    installed.matched_control.as_mut().unwrap().lane = Lane::Installed;
    let mut directories = vec![
        (DirectoryRole::Cwd, root.clone()),
        (DirectoryRole::DirectOutput, direct.output_root.clone()),
        (
            DirectoryRole::InstalledOutput,
            installed.output_root.clone(),
        ),
    ];
    if protected {
        directories.extend([
            (DirectoryRole::DriverParent, root.join("driver")),
            (DirectoryRole::ProviderParent, root.join("provider")),
        ]);
    }
    let mut plan = Plan {
        revision: 1,
        pair_sha256: [1; 32],
        input_sha256: [0; 32],
        scope,
        restricted,
        fixture_sha256: memcordon_core::hash_bytes(b"fixture").into(),
        cli_sha256: memcordon_core::hash_bytes(b"cli").into(),
        direct_descriptor: root.join("direct.json"),
        installed_descriptor: root.join("installed.json"),
        cwd: root.clone(),
        work_clock: clock,
        cleanup_cutoff_qpc: 2000,
        record: root.join("paired.json"),
        environment: vec![memcordon_core::WindowsEnvironmentEntryV1 {
            name: "SystemRoot".encode_utf16().collect(),
            value: "C:\\Windows".encode_utf16().collect(),
        }],
        directories: directories
            .into_iter()
            .enumerate()
            .map(|(index, (role, path))| Directory {
                role,
                path,
                volume_serial: 1,
                file_index: index as u64 + 1,
                attributes: 0x10,
                security_information: 23,
                security_bytes: 80,
                security_sha256: [8; 32],
            })
            .collect(),
    };
    bind(&mut plan, &mut direct, &mut installed);
    (plan, direct, installed)
}
fn bind(
    plan: &mut Plan,
    direct: &mut descriptor::Descriptor,
    installed: &mut descriptor::Descriptor,
) {
    plan.input_sha256 = plan.input_digest(direct).unwrap();
    for descriptor in [direct, installed] {
        descriptor.matched_control.as_mut().unwrap().input_sha256 = plan.input_sha256;
    }
}

#[test]
fn all_declared_stage1_pairs_bind_actual_directory_roles_to_one_input_digest() {
    for (restricted, scope) in [
        (false, Scope::BinaryFiles),
        (true, Scope::BinaryFiles),
        (false, Scope::Envelope),
        (true, Scope::Envelope),
    ] {
        let (plan, direct, installed) = pair(restricted, scope);
        plan.validate(&direct, &installed).unwrap();
        let derived = plan.direct_descriptor_for(&installed).unwrap();
        assert_eq!(derived.output_root, direct.output_root);
        assert_eq!(
            derived.transcript,
            direct.output_root.join("fixture-events.bin")
        );
        assert_eq!(derived.matched_control, direct.matched_control);
        assert_eq!(derived.arguments, direct.arguments);
        plan.validate(&derived, &installed).unwrap();
        let decoded: Plan = serde_json::from_slice(&serde_json::to_vec(&plan).unwrap()).unwrap();
        decoded.validate(&direct, &installed).unwrap();
    }
}
#[test]
fn missing_reordered_aliased_or_malformed_directory_witnesses_are_rejected() {
    let (original, direct, installed) = pair(true, Scope::Envelope);
    for field in [
        "missing",
        "order",
        "alias",
        "reparse",
        "device",
        "kind",
        "mask",
        "emptysecurity",
        "oversizedsecurity",
        "differentsecurity",
        "differentoutput",
        "protectedalias",
        "protectedpath",
    ] {
        let mut plan = original.clone();
        match field {
            "missing" => {
                plan.directories.pop();
            }
            "order" => plan.directories.swap(1, 2),
            "alias" => plan.directories[2].file_index = plan.directories[1].file_index,
            "reparse" => plan.directories[0].attributes |= 0x400,
            "device" => plan.directories[0].attributes |= 0x40,
            "kind" => plan.directories[0].attributes = 0,
            "mask" => plan.directories[0].security_information = 7,
            "emptysecurity" => plan.directories[0].security_bytes = 0,
            "oversizedsecurity" => plan.directories[0].security_bytes = 8193,
            "differentsecurity" => plan.directories[2].security_sha256[0] ^= 1,
            "differentoutput" => plan.directories[2].path = plan.cwd.join("other"),
            "protectedalias" => plan.directories[4].file_index = plan.directories[3].file_index,
            "protectedpath" => plan.directories[3].path = plan.cwd.join("other-parent"),
            _ => unreachable!(),
        }
        assert!(plan.validate(&direct, &installed).is_err(), "{field}");
    }
}
#[test]
fn digest_binds_executable_bytes_security_native_identity_arguments_data_and_environment() {
    let (original, direct, installed) = pair(true, Scope::Envelope);
    for field in [
        "fixture",
        "cli",
        "id",
        "security",
        "challenge",
        "arguments",
        "stdout",
        "stderr",
        "environment",
        "protected",
    ] {
        let mut plan = original.clone();
        let mut changed = direct.clone();
        match field {
            "fixture" => {
                plan.fixture_sha256 = memcordon_core::hash_bytes(b"changed fixture").into()
            }
            "cli" => plan.cli_sha256 = memcordon_core::hash_bytes(b"changed cli").into(),
            "id" => plan.directories[0].file_index += 1,
            "security" => plan.directories[0].security_sha256[0] ^= 1,
            "challenge" => changed.challenge.push(2),
            "arguments" => changed.arguments.push("changed".into()),
            "stdout" => changed.stdout.push(2),
            "stderr" => changed.stderr.push(2),
            "environment" => plan.environment[0].value.push(b'X' as u16),
            "protected" => {
                changed.denied_write_paths[0] = plan.directories[3].path.join("other.bin")
            }
            _ => unreachable!(),
        }
        assert_ne!(
            plan.input_digest(&changed).unwrap(),
            original.input_sha256,
            "{field}"
        );
        assert!(plan.validate(&changed, &installed).is_err(), "{field}");
    }
}
#[test]
fn protocol_identity_and_cutoffs_are_bound_separately_from_logical_inputs() {
    let (original, direct, installed) = pair(false, Scope::Envelope);
    let mut plan = original.clone();
    plan.pair_sha256 = [2; 32];
    plan.record = plan.cwd.join("other-record.json");
    plan.work_clock.work_cutoff_qpc += 1;
    plan.cleanup_cutoff_qpc += 1;
    assert_eq!(plan.input_digest(&direct).unwrap(), original.input_sha256);
    assert!(plan.validate(&direct, &installed).is_err());
    for field in ["frequency", "cleanup", "lane", "descriptor"] {
        let mut plan = original.clone();
        let mut changed = installed.clone();
        match field {
            "frequency" => plan.work_clock.qpc_frequency = 0,
            "cleanup" => plan.cleanup_cutoff_qpc = plan.work_clock.work_cutoff_qpc,
            "lane" => changed.matched_control.as_mut().unwrap().lane = Lane::Direct,
            "descriptor" => plan.installed_descriptor = plan.direct_descriptor.clone(),
            _ => unreachable!(),
        }
        assert!(plan.validate(&direct, &changed).is_err(), "{field}");
    }
}
#[test]
fn environment_is_complete_unique_and_canonical_in_the_input_hash() {
    let (original, direct, _) = pair(false, Scope::BinaryFiles);
    for field in ["missing", "duplicate", "alias", "nul"] {
        let mut plan = original.clone();
        match field {
            "missing" => plan.environment.clear(),
            "duplicate" => plan.environment.push(plan.environment[0].clone()),
            "alias" => {
                let mut entry = plan.environment[0].clone();
                entry.name = "SYSTEMROOT".encode_utf16().collect();
                plan.environment.push(entry)
            }
            "nul" => plan.environment[0].value.push(0),
            _ => unreachable!(),
        }
        assert!(plan.input_digest(&direct).is_err(), "{field}");
    }
    let mut plan = original.clone();
    plan.environment
        .push(memcordon_core::WindowsEnvironmentEntryV1 {
            name: vec![b'A' as u16],
            value: vec![],
        });
    let digest = plan.input_digest(&direct).unwrap();
    plan.environment.reverse();
    assert_eq!(plan.input_digest(&direct).unwrap(), digest);
}
#[test]
fn plan_wire_rejects_unknown_fields_and_unavailable_scopes() {
    let (plan, _, _) = pair(false, Scope::Envelope);
    for field in ["extra", "directory", "scope", "missing"] {
        let mut value = serde_json::to_value(&plan).unwrap();
        match field {
            "extra" => value["extra"] = true.into(),
            "directory" => value["directories"][0]["extra"] = true.into(),
            "scope" => value["scope"] = "joint".into(),
            "missing" => {
                value.as_object_mut().unwrap().remove("directories");
            }
            _ => unreachable!(),
        }
        assert!(serde_json::from_value::<Plan>(value).is_err(), "{field}");
    }
}
