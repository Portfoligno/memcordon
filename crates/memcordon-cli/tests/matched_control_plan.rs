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
        case: match scope {
            Scope::BinaryFiles => descriptor::Case::BinaryFiles,
            Scope::Envelope => descriptor::Case::Envelope,
            Scope::JointListenerPrefix | Scope::ProviderListenerSelection => {
                descriptor::Case::Joint
            }
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
            version: if scope == Scope::JointListenerPrefix {
                descriptor::controller_start::REGISTRY_VERSION
            } else {
                descriptor::controller_start::VERSION
            },
        },
        control_clock: Some(clock.clone()),
        winsock_registry: (scope == Scope::JointListenerPrefix).then_some(
            descriptor::winsock_registry::Declaration {
                version: descriptor::winsock_registry::VERSION,
                view: descriptor::winsock_registry::View::Native,
                sha256: [9; 32],
            },
        ),
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
        provider: None,
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

fn provider_pair() -> (Plan, descriptor::Descriptor, descriptor::Descriptor) {
    use descriptor::matched_plan::{ProviderControl, ProviderInput};
    use memcordon_platform::windows_private_fixture_binding::{
        DotLocalInput, PrivateFixtureAncestor, PrivateFixtureBinding,
    };
    let (mut plan, mut direct, mut installed) = pair(false, Scope::JointListenerPrefix);
    fn identity(path: &std::path::Path) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut hash);
        hash.finish().max(1)
    }
    let chain = |path: &std::path::Path| {
        path.ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|path| PrivateFixtureAncestor {
                path: path.to_owned(),
                volume_serial: 1,
                file_index: identity(path),
                attributes: 0x10,
            })
            .collect::<Vec<_>>()
    };
    let parent = plan.cwd.join("inputs");
    let fixture = parent.join("fixture.exe");
    let local = parent.join("fixture.exe.local");
    let provider_path = local.join("provider.dll");
    let binding = PrivateFixtureBinding {
        revision: 2,
        fixture: fixture.clone(),
        volume_serial: 1,
        file_index: identity(&fixture),
        attributes: 0x20,
        links: 1,
        bytes: 4096,
        sha256: plan.fixture_sha256.clone(),
        native_path_utf16: "\\Device\\Model\\inputs\\fixture.exe"
            .encode_utf16()
            .collect(),
        ancestors: chain(&parent),
        local_input: DotLocalInput::Directory(PrivateFixtureAncestor {
            path: local.clone(),
            volume_serial: 1,
            file_index: identity(&local),
            attributes: 0x10,
        }),
        output_ancestors: chain(&direct.output_root),
    };
    let mut installed_binding = binding.clone();
    installed_binding.output_ancestors = chain(&installed.output_root);
    let control = ProviderControl {
        direct: binding,
        installed: installed_binding,
        paths: vec![fixture, provider_path.clone()],
        providers: vec![ProviderInput {
            path: provider_path.clone(),
            original_path: "C:\\Windows\\provider.dll".encode_utf16().collect(),
            private_native_path: "\\Device\\Model\\inputs\\fixture.exe.local\\provider.dll"
                .encode_utf16()
                .collect(),
            volume_serial: 1,
            file_index: identity(&provider_path),
            bytes: 8192,
            sha256: "ab".repeat(32),
        }],
    };
    plan.scope = Scope::ProviderListenerSelection;
    for (descriptor, binding) in [
        (&mut direct, &control.direct),
        (&mut installed, &control.installed),
    ] {
        descriptor.matched_control.as_mut().unwrap().scope = plan.scope;
        descriptor.provider_input_experiment = true;
        descriptor.provider_input_paths = control.paths.clone();
        descriptor.provider_input_binding = Some(binding.clone());
        descriptor.start_transport = descriptor::StartTransport::ControllerStdin {
            version: descriptor::controller_start::PRIVATE_VERSION,
        };
    }
    plan.provider = Some(control);
    for directory in &mut plan.directories {
        let control = plan.provider.as_ref().unwrap();
        let native = control
            .direct
            .output_ancestors
            .iter()
            .chain(&control.installed.output_ancestors)
            .find(|native| native.path == directory.path)
            .unwrap();
        directory.volume_serial = u64::from(native.volume_serial);
        directory.file_index = native.file_index;
    }
    bind(&mut plan, &mut direct, &mut installed);
    (plan, direct, installed)
}

#[test]
fn provider_control_binds_shared_immutable_inputs_and_distinct_output_owners() {
    let (plan, direct, installed) = provider_pair();
    plan.validate(&direct, &installed).unwrap();
    let derived = plan.direct_descriptor_for(&installed).unwrap();
    assert_eq!(
        derived.provider_input_binding,
        direct.provider_input_binding
    );
    assert_ne!(
        derived.provider_input_binding,
        installed.provider_input_binding
    );
    let mut inconsistent = plan.clone();
    let mut changed_direct = direct.clone();
    let mut changed_installed = installed.clone();
    inconsistent.directories[1].file_index ^= 1;
    bind(
        &mut inconsistent,
        &mut changed_direct,
        &mut changed_installed,
    );
    assert!(
        inconsistent
            .validate(&changed_direct, &changed_installed)
            .is_err(),
        "rehashed output native identity contradicts lane metadata"
    );
    for field in [
        "missing",
        "scope",
        "fixture_identity",
        "local_identity",
        "output_alias",
        "provider_identity",
        "provider_hash",
        "provider_path",
        "native_path",
        "duplicate",
        "too_many",
        "empty",
        "descriptor_binding",
    ] {
        let mut changed = plan.clone();
        let mut target = installed.clone();
        match field {
            "missing" => changed.provider = None,
            "scope" => changed.scope = Scope::JointListenerPrefix,
            "fixture_identity" => changed.provider.as_mut().unwrap().installed.file_index += 1,
            "local_identity" => if let memcordon_platform::windows_private_fixture_binding::DotLocalInput::Directory(local) = &mut changed.provider.as_mut().unwrap().installed.local_input { local.file_index += 1; },
            "output_alias" => changed.provider.as_mut().unwrap().installed.output_ancestors = changed.provider.as_ref().unwrap().direct.output_ancestors.clone(),
            "provider_identity" => changed.provider.as_mut().unwrap().providers[0].file_index += 1,
            "provider_hash" => changed.provider.as_mut().unwrap().providers[0].sha256 = "cd".repeat(32),
            "provider_path" => changed.provider.as_mut().unwrap().providers[0].path = plan.cwd.join("unowned.dll"),
            "native_path" => changed.provider.as_mut().unwrap().providers[0].private_native_path.clear(),
            "duplicate" => { let original=changed.provider.as_ref().unwrap().providers[0].clone(); changed.provider.as_mut().unwrap().providers.push(original); },
            "too_many" => { let original=changed.provider.as_ref().unwrap().providers[0].clone(); changed.provider.as_mut().unwrap().providers = vec![original;9]; },
            "empty" => changed.provider.as_mut().unwrap().providers.clear(),
            "descriptor_binding" => target.provider_input_binding = direct.provider_input_binding.clone(),
            _=>unreachable!(),
        }
        assert!(changed.validate(&direct, &target).is_err(), "{field}");
        if matches!(field, "provider_identity" | "provider_hash") {
            assert_ne!(
                plan.input_digest(&direct).unwrap(),
                changed.input_digest(&direct).unwrap()
            );
        }
    }
    let old = pair(false, Scope::BinaryFiles).0;
    assert!(
        serde_json::to_value(&old)
            .unwrap()
            .get("provider")
            .is_none()
    );
    for field in ["fixture", "local", "ancestor", "output", "native_relative"] {
        let mut control = plan.provider.clone().unwrap();
        let identity = match field {
            "fixture" => (control.direct.volume_serial, control.direct.file_index),
            "local" => control.direct.local_input.identity(),
            "ancestor" => {
                let item = control.direct.ancestors.last().unwrap();
                (item.volume_serial, item.file_index)
            }
            "output" => {
                let item = control.installed.output_ancestors.last().unwrap();
                (item.volume_serial, item.file_index)
            }
            "native_relative" => {
                control.providers[0].private_native_path = vec![65];
                (
                    control.providers[0].volume_serial,
                    control.providers[0].file_index,
                )
            }
            _ => unreachable!(),
        };
        (
            control.providers[0].volume_serial,
            control.providers[0].file_index,
        ) = identity;
        assert!(
            control
                .validate(&direct.output_root, &installed.output_root)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn all_declared_stage1_pairs_bind_actual_directory_roles_to_one_input_digest() {
    for (restricted, scope) in [
        (false, Scope::BinaryFiles),
        (true, Scope::BinaryFiles),
        (false, Scope::Envelope),
        (true, Scope::Envelope),
        (false, Scope::JointListenerPrefix),
        (true, Scope::JointListenerPrefix),
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
fn listener_prefix_requires_exact_registry_and_start_scope_without_private_or_joint_claims() {
    let (plan, direct, installed) = pair(true, Scope::JointListenerPrefix);
    for field in [
        "registry",
        "registry_digest",
        "registry_version",
        "start",
        "case",
        "private",
        "scope",
        "arguments",
        "environment",
    ] {
        let mut altered = installed.clone();
        let mut changed_plan = plan.clone();
        match field {
            "registry" => altered.winsock_registry = None,
            "registry_digest" => altered.winsock_registry.as_mut().unwrap().sha256[0] ^= 1,
            "registry_version" => altered.winsock_registry.as_mut().unwrap().version = 0,
            "start" => {
                altered.start_transport = descriptor::StartTransport::ControllerStdin {
                    version: descriptor::controller_start::VERSION,
                }
            }
            "case" => altered.case = descriptor::Case::Envelope,
            "private" => altered.provider_input_experiment = true,
            "scope" => altered.matched_control.as_mut().unwrap().scope = Scope::Envelope,
            "arguments" => altered.arguments.push("undeclared".into()),
            "environment" => changed_plan.environment[0].value.push(b'x' as u16),
            _ => unreachable!(),
        }
        assert!(changed_plan.validate(&direct, &altered).is_err(), "{field}");
    }
    let mut changed = direct.clone();
    changed.winsock_registry.as_mut().unwrap().sha256[0] ^= 1;
    assert_ne!(
        plan.input_digest(&direct).unwrap(),
        plan.input_digest(&changed).unwrap()
    );
}

#[cfg(windows)]
#[test]
fn native_probe_cleanup_rejects_a_replacement_directory_and_preserves_both_objects() {
    use descriptor::matched_plan::{hold_chain, remove_empty_directory};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("probe");
    let original_path = root.path().join("retained-original");
    std::fs::create_dir(&path).unwrap();
    let cutoff = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut guards = hold_chain(&path, cutoff).unwrap();
    let original = memcordon_testkit::windows_held_file_metadata(guards.last().unwrap()).unwrap();
    let identity = (original.volume_serial, original.file_index);
    // Release only the original leaf; keep every original ancestor pinned.
    drop(guards.pop());
    std::fs::rename(&path, &original_path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let mut replacement_guards = hold_chain(&path, cutoff).unwrap();
    let replacement =
        memcordon_testkit::windows_held_file_metadata(replacement_guards.last().unwrap()).unwrap();
    let replacement_identity = (replacement.volume_serial, replacement.file_index);
    assert_ne!(identity, replacement_identity);
    drop(replacement_guards.pop());
    assert!(remove_empty_directory(&path, identity, cutoff).is_err());
    assert!(path.is_dir());
    assert!(original_path.is_dir());
    let replacement_after = hold_chain(&path, cutoff).unwrap();
    let actual =
        memcordon_testkit::windows_held_file_metadata(replacement_after.last().unwrap()).unwrap();
    assert_eq!(
        (actual.volume_serial, actual.file_index),
        replacement_identity
    );
    drop(replacement_after);
    drop(replacement_guards);
    drop(guards);
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
fn a_single_native_tick_change_in_either_lane_is_rejected() {
    let (plan, direct, installed) = pair(false, Scope::BinaryFiles);
    plan.validate(&direct, &installed).unwrap();
    for lane in [Lane::Direct, Lane::Installed] {
        let mut changed_direct = direct.clone();
        let mut changed_installed = installed.clone();
        let changed = match lane {
            Lane::Direct => &mut changed_direct,
            Lane::Installed => &mut changed_installed,
        };
        changed.control_clock.as_mut().unwrap().work_cutoff_qpc += 1;
        assert!(
            plan.validate(&changed_direct, &changed_installed).is_err(),
            "a one-tick {lane:?} clock mutation must not alter the frozen plan"
        );
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
