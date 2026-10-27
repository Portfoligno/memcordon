use memcordon_readiness_verifier::{
    sha256, validate_linux_export_outcome, validate_linux_export_permission_settlement,
    validate_linux_export_source,
};
use serde_json::{Value, json};

#[test]
fn export_memory_receipt_cannot_replace_image_charge_headroom_or_source() {
    for field in [
        "image_bytes",
        "rounded_image_bytes",
        "headroom_bytes",
        "limit_bytes",
        "page_bytes",
        "runtime_image",
    ] {
        let mut case = linux_export_case::finish(linux_export_case::original_graph("symlink"));
        case.validate().unwrap();
        case.mutate(
            "installed/mixed-cases/image-cases/export-symlink/fixture-memory-budget.json",
            |receipt| receipt["budget"][field] = json!(1),
        );
        assert!(case.validate().is_err(), "accepted changed fixture {field}");
    }
    for field in ["source", "cell", "lease_id", "key"] {
        let mut case = linux_export_case::finish(linux_export_case::original_graph("symlink"));
        case.mutate(
            "installed/mixed-cases/image-cases/export-symlink/fixture-memory-budget.json",
            |receipt| receipt[field] = json!("unrelated"),
        );
        assert!(
            case.validate().is_err(),
            "accepted unrelated fixture {field}"
        );
    }
}
#[path = "support/linux_export_case.rs"]
mod linux_export_case;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_prepared_case.rs"]
mod linux_prepared_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;

#[test]
fn fifo_administrative_setup_must_join_original_attempt_target_source_and_account() {
    let factory = || linux_export_case::finish(linux_export_case::fifo_graph());
    factory().validate().unwrap();
    let prefix = "installed/mixed-cases/image-cases/export-fifo";
    for (field, value) in [
        ("format", json!("memcordon.linux-native-export-device")),
        ("attempt_id", json!("f".repeat(32))),
        ("target_pid", json!(999)),
        ("target_birth", json!(999)),
        ("root_device", json!(999)),
        ("root_inode", json!(999)),
        ("work_device", json!(0)),
        ("work_inode", json!(0)),
        ("device", json!(999)),
        ("inode", json!(999)),
        ("mode", json!(0o100600)),
        ("links", json!(2)),
        ("rdev", json!(259)),
        ("uid", json!(0)),
        ("gid", json!(0)),
        ("path", json!("/work/unrelated")),
        ("held_live_before_and_after", json!(false)),
    ] {
        let mut case = factory();
        case.mutate(&format!("{prefix}/fifo-created.json"), |setup| {
            setup[field] = value
        });
        assert!(
            case.validate().is_err(),
            "accepted FIFO setup substitution {field}"
        );
    }
    for (field, value) in [
        ("mode", json!(0o100600)),
        ("uid", json!(0)),
        ("gid", json!(0)),
        ("nlink", json!(2)),
        ("inode", json!(999)),
    ] {
        let mut case = factory();
        case.mutate(&format!("{prefix}/native-export-source.json"), |source| {
            source[field] = value
        });
        assert!(
            case.validate().is_err(),
            "accepted FIFO source substitution {field}"
        );
    }
    let case = linux_export_case::finish(linux_export_case::original_graph("fifo"));
    assert!(
        case.validate().is_err(),
        "readiness without actual administrative setup is not creation proof"
    );
    let mut case = factory();
    case.mutate(&format!("{prefix}/ready.json"), |ready| {
        ready["observation"]["kind"] = json!("fifo")
    });
    assert!(
        case.validate().is_err(),
        "fixture readiness must explicitly request administrative FIFO setup"
    );
}

#[test]
fn special_object_closure_requires_three_distinct_ordered_successful_native_closes() {
    for scenario in ["fifo", "device"] {
        let factory = || {
            linux_export_case::finish(if scenario == "fifo" {
                linux_export_case::fifo_graph()
            } else {
                linux_export_case::device_graph()
            })
        };
        factory().validate().unwrap();
        let path = format!(
            "installed/mixed-cases/image-cases/export-{scenario}/{scenario}-admin-handles-retired.json"
        );
        let mut missing = if scenario == "fifo" {
            linux_export_case::fifo_graph()
        } else {
            linux_export_case::device_graph()
        };
        missing
            .evidence
            .external
            .remove(&format!("{scenario}-admin-handles-retired.json"));
        assert!(linux_export_case::finish(missing).validate().is_err());
        for mutation in 0..7 {
            let mut case = factory();
            case.mutate(&path, |closure| match mutation {
                0 => { closure["closures"].as_array_mut().unwrap().pop(); },
                1 => closure["closures"][2] = closure["closures"][0].clone(),
                2 => closure["closures"][1]["native_close_succeeded"] = json!(false),
                3 => closure["closures"][1]["native_close_errno"] = json!(5),
                4 => closure["attempt_id"] = json!("f".repeat(32)),
                5 => closure["before_root_release"] = json!(false),
                _ => closure["closures"] = json!([{"completed":true,"errno":null},{"completed":true,"errno":null},{"completed":true,"errno":null}]),
            });
            assert!(
                case.validate().is_err(),
                "accepted {scenario} closure mutation {mutation}"
            );
        }
    }
}

#[test]
fn complete_export_records_require_original_native_retirement_and_recovery() {
    for scenario in [
        "symlink",
        "fifo",
        "socket",
        "traversal",
        "device",
        "concurrent-writer",
    ] {
        let factory = || match scenario {
            "device" => linux_export_case::device_graph(),
            "fifo" => linux_export_case::fifo_graph(),
            "concurrent-writer" => linux_export_case::concurrent_graph(),
            _ => linux_export_case::original_graph(scenario),
        };
        let mut case = linux_export_case::finish(factory());
        case.validate().unwrap();
        let prefix = format!("installed/mixed-cases/image-cases/export-{scenario}");
        case.mutate(&format!("{prefix}/export-recovery.json"), |raw| {
            raw["held_retirement"][0]["nlink"] = json!(1)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} accepted still-linked original allocation owner"
        );
        let mut case = linux_export_case::finish(factory());
        case.mutate(&format!("{prefix}/export-recovery.json"), |raw| {
            raw["before_paths"] = json!([]);
            raw["after_absence"] = json!([]);
            raw["held_retirement"] = json!([]);
        });
        assert!(
            case.validate().is_err(),
            "{scenario} omitted actual original journal allocations"
        );
        let mut case = linux_export_case::finish(factory());
        case.mutate(&format!("{prefix}/export-worker.json"), |raw| {
            raw["worker"]["birth"] = json!(301)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} reassociated original native export worker"
        );
        let mut case = linux_export_case::finish(factory());
        case.mutate(&format!("{prefix}/export-recovery.json"), |raw| {
            raw["reservation_parents"][4]["inode"] = json!(999);
            raw["reservation_parents"][4]["named_inode"] = json!(999);
        });
        assert!(
            case.validate().is_err(),
            "{scenario} reassociated held native journal parent"
        );
        let graph = factory();
        let request = graph.evidence.provider_request.clone();
        let mut case = linux_export_case::finish(graph);
        case.mutate(&request, |raw| {
            raw["attempt_deadline_millis"] = json!(59999)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} accepted another outer public time budget"
        );
        for foreign_frontend in [false, true] {
            let mut case = linux_export_case::finish(factory());
            case.mutate(&format!("{prefix}/export-worker.json"), |raw| {
                let bytes: Vec<u8> = serde_json::from_value(raw["journal_bytes"].clone()).unwrap();
                let body = bytes
                    .split(|byte| *byte == b'\n')
                    .nth(3)
                    .unwrap()
                    .strip_prefix(b"payload=")
                    .unwrap();
                let mut journal: serde_json::Value = serde_json::from_slice(body).unwrap();
                if foreign_frontend {
                    journal["frontend"]["start_time"] = json!(999);
                } else {
                    journal["mixed_export_intent"] =
                        json!("/var/lib/memcordon/sealed/foreign-export");
                }
                let bytes = linux_prepared_case::durable_journal(&journal);
                raw["journal_sha256"] = json!(sha256(&bytes));
                raw["journal_bytes"] = json!(bytes);
            });
            assert!(
                case.validate().is_err(),
                "{scenario} accepted foreign frontend/later pre-release authority"
            );
        }
        if scenario == "concurrent-writer" {
            let mut case = linux_export_case::finish(factory());
            case.mutate(&format!("{prefix}/external-helper-settled.json"), |raw| {
                raw["permission_answer"]["fan_allow_written"] = json!(false)
            });
            assert!(
                case.validate().is_err(),
                "concurrent export omitted actual kernel permission settlement"
            );
        }
        if scenario == "device" {
            let mut case = linux_export_case::finish(factory());
            case.mutate(
                &format!("{prefix}/device-admin-handles-retired.json"),
                |raw| raw["closures"][1]["completed"] = json!(false),
            );
            assert!(
                case.validate().is_err(),
                "device export left actual controller capability open"
            );
        }
    }
}

// Independent codec vectors. Native execution evidence is acquired by the producer.
#[test]
fn all_six_export_effects_require_native_object_and_original_authorized_cause() {
    for (scenario, kind) in [
        ("symlink", 0o120000),
        ("traversal", 0o120000),
        ("fifo", 0o010000),
        ("device", 0o020000),
        ("socket", 0o140000),
        ("concurrent-writer", 0o100000),
    ] {
        let cause = linux_export_case::native_cause(scenario);
        let prepared = json!({"attempt_id":"attempt","target":{"process_id":101,"birth":123},"root_device":7,"root_inode":8});
        let account = json!({"uid":61001,"gid":61001});
        let source = json!({"format":"memcordon.linux-export-native-source","revision":1,"scenario":scenario,"attempt_id":"attempt","target":prepared["target"],"root_device":7,"root_inode":8,
            "member":if scenario=="traversal"{"parent"}else{"exported.bin"},"device":7,"inode":9,"mode":kind|0o600,"uid":if scenario=="device"{0}else{61001},"gid":if scenario=="device"{0}else{61001},"nlink":1,"length":32,"ctime_seconds":100,"ctime_nanoseconds":1,
            "symlink_target":match scenario{"symlink"=>json!("/owned-source/Cargo.toml"),"traversal"=>json!("/work/other"),_=>Value::Null},"exclusive_uid":61001,"exclusive_gid":61001});
        validate_linux_export_source(scenario, &source, &prepared, &account).unwrap();
        for (field, value) in [
            ("mode", json!(0o040700)),
            ("uid", json!(61002)),
            ("root_inode", json!(10)),
            ("ctime_nanoseconds", json!(1_000_000_000)),
            ("nlink", json!(0)),
        ] {
            let mut hostile = source.clone();
            hostile[field] = value;
            assert!(
                validate_linux_export_source(scenario, &hostile, &prepared, &account).is_err(),
                "{scenario} accepted {field}"
            );
        }
        let result = json!({"format":"memcordon.result","revision":2,"tool":{},"invocation":{},"delivery":{},"frontend":{"relay_drained":true,"interruption":null,"relay_error":null},"wrapper_status":125,
            "runtime":{"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,"outcome":{"kind":"indeterminate","attempt_id":"attempt","request_sha256":"digest","retained_obligations":{"authorization":"authorized","obligations":[cause]}}}});
        assert_eq!(
            validate_linux_export_outcome(scenario, &result, "attempt", "digest", 125).unwrap(),
            cause
        );
        for (pointer, value) in [
            ("/runtime/outcome/kind", json!("executed")),
            ("/runtime/outcome/attempt_id", json!("other")),
            ("/runtime/outcome/request_sha256", json!("other-request")),
            ("/runtime/carrier_revision", json!(0)),
            ("/frontend/relay_drained", json!(false)),
            ("/frontend/relay_error", json!("unsettled original relay")),
            (
                "/runtime/outcome/retained_obligations/authorization",
                json!("never-authorized"),
            ),
            (
                "/runtime/outcome/retained_obligations/obligations",
                json!(["selected output missing"]),
            ),
            ("/wrapper_status", json!(0)),
        ] {
            let mut hostile = result.clone();
            *hostile.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_linux_export_outcome(scenario, &hostile, "attempt", "digest", 125)
                    .is_err(),
                "{scenario} accepted {pointer}"
            );
        }
        let prefix = concat!(
            "retire mixed native execution: ",
            "export mixed private root: ",
            "export selected private root outputs: "
        );
        let mut changed_causes = vec![
            cause.replacen(
                "retire mixed native execution: ",
                "retire unrelated native execution: ",
                1,
            ),
            cause.replacen(
                "export mixed private root: ",
                "export unrelated private root: ",
                1,
            ),
            cause.replacen(
                "export selected private root outputs: ",
                "export unselected private root outputs: ",
                1,
            ),
            cause
                .strip_prefix("retire mixed native execution: ")
                .unwrap()
                .to_owned(),
            cause.strip_prefix(prefix).unwrap().to_owned(),
            format!("retire mixed native execution: {cause}"),
            format!("unexpected {cause}"),
            format!("{cause}\n"),
        ];
        if matches!(scenario, "symlink" | "traversal" | "socket") {
            changed_causes.push(cause.replacen(
                "from writable mount work:",
                "from writable mount other:",
                1,
            ));
            changed_causes.push(cause.replacen(
                "selected output work/",
                "selected output other/",
                1,
            ));
            changed_causes.push(cause.replacen(
                if scenario == "socket" {
                    "(os error 6)"
                } else {
                    "(os error 40)"
                },
                "(os error 1)",
                1,
            ));
            changed_causes.push(
                if scenario == "socket" {
                    "No such device or address (os error 6)"
                } else {
                    "Too many levels of symbolic links (os error 40)"
                }
                .to_owned(),
            );
        }
        if matches!(scenario, "symlink" | "traversal") {
            changed_causes.push(
                linux_export_case::native_cause(if scenario == "symlink" {
                    "traversal"
                } else {
                    "symlink"
                })
                .to_owned(),
            );
        }
        for changed in changed_causes {
            let mut hostile = result.clone();
            hostile["runtime"]["outcome"]["retained_obligations"]["obligations"] = json!([changed]);
            assert!(
                validate_linux_export_outcome(scenario, &hostile, "attempt", "digest", 125)
                    .is_err(),
                "{scenario} accepted altered full native cause"
            );
        }
        let mut additional = result.clone();
        additional["runtime"]["outcome"]["retained_obligations"]["obligations"] =
            json!([cause, "unrelated retained obligation"]);
        assert!(
            validate_linux_export_outcome(scenario, &additional, "attempt", "digest", 125).is_err()
        );
        let mut hostile = result;
        hostile["runtime"]["outcome"]["forged_retirement"] = json!(true);
        assert!(
            validate_linux_export_outcome(scenario, &hostile, "attempt", "digest", 125).is_err()
        );
    }
}

#[test]
fn post_empty_permission_graph_rejects_rehashed_live_owner_and_incomplete_ordered_closure() {
    let challenge = "a".repeat(64);
    let event_id = "b".repeat(64);
    let source = json!({"device":7,"inode":8,"uid":61001,"gid":61001,"length":32,"ctime_seconds":100,"ctime_nanoseconds":1});
    let worker = json!({"pid":201,"birth":301,"image_sha256":"c".repeat(64)});
    let group = json!({"device":9,"inode":10,"native_links":0,"filesystem":"cgroup2","kind":"removed-held-inode"});
    let setup = json!({"format":"memcordon.native-export-permission-setup","revision":1,"challenge_hex":challenge,"work_unix_ms":100,"cleanup_unix_ms":200,"source":source,"cgroup":{"device":9,"inode":10},"worker":worker});
    let event = json!({"format":"memcordon.native-export-permission-event","revision":1,"event_id":event_id,"challenge_hex":challenge,"source":source,"worker":worker,"cgroup_retirement":group});
    let prepared = json!({"admission":{"attempt_id":"1".repeat(32)},"target":{"pid":101,"birth":201},"namespace_init":{"pid":102,"birth":202},"guardian":{"pid":103,"birth":203}});
    let mut family = json!({"format":"memcordon.linux-export-native-family-retirement","revision":1,"prepared":prepared,"challenge_hex":challenge});
    for role in ["target", "namespace_init", "guardian"] {
        family[role] = json!({"pid":prepared[role]["pid"],"birth":prepared[role]["birth"],"parent_pid":null,"parent_birth":null,"retirement_observed":true});
    }
    let cgroup = json!({"format":"memcordon.linux-export-native-cgroup-retirement","revision":1,"attempt_id":"1".repeat(32),"prepared":prepared,"held":group,"parent":{"path":"/sys/fs/cgroup/memcordon-sealed","device":9,"inode":11,"uid":0,"mode":0o040700},"named_attempt_errno":2});
    let family_bytes = serde_json::to_vec(&family).unwrap();
    let cgroup_bytes = serde_json::to_vec(&cgroup).unwrap();
    let ack = json!({"format":"memcordon.native-export-permission-ack","revision":1,"event_id":event_id,"challenge_hex":challenge,"source_device":7,"source_inode":8,"worker_pid":201,"worker_birth":301,"family_retirement_sha256":sha256(&family_bytes),"cgroup_retirement_sha256":sha256(&cgroup_bytes),"retirement_kind":"removed-held-inode"});
    let settled = json!({"format":"memcordon.native-export-permission-settled","revision":1,"challenge_hex":challenge,"work_unix_ms":100,"cleanup_unix_ms":200,
        "permission_answer":{"attempted":true,"fan_allow_written":true},"mark_installed":true,"unmark":{"attempted":true,"completed":true,"errno":null},
        "closures":(["event","event-pidfd","worker-pidfd","group","source","cgroup"].into_iter().map(|role|json!({"role":role,"attempted":true,"completed":true,"errno":null})).collect::<Vec<_>>()),
        "operation":{"event_id":event_id,"before_length":32,"after_length":64,"before_ctime_seconds":100,"before_ctime_nanoseconds":1,"after_ctime_seconds":101,"after_ctime_nanoseconds":2,"family_retirement_sha256":sha256(&family_bytes),"cgroup_retirement_sha256":sha256(&cgroup_bytes),"cgroup_retirement":group},"operation_error":null,"settlement_errors":[]});
    validate_linux_export_permission_settlement(
        &setup,
        &event,
        &ack,
        &settled,
        &family_bytes,
        &cgroup_bytes,
    )
    .unwrap();
    let validate_removal = |removal: Value| {
        let mut event = event.clone();
        event["cgroup_retirement"] = removal.clone();
        let mut cgroup = cgroup.clone();
        cgroup["held"] = removal.clone();
        let cgroup_bytes = serde_json::to_vec(&cgroup).unwrap();
        let mut ack = ack.clone();
        ack["cgroup_retirement_sha256"] = json!(sha256(&cgroup_bytes));
        let mut settled = settled.clone();
        settled["operation"]["cgroup_retirement"] = removal;
        settled["operation"]["cgroup_retirement_sha256"] = json!(sha256(&cgroup_bytes));
        validate_linux_export_permission_settlement(
            &setup,
            &event,
            &ack,
            &settled,
            &family_bytes,
            &cgroup_bytes,
        )
    };
    let mut kernfs_removed = group.clone();
    kernfs_removed["native_links"] = json!(2);
    kernfs_removed["handle_retirement"] = json!({
        "handle_type":254,"handle_bytes":8,"handle_id":10,"mount_id":17,"open_errno":116
    });
    validate_removal(kernfs_removed.clone()).unwrap();
    for (field, invalid) in [
        ("handle_type", json!(1)),
        ("handle_bytes", json!(16)),
        ("handle_id", json!(11)),
        ("mount_id", json!(0)),
        ("open_errno", json!(2)),
        ("open_errno", json!(1)),
    ] {
        let mut invalid_removal = kernfs_removed.clone();
        invalid_removal["handle_retirement"][field] = invalid;
        assert!(
            validate_removal(invalid_removal).is_err(),
            "accepted {field}"
        );
    }
    kernfs_removed
        .as_object_mut()
        .unwrap()
        .remove("handle_retirement");
    assert!(validate_removal(kernfs_removed).is_err());
    for pointer in [
        "/permission_answer/fan_allow_written",
        "/unmark/completed",
        "/closures/3/completed",
    ] {
        let mut hostile = settled.clone();
        *hostile.pointer_mut(pointer).unwrap() = json!(false);
        assert!(
            validate_linux_export_permission_settlement(
                &setup,
                &event,
                &ack,
                &hostile,
                &family_bytes,
                &cgroup_bytes
            )
            .is_err(),
            "accepted {pointer}"
        );
    }
    let mut reordered = settled.clone();
    reordered["closures"].as_array_mut().unwrap().swap(3, 4);
    assert!(
        validate_linux_export_permission_settlement(
            &setup,
            &event,
            &ack,
            &reordered,
            &family_bytes,
            &cgroup_bytes
        )
        .is_err()
    );
    for mutate_family in [true, false] {
        let mut hostile_family = family.clone();
        let mut hostile_cgroup = cgroup.clone();
        if mutate_family {
            hostile_family["target"]["retirement_observed"] = json!(false);
        } else {
            hostile_cgroup["named_attempt_errno"] = json!(0);
        }
        let family_bytes = serde_json::to_vec(&hostile_family).unwrap();
        let cgroup_bytes = serde_json::to_vec(&hostile_cgroup).unwrap();
        let mut ack = ack.clone();
        let mut settled = settled.clone();
        for field in ["family_retirement_sha256", "cgroup_retirement_sha256"] {
            let digest = sha256(if field == "family_retirement_sha256" {
                &family_bytes
            } else {
                &cgroup_bytes
            });
            ack[field] = json!(digest);
            settled["operation"][field] = json!(digest);
        }
        assert!(
            validate_linux_export_permission_settlement(
                &setup,
                &event,
                &ack,
                &settled,
                &family_bytes,
                &cgroup_bytes
            )
            .is_err()
        );
    }
}

#[test]
fn public_native_launch_checks_exact_memory_and_preserves_frozen_optional_fixture_semantics() {
    use memcordon_readiness_verifier::{
        CaseKey, EvidenceClass, FixtureInput, NativeArguments, NativeEnvironment,
        validate_linux_mixed_public_arguments, validate_linux_mixed_public_invocation,
    };
    let reference = |id: &str, byte: u8| json!({"id":id,"digest":hex::encode([byte;32])});
    let contract = json!({"schema_version":3,"workload_plan_digest":"01".repeat(32),
        "authorized_profile":{"id":"linux-tcp4-unix-private-v1","semantic_digest":"02".repeat(32)},
        "authorization":{"grant_id":"combined-grant","grant_revision":1,"approved_plan_digest":"01".repeat(32)},
        "ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain","requirements":[],
        "execution_identity":{"identity":reference("account",3),"exclusive_use_policy":reference("exclusive",4)},
        "runtime_image":reference("toolchain",5),"input_image":reference("fixture",6),"root_layout":reference("root",7),
        "launch":{"entrypoint":"owned-readiness","working_directory":"work"},"expected_epoch":{"service_instance":vec![8u8;16],"revision":1}});
    let actual: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(contract.clone()).unwrap();
    actual.validate().unwrap();
    let request = serde_json::to_vec(&contract).unwrap();
    let request_digest = actual.digest().unwrap().bytes().to_vec();
    let arguments = vec![
        b"export-object".to_vec(),
        b"challenge".to_vec(),
        b"fifo".to_vec(),
    ];
    let encode = |memory: Option<u64>| {
        fn value(bytes: &mut Vec<u8>, value: &[u8]) {
            bytes.extend((value.len() as u32).to_be_bytes());
            bytes.extend(value);
        }
        let mut bytes = Vec::new();
        bytes.extend(3u16.to_be_bytes());
        bytes.extend(0u64.to_be_bytes());
        value(&mut bytes, b"owned-readiness");
        bytes.extend((arguments.len() as u32).to_be_bytes());
        for argument in &arguments {
            value(&mut bytes, argument);
        }
        bytes.extend(0u32.to_be_bytes());
        if let Some(memory) = memory {
            bytes.push(1);
            bytes.extend(memory.to_be_bytes());
        } else {
            bytes.push(0);
        }
        bytes.extend([2, 0, 1, 1]);
        bytes.extend([9u8; 32]);
        bytes.extend(0u32.to_be_bytes());
        bytes.push(0);
        bytes.extend(&request_digest);
        bytes
    };
    let with_memory = encode(Some(512 * 1024 * 1024));
    let without_memory = encode(None);
    validate_linux_mixed_public_arguments(
        &with_memory,
        &request,
        &arguments,
        &[],
        Some(512 * 1024 * 1024),
    )
    .unwrap();
    validate_linux_mixed_public_arguments(&without_memory, &request, &arguments, &[], None)
        .unwrap();
    let mut restarted = with_memory.clone();
    restarted[2..10].copy_from_slice(&123u64.to_be_bytes());
    assert!(
        validate_linux_mixed_public_arguments(
            &restarted,
            &request,
            &arguments,
            &[],
            Some(512 * 1024 * 1024)
        )
        .is_err()
    );
    assert!(
        validate_linux_mixed_public_arguments(&with_memory, &request, &arguments, &[], None)
            .is_err()
    );
    assert!(
        validate_linux_mixed_public_arguments(
            &without_memory,
            &request,
            &arguments,
            &[],
            Some(512 * 1024 * 1024)
        )
        .is_err()
    );
    assert!(
        validate_linux_mixed_public_arguments(
            &with_memory,
            &request,
            &arguments,
            &[],
            Some(256 * 1024 * 1024)
        )
        .is_err()
    );
    let fixture = FixtureInput {
        format: "memcordon.consumer-readiness.input".into(),
        revision: 1,
        run_id: "codec-vector".into(),
        key: CaseKey {
            target: "aarch64-unknown-linux-gnu".into(),
            channel: Some("candidate-native".into()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: "L-IMG-04".into(),
            scenario: "export-fifo".into(),
        },
        challenge_sha256: "a".repeat(64),
        binary: Vec::new(),
        target_argv: NativeArguments::UnixBytes(arguments),
        deadline_millis: None,
        memory_bytes: None,
        toolchain_identity: None,
    };
    let environment = serde_json::to_vec(&NativeEnvironment::UnixBytes(Vec::new())).unwrap();
    validate_linux_mixed_public_invocation(
        &with_memory,
        &request,
        &serde_json::to_vec(&fixture).unwrap(),
        &environment,
    )
    .unwrap();
    validate_linux_mixed_public_invocation(
        &restarted,
        &request,
        &serde_json::to_vec(&fixture).unwrap(),
        &environment,
    )
    .unwrap();
    let mut bounded = fixture;
    bounded.memory_bytes = Some(256 * 1024 * 1024);
    assert!(
        validate_linux_mixed_public_invocation(
            &with_memory,
            &request,
            &serde_json::to_vec(&bounded).unwrap(),
            &environment
        )
        .is_err()
    );
}
