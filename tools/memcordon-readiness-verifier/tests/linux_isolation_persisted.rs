#[path = "support/linux_account_case.rs"]
mod linux_account_case;
#[path = "support/linux_cross_account_case.rs"]
mod linux_cross_account_case;
#[path = "support/linux_cross_attempt_case.rs"]
mod linux_cross_attempt_case;
#[path = "support/linux_image_entrypoint_case.rs"]
mod linux_image_entrypoint_case;
#[path = "support/linux_import_case.rs"]
mod linux_import_case;
#[path = "support/linux_ingress_case.rs"]
mod linux_ingress_case;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_isolation_case.rs"]
mod linux_isolation_case;
#[path = "support/linux_lifecycle_case.rs"]
mod linux_lifecycle_case;
#[path = "support/linux_limits_case.rs"]
mod linux_limits_case;
#[path = "support/linux_prepared_case.rs"]
mod linux_prepared_case;
#[path = "linux_isolation.rs"]
mod original_vectors;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;

#[test]
fn complete_original_concurrent_other_attempt_abstract() {
    let mut case = linux_cross_attempt_case::baseline();
    case.validate().unwrap();
    case.mutate("cross/canary.json", |raw| {
        raw["held_peer_after"]["birth"] = json!(999)
    });
    assert!(case.validate().is_err());
    let mut case = linux_cross_attempt_case::baseline();
    case.mutate("peer/native-family-retirement.json", |raw| {
        raw["namespace_init"]["birth"] = json!(999)
    });
    assert!(case.validate().is_err());
    let mut case = linux_cross_attempt_case::baseline();
    case.mutate("cross/account-original-command-0.creation.json", |raw| {
        raw["process_id"] = json!(901)
    });
    assert!(case.validate().is_err());
    let mut case = linux_cross_attempt_case::baseline();
    case.mutate("cross/account-original-command-0.invocation.json", |raw| {
        raw["cleanup_deadline_unix_millis"] = json!(201)
    });
    assert!(case.validate().is_err());
    let mut case = linux_cross_attempt_case::baseline();
    case.mutate("cross/account-task-census-1.json", |raw| {
        raw["tasks"][0]["status"] = json!(
            b"Tgid:\t106\nPid:\t106\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t61002\n"
                .as_slice()
        );
        raw["tasks"][0]["credentials"][2] = json!([61002]);
    });
    assert!(case.validate().is_err());
    let mut case = linux_cross_attempt_case::baseline();
    case.mutate("cross/account/exclusive-account-intent.json", |raw| {
        raw["purpose"] = json!("different-original-purpose")
    });
    assert!(case.validate().is_err());
    let mut case = linux_cross_attempt_case::baseline();
    let original = linux_installed_case::read(&case, "cross/canary.json");
    let name = original["peer_account"]["name"].as_str().unwrap();
    case.mutate("cross/canary.json", |raw| {
        raw["peer_account"]["uid"] = json!(65533);
        raw["peer_account"]["gid"] = json!(65533);
    });
    case.write(
        "cross/account/exclusive-account-getent.bin",
        format!("{name}:x:65533:65533::/nonexistent:/usr/sbin/nologin\n").as_bytes(),
    );
    case.write(
        "cross/account/exclusive-group-getent.bin",
        format!("{name}:x:65533:\n").as_bytes(),
    );
    let error = case.validate().unwrap_err();
    assert!(error.contains("aliases frozen owner"), "{error}");
}

#[test]
fn complete_original_three_hostile_input_imports() {
    for scenario in ["input-socket", "imported-socket", "caller-writable-tree"] {
        let mut case = linux_import_case::baseline(scenario);
        case.validate().unwrap();
        case.mutate("import-original-inventory.json", |raw| {
            raw["members"][4]["sha256"] =
                json!(memcordon_readiness_verifier::sha256(b"foreign source"))
        });
        assert!(
            case.validate().is_err(),
            "{scenario} adopts another original complete input member"
        );
        let mut case = linux_import_case::baseline(scenario);
        case.mutate("import-source-closed.json", |raw| {
            raw["parent_closed"] = json!(false)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} omits original native parent close"
        );
        let mut case = linux_import_case::baseline(scenario);
        case.mutate("import-census.json", |raw| {
            raw["original_probe_nonce"] = json!(hex::encode([8; 16]))
        });
        assert!(
            case.validate().is_err(),
            "{scenario} adopts provider-attempt census instead of original probe"
        );
    }
}

#[test]
fn complete_original_private_abstract_positive() {
    let mut case = linux_isolation_case::own_abstract();
    case.validate().unwrap();
    case.write("abstract.bin", b"unrelated bytes");
    assert!(case.validate().is_err());
}

#[test]
fn complete_original_path_sockets_and_hostile_descriptor_handoffs() {
    for scenario in ["host-run-socket", "host-temp-socket"] {
        let mut case = linux_isolation_case::host_path(scenario);
        case.validate().unwrap();
        case.mutate("host-path-canary.json", |raw| {
            raw["original"]["peer"]["birth"] = json!(999)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} adopts another native host peer"
        );
    }
    for scenario in ["stdio-host-socket", "extra-host-fd"] {
        let mut case = linux_isolation_case::descriptor(scenario);
        case.validate().unwrap();
        case.mutate("descriptor-closure.json", |raw| {
            raw["source_closed"] = json!(false)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} loses original host descriptor custody"
        );
    }
}

#[test]
fn complete_original_three_account_admission_refusals() {
    for scenario in ["same-uid-process", "account-alias", "stale-reservation"] {
        let mut case = linux_account_case::baseline(scenario);
        case.validate().unwrap();
        case.mutate("account-exit.json", |raw| raw["process_birth"] = json!(0));
        assert!(
            case.validate().is_err(),
            "{scenario} accepts missing original Child birth"
        );
        if scenario != "account-alias" {
            let mut case = linux_account_case::baseline(scenario);
            case.mutate("external-retired.json", |raw| {
                raw["held"]["birth"] = json!(901)
            });
            assert!(
                case.validate().is_err(),
                "{scenario} accepts foreign occupation retirement"
            );
        }
        if scenario != "account-alias" {
            let mut case = linux_account_case::baseline(scenario);
            case.mutate("external-live.json", |raw| {
                raw["held"]["namespace_pids"][0] = json!(999)
            });
            assert!(
                case.validate().is_err(),
                "{scenario} accepts foreign native namespace host PID"
            );
            let mut case = linux_account_case::baseline(scenario);
            case.mutate("external-live.json", |raw| {
                raw["creator"]["birth"] = json!(999999)
            });
            assert!(
                case.validate().is_err(),
                "{scenario} accepts creator born after original child"
            );
        }
        if scenario == "stale-reservation" {
            let mut case = linux_account_case::baseline(scenario);
            case.mutate("reservation-retired.json", |raw| {
                raw["parents"][4]["named_inode"] = json!(999)
            });
            assert!(
                case.validate().is_err(),
                "stale accepts transplanted original protected parent"
            );
        }
    }
}

#[test]
fn complete_original_three_host_network_canaries() {
    for scenario in ["host-tcp", "nonloopback", "host-abstract"] {
        let mut case = linux_isolation_case::host(scenario);
        case.validate().unwrap();
        case.mutate("host-canary.json", |raw| {
            raw["network_namespace_inode"] = json!(999)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} accepts foreign original host namespace"
        );
    }
}

#[test]
fn complete_original_eight_native_authority_syscall_records() {
    for (family, scenario) in [
        ("L-ISO-01", "ipv6"),
        ("L-ISO-01", "udp"),
        ("L-ISO-01", "raw"),
        ("L-ISO-01", "packet"),
        ("L-ISO-01", "netlink"),
        ("L-ISO-05", "pidfd-getfd"),
        ("L-ISO-05", "ptrace"),
        ("L-ISO-05", "namespace-entry"),
    ] {
        let mut case = linux_isolation_case::authority(family, scenario);
        case.validate().unwrap();
        case.mutate("prepared-native.json", |raw| {
            raw["target"]["network"]["inode"] = json!(999)
        });
        assert!(
            case.validate().is_err(),
            "{family}/{scenario} accepts transplanted native namespace"
        );
    }
}

#[test]
fn complete_original_eight_outside_alias_records_and_rehashed_custody_hostiles() {
    for scenario in [
        "symlink",
        "dotdot",
        "proc-root",
        "proc-cwd",
        "proc-fd",
        "opath",
        "hardlink",
        "mount-alias",
    ] {
        let mut case = linux_isolation_case::outside(scenario);
        case.validate().unwrap();
        case.mutate("outside-canary.json", |raw| {
            raw["after"]["inode"] = json!(999)
        });
        assert!(
            case.validate().is_err(),
            "{scenario} accepts another original host inode"
        );
    }
}
