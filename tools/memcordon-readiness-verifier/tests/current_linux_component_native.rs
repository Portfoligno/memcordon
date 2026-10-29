//! Data-only observation vectors. These never create native owners or qualify a
//! readiness row; actual lifecycle experiments run only on the native CI host.
use memcordon_readiness_verifier::current::linux_components::validate_recovered_native_observation;
use serde_json::{Value, json};

fn prepared() -> Value {
    json!({"caller_namespaces":[{"device":1,"inode":10},{"device":1,"inode":11},{"device":1,"inode":12},{"device":1,"inode":13},{"device":1,"inode":14}],"user_namespace":{"device":1,"inode":10},"boot_id":"data-only-boot",
        "caller":{"pid":10,"birth":100},"target":{"pid":11,"birth":101},"target_namespace_pid":2,"namespace_init":{"pid":12,"birth":102},"guardian":{"pid":13,"birth":103},
        "caller_uid":1000,"target_uid":900,"target_gid":900,"cgroup_device":2,"cgroup_inode":20,"init_uid":0,"init_nondumpable":true,
        "mount_namespace":{"device":1,"inode":21},"pid_namespace":{"device":1,"inode":22},"network_namespace":{"device":1,"inode":23},"ipc_namespace":{"device":1,"inode":24},
        "root_device":3,"root_inode":30,"filter_abi":"aarch64","filter_instruction_sha256":"11".repeat(32),"supplementary_groups":[],"no_new_privileges":true,"capabilities_empty":true,
        "exec_observed":false,"release_monotonic_millis":null,"exec_observed_monotonic_millis":null,"native_wait_status":null,"memory_oom_kill_count":null,"memory_oom_event_count":null,"memory_max_bytes":134217728})
}

#[test]
fn lost_direct_wait_remains_unknown_instead_of_becoming_original_success() {
    let before = prepared();
    let mut recovery =
        json!({"native":before,"release":"not-released","outcome":{"kind":"unknown"}});
    validate_recovered_native_observation(&recovery, &before).unwrap();
    recovery["outcome"] = json!({"kind":"exited","code":0});
    assert!(validate_recovered_native_observation(&recovery, &before).is_err());
    recovery["native"] = Value::Null;
    recovery["release"] = json!("released");
    assert!(validate_recovered_native_observation(&recovery, &before).is_err());
}

#[test]
fn retained_wait_is_correlated_with_original_exec_timing_and_raw_status() {
    let before = prepared();
    let mut native = before.clone();
    native["exec_observed"] = json!(true);
    native["release_monotonic_millis"] = json!(100);
    native["exec_observed_monotonic_millis"] = json!(101);
    native["native_wait_status"] = json!(7 << 8);
    let recovery =
        json!({"native":native,"release":"released","outcome":{"kind":"exited","code":7}});
    validate_recovered_native_observation(&recovery, &before).unwrap();
    let mut changed = recovery.clone();
    changed["native"]["native_wait_status"] = json!(0);
    assert!(validate_recovered_native_observation(&changed, &before).is_err());
    let mut changed = recovery;
    changed["native"]["release_monotonic_millis"] = json!(102);
    assert!(validate_recovered_native_observation(&changed, &before).is_err());
}

#[test]
fn recovery_cannot_exchange_original_process_credentials_or_root() {
    let before = prepared();
    let recovery = json!({"native":before,"release":"not-released","outcome":{"kind":"unknown"}});
    validate_recovered_native_observation(&recovery, &before).unwrap();
    for (field, value) in [
        ("target", json!({"pid":11,"birth":999})),
        ("caller_uid", json!(1001)),
        ("root_inode", json!(31)),
        ("filter_instruction_sha256", json!("22".repeat(32))),
    ] {
        let mut changed = recovery.clone();
        changed["native"][field] = value;
        assert!(
            validate_recovered_native_observation(&changed, &before).is_err(),
            "exchanged {field}"
        );
    }
}
