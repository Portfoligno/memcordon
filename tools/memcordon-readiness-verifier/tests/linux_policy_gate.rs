//! Native-format hostile vectors; these do not claim an installed execution.
use memcordon_readiness_verifier::validate_linux_policy_gate;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn observations() -> (
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
) {
    let reference = |id: &str, byte: u8| json!({"id":id,"digest":hex::encode([byte;32])});
    let request = json!({"schema_version":3,"workload_plan_digest":"01".repeat(32),
        "authorized_profile":{"id":"linux-tcp4-unix-private-v1","semantic_digest":"02".repeat(32)},
        "authorization":{"grant_id":"combined-grant","grant_revision":1,"approved_plan_digest":"01".repeat(32)},
        "ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain","requirements":[],
        "execution_identity":{"identity":reference("account",3),"exclusive_use_policy":reference("exclusive",4)},
        "runtime_image":reference("toolchain",5),"input_image":reference("fixture",6),"root_layout":reference("build-root",7),
        "launch":{"entrypoint":"build-driver","working_directory":"work"},"expected_epoch":{"service_instance":vec![8u8;16],"revision":1}});
    let actual: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(request.clone()).unwrap();
    actual.validate().unwrap();
    let baseline = json!({"grants":[{"enabled":true,"revision":1}],"active_attempt_disposition":"drain-existing"});
    let mut revoked = baseline.clone();
    revoked["grants"][0]["enabled"] = false.into();
    revoked["active_attempt_disposition"] = "revoke-active".into();
    let activation = |revision, registry: &Value| {
        json!({"format":"memcordon.local-private-activation","revision":2,
        "registry":registry,"registry_digest":"d".repeat(64),"epoch":{"service_instance":vec![8u8;16],"revision":revision},"revoked_admissions":[]})
    };
    let provider = json!({"generation":"version:source","source_commit":"a".repeat(40),"runtime_manifest_sha256":"b".repeat(64)});
    let namespace = |inode| json!({"device":1,"inode":inode});
    let process = |pid| json!({"pid":pid,"birth":100+pid});
    let prepared = json!({"format":"memcordon.mixed-prepared-observation","revision":2,"provider":provider,
        "admission":{"format":"memcordon.private-admission-metadata","revision":2,"attempt_id":"a".repeat(32),"request":request,
            "request_sha256":hex::encode(Sha256::digest(actual.canonical_bytes().unwrap())),"invocation_sha256":"e".repeat(64),
            "caller_uid":65534,"registry_digest":"d".repeat(64),"epoch":request["expected_epoch"],"admission_nonce":vec![9u8;16],"profile_id":request["authorized_profile"]},
        "caller":process(10),"target":process(20),"namespace_init":process(30),"guardian":process(40),
        "user_namespace":namespace(1),"mount_namespace":namespace(2),"pid_namespace":namespace(3),"network_namespace":namespace(4),
        "ipc_namespace":namespace(5),"root_device":9,"root_inode":10,"authorizes_launch":false});
    let snapshot = |pid, last, caller| {
        json!({"process_id":pid,"birth":100+pid,"namespace_pids":if last==0{vec![pid]}else{vec![pid,last]},
        "user":namespace(1),"mount":namespace(if caller{12}else{2}),"pid":namespace(if caller{13}else{3}),
        "network":namespace(if caller{14}else{4}),"ipc":namespace(if caller{15}else{5})})
    };
    let native = json!({"format":"memcordon.linux-prepared-native-observation","revision":1,"run_id":"run","attempt_id":"a".repeat(32),
        "prepared_sha256":"f".repeat(64),"observer":process(99),"held_before_authorization":true,
        "target":snapshot(20,2,false),"namespace_init":snapshot(30,1,false),"guardian":snapshot(40,0,true),"caller":snapshot(10,0,true),
        "root_device":9,"root_inode":10});
    let settlement = |pid| json!({"pid":pid,"birth":100+pid,"parent_pid":null,"parent_birth":null,"retirement_observed":true});
    let retired = json!({"format":"memcordon.linux-policy-prepared-family-retirement","revision":1,"attempt_id":"a".repeat(32),
        "admission_nonce":vec![9u8;16],"target":process(20),"namespace_init":process(30),"guardian":process(40),
        "target_retirement":settlement(20),"namespace_init_retirement":settlement(30),"guardian_retirement":settlement(40),
        "held_before_revocation":true,"native_family_retired":true,"held_descendants":[]});
    let ack = json!({"format":"memcordon.linux-policy-observer-ack-operation","revision":1,"after_revocation":true,
        "acknowledgment_published":true,"error":null});
    (
        prepared,
        native,
        retired,
        ack,
        request,
        provider,
        baseline.clone(),
        revoked.clone(),
        activation(1, &baseline),
        activation(2, &revoked),
        activation(3, &baseline),
    )
}

#[test]
fn native_gate_requires_exact_preparation_and_individual_settlement() {
    let (
        prepared,
        native,
        retired,
        ack,
        request,
        provider,
        baseline,
        revoked,
        active,
        revoke,
        restore,
    ) = observations();
    let check =
        |prepared: &Value, native: &Value, retired: &Value, ack: &Value, revoked: &Value| {
            validate_linux_policy_gate(
                "revoke-preparation",
                prepared,
                native,
                retired,
                ack,
                &request,
                &provider,
                &baseline,
                revoked,
                &active,
                &revoke,
                &restore,
                &"f".repeat(64),
                "run",
                &"a".repeat(32),
                None,
                None,
            )
        };
    assert!(check(&prepared, &native, &retired, &ack, &revoked).is_ok());
    let mut changed = prepared.clone();
    changed["authorizes_launch"] = true.into();
    assert!(check(&changed, &native, &retired, &ack, &revoked).is_err());
    changed = prepared.clone();
    changed["admission"]["request"]["expected_epoch"]["revision"] = 2.into();
    assert!(check(&changed, &native, &retired, &ack, &revoked).is_err());
    changed = native.clone();
    changed["target"]["birth"] = 999.into();
    assert!(check(&prepared, &changed, &retired, &ack, &revoked).is_err());
    changed = native.clone();
    changed["target"]["network"] = native["caller"]["network"].clone();
    assert!(check(&prepared, &changed, &retired, &ack, &revoked).is_err());
    for role in [
        "target_retirement",
        "namespace_init_retirement",
        "guardian_retirement",
    ] {
        changed = retired.clone();
        changed[role]["retirement_observed"] = false.into();
        assert!(
            check(&prepared, &native, &changed, &ack, &revoked).is_err(),
            "{role}"
        );
    }
    changed = ack.clone();
    changed["after_revocation"] = false.into();
    assert!(check(&prepared, &native, &retired, &changed, &revoked).is_err());
    changed = revoked.clone();
    changed["grants"][0]["revision"] = 2.into();
    assert!(check(&prepared, &native, &retired, &ack, &changed).is_err());
}

#[test]
fn final_lease_gate_requires_original_second_observation_and_ack() {
    let (
        prepared,
        native,
        retired,
        ack,
        request,
        provider,
        baseline,
        revoked,
        active,
        revoke,
        restore,
    ) = observations();
    let release = json!({"format":"memcordon.mixed-release-observation","revision":2,"prepared":prepared,"authorizes_launch":false});
    let release_ack = json!({"format":"memcordon.mixed-release-observer-acknowledgment","revision":2,"attempt_id":"a".repeat(32),
        "admission_nonce":vec![9u8;16],"target":prepared["target"],"observer":native["observer"]});
    let check = |release: Option<&Value>, release_ack: Option<&Value>| {
        validate_linux_policy_gate(
            "revoke-release",
            &prepared,
            &native,
            &retired,
            &ack,
            &request,
            &provider,
            &baseline,
            &revoked,
            &active,
            &revoke,
            &restore,
            &"f".repeat(64),
            "run",
            &"a".repeat(32),
            release,
            release_ack,
        )
    };
    assert!(check(Some(&release), Some(&release_ack)).is_ok());
    assert!(check(None, Some(&release_ack)).is_err());
    assert!(check(Some(&release), None).is_err());
    let mut changed = release.clone();
    changed["authorizes_launch"] = true.into();
    assert!(check(Some(&changed), Some(&release_ack)).is_err());
    changed = release_ack.clone();
    changed["admission_nonce"][0] = 1.into();
    assert!(check(Some(&release), Some(&changed)).is_err());
    changed = release_ack.clone();
    changed["observer"]["birth"] = 999.into();
    assert!(check(Some(&release), Some(&changed)).is_err());
}
