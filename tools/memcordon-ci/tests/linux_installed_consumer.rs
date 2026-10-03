use memcordon_ci::release::linux_installed_consumer::{
    validate_private_fixture, validate_tcp_anchor,
};

#[test]
fn exact_listener_anchor_retains_port_and_does_not_substitute_prelaunch_denial() {
    let ready = serde_json::json!({"format":"memcordon.prebound-listener", "revision":1, "state":"ready", "bound_port":40000, "competitor":"address-in-use"});
    let completed = serde_json::json!({"format":"memcordon.prebound-listener", "revision":1, "state":"completed", "bound_port":40000, "http_body":"owned", "server_joined":true});
    let encode = |items: &[serde_json::Value]| {
        let mut bytes = Vec::new();
        for item in items {
            bytes.extend(serde_json::to_vec(item).unwrap());
            bytes.push(b'\n');
        }
        bytes
    };
    validate_tcp_anchor(&encode(&[ready.clone(), completed.clone()]), false).unwrap();
    assert!(validate_tcp_anchor(&encode(std::slice::from_ref(&completed)), false).is_err());
    let mut changed = completed.clone();
    changed["bound_port"] = 40001.into();
    assert!(validate_tcp_anchor(&encode(&[ready.clone(), changed]), false).is_err());
    let mut changed = ready.clone();
    changed["competitor"] = "success".into();
    assert!(validate_tcp_anchor(&encode(&[changed, completed.clone()]), false).is_err());
    assert!(validate_tcp_anchor(&encode(&[ready, completed]), true).is_err());
    let failure = serde_json::json!({"format":"memcordon.prebound-listener", "revision":1, "state":"listener-policy-failure", "bound_port":40000, "requested_port":40001, "readiness_emitted":false, "dispatch_started":false});
    validate_tcp_anchor(&encode(std::slice::from_ref(&failure)), true).unwrap();
    for (field, value) in [
        ("bound_port", serde_json::json!(0)),
        ("requested_port", serde_json::json!(40000)),
        ("readiness_emitted", serde_json::json!(true)),
        ("dispatch_started", serde_json::json!(true)),
    ] {
        let mut changed = failure.clone();
        changed[field] = value;
        assert!(validate_tcp_anchor(&encode(&[changed]), true).is_err());
    }
    let mut changed = failure;
    changed["saved_approval"] = true.into();
    assert!(validate_tcp_anchor(&encode(&[changed]), true).is_err());
}

fn observation() -> serde_json::Value {
    serde_json::json!({
        "format":"memcordon.private-native-fixture", "revision":1,
        "uid":[65534,65534,65534,65534], "gid":[65534,65534,65534,65534],
        "groups":[40], "no_new_privileges":true,
        "capabilities":{"CapInh":"0","CapPrm":"0","CapEff":"0","CapBnd":"0","CapAmb":"0"},
        "entry_fds":[0,1,2], "network_namespace":"net:[200]", "ipv6_addresses":0,
        "tcp_port":32768, "tcp_bytes":"private",
        "denied":["unix","ipv6","udp","raw","netlink","packet","socketpair","recvmsg","sendmsg","unshare","setns","ptrace","pidfd_getfd","io_uring_setup","setresuid","setresgid","fcntl-async","clone-newnet","clone-detached"]
    })
}

#[test]
fn private_native_observation_binds_independent_credentials_and_namespace() {
    let value = observation();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        validate_private_fixture(&bytes, 65534, 65534, &[40], 100).unwrap(),
        200
    );
    assert!(validate_private_fixture(&bytes, 65533, 65533, &[], 100).is_err());
    assert!(validate_private_fixture(&bytes, 65534, 65534, &[], 100).is_err());
    assert!(validate_private_fixture(&bytes, 65534, 65534, &[40], 200).is_err());
}

#[test]
fn private_native_observation_rejects_false_filter_resource_and_tcp_claims() {
    for (field, replacement) in [
        (
            "format",
            serde_json::json!("memcordon.private-runtime-terminal"),
        ),
        ("revision", serde_json::json!(2)),
        ("no_new_privileges", serde_json::json!(false)),
        ("entry_fds", serde_json::json!([0, 1, 2, 3])),
        ("ipv6_addresses", serde_json::json!(1)),
        ("tcp_port", serde_json::json!(1024)),
        ("tcp_bytes", serde_json::json!("partial")),
        ("denied", serde_json::json!(["unix"])),
    ] {
        let mut value = observation();
        value[field] = replacement;
        assert!(
            validate_private_fixture(
                &serde_json::to_vec(&value).unwrap(),
                65534,
                65534,
                &[40],
                100
            )
            .is_err()
        );
    }
    let mut value = observation();
    value["capabilities"]["CapBnd"] = serde_json::json!("1");
    assert!(
        validate_private_fixture(
            &serde_json::to_vec(&value).unwrap(),
            65534,
            65534,
            &[40],
            100
        )
        .is_err()
    );
    let mut value = observation();
    value["saved_permission"] = serde_json::json!(true);
    assert!(
        validate_private_fixture(
            &serde_json::to_vec(&value).unwrap(),
            65534,
            65534,
            &[40],
            100
        )
        .is_err()
    );
    let mut bytes = serde_json::to_vec(&observation()).unwrap();
    bytes.pop();
    bytes.extend(b",\"revision\":1}");
    assert!(validate_private_fixture(&bytes, 65534, 65534, &[40], 100).is_err());
}
