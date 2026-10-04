use memcordon_ci::release::linux_installed_consumer::{
    start_private_socket_after_policy, validate_incomplete_package_advisory,
    validate_lost_private_transaction, validate_private_fixture, validate_tcp_anchor,
};

#[test]
fn lost_worker_result_retains_uncertain_authorization_and_unproved_cleanup() {
    use memcordon_core::result_v1::{CleanupStateV1, ResultV1};

    // Actual 29ec x64 worker-loss named Result: its restart error carries no
    // authenticated native retirement proof and correctly projects Incomplete.
    let bytes = include_bytes!("fixtures/private_worker_loss_result.json");
    let actual = ResultV1::parse(bytes).unwrap();
    assert_eq!(actual.cleanup.state, CleanupStateV1::Incomplete);
    let version = actual.tool.version.clone();
    validate_lost_private_transaction(&actual, &version, Some(125), 125).unwrap();
    let mut unknown = actual.clone();
    unknown.cleanup.state = CleanupStateV1::Unknown;
    unknown.attempts[0].restart_safety.errors.clear();
    ResultV1::parse(&serde_json::to_vec(&unknown).unwrap()).unwrap();
    validate_lost_private_transaction(&unknown, &version, Some(125), 125).unwrap();
    assert!(validate_lost_private_transaction(&actual, &version, Some(0), 125).is_err());
    assert!(validate_lost_private_transaction(&actual, &version, None, 125).is_err());
    assert!(
        validate_lost_private_transaction(&actual, "different-source", Some(125), 125).is_err()
    );

    let original = serde_json::to_value(&actual).unwrap();
    for (section, field, value) in [
        ("cleanup", "state", serde_json::json!("complete")),
        ("cleanup", "direct_child_reaped", serde_json::json!(true)),
        ("cleanup", "workload_empty", serde_json::json!(true)),
        ("cleanup", "workload_empty", serde_json::json!(false)),
        ("launch", "target_pid", serde_json::json!(42)),
        ("launch", "state", serde_json::json!("exec-observed")),
        ("outcome", "kind", serde_json::json!("completed")),
        ("outcome", "wrapper_status", serde_json::json!(0)),
        (
            "outcome",
            "native_termination",
            serde_json::json!({"kind":"exit-code", "code":0}),
        ),
    ] {
        let mut changed = original.clone();
        changed[section][field] = value;
        let changed: ResultV1 = serde_json::from_value(changed).unwrap();
        assert!(
            validate_lost_private_transaction(&changed, &version, Some(125), 125).is_err(),
            "{section}.{field}"
        );
    }
    let mut changed = actual;
    changed.authorization = memcordon_core::result_v1::AuthorizationV1::RejectedBeforeRelease;
    assert!(validate_lost_private_transaction(&changed, &version, Some(125), 125).is_err());
}

#[test]
fn incomplete_package_advisory_requires_actual_failed_cli_output_without_a_plan() {
    use std::{path::Path, time::Duration};

    use memcordon_ci::{command::CommandSpec, config};

    // This real child tests the failed advisory observation contract; it does
    // not install a package or impersonate an authenticated provider response.
    let owner = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let binary = owner.path().join(if cfg!(windows) {
        "advisory-child.exe"
    } else {
        "advisory-child"
    });
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let compiled = CommandSpec::toolchain_program(
        "rustup",
        owner.path(),
        &config::toolchains(root).unwrap().stable,
        "rustc",
        Duration::from_secs(30),
    )
    .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/incomplete_advisory_child.rs"))
    .args(["--edition", "2024", "-o"])
    .arg(&binary)
    .output_quiet()
    .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    for (mode, accepted) in [
        ("rejected", true),
        ("success", false),
        ("plan-on-error", false),
        ("no-diagnostic", false),
        ("launcher-error", false),
        ("empty-cli-error", false),
    ] {
        let observed = CommandSpec::new(&binary, owner.path(), Duration::from_secs(5))
            .arg(mode)
            .output_quiet()
            .unwrap();
        assert_eq!(
            validate_incomplete_package_advisory(&observed).is_ok(),
            accepted,
            "{mode}: {observed:?}"
        );
        if accepted {
            assert_eq!(observed.status.code(), Some(125));
            assert!(observed.stdout.is_empty());
            assert_eq!(observed.stderr, b"memcordon: failed to fill whole buffer\n");
        }
    }
}

#[test]
fn optional_socket_activation_requires_published_policy_and_actual_start_success() {
    use std::{cell::Cell, ffi::OsStr, path::Path};

    use memcordon_ci::CiError;

    let published = Cell::new(false);
    let publish = || {
        published.set(true);
        Ok(73_u64)
    };
    let epoch = start_private_socket_after_policy(Path::new("/tmp"), publish(), |command| {
        assert!(published.get());
        let native = command.materialize().unwrap();
        assert_eq!(native.get_program(), OsStr::new("sudo"));
        assert_eq!(native.get_current_dir(), Some(Path::new("/tmp")));
        assert_eq!(
            native.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-n"),
                OsStr::new("systemctl"),
                OsStr::new("start"),
                OsStr::new("memcordon-sealed-network-launcher.socket"),
            ]
        );
        Ok(())
    })
    .unwrap();
    assert_eq!(epoch, 73);

    let failure = start_private_socket_after_policy::<u64>(
        Path::new("/tmp"),
        Err(CiError::Message("policy publication rejected".into())),
        |_| panic!("failed publication must not start an optional socket"),
    )
    .unwrap_err();
    assert!(failure.to_string().contains("policy publication rejected"));

    let failure = start_private_socket_after_policy(Path::new("/tmp"), Ok(epoch), |_| {
        Err(CiError::Message("native socket start rejected".into()))
    })
    .unwrap_err();
    assert!(failure.to_string().contains("native socket start rejected"));
}

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
