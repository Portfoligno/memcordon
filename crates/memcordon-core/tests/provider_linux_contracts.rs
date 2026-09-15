use memcordon_core::sealed_provider::{
    cgroup_membership::is_sealed,
    envelope::{parse_capability_mask, parse_namespace_identity, parse_proc_status},
    terminal::{TerminalExecFailureClass, TerminalExecStatus, parse_terminal},
};

fn terminal(status: i32, exec_status: &str, os_code: &str) -> Vec<u8> {
    const CALLER_ENVELOPE_DIGEST: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const CALLER_CAPABILITY_BOUNDING_SET_DIGEST: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const CALLER_MOUNT_NAMESPACE_DIGEST: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    format!(
        concat!(
            "schema-version=2\n",
            "mechanism=linux-pid-namespace-cgroup-v2\n",
            "policy-enforcement={policy_enforcement}\n",
            "status={status}\n",
            "exec-status={exec_status}\n",
            "exec-os-code={os_code}\n",
            "spawn-error-reported=true\n",
            "target-pid=71\n",
            "authorization-offset-millis=9\n",
            "memory-limit-exceeded=false\n",
            "deadline-exceeded=false\n",
            "assignment-verified=true\n",
            "namespaces-verified=true\n",
            "target-initial-credentials-verified=true\n",
            "initial-provider-capabilities-absent=true\n",
            "caller-envelope-digest={caller_envelope_digest}\n",
            "caller-no-new-privs=false\n",
            "target-no-new-privs-matched=true\n",
            "caller-capability-bounding-set-digest={caller_capability_bounding_set_digest}\n",
            "target-capability-bounding-set-matched=true\n",
            "caller-mount-namespace-digest={caller_mount_namespace_digest}\n",
            "target-mount-context-derived-from-caller=true\n",
            "credential-transition-disposition=preserve-caller-envelope\n",
            "boundary-independent-of-credentials=true\n",
            "descriptors-verified=true\n",
            "writable-ancestor-cgroup-denied=true\n",
            "parent-namespace-handles-denied=true\n",
            "recursive-provider-request-denied=true\n",
            "guardian-ready-before-authorization=true\n",
            "frontend-loss-authority-verified=true\n",
            "cgroup-kill-invoked=true\n",
            "cgroup-empty=true\n",
            "init-reaped=true\n",
            "guardian-reaped=true\n",
            "boundary-retired=true\n",
        ),
        status = status,
        exec_status = exec_status,
        os_code = os_code,
        policy_enforcement = serde_json::to_string(
            &memcordon_core::workload_evidence::AttemptPolicyEnforcementV1::LegacyUnspecified,
        )
        .unwrap(),
        caller_envelope_digest = CALLER_ENVELOPE_DIGEST,
        caller_capability_bounding_set_digest = CALLER_CAPABILITY_BOUNDING_SET_DIGEST,
        caller_mount_namespace_digest = CALLER_MOUNT_NAMESPACE_DIGEST,
    )
    .into_bytes()
}

#[test]
fn linux_terminal_errno_and_exit_status_are_host_independent() {
    for (errno, name, class, exit) in [
        (2, "not-found", TerminalExecFailureClass::NotFound, 127),
        (20, "not-found", TerminalExecFailureClass::NotFound, 127),
        (
            1,
            "not-executable",
            TerminalExecFailureClass::NotExecutable,
            126,
        ),
        (
            8,
            "not-executable",
            TerminalExecFailureClass::NotExecutable,
            126,
        ),
        (
            13,
            "not-executable",
            TerminalExecFailureClass::NotExecutable,
            126,
        ),
        (
            21,
            "not-executable",
            TerminalExecFailureClass::NotExecutable,
            126,
        ),
        (26, "failed", TerminalExecFailureClass::Other, 126),
    ] {
        let code = errno.to_string();
        let receipt = parse_terminal(&terminal(exit, name, &code)).unwrap();
        assert_eq!(
            receipt.exec_status,
            TerminalExecStatus::Failed {
                class,
                os_code: errno
            }
        );
        assert!(parse_terminal(&terminal(0, name, &code)).is_err());
        assert!(parse_terminal(&terminal(exit, "success", &code)).is_err());
    }
    let receipt = terminal(17, "success", "none");
    assert_eq!(parse_terminal(&receipt).unwrap().status, Some(17));
    let mut duplicate = receipt.clone();
    duplicate.extend_from_slice(b"schema-version=2\n");
    assert!(parse_terminal(&duplicate).is_err());
    let mut unknown = receipt;
    unknown.extend_from_slice(b"unreviewed-authority=true\n");
    assert!(parse_terminal(&unknown).is_err());
}

#[test]
fn linux_cgroup_paths_use_slashes_even_on_windows() {
    for path in [
        "/memcordon-sealed/attempt",
        "/foo//memcordon-sealed/./attempt",
        "/memcordon-sealed/../attempt",
    ] {
        assert_eq!(is_sealed(&format!("0::{path}\n")), Ok(true));
    }
    for path in [
        "/memcordon-sealed-other",
        "/other-memcordon-sealed",
        "/foo\\memcordon-sealed\\attempt",
    ] {
        assert_eq!(is_sealed(&format!("0::{path}\n")), Ok(false));
    }
    for invalid in [
        "",
        "0::/memcordon-sealed",
        "0::/\n0::/\n",
        "0:cpu:/\n",
        "x::/\n",
        "0::relative\n",
        "0::/\0\n",
    ] {
        assert!(is_sealed(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn caller_status_preserves_identity_and_rejects_invalid_required_fields() {
    let status = "Uid:\t1 2 3 4\nGid:\t5 6 7 8\nGroups:\t9 10\nNoNewPrivs:\t1\nCapInh:\t0\nCapPrm:\t1\nCapEff:\t2\nCapBnd:\tffffffffffffffff\nCapAmb:\t4\n";
    let parsed = parse_proc_status(status).unwrap();
    assert_eq!(parsed.uids, [1, 2, 3, 4]);
    assert_eq!(parsed.gids, [5, 6, 7, 8]);
    assert_eq!(parsed.supplementary_groups, [9, 10]);
    assert!(parsed.no_new_privs);
    assert_eq!(parsed.capability_bounding_set, u64::MAX);
    assert!(parse_proc_status(&status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t2")).is_err());
    assert!(parse_proc_status(&status.replace("Uid:\t1 2 3 4", "Uid:\t1 2 3")).is_err());
    for invalid in ["", "+1", "0x1", "10000000000000000", "ff ", "é"] {
        assert!(parse_capability_mask(invalid).is_err());
    }
    assert_eq!(
        parse_namespace_identity("pid:[4294967295]", "pid"),
        Ok(4294967295)
    );
    assert!(parse_namespace_identity("mnt:[42]", "pid").is_err());
    assert!(parse_namespace_identity("pid:[42]trailing", "pid").is_err());
}
