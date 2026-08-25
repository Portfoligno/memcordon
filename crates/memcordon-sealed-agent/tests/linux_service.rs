#![cfg(all(target_os = "linux", feature = "test-support"))]

use memcordon_sealed_agent::linux::qualification::QualificationReceipt;
use memcordon_sealed_agent::protocol::{Frame, MessageKind};
use memcordon_sealed_agent::rejection::{RejectionPhaseV1, RejectionV1};
use std::path::Path;

const PEER_PID: libc::pid_t = 100;
const MEMBER_PID: libc::pid_t = 200;
const ATTEMPT_ID: &str = "0123456789abcdef0123456789abcdef";

fn write_process_cgroup(proc_root: &Path, pid: libc::pid_t, membership: &str) {
    let process = proc_root.join(pid.to_string());
    std::fs::create_dir_all(&process).expect("synthetic process directory must exist");
    std::fs::write(process.join("cgroup"), membership)
        .expect("synthetic process cgroup must exist");
}

fn write_namespaces(proc_root: &Path, pid: libc::pid_t) {
    let namespaces = proc_root.join(pid.to_string()).join("ns");
    std::fs::create_dir_all(&namespaces).expect("synthetic namespace directory must exist");
    for kind in ["pid", "mnt", "cgroup"] {
        std::fs::write(namespaces.join(kind), kind)
            .expect("synthetic namespace identity must exist");
    }
}

fn link_namespaces(proc_root: &Path, source_pid: libc::pid_t, target_pid: libc::pid_t) {
    let source = proc_root.join(source_pid.to_string()).join("ns");
    let target = proc_root.join(target_pid.to_string()).join("ns");
    std::fs::create_dir_all(&target).expect("synthetic member namespace directory must exist");
    for kind in ["pid", "mnt", "cgroup"] {
        std::fs::hard_link(source.join(kind), target.join(kind))
            .expect("synthetic namespace identity must be shared");
    }
}

fn synthetic_inventory() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temporary = tempfile::tempdir().expect("synthetic inventory root must exist");
    let proc_root = temporary.path().join("proc");
    let cgroup_root = temporary.path().join("cgroup");
    std::fs::create_dir_all(&proc_root).expect("synthetic proc root must exist");
    std::fs::create_dir_all(&cgroup_root).expect("synthetic cgroup root must exist");
    write_process_cgroup(&proc_root, PEER_PID, "0::/\n");
    write_namespaces(&proc_root, PEER_PID);
    (temporary, proc_root, cgroup_root)
}

fn recursive_inventory(proc_root: &Path, cgroup_root: &Path) -> Result<bool, String> {
    memcordon_sealed_agent::linux::service::peer_inside_active_attempt_for_test(
        PEER_PID,
        proc_root,
        cgroup_root,
    )
}

fn qualification() -> QualificationReceipt {
    QualificationReceipt {
        schema_version: 2,
        mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        provider_identity: "memcordon-sealed-agent-v2".to_owned(),
        control_service_identity: "memcordon-sealed-agent.service:v2".to_owned(),
        launcher_service_identity: "memcordon-sealed-launcher.service:v2".to_owned(),
        receipt_digest: "0".repeat(64),
        unified_cgroup_v2: true,
        private_cgroup_subtree: true,
        clone3: true,
        clone3_into_cgroup: true,
        pid_namespace: true,
        mount_namespace: true,
        cgroup_namespace: true,
        pidfd: true,
        close_range: true,
        guardian_outside_boundary: true,
        target_gated: true,
        assignment_verified: true,
        inherited_descriptors_verified: true,
        spawn_error_reporting_verified: true,
        frontend_loss_authority_verified: true,
        cgroup_kill: true,
        workload_empty: true,
        helpers_reaped: true,
        boundary_retired: true,
        recovery_complete: true,
        split_control_and_launcher_services: true,
        launcher_no_new_privs_disabled: true,
        caller_mount_namespace_reproduction_verified: true,
        caller_no_new_privs_reproduction_verified: true,
        caller_capability_bounding_set_reproduction_verified: true,
        initial_provider_capabilities_absent: true,
        credential_transition_disposition: "preserve-caller-envelope".to_owned(),
        setid_transition_certification_digest: "1".repeat(64),
        sudo_transition_certification_digest: "2".repeat(64),
        post_transition_cgroup_membership_verified: true,
        post_transition_pid_namespace_verified: true,
        post_transition_cleanup_verified: true,
        recursive_provider_request_rejected: true,
    }
}

#[test]
fn probe_returns_the_cached_startup_qualification_without_requalifying() {
    let request = Frame {
        kind: MessageKind::Probe,
        nonce: [7; 16],
        attempt_id: [0; 16],
        payload: Vec::new(),
    };
    let qualification = qualification();

    let response = memcordon_sealed_agent::linux::service::cached_probe_response_for_test(
        &request,
        0,
        &qualification,
    );

    assert_eq!(response.kind, MessageKind::ProbeReceipt);
    assert_eq!(response.nonce, request.nonce);
    assert_eq!(response.attempt_id, request.attempt_id);
    assert_eq!(response.payload, qualification.render().into_bytes());
}

#[test]
fn probe_with_descriptors_receives_a_typed_rejection() {
    let request = Frame {
        kind: MessageKind::Probe,
        nonce: [9; 16],
        attempt_id: [0; 16],
        payload: Vec::new(),
    };

    let response = memcordon_sealed_agent::linux::service::cached_probe_response_for_test(
        &request,
        1,
        &qualification(),
    );

    assert_eq!(response.kind, MessageKind::Rejected);
    assert_eq!(response.nonce, request.nonce);
    let rejection: RejectionV1 =
        serde_json::from_slice(&response.payload).expect("rejection must be typed JSON");
    rejection.validate().expect("rejection must validate");
    assert_eq!(rejection.schema_version, 1);
    assert_eq!(rejection.code, "MCSEALED-PROVIDER-REJECTION");
    assert_eq!(rejection.phase, RejectionPhaseV1::RequestValidation);
    assert!(rejection.detail.contains("must not carry descriptors"));
    assert!(!rejection.target_created);
    assert!(!rejection.cleanup.attempted);
}

#[test]
fn peer_authorization_requires_root_or_exact_access_group() {
    let authorized = memcordon_sealed_agent::linux::service::peer_is_authorized_for_test;
    assert!(authorized(0, 0, &[], 81));
    assert!(authorized(1000, 81, &[], 81));
    assert!(authorized(1000, 1000, &[7, 81, 90], 81));
    assert!(!authorized(1000, 1000, &[7, 80, 90], 81));
    assert!(!authorized(1000, 1000, &[], 81));
}

#[test]
fn recursive_inventory_skips_root_cgroup_controls() {
    let (_temporary, proc_root, cgroup_root) = synthetic_inventory();
    for control in ["cgroup.controllers", "cgroup.events", "cgroup.procs"] {
        std::fs::write(cgroup_root.join(control), b"")
            .expect("synthetic cgroup control must exist");
    }

    assert!(!recursive_inventory(&proc_root, &cgroup_root).expect("controls are not attempts"));
}

#[test]
fn recursive_inventory_matches_all_peer_and_member_namespaces() {
    let (_temporary, proc_root, cgroup_root) = synthetic_inventory();
    std::fs::write(cgroup_root.join("cgroup.procs"), b"")
        .expect("synthetic root cgroup control must exist");
    let attempt = cgroup_root.join(ATTEMPT_ID);
    std::fs::create_dir(&attempt).expect("synthetic attempt must exist");
    std::fs::write(attempt.join("cgroup.procs"), format!("{MEMBER_PID}\n"))
        .expect("synthetic attempt membership must exist");
    write_process_cgroup(&proc_root, MEMBER_PID, "0::/memcordon-sealed/member\n");
    link_namespaces(&proc_root, PEER_PID, MEMBER_PID);

    assert!(recursive_inventory(&proc_root, &cgroup_root).expect("matching member must be found"));
}

#[test]
fn recursive_inventory_rejects_an_unrelated_namespace_identity() {
    let (_temporary, proc_root, cgroup_root) = synthetic_inventory();
    let attempt = cgroup_root.join(ATTEMPT_ID);
    std::fs::create_dir(&attempt).expect("synthetic attempt must exist");
    std::fs::write(attempt.join("cgroup.procs"), format!("{MEMBER_PID}\n"))
        .expect("synthetic attempt membership must exist");
    write_process_cgroup(&proc_root, MEMBER_PID, "0::/memcordon-sealed/member\n");
    link_namespaces(&proc_root, PEER_PID, MEMBER_PID);
    let member_mount = proc_root.join(MEMBER_PID.to_string()).join("ns/mnt");
    std::fs::remove_file(&member_mount).expect("shared mount identity must be removable");
    std::fs::write(member_mount, b"different").expect("different mount identity must be created");

    assert!(!recursive_inventory(&proc_root, &cgroup_root).expect("unrelated peer is allowed"));
}

#[test]
fn recursive_inventory_tolerates_only_not_found_retirement_races() {
    let (_temporary, proc_root, cgroup_root) = synthetic_inventory();
    std::fs::create_dir(cgroup_root.join(ATTEMPT_ID))
        .expect("retiring synthetic attempt must exist");
    assert!(!recursive_inventory(&proc_root, &cgroup_root).expect("retired attempt is skipped"));

    let membership = cgroup_root.join(ATTEMPT_ID).join("cgroup.procs");
    std::fs::write(&membership, format!("{MEMBER_PID}\n"))
        .expect("departed member fixture must exist");
    assert!(
        !recursive_inventory(&proc_root, &cgroup_root)
            .expect("a departed member's missing proc entry is skipped")
    );
    std::fs::remove_file(&membership).expect("departed member fixture must be removable");
    std::fs::create_dir(&membership).expect("unreadable membership fixture must exist");
    assert!(
        recursive_inventory(&proc_root, &cgroup_root)
            .expect_err("non-NotFound membership errors must fail closed")
            .contains("membership readback failed")
    );
}

#[test]
fn recursive_inventory_fails_closed_for_malformed_root_state() {
    let (_temporary, proc_root, cgroup_root) = synthetic_inventory();
    std::fs::create_dir(cgroup_root.join("not-an-attempt"))
        .expect("invalid attempt directory must exist");
    assert!(
        recursive_inventory(&proc_root, &cgroup_root)
            .expect_err("invalid attempt directory must fail closed")
            .contains("invalid attempt directory")
    );
    std::fs::remove_dir(cgroup_root.join("not-an-attempt"))
        .expect("invalid attempt directory must be removable");

    std::os::unix::fs::symlink("cgroup.procs", cgroup_root.join("unsafe-link"))
        .expect("unsafe cgroup symlink must exist");
    assert!(
        recursive_inventory(&proc_root, &cgroup_root)
            .expect_err("unsafe entry must fail closed")
            .contains("unsafe entry")
    );
    std::fs::remove_file(cgroup_root.join("unsafe-link"))
        .expect("unsafe cgroup symlink must be removable");

    let socket_path = cgroup_root.join("unsafe-socket");
    let socket = std::os::unix::net::UnixListener::bind(&socket_path)
        .expect("unsafe cgroup socket must exist");
    assert!(
        recursive_inventory(&proc_root, &cgroup_root)
            .expect_err("special entry must fail closed")
            .contains("unsafe entry")
    );
    drop(socket);
    std::fs::remove_file(socket_path).expect("unsafe cgroup socket must be removable");

    let attempt = cgroup_root.join(ATTEMPT_ID);
    std::fs::create_dir(&attempt).expect("synthetic attempt must exist");
    std::fs::write(attempt.join("cgroup.procs"), b"not-a-pid\n")
        .expect("malformed membership must exist");
    assert!(
        recursive_inventory(&proc_root, &cgroup_root)
            .expect_err("malformed member pid must fail closed")
            .contains("invalid pid")
    );
}

#[test]
fn recursive_inventory_requires_the_private_root() {
    let (_temporary, proc_root, cgroup_root) = synthetic_inventory();
    std::fs::remove_dir(&cgroup_root).expect("empty cgroup root must be removable");

    assert!(
        recursive_inventory(&proc_root, &cgroup_root)
            .expect_err("missing private root must fail closed")
            .contains("inventory root failed")
    );
}

#[test]
fn direct_cgroup_membership_short_circuits_inventory() {
    let temporary = tempfile::tempdir().expect("synthetic inventory root must exist");
    let proc_root = temporary.path().join("proc");
    let missing_cgroup_root = temporary.path().join("missing-cgroup");
    write_process_cgroup(
        &proc_root,
        PEER_PID,
        "0::/system.slice/memcordon-sealed/0123456789abcdef0123456789abcdef\n",
    );

    assert!(
        recursive_inventory(&proc_root, &missing_cgroup_root)
            .expect("direct membership must not require inventory")
    );
    assert!(
        memcordon_sealed_agent::linux::service::cgroup_membership_is_sealed("0::/\n")
            .is_ok_and(|sealed| !sealed)
    );
    assert!(memcordon_sealed_agent::linux::service::cgroup_membership_is_sealed("0::/").is_err());
    assert!(
        memcordon_sealed_agent::linux::service::cgroup_membership_is_sealed(&format!(
            "0::/{}\n",
            "x".repeat(70 * 1024)
        ))
        .is_err()
    );
}
