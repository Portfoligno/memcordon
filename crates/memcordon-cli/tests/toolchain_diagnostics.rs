#[path = "../src/bin/consumer_readiness_windows/controller_gate_error.rs"]
mod controller_gate_error;
#[path = "../src/bin/consumer_readiness_windows/toolchain_diagnostics.rs"]
mod diagnostics;

// Native CI only. Exercise the actual publisher and retained old readers;
// portability checks must not simulate native replacement success.
#[cfg(all(windows, feature = "test-fixtures"))]
#[test]
fn native_current_record_replacement_retains_old_readers_and_refuses_foreign_destinations() {
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};
    let root = tempfile::tempdir().unwrap();
    let owner =
        diagnostics::PublicationOwner::new(root.path(), Instant::now() + Duration::from_secs(5))
            .unwrap();
    let publisher = diagnostics::Publisher::new(&owner, json!({"challenge":[7]})).unwrap();
    publisher
        .publish(false, "first", &json!({"value":1}))
        .unwrap();
    let path = root.path().join("toolchain-current-phase.json");
    let mut old = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(&path)
        .unwrap();
    publisher
        .publish(false, "second", &json!({"value":2}))
        .unwrap();
    let mut previous = Vec::new();
    old.read_to_end(&mut previous).unwrap();
    let previous: serde_json::Value = serde_json::from_slice(&previous).unwrap();
    let current: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(previous["phase"], "first");
    assert_eq!(current["phase"], "second");
    assert!(!root.path().join("toolchain-current-phase.pending").exists());
    let pending = root.path().join("toolchain-current-phase.pending");
    let current_bytes = std::fs::read(&path).unwrap();
    std::fs::write(&pending, b"preserve failed stage evidence").unwrap();
    assert!(
        publisher
            .publish(false, "blocked-stage", &json!({}))
            .is_err()
    );
    assert_eq!(
        std::fs::read(&pending).unwrap(),
        b"preserve failed stage evidence"
    );
    assert_eq!(std::fs::read(&path).unwrap(), current_bytes);
    std::fs::remove_file(&pending).unwrap();
    publisher
        .publish(false, "after-refusal", &json!({}))
        .unwrap();
    let current: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(current["transition_sequence"], 3);
    // A second compiler publisher shares the same real destination custody.
    let next = diagnostics::Publisher::new(&owner, json!({"challenge":[8]})).unwrap();
    next.publish(false, "next-compiler", &json!({})).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"foreign bytes").unwrap();
    assert!(next.publish(false, "must-refuse", &json!({})).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"foreign bytes");
    drop(next);
    drop(publisher);
    drop(owner);

    let foreign = tempfile::tempdir().unwrap();
    std::fs::write(
        foreign.path().join("toolchain-current-phase.json"),
        b"foreign",
    )
    .unwrap();
    let owner =
        diagnostics::PublicationOwner::new(foreign.path(), Instant::now() + Duration::from_secs(5))
            .unwrap();
    let publisher = diagnostics::Publisher::new(&owner, json!({})).unwrap();
    assert!(publisher.publish(false, "must-refuse", &json!({})).is_err());

    let reparse = tempfile::tempdir().unwrap();
    let target = reparse.path().join("foreign-target");
    std::fs::write(&target, b"foreign target").unwrap();
    std::os::windows::fs::symlink_file(
        &target,
        reparse.path().join("toolchain-current-phase.json"),
    )
    .unwrap();
    let owner =
        diagnostics::PublicationOwner::new(reparse.path(), Instant::now() + Duration::from_secs(5))
            .unwrap();
    let publisher = diagnostics::Publisher::new(&owner, json!({})).unwrap();
    assert!(
        publisher
            .publish(false, "must-refuse-reparse", &json!({}))
            .is_err()
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"foreign target");
}

#[cfg(all(windows, feature = "test-fixtures"))]
#[test]
fn native_source_substitution_and_expired_publication_never_replace_destination() {
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Storage::FileSystem::*;
    let root = tempfile::tempdir().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root.path())
        .unwrap();
    let stage = root.path().join("source.pending");
    std::fs::write(&stage, b"original verified bytes").unwrap();
    let original = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&stage)
        .unwrap();
    std::fs::rename(&stage, root.path().join("original-retained")).unwrap();
    std::fs::write(&stage, b"substituted bytes").unwrap();
    assert!(
        memcordon_platform::test_support::windows_open_synchronous_rename_source(
            &parent,
            std::ffi::OsStr::new("source.pending"),
            &original,
            deadline,
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&stage).unwrap(), b"substituted bytes");
    assert!(diagnostics::PublicationOwner::new(root.path(), Instant::now()).is_err());
    assert!(!root.path().join("toolchain-current-phase.json").exists());
}

use serde_json::json;

fn creation(pid: u32, birth: u64) -> diagnostics::CreationIdentity {
    use sha2::{Digest, Sha256};
    diagnostics::CreationIdentity {
        pid,
        birth,
        parent_pid: 10,
        parent_birth: 100,
        image_sha256: String::from(memcordon_core::DiagnosticSha256::from_bytes(
            Sha256::digest(b"selected-original-image").into(),
        )),
        held_process_owner: true,
        image_observation: "creation-event-owned-file",
    }
}

#[test]
fn original_native_exit_zero_or_nonzero_survives_helper_events_and_reused_pid() {
    for code in [0, 23, u32::MAX] {
        let original = creation(20, 200);
        let helper = creation(30, 300);
        let mut state = diagnostics::ExitState::new(original.pid);
        assert_eq!(
            state.snapshot()["original_compiler_exit_observation"],
            "not-observed"
        );
        state.created(&original);
        let mut event = state.observe_exit(original.pid, 21, code, Some(&original));
        assert!(event.original_compiler);
        assert_eq!(event.native_exit_status, code);
        assert_eq!(event.continuation, "pending");
        state.continuation_result(&mut event, Ok(()));
        let retained = state.snapshot()["original_compiler_exit"].clone();
        let mut event = state.observe_exit(helper.pid, 31, 99, Some(&helper));
        state.continuation_result(&mut event, Ok(()));
        let replacement = creation(original.pid, original.birth + 1);
        state.created(&replacement);
        let mut event = state.observe_exit(replacement.pid, 22, 125, Some(&replacement));
        assert!(!event.original_compiler);
        state.continuation_result(&mut event, Ok(()));
        let snapshot = state.snapshot();
        assert_eq!(snapshot["original_compiler_exit"], retained);
        assert_eq!(retained["native_exit_status"], code);
        assert_eq!(retained["creation"]["birth"], original.birth);
        assert_eq!(retained["creation"]["image_sha256"], original.image_sha256);
        assert_eq!(retained["continuation"], "continued");
        assert_eq!(snapshot["whole_family_retirement_proof"], false);
    }
}

#[test]
fn pending_and_failed_continue_keep_original_exit_but_missing_creation_never_claims_binding() {
    let original = creation(20, 200);
    let mut state = diagnostics::ExitState::new(original.pid);
    state.created(&original);
    let mut event = state.observe_exit(original.pid, 21, 7, Some(&original));
    assert_eq!(
        state.snapshot()["original_compiler_exit"]["continuation"],
        "pending"
    );
    state.continuation_result(&mut event, Err(Some(6)));
    let snapshot = state.snapshot();
    assert_eq!(snapshot["original_compiler_exit"]["native_exit_status"], 7);
    assert_eq!(snapshot["original_compiler_exit"]["continuation"], "failed");
    assert_eq!(
        snapshot["original_compiler_exit"]["continuation_raw_os_error"],
        6
    );
    assert_eq!(
        snapshot["exited_members"][0],
        snapshot["original_compiler_exit"]
    );
    for candidate in [
        None,
        Some(creation(21, 200)),
        Some(creation(20, 0)),
        Some(diagnostics::CreationIdentity {
            held_process_owner: false,
            ..creation(20, 200)
        }),
    ] {
        let mut unbound = diagnostics::ExitState::new(original.pid);
        unbound.created(&original);
        let event = unbound.observe_exit(original.pid, 21, 0, candidate.as_ref());
        assert!(!event.original_compiler);
        assert!(event.creation.is_none());
        assert!(unbound.snapshot()["original_compiler_exit"].is_null());
        assert_eq!(
            unbound.snapshot()["original_compiler_exit_observation"],
            "not-observed"
        );
    }
}

#[test]
fn original_slot_survives_full_summary_and_full_production_record_stays_bounded() {
    let original = creation(20, 200);
    let mut state = diagnostics::ExitState::new(original.pid);
    state.created(&original);
    let members = (0..diagnostics::INVENTORY_BOUND)
        .map(|index| diagnostics::CreationIdentity {
            parent_pid: u32::MAX - diagnostics::INVENTORY_BOUND as u32,
            parent_birth: u64::MAX - diagnostics::INVENTORY_BOUND as u64,
            ..creation(u32::MAX - index as u32, u64::MAX - index as u64)
        })
        .collect::<Vec<_>>();
    for member in &members {
        let mut event = state.observe_exit(member.pid, u32::MAX, u32::MAX, Some(member));
        state.continuation_result(&mut event, Ok(()));
    }
    let mut event = state.observe_exit(original.pid, 21, 23, Some(&original));
    state.continuation_result(&mut event, Ok(()));
    let snapshot = state.snapshot();
    assert_eq!(
        snapshot["exited_members"].as_array().unwrap().len(),
        diagnostics::INVENTORY_BOUND
    );
    assert_eq!(snapshot["omitted_count"], 1);
    assert_eq!(snapshot["observed_count"], diagnostics::INVENTORY_BOUND + 1);
    assert_eq!(snapshot["original_compiler_exit"]["native_exit_status"], 23);
    assert_eq!(
        snapshot["original_compiler_exit"]["continuation"],
        "continued"
    );
    let active = (0..diagnostics::INVENTORY_BOUND)
        .map(|index| diagnostics::CreationIdentity {
            parent_pid: original.pid,
            parent_birth: original.birth,
            ..creation(
                u32::MAX - diagnostics::INVENTORY_BOUND as u32 - index as u32,
                u64::MAX - diagnostics::INVENTORY_BOUND as u64 - index as u64,
            )
        })
        .collect::<Vec<_>>();
    let record=diagnostics::encode(&json!({"role":"original-compiler","original_child":{"process_id":20,"creation_time_100ns":200}}),
        9,"before-debug-wait",&json!({"active":diagnostics::inventory(active.iter(),active.len()),"exit_observations":snapshot,"last_event":event})).unwrap();
    assert!(record.len() < diagnostics::RECORD_BOUND);
    let parsed: serde_json::Value = serde_json::from_slice(&record).unwrap();
    assert_eq!(
        parsed["state"]["exit_observations"]["whole_family_retirement_proof"],
        false
    );
}

#[test]
fn socket_stage_preserves_original_error_kind_and_native_code() {
    for stage in [
        "connect",
        "send-request",
        "receive-header",
        "framed-send",
        "framed-receive",
        "shutdown-write",
        "wait-server-eof",
    ] {
        let original = std::io::Error::from_raw_os_error(10060);
        let kind = original.kind();
        let error = diagnostics::socket_error(stage, 49152, original);
        assert_eq!(error.kind(), kind);
        let message = error.to_string();
        assert!(message.contains(stage));
        assert!(message.contains("original-raw-os-error=Some(10060)"));
        assert!(message.contains("endpoint=127.0.0.1:49152"));
        assert!(message.contains(&std::process::id().to_string()));
    }
    let original = std::io::Error::from_raw_os_error(5);
    let kind = original.kind();
    let error = diagnostics::publication_error("before-debug-wait", original);
    assert_eq!(error.kind(), kind);
    assert!(
        error
            .to_string()
            .contains("toolchain-diagnostic-publication=before-debug-wait")
    );
    assert!(error.to_string().contains("original-raw-os-error=Some(5)"));
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(5)
    );
    let missing = diagnostics::observer_gate_error(
        "selected-start-toolchain-observer",
        controller_gate_error::open_diagnostic(
            std::io::Error::from_raw_os_error(2),
            Ok("{}".into()),
        ),
    );
    assert!(
        missing
            .to_string()
            .contains("toolchain-operation=open-toolchain-observer-gate")
    );
    assert!(
        missing
            .to_string()
            .contains("original-raw-os-error=Some(2)")
    );
    let blocked = diagnostics::observer_gate_error(
        "selected-start-toolchain-observer",
        controller_gate_error::context(
            controller_gate_error::Stage::Wait,
            Some(258),
            std::io::Error::other("controller descendant gate did not release"),
        ),
    );
    assert!(
        blocked
            .to_string()
            .contains("toolchain-operation=wait-toolchain-observer-gate")
    );
}

#[test]
fn observer_gate_context_keeps_typed_operation_and_original_error_chain() {
    use std::io;
    for (stage, operation, code) in [
        (
            controller_gate_error::Stage::Open,
            "open-toolchain-observer-gate",
            5,
        ),
        (
            controller_gate_error::Stage::Wait,
            "wait-toolchain-observer-gate",
            6,
        ),
        (
            controller_gate_error::Stage::PublishRelease,
            "publish-toolchain-observer-release",
            32,
        ),
    ] {
        let native = io::Error::from_raw_os_error(code);
        let kind = native.kind();
        let boundary = controller_gate_error::context(stage, Some(u32::MAX), native);
        assert_eq!(boundary.raw_os_error(), None);
        let projected = diagnostics::observer_gate_error("exact-selected-gate", boundary);
        assert_eq!(projected.kind(), kind);
        assert!(
            projected
                .to_string()
                .contains(&format!("toolchain-operation={operation}"))
        );
        assert!(
            projected
                .to_string()
                .contains(&format!("original-raw-os-error=Some({code})"))
        );
        let original = projected
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(
            original
                .get_ref()
                .unwrap()
                .downcast_ref::<controller_gate_error::BoundaryError>()
                .unwrap()
                .observation(),
            (stage, Some(code))
        );
        let native = original
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(native.raw_os_error(), Some(code));
    }
    let unknown = diagnostics::observer_gate_error("gate", io::Error::from_raw_os_error(2));
    assert!(
        unknown
            .to_string()
            .contains("toolchain-operation=toolchain-observer-gate;")
    );
    assert!(!unknown.to_string().contains("toolchain-operation=open-"));
}

#[test]
fn current_phase_preserves_original_binding_and_refuses_oversized_state() {
    let binding = json!({"role":"child","challenge":[0,255,7],
        "parent":{"process_id":10,"creation_time_100ns":100},
        "original_child":{"process_id":20,"creation_time_100ns":200},
        "selected_image_sha256":"fixture-image-digest","native_work_cutoff_ticks":900,
        "native_work_frequency":10});
    let bytes = diagnostics::encode(
        &binding,
        7,
        "before-stdout-capture-receive",
        &json!({"native_status":0}),
    )
    .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["binding"], binding);
    assert_eq!(record["phase"], "before-stdout-capture-receive");
    assert_eq!(record["transition_sequence"], 7);
    assert_eq!(record["diagnostic_only"], true);
    assert_eq!(record["transition_snapshot_not_live_probe"], true);
    assert!(bytes.len() <= diagnostics::RECORD_BOUND);
    let oversized = vec![0u8; diagnostics::RECORD_BOUND];
    assert!(
        diagnostics::encode(
            &binding,
            8,
            "before-debug-wait",
            &json!({"bytes":oversized})
        )
        .is_err()
    );
}

#[test]
fn active_descendant_survives_original_exit_and_omission_is_explicit() {
    let root =
        json!({"pid":20,"birth":200,"parent_pid":10,"parent_birth":100,"held_process_owner":true});
    let child =
        json!({"pid":30,"birth":300,"parent_pid":20,"parent_birth":200,"held_process_owner":true});
    let mut held = std::collections::BTreeMap::from([(20, root), (30, child.clone())]);
    held.remove(&20);
    let state = diagnostics::inventory(held.values(), held.len());
    assert_eq!(state["active_count"], 1);
    assert_eq!(state["members"], json!([child]));
    assert_eq!(state["complete"], true);
    let members: Vec<_> = (0..=diagnostics::INVENTORY_BOUND)
        .map(|pid| json!({"pid":pid,"birth":pid+1}))
        .collect();
    let incomplete = diagnostics::inventory(members.iter(), members.len());
    assert_eq!(
        incomplete["members"].as_array().unwrap().len(),
        diagnostics::INVENTORY_BOUND
    );
    assert_eq!(incomplete["omitted_count"], 1);
    assert_eq!(incomplete["complete"], false);
}

#[cfg(all(windows, feature = "test-fixtures"))]
#[test]
fn native_current_record_replacement_publishes_only_complete_readback() {
    let directory = tempfile::tempdir().unwrap();
    let cutoff = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let owner = diagnostics::PublicationOwner::new(directory.path(), cutoff).unwrap();
    let binding = json!({"role":"child","original_child":{"process_id":20,"creation_time_100ns":200},"native_work_cutoff_ticks":900});
    let publisher = diagnostics::Publisher::new(&owner, binding.clone()).unwrap();
    for phase in ["before-debug-run", "after-debug-run-before-wait-retired"] {
        publisher
            .publish(false, phase, &json!({"diagnostic_only":true}))
            .unwrap();
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("toolchain-current-phase.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(record["phase"], phase);
        assert_eq!(record["binding"], binding);
        assert!(
            !directory
                .path()
                .join("toolchain-current-phase.pending")
                .exists()
        );
    }
    publisher
        .publish(true, "before-debug-wait", &json!({"pending_event":null}))
        .unwrap();
    assert!(
        directory
            .path()
            .join("toolchain-current-debug.json")
            .is_file()
    );
}
