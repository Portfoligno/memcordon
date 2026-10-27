#[path = "../src/bin/consumer_readiness_windows/toolchain_diagnostics.rs"]
mod diagnostics;

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
    let missing = diagnostics::observer_gate_error(
        "selected-start-toolchain-observer",
        std::io::Error::from_raw_os_error(2),
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
        std::io::Error::other("controller descendant gate did not release"),
    );
    assert!(
        blocked
            .to_string()
            .contains("toolchain-operation=wait-toolchain-observer-gate")
    );
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

#[cfg(windows)]
#[test]
fn native_current_record_replacement_publishes_only_complete_readback() {
    let directory = tempfile::tempdir().unwrap();
    let binding = json!({"role":"child","original_child":{"process_id":20,"creation_time_100ns":200},"native_work_cutoff_ticks":900});
    let publisher = diagnostics::Publisher::new(directory.path(), binding.clone()).unwrap();
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
