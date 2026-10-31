#[path = "../src/bin/workload_terminal_refinement.rs"]
mod refinement;

use memcordon_core::{
    BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1,
    execution_facts::{CleanupStateV1, MixedFilterAbiV2, NativeNamespaceV2, NativeProcessV2},
    result_v3::*,
    workload_request::WorkloadAttemptAssociationV1,
};

fn terminal() -> LinuxWorkloadTerminalV1 {
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let process = |pid| NativeProcessV2 {
        pid,
        birth: u64::from(pid) + 100,
    };
    let namespace = |inode| NativeNamespaceV2 { device: 4, inode };
    let mut obligations = BoundedVec::default();
    for resource in [
        CleanupResourceV3::Target,
        CleanupResourceV3::Aggregate,
        CleanupResourceV3::Guardian,
        CleanupResourceV3::NamespaceInit,
        CleanupResourceV3::Relays,
        CleanupResourceV3::RootReferences,
        CleanupResourceV3::Staging,
        CleanupResourceV3::Footprint,
    ] {
        obligations
            .try_push(CleanupObligationV3 {
                resource,
                settled: true,
            })
            .unwrap();
    }
    let mut failures = BoundedVec::default();
    failures
        .try_push(BoundedText::new("original adverse workload observation").unwrap())
        .unwrap();
    let value = LinuxWorkloadTerminalV1 {
        format: LINUX_WORKLOAD_TERMINAL_FORMAT.into(),
        revision: 1,
        association: WorkloadAttemptAssociationV1 {
            format: "memcordon.workload-attempt".into(),
            revision: 1,
            attempt: [1; 16],
            challenge: [2; 16],
            request_sha256: digest.clone(),
            boot_id: BoundedText::new("synthetic-boot").unwrap(),
            provider: PublicProviderBindingV1 {
                generation: BoundedText::new("fixture-generation").unwrap(),
                source_commit: BoundedText::new(&"a".repeat(40)).unwrap(),
                runtime_manifest_sha256: digest.clone(),
            },
            control: process(10),
        },
        request: WorkloadRequestAssociationV1 {
            request_sha256: digest.clone(),
            invocation_sha256: digest.clone(),
            resource_policy_sha256: digest.clone(),
            runtime_sha256: Some(digest.clone()),
            input_sha256: Some(digest.clone()),
        },
        release: ReleaseKnowledgeV3::Released,
        native: Some(LinuxNativeExecutionV3 {
            caller_namespaces: [
                namespace(15),
                namespace(16),
                namespace(17),
                namespace(18),
                namespace(19),
            ],
            user_namespace: namespace(15),
            boot_id: BoundedText::new("synthetic-boot").unwrap(),
            caller: process(11),
            target: process(12),
            target_namespace_pid: 2,
            namespace_init: process(13),
            guardian: process(14),
            caller_uid: 1000,
            target_uid: 900,
            target_gid: 900,
            cgroup_device: 3,
            cgroup_inode: 4,
            init_uid: 0,
            init_nondumpable: true,
            mount_namespace: namespace(5),
            pid_namespace: namespace(6),
            network_namespace: namespace(7),
            ipc_namespace: namespace(8),
            root_device: 9,
            root_inode: 10,
            filter_abi: MixedFilterAbiV2::Aarch64,
            filter_instruction_sha256: digest.clone(),
            entrypoint_sha256: digest,
            supplementary_groups: BoundedVec::default(),
            no_new_privileges: true,
            capabilities_empty: true,
            exec_observed: true,
            release_monotonic_millis: Some(100),
            exec_observed_monotonic_millis: Some(101),
            native_wait_status: Some(7 << 8),
            memory_oom_kill_count: Some(0),
            memory_oom_event_count: Some(0),
            memory_max_bytes: Some(1024 * 1024 * 1024),
        }),
        outcome: NativeWorkloadOutcomeV1::Exited { code: 7 },
        cleanup: CleanupV3 {
            state: CleanupStateV1::Complete,
            obligations,
        },
        output_delivery: OutputDeliveryStateV3::Incomplete,
        failures,
    };
    value.validate().unwrap();
    value
}

fn with_control(mut terminal: LinuxWorkloadTerminalV1, settled: bool) -> LinuxWorkloadTerminalV1 {
    let mut obligations = BoundedVec::default();
    for (index, obligation) in terminal.cleanup.obligations.as_slice().iter().enumerate() {
        if index == 2 {
            obligations
                .try_push(CleanupObligationV3 {
                    resource: CleanupResourceV3::ControlHandles,
                    settled,
                })
                .unwrap();
        }
        obligations.try_push(obligation.clone()).unwrap();
    }
    terminal.cleanup.obligations = obligations;
    if !settled {
        terminal.cleanup.state = CleanupStateV1::Incomplete;
    }
    terminal.validate().unwrap();
    terminal
}

fn assert_only_obligations_changed(
    original: &LinuxWorkloadTerminalV1,
    refined: &LinuxWorkloadTerminalV1,
) {
    let mut restored = refined.clone();
    restored.cleanup.obligations = original.cleanup.obligations.clone();
    assert_eq!(&restored, original);
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(original).unwrap()
    );
}

#[test]
fn absent_control_handles_append_once_without_rewriting_original_terminal_facts() {
    let original = terminal();
    let bytes = serde_json::to_vec(&original).unwrap();
    let refined = refinement::settle_control_handles(&original)
        .unwrap()
        .unwrap();
    assert_only_obligations_changed(&original, &refined);
    let previous = original.cleanup.obligations.as_slice();
    let actual = refined.cleanup.obligations.as_slice();
    assert_eq!(&actual[..previous.len()], previous);
    assert_eq!(
        actual.last(),
        Some(&CleanupObligationV3 {
            resource: CleanupResourceV3::ControlHandles,
            settled: true
        })
    );
    assert_eq!(actual.len(), previous.len() + 1);
    assert_eq!(serde_json::to_vec(&original).unwrap(), bytes);
    assert!(
        refinement::settle_control_handles(&refined)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        LinuxWorkloadTerminalV1::parse(&serde_json::to_vec(&refined).unwrap()).unwrap(),
        refined
    );
}

#[test]
fn existing_control_fact_changes_only_its_bit_in_place_and_stays_idempotent() {
    let original = with_control(terminal(), false);
    let refined = refinement::settle_control_handles(&original)
        .unwrap()
        .unwrap();
    assert_only_obligations_changed(&original, &refined);
    for (old, new) in original
        .cleanup
        .obligations
        .as_slice()
        .iter()
        .zip(refined.cleanup.obligations.as_slice())
    {
        assert_eq!(old.resource, new.resource);
        assert_eq!(
            new.settled,
            old.settled || old.resource == CleanupResourceV3::ControlHandles
        );
    }
    assert_eq!(refined.cleanup.state, CleanupStateV1::Incomplete);
    assert!(
        refinement::settle_control_handles(&refined)
            .unwrap()
            .is_none()
    );
    let settled = with_control(terminal(), true);
    let bytes = serde_json::to_vec(&settled).unwrap();
    assert!(
        refinement::settle_control_handles(&settled)
            .unwrap()
            .is_none()
    );
    assert_eq!(serde_json::to_vec(&settled).unwrap(), bytes);
}

#[test]
fn invalid_original_terminal_is_rejected_without_erasing_other_facts() {
    let original = terminal();
    for invalid in [
        {
            let mut v = original.clone();
            v.cleanup
                .obligations
                .try_push(v.cleanup.obligations.as_slice()[0].clone())
                .unwrap();
            v
        },
        {
            let mut v = with_control(original.clone(), false);
            v.cleanup.state = CleanupStateV1::Complete;
            v
        },
        {
            let mut v = original.clone();
            v.request.request_sha256 = DiagnosticSha256::from_bytes([8; 32]);
            v
        },
        {
            let mut v = with_control(original, true);
            v.native.as_mut().unwrap().native_wait_status = Some(0);
            v
        },
    ] {
        let bytes = serde_json::to_vec(&invalid).unwrap();
        assert!(refinement::settle_control_handles(&invalid).is_err());
        assert_eq!(serde_json::to_vec(&invalid).unwrap(), bytes);
    }
}
