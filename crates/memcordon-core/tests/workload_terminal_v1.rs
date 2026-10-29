use memcordon_core::execution_facts::CleanupStateV1;
use memcordon_core::execution_facts::{MixedFilterAbiV2, NativeNamespaceV2, NativeProcessV2};
use memcordon_core::result_v3::*;
use memcordon_core::workload_request::WorkloadAttemptAssociationV1;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};

fn terminal() -> LinuxWorkloadTerminalV1 {
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let source = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let process = |pid| NativeProcessV2 { pid, birth: 0 };
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
    LinuxWorkloadTerminalV1 {
        format: LINUX_WORKLOAD_TERMINAL_FORMAT.into(),
        revision: 1,
        association: WorkloadAttemptAssociationV1 {
            format: "memcordon.workload-attempt".into(),
            revision: 1,
            attempt: [1; 16],
            challenge: [2; 16],
            request_sha256: digest.clone(),
            boot_id: BoundedText::new("actual-boot").unwrap(),
            provider: PublicProviderBindingV1 {
                generation: BoundedText::new(&format!("0.5.8-dev:{source}")).unwrap(),
                source_commit: BoundedText::new(source).unwrap(),
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
            boot_id: BoundedText::new("actual-boot").unwrap(),
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
        output_delivery: OutputDeliveryStateV3::Complete,
        failures: BoundedVec::default(),
    }
}

#[test]
fn recovered_bytes_cannot_exchange_attempt_or_invent_native_wait() {
    let original = terminal();
    assert_eq!(
        LinuxWorkloadTerminalV1::parse(&serde_json::to_vec(&original).unwrap()).unwrap(),
        original
    );
    let mut changed = original.clone();
    changed.request.request_sha256 = DiagnosticSha256::from_bytes([8; 32]);
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.as_mut().unwrap().native_wait_status = Some(0);
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.as_mut().unwrap().boot_id = BoundedText::new("different-boot").unwrap();
    assert!(changed.validate().is_err());
    let mut changed = original;
    changed.native = None;
    assert!(changed.validate().is_err());
}

#[test]
fn cleanup_and_release_need_their_actual_native_observations() {
    let original = terminal();
    let mut changed = original.clone();
    changed.cleanup.obligations = BoundedVec::default();
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed
        .native
        .as_mut()
        .unwrap()
        .supplementary_groups
        .try_push(100)
        .unwrap();
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.as_mut().unwrap().release_monotonic_millis = Some(102);
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.as_mut().unwrap().entrypoint_sha256 =
        memcordon_core::DiagnosticSha256::from_bytes([0; 32]);
    assert!(changed.validate().is_err());
    let mut changed = original;
    changed.release = ReleaseKnowledgeV3::NotReleased;
    assert!(changed.validate().is_err());
}

fn prepared() -> LinuxWorkloadPreparedV1 {
    let original = terminal();
    let mut native = original.native.unwrap();
    native.exec_observed = false;
    native.release_monotonic_millis = None;
    native.exec_observed_monotonic_millis = None;
    native.native_wait_status = None;
    LinuxWorkloadPreparedV1 {
        format: "memcordon.linux-workload-prepared".into(),
        revision: 1,
        association: original.association,
        request: original.request,
        native,
    }
}
#[test]
fn original_prepared_gate_rejects_released_or_inherited_namespace_observations() {
    let original = prepared();
    let bytes = serde_json::to_vec(&original).unwrap();
    assert_eq!(LinuxWorkloadPreparedV1::parse(&bytes).unwrap(), original);
    let mut changed = original.clone();
    changed.native.caller.pid = 0;
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.caller_namespaces[0].inode = 0;
    changed.native.user_namespace.inode = 0;
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.filter_instruction_sha256 = DiagnosticSha256::from_bytes([0; 32]);
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.exec_observed = true;
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.native_wait_status = Some(0);
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.release_monotonic_millis = Some(1);
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.native.mount_namespace = changed.native.caller_namespaces[1].clone();
    assert!(changed.validate().is_err());
    let mut changed = original;
    changed.association.request_sha256 = DiagnosticSha256::from_bytes([9; 32]);
    assert!(changed.validate().is_err());
}

#[test]
fn public_linux_result_closes_native_session_timing_credentials_and_direct_wait() {
    let mut terminal = terminal();
    terminal
        .cleanup
        .obligations
        .try_push(CleanupObligationV3 {
            resource: CleanupResourceV3::ControlHandles,
            settled: true,
        })
        .unwrap();
    let report = ResultV3 {
        format: "memcordon.result".into(),
        revision: 3,
        tool: memcordon_core::execution_facts::OperationalToolV1 {
            name: "memcordon".into(),
            version: "test".into(),
            os: "linux".into(),
            architecture: "aarch64".into(),
            runtime_features: Vec::new(),
        },
        invocation: memcordon_core::InvocationReport {
            syntax: "plus-budgets-v1".into(),
            budget_tokens: Vec::new(),
            memory_token: None,
            deadline_token: None,
            argv: vec![memcordon_core::NativeArgument::from_os(
                std::ffi::OsStr::new("program"),
            )],
        },
        request: Some(terminal.request),
        provider: Some(terminal.association.provider.clone()),
        workload_attempt: Some(terminal.association),
        release: ReleaseKnowledgeV3::Released,
        outcome: memcordon_core::execution_facts::OutcomeV1 {
            kind: memcordon_core::execution_facts::OutcomeKindV1::Completed,
            native_termination: Some(memcordon_core::ChildTermination::ExitCode { code: 7 }),
            wrapper_status: 7,
        },
        cleanup: terminal.cleanup,
        delivery: DeliveryStateV3::Complete,
        output_delivery: Some(OutputDeliveryStateV3::Complete),
        diagnostics: BoundedVec::default(),
        provider_failure: None,
        request_rejection: None,
        windows_rejection: None,
        windows_attempt: None,
        runtime: RuntimeExecutionV3::LinuxPrivate {
            profile: memcordon_core::workload_request::LinuxPrivateProfileV1::LinuxPrivateWorkload,
            native: Box::new(terminal.native.unwrap()),
        },
    };
    report.validate().unwrap();
    let original = serde_json::to_value(&report).unwrap();
    for changed in [
        {
            let mut value = original.clone();
            value["request"] = serde_json::Value::Null;
            value
        },
        {
            let mut value = original.clone();
            value["runtime"]["native"]["caller"]["pid"] = 0.into();
            value
        },
        {
            let mut value = original.clone();
            value["runtime"]["native"]["boot_id"] = "another-boot".into();
            value
        },
        {
            let mut value = original.clone();
            value["runtime"]["native"]["target_uid"] = 1000.into();
            value
        },
        {
            let mut value = original.clone();
            value["runtime"]["native"]["exec_observed_monotonic_millis"] = serde_json::Value::Null;
            value
        },
        {
            let mut value = original.clone();
            value["outcome"]["native_termination"]["code"] = 0.into();
            value
        },
    ] {
        assert!(
            ResultV3::parse(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "accepted substituted native public result {changed}"
        );
    }
}
#[test]
fn prepared_acknowledgment_binds_original_association_and_exact_wire_bytes() {
    let original = prepared();
    let bytes = serde_json::to_vec(&original).unwrap();
    let ack = WorkloadPreparedAckV1 {
        format: "memcordon.workload-prepared-ack".into(),
        revision: 1,
        association: original.association.clone(),
        prepared_sha256: memcordon_core::hash_bytes(&bytes),
    };
    original.validate_ack(&bytes, &ack).unwrap();
    let mut changed = ack.clone();
    changed.association.challenge[0] ^= 1;
    assert!(original.validate_ack(&bytes, &changed).is_err());
    let mut changed = ack.clone();
    changed.prepared_sha256 = DiagnosticSha256::from_bytes([0; 32]);
    assert!(original.validate_ack(&bytes, &changed).is_err());
    let pretty = serde_json::to_vec_pretty(&original).unwrap();
    assert!(original.validate_ack(&pretty, &ack).is_err());
    let mut duplicate = serde_json::to_value(&ack).unwrap();
    duplicate["unknown_authority"] = true.into();
    assert!(WorkloadPreparedAckV1::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err());
}
