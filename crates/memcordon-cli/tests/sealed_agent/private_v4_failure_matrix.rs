#![cfg(target_os = "linux")]

use std::num::{NonZeroU32, NonZeroU64};

use crate::linux::private_attempt::{
    DurablePrivateAttempt, PrivateAttemptPhase, PrivateAttemptRecordV4, ProcessIdentityV4,
    ReleaseKnowledge,
};
use crate::linux::private_guardian::{GuardianTerminalV4, GuardianTriggerV4};
use memcordon_core::workload_admission_v2::ProviderAdmissionSnapshotV2;
use memcordon_core::workload_contract::*;
use memcordon_core::workload_evidence_v2::{
    EntryResourceObservationV2, NamespaceObservationV2, PrivatePortPolicyV1,
    PrivateTcpCheckpointV2, QualifiedNativeAbiV2, TargetIdentityKindV2,
    TargetIdentityObservationV2, VerifiedTrue,
};
use memcordon_core::workload_registry::{CallerSelector, GrantChangeDisposition};
use memcordon_core::workload_registry_v2::*;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};
use tempfile::TempDir;

const ATTEMPT_ID: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.into()).unwrap()
}

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn process(pid: u32) -> ProcessIdentityV4 {
    ProcessIdentityV4 {
        pid,
        start_time: u64::from(pid) + 100,
    }
}

fn frozen_authority() -> ProviderAdmissionSnapshotV2 {
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    let mut entrypoints = BoundedVec::default();
    entrypoints
        .try_push(ApprovedEntrypointV2 {
            id: id("approved"),
            absolute_path: BoundedText::new("/opt/approved").unwrap(),
            sha256: digest(2),
            size: NonZeroU64::new(1024).unwrap(),
        })
        .unwrap();
    let mut identity = LinuxExecutionIdentityV2 {
        reference: ExecutionIdentityRefV2 {
            id: id("candidate"),
            semantic_digest: digest(1),
        },
        enabled: true,
        uid: NonZeroU32::new(2000).unwrap(),
        gid: NonZeroU32::new(2000).unwrap(),
        supplementary_groups: BoundedVec::default(),
        entrypoints,
    };
    identity.reference.semantic_digest = identity.semantic_digest().unwrap();
    let mut profiles = BoundedVec::default();
    profiles
        .try_push(ProfileDefinitionV2 {
            profile,
            reference: profile.reference(),
            enabled: true,
            qualification_digest: digest(3),
        })
        .unwrap();
    let mut identities = BoundedVec::default();
    identities.try_push(identity.clone()).unwrap();
    let mut callers = BoundedVec::default();
    callers
        .try_push(CallerSelector::Linux { uid: 1000 })
        .unwrap();
    let mut plans = BoundedVec::default();
    plans.try_push(digest(4)).unwrap();
    let mut grants = BoundedVec::default();
    grants
        .try_push(PolicyGrantV2 {
            id: id("grant"),
            revision: NonZeroU64::MIN,
            profile: profile.reference(),
            ceiling: profile.ceiling(),
            enabled: true,
            callers,
            approved_plans: plans,
            execution_identity: ExecutionIdentityRequestV2::AdministratorProfile {
                reference: identity.reference.clone(),
            },
        })
        .unwrap();
    let registry = PolicyRegistryV2 {
        schema_version: ContractVersionTwo::default(),
        profiles,
        execution_identities: identities,
        grants,
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    };
    let request = WorkloadContractV2 {
        schema_version: ContractVersionTwo::default(),
        workload_plan_digest: digest(4),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: id("grant"),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest(4),
        },
        ceiling: profile.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([5; 16]),
            revision: NonZeroU64::MIN,
        },
        execution_identity: ExecutionIdentityRequestV2::AdministratorProfile {
            reference: identity.reference,
        },
    };
    ProviderAdmissionSnapshotV2::freeze(
        &registry,
        &request.expected_epoch,
        &request,
        &CallerSelector::Linux { uid: 1000 },
        digest(3),
        digest(6),
        QualifiedNativeAbiV2::X86_64LinuxGnu,
        Nonce128([7; 16]),
        Nonce128([8; 16]),
        digest(9),
        digest(10),
    )
    .unwrap()
}

fn allocated() -> PrivateAttemptRecordV4 {
    PrivateAttemptRecordV4::allocated(
        BoundedText::new(ATTEMPT_ID).unwrap(),
        BoundedText::new("boot-1").unwrap(),
        process(100),
        digest(9),
    )
    .unwrap()
}

fn gated(state: &TempDir) -> (DurablePrivateAttempt, ProviderAdmissionSnapshotV2) {
    let authority = frozen_authority();
    let mut durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    durable.freeze_authority(authority.clone()).unwrap();
    durable.boundary_created().unwrap();
    durable.guardian_ready(process(101)).unwrap();
    durable
        .target_gated(process(102), process(103), 22)
        .unwrap();
    (durable, authority)
}

fn checkpoint(
    durable: &DurablePrivateAttempt,
    authority: &ProviderAdmissionSnapshotV2,
) -> PrivateTcpCheckpointV2 {
    let yes = VerifiedTrue::observed(true).unwrap();
    PrivateTcpCheckpointV2 {
        attempt_binding: durable
            .record()
            .binding
            .as_ref()
            .unwrap()
            .canonical_digest()
            .unwrap(),
        profile: authority.profile.reference.clone(),
        identity: TargetIdentityObservationV2 {
            kind: TargetIdentityKindV2::AdministratorProfile {
                reference: authority.identity.reference.clone(),
            },
            entrypoint_digest: authority.identity.entrypoints.as_slice()[0].sha256.clone(),
            exact_credentials_verified: yes,
            no_new_privileges_verified: yes,
            capability_sets_empty: yes,
            bounding_set_empty: yes,
        },
        caller_envelope_reference: authority.caller_envelope_reference,
        target_network_namespace: NamespaceObservationV2::observed(
            NonZeroU64::new(11).unwrap(),
            NonZeroU64::new(22).unwrap(),
            true,
            true,
        )
        .unwrap(),
        topology_digest: digest(11),
        filter_digest: digest(12),
        native_abi: authority.native_abi,
        port_policy: PrivatePortPolicyV1::observed(0, 32768, 60999, true).unwrap(),
        resources: EntryResourceObservationV2::observed(5, 3, true, true, true, true, true)
            .unwrap(),
        guardian_verified: yes,
        epoch_revalidated: yes,
        checkpoint_durable: yes,
    }
}

#[test]
fn v4_phase_faults_leave_the_last_durable_state_and_recovery_ambiguous() {
    let state = TempDir::new().unwrap();
    let cgroups = TempDir::new().unwrap();
    let authority = frozen_authority();
    let mut durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    assert!(durable.guardian_ready(process(101)).is_err());
    assert!(
        durable
            .target_gated(process(102), process(103), 22)
            .is_err()
    );
    assert_eq!(
        durable.read_back().unwrap().phase,
        PrivateAttemptPhase::Allocated
    );
    durable.freeze_authority(authority).unwrap();
    assert!(
        durable
            .target_gated(process(102), process(103), 22)
            .is_err()
    );
    durable.boundary_created().unwrap();
    assert!(
        durable
            .target_gated(process(102), process(103), 22)
            .is_err()
    );
    durable.guardian_ready(process(101)).unwrap();
    assert!(durable.target_gated(process(102), process(103), 0).is_err());
    assert_eq!(
        durable.read_back().unwrap().phase,
        PrivateAttemptPhase::GuardianReady
    );
    assert_eq!(
        durable.read_back().unwrap().release_knowledge,
        ReleaseKnowledge::NotReleased
    );
    assert_eq!(
        crate::linux::recovery::recover_test_roots(state.path(), cgroups.path()).unwrap(),
        vec![ATTEMPT_ID.to_owned()]
    );
    assert!(durable.retire_unallocated().is_err());
    assert!(state.path().join(ATTEMPT_ID).exists());
}

#[test]
fn v4_forged_checkpoint_never_creates_a_release_capability() {
    let state = TempDir::new().unwrap();
    let cgroups = TempDir::new().unwrap();
    let (mut durable, authority) = gated(&state);
    let genuine = checkpoint(&durable, &authority);
    let mut variants = Vec::new();
    let mut changed = genuine.clone();
    changed.attempt_binding = digest(99);
    variants.push(changed);
    let mut changed = genuine.clone();
    changed.profile.semantic_digest = digest(99);
    variants.push(changed);
    let mut changed = genuine.clone();
    changed.caller_envelope_reference = Nonce128([99; 16]);
    variants.push(changed);
    let mut changed = genuine.clone();
    changed.native_abi = QualifiedNativeAbiV2::Aarch64LinuxGnu;
    variants.push(changed);
    let mut changed = genuine.clone();
    changed.identity.entrypoint_digest = digest(99);
    variants.push(changed);
    let mut changed = genuine.clone();
    changed.target_network_namespace.target_network_inode = NonZeroU64::new(23).unwrap();
    variants.push(changed);
    for changed in variants {
        assert!(durable.commit_checkpoint(changed).is_err());
        let observed = durable.read_back().unwrap();
        assert_eq!(observed.phase, PrivateAttemptPhase::TargetGated);
        assert!(observed.checkpoint.is_none());
        assert_eq!(observed.release_knowledge, ReleaseKnowledge::NotReleased);
    }
    assert_eq!(
        crate::linux::recovery::recover_test_roots(state.path(), cgroups.path()).unwrap(),
        vec![ATTEMPT_ID.to_owned()]
    );
}

#[test]
fn v4_failed_release_send_keeps_uncertainty_and_blocks_success_projection() {
    let state = TempDir::new().unwrap();
    let cgroups = TempDir::new().unwrap();
    let (mut durable, authority) = gated(&state);
    let exact = checkpoint(&durable, &authority);
    let checkpoint_digest = exact.canonical_digest().unwrap();
    let committed = durable.commit_checkpoint(exact).unwrap();
    assert!(durable.execution_observed().is_err());
    let permit = durable.release_intent(committed).unwrap();
    let mut sink = tempfile::tempfile().unwrap();
    assert!(
        permit
            .send(&mut sink, "wrong-attempt", &checkpoint_digest)
            .is_err()
    );
    assert_eq!(sink.metadata().unwrap().len(), 0);
    assert_eq!(
        durable.read_back().unwrap().phase,
        PrivateAttemptPhase::ReleaseIntent
    );
    assert_eq!(
        durable.read_back().unwrap().release_knowledge,
        ReleaseKnowledge::PossiblyReleased
    );
    assert_eq!(
        crate::linux::recovery::recover_test_roots(state.path(), cgroups.path()).unwrap(),
        vec![ATTEMPT_ID.to_owned()]
    );
    durable
        .cleanup_incomplete("simulated failed cleanup")
        .unwrap();
    assert!(durable.execution_observed().is_err());
    assert_eq!(
        durable.read_back().unwrap().phase,
        PrivateAttemptPhase::CleanupIncomplete
    );
    assert!(state.path().join(ATTEMPT_ID).exists());
    assert_eq!(
        crate::linux::recovery::recover_test_roots(state.path(), cgroups.path()).unwrap(),
        vec![ATTEMPT_ID.to_owned()]
    );
}

#[test]
fn v4_release_intent_cannot_use_preboundary_retirement() {
    let state = TempDir::new().unwrap();
    let cgroups = TempDir::new().unwrap();
    let (mut durable, authority) = gated(&state);
    let exact = checkpoint(&durable, &authority);
    let committed = durable.commit_checkpoint(exact).unwrap();
    let _permit = durable.release_intent(committed).unwrap();
    assert!(durable.retire_unallocated().is_err());
    assert!(state.path().join(ATTEMPT_ID).exists());
    assert_eq!(
        crate::linux::recovery::recover_test_roots(state.path(), cgroups.path()).unwrap(),
        vec![ATTEMPT_ID.to_owned()]
    );
}

#[test]
fn v4_guardian_loss_without_cleanup_cannot_be_relabelled_as_stop() {
    let attempt_id = [7; 16];
    let terminal = GuardianTerminalV4 {
        attempt_id,
        trigger: GuardianTriggerV4::WorkerLost,
        boundary_retired: false,
    };
    let bytes = terminal.encode();
    assert_eq!(
        GuardianTerminalV4::decode(bytes, attempt_id).unwrap(),
        terminal
    );
    let mut forged = bytes;
    forged[0] = 3;
    assert!(GuardianTerminalV4::decode(forged, attempt_id).is_err());
    let mut forged = bytes;
    forged[17] = 1;
    forged[18] = 1;
    assert!(GuardianTerminalV4::decode(forged, attempt_id).is_err());
    assert!(GuardianTerminalV4::decode(bytes, [8; 16]).is_err());
}
