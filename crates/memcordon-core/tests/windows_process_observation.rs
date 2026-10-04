use memcordon_core::{
    BoundedProcessIdentitySample, ProcessObservationCoverageV1, ProcessObservationPolicyV1,
    ProcessObservationUnavailableReasonV1, ProcessObserver, WindowsProcessIdentityV1,
    WindowsProcessObservationV2, WindowsQualificationMembershipWitnessV1,
    WindowsQualificationWitnessRoleV1,
};

#[test]
fn cumulative_churn_evicts_evidence_without_limiting_execution() {
    let mut observer = ProcessObserver::new(ProcessObservationPolicyV1::SERVICE).unwrap();
    observer.attempt_poll();
    observer.snapshot_obtained();
    let slots = ProcessObservationPolicyV1::SERVICE.sample_slots();
    let slots_u64 = u64::try_from(slots).unwrap();
    let births = if cfg!(miri) {
        slots_u64 + 32
    } else {
        1_000_000
    };
    assert!(births > slots_u64);
    for birth in 1..=births {
        observer.identity_query_attempted();
        observer
            .observe_identity(WindowsProcessIdentityV1 {
                process_id: 42,
                creation_time_100ns: birth,
            })
            .unwrap();
    }
    let frozen = observer.freeze(None, None);
    frozen.validate("attempt", "nonce", "digest").unwrap();
    let ProcessObservationCoverageV1::Sampled {
        counters,
        omissions,
        sample,
        ..
    } = frozen.coverage
    else {
        panic!("observer must produce sampled coverage");
    };
    assert_eq!(sample.0.len(), slots);
    assert_eq!(counters.identity_observations_verified, births);
    assert_eq!(counters.sample_evictions, births - slots_u64);
    assert_eq!(omissions.sample_eviction, counters.sample_evictions);
    assert_eq!(
        sample.0.first().unwrap().identity.creation_time_100ns,
        births - slots_u64 + 1
    );
}

#[test]
fn retained_identity_updates_without_duplicate_or_eviction() {
    let mut observer = ProcessObserver::new(ProcessObservationPolicyV1::SERVICE).unwrap();
    observer.identity_query_attempted();
    observer
        .observe_identity(WindowsProcessIdentityV1 {
            process_id: 7,
            creation_time_100ns: 11,
        })
        .unwrap();
    observer.identity_query_attempted();
    observer
        .observe_identity(WindowsProcessIdentityV1 {
            process_id: 7,
            creation_time_100ns: 11,
        })
        .unwrap();
    let frozen = observer.freeze(None, None);
    let ProcessObservationCoverageV1::Sampled {
        counters, sample, ..
    } = frozen.coverage
    else {
        panic!("sampled");
    };
    assert_eq!(sample.0.len(), 1);
    assert_eq!(sample.0[0].last_observation_sequence, 2);
    assert_eq!(counters.sample_evictions, 0);
}

#[test]
fn decoding_rejects_element_after_bound() {
    let slots = ProcessObservationPolicyV1::SERVICE.sample_slots();
    let mut bytes = String::from("[");
    for index in 0..=slots {
        if index > 0 {
            bytes.push(',');
        }
        bytes.push_str("{\"identity\":{\"process_id\":1,\"creation_time_100ns\":1},\"last_observation_sequence\":1}");
    }
    bytes.push(']');
    assert!(serde_json::from_str::<BoundedProcessIdentitySample>(&bytes).is_err());
}

#[test]
fn optional_sample_allocation_failure_keeps_observation_truthful() {
    let mut observer = ProcessObserver::without_sample_storage();
    observer.identity_query_attempted();
    observer
        .observe_identity(WindowsProcessIdentityV1 {
            process_id: 17,
            creation_time_100ns: 23,
        })
        .unwrap();
    let frozen = observer.freeze(None, None);
    frozen.validate("attempt", "nonce", "digest").unwrap();
    let ProcessObservationCoverageV1::Sampled {
        counters,
        omissions,
        sample,
        ..
    } = frozen.coverage
    else {
        panic!("sampled");
    };
    assert!(sample.0.is_empty());
    assert_eq!(counters.identity_observations_verified, 1);
    assert_eq!(omissions.allocation_unavailable, 1);
}

#[test]
fn unavailable_observation_cannot_claim_a_verified_witness_or_uncreated_root() {
    let mut unavailable = WindowsProcessObservationV2::unavailable(
        ProcessObservationUnavailableReasonV1::WorkerLostBeforeFreeze,
    );
    unavailable.required_witness = Some(WindowsQualificationMembershipWitnessV1 {
        schema_version: 1,
        role: WindowsQualificationWitnessRoleV1::NestedAlternateToken,
        child_identity: WindowsProcessIdentityV1 {
            process_id: 7,
            creation_time_100ns: 11,
        },
        attempt_id: "attempt".into(),
        nonce: "nonce".into(),
        request_sha256: "digest".into(),
        qualification_lease: "lease".into(),
    });
    assert_eq!(
        unavailable.validate("attempt", "nonce", "digest"),
        Err("process_observation.unavailable")
    );

    let mut uncreated = WindowsProcessObservationV2::unavailable(
        ProcessObservationUnavailableReasonV1::TargetNotCreated,
    );
    uncreated.root_identity = Some(WindowsProcessIdentityV1 {
        process_id: 7,
        creation_time_100ns: 11,
    });
    assert_eq!(
        uncreated.validate("attempt", "nonce", "digest"),
        Err("process_observation.unavailable")
    );
}
