#![cfg(target_os = "linux")]

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};

use crate::linux::private_attempt::ProcessIdentityV4;
use crate::linux::private_release_alt_abi::{
    I386AlternateAbiSubwitnessV1, SELECTOR, X32AlternateAbiSubwitnessV1, X32ControlOutcomeV1,
    i386_response_digest_for_test, x32_control_response_digest_for_test,
};
use crate::linux::private_release_alt_abi_raw::readback_closed_x32_raw;
use crate::linux::private_release_case::{ReleaseCaseRequestV1, ReleaseStageV1};
use crate::linux::private_release_i386_raw::readback_i386_raw;

fn unit_witness(challenge: &[u8; 32], filter: &DiagnosticSha256) -> X32AlternateAbiSubwitnessV1 {
    // These deterministic values test binding only; they are never treated
    // as observed child processes or native release evidence.
    let native = ProcessIdentityV4 {
        pid: 1234,
        start_time: 17,
    };
    let alternate = ProcessIdentityV4 {
        pid: 1235,
        start_time: 18,
    };
    let outer_control = ProcessIdentityV4 {
        pid: 1236,
        start_time: 19,
    };
    let mut response = b"memcordon-private-release-native-getpid-v1\0".to_vec();
    response.extend_from_slice(challenge);
    response.extend_from_slice(filter.bytes());
    response.extend_from_slice(&(native.pid as libc::pid_t).to_be_bytes());
    response.extend_from_slice(&(native.pid as libc::c_long).to_be_bytes());
    X32AlternateAbiSubwitnessV1 {
        challenge_sha256: hash_bytes(challenge),
        filter_sha256: filter.clone(),
        native,
        native_response_sha256: hash_bytes(&response),
        outer_control_response_sha256: x32_control_response_digest_for_test(
            challenge,
            filter,
            outer_control.pid as libc::pid_t,
            X32ControlOutcomeV1::Enosys,
        ),
        outer_control,
        outer_control_outcome: X32ControlOutcomeV1::Enosys,
        alternate,
        alternate_signal: libc::SIGSYS,
    }
}

#[test]
fn x32_raw_witness_rejects_challenge_filter_terminal_and_identity_substitution() {
    let challenge = [0x41; 32];
    let filter = hash_bytes(b"reviewed-filter-unit-only");
    let witness = unit_witness(&challenge, &filter);
    assert!(witness.verify_binding(&challenge, &filter).is_ok());
    assert!(witness.verify_binding(&[0x42; 32], &filter).is_err());
    assert!(
        witness
            .verify_binding(&challenge, &hash_bytes(b"other-filter"))
            .is_err()
    );
    let mut changed = witness.clone();
    changed.alternate_signal = libc::SIGKILL;
    assert!(changed.verify_binding(&challenge, &filter).is_err());
    changed = witness.clone();
    changed.alternate = changed.native.clone();
    assert!(changed.verify_binding(&challenge, &filter).is_err());
    changed = witness.clone();
    changed.outer_control = changed.alternate.clone();
    assert!(changed.verify_binding(&challenge, &filter).is_err());
    changed = witness.clone();
    changed.outer_control_outcome = X32ControlOutcomeV1::Getpid;
    assert!(changed.verify_binding(&challenge, &filter).is_err());
    changed = witness.clone();
    changed.outer_control_response_sha256 = hash_bytes(b"forged-outer-response");
    assert!(changed.verify_binding(&challenge, &filter).is_err());
    changed = witness;
    changed.native_response_sha256 = hash_bytes(b"forged-response");
    assert!(changed.verify_binding(&challenge, &filter).is_err());
}

#[test]
fn detached_x32_readback_rejects_final_public_stage_without_opening_raw() {
    let directory = std::fs::File::open("/dev/null").expect("fixed Linux device exists");
    let request = ReleaseCaseRequestV1 {
        stage: ReleaseStageV1::FinalPublic,
        selector: SELECTOR,
        challenge: [0x55; 32],
    };
    let identity = ProcessIdentityV4 {
        pid: 1234,
        start_time: 17,
    };
    let expected = hash_bytes(b"unit-only");
    assert!(
        readback_closed_x32_raw(
            &directory, &request, &expected, &expected, &identity, &identity
        )
        .is_err()
    );
}

#[test]
fn i386_witness_rejects_challenge_filter_response_signal_and_alias() {
    let challenge = [0x63; 32];
    let filter = hash_bytes(b"reviewed-i386-filter-unit-only");
    let control = ProcessIdentityV4 {
        pid: 2240,
        start_time: 27,
    };
    let filtered = ProcessIdentityV4 {
        pid: 2241,
        start_time: 28,
    };
    let witness = I386AlternateAbiSubwitnessV1 {
        challenge_sha256: hash_bytes(&challenge),
        filter_sha256: filter.clone(),
        outer_control_response_sha256: i386_response_digest_for_test(
            &challenge,
            &filter,
            control.pid as libc::pid_t,
        ),
        outer_control: control,
        filtered,
        filtered_signal: libc::SIGSYS,
    };
    assert!(witness.verify_binding(&challenge, &filter).is_ok());
    assert!(witness.verify_binding(&[0x64; 32], &filter).is_err());
    assert!(
        witness
            .verify_binding(&challenge, &hash_bytes(b"other"))
            .is_err()
    );
    let mut changed = witness.clone();
    changed.outer_control_response_sha256 = hash_bytes(b"forged-return");
    assert!(changed.verify_binding(&challenge, &filter).is_err());
    changed = witness.clone();
    changed.filtered_signal = libc::SIGKILL;
    assert!(changed.verify_binding(&challenge, &filter).is_err());
    changed = witness;
    changed.filtered = changed.outer_control.clone();
    assert!(changed.verify_binding(&challenge, &filter).is_err());
}

#[test]
fn detached_i386_readback_rejects_final_public_stage_without_opening_raw() {
    let directory = std::fs::File::open("/dev/null").expect("fixed Linux device exists");
    let request = ReleaseCaseRequestV1 {
        stage: ReleaseStageV1::FinalPublic,
        selector: SELECTOR,
        challenge: [0x65; 32],
    };
    let identity = ProcessIdentityV4 {
        pid: 2240,
        start_time: 27,
    };
    let expected = hash_bytes(b"unit-only");
    assert!(
        readback_i386_raw(
            &directory, &request, &expected, &expected, &identity, &identity
        )
        .is_err()
    );
}
