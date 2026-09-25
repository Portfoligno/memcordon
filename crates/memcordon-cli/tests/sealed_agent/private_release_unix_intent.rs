#![cfg(target_os = "linux")]

use crate::linux::private_attempt::ProcessIdentityV4;
use crate::linux::private_release_unix_gate::{ack_bytes_for_test, verify_ack_for_test};
use crate::linux::private_release_unix_intent::{
    SELECTOR, UnixAbsenceSnapshotV1, UnixIntentSupervisorAbsenceV1, expected_observation_bytes,
    observer_ack_digest, proc_unix_endpoint_absent,
};
use memcordon_core::workload_codec::hash_bytes;

#[test]
fn abstract_and_pathname_intents_record_socket_denial_before_bind() {
    assert_eq!(
        SELECTOR,
        "private_tcp::af_unix_abstract_and_pathname_denied"
    );
    let challenge = [0x5a; 32];
    let bytes = expected_observation_bytes(&challenge).unwrap();
    let mut cursor = b"memcordon-private-unix-intent-v1\0".len() + challenge.len();
    assert_eq!(
        &bytes[..cursor],
        b"memcordon-private-unix-intent-v1\0"
            .iter()
            .copied()
            .chain(challenge)
            .collect::<Vec<_>>()
    );
    for kind in [1_u8, 2_u8] {
        assert_eq!(bytes[cursor], kind);
        cursor += 1;
        let length = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        let address = &bytes[cursor..cursor + length];
        cursor += length;
        if kind == 1 {
            assert_eq!(address.last(), Some(&0));
            assert!(address.starts_with(b"/tmp/"));
            assert!(
                address
                    .windows(b"-path".len())
                    .any(|bytes| bytes == b"-path")
            );
        } else {
            assert_eq!(address.first(), Some(&0));
            assert!(
                address
                    .windows(b"-abstract".len())
                    .any(|bytes| bytes == b"-abstract")
            );
        }
        assert_eq!(
            i32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()),
            libc::EAFNOSUPPORT
        );
        cursor += 4;
        assert_eq!(&bytes[cursor..cursor + 2], &[0, 0]);
        cursor += 2;
    }
    assert_eq!(cursor, bytes.len());
    assert_ne!(bytes, expected_observation_bytes(&[0x5b; 32]).unwrap());
    assert!(expected_observation_bytes(&[0; 32]).is_err());
}

#[test]
fn unix_intent_has_a_dedicated_physical_route() {
    assert!(!crate::linux::private_release_case::candidate_fixture_supported(SELECTOR));
    assert!(!crate::linux::private_release_case::candidate_executable_fixture_supported(SELECTOR));
    assert!(crate::linux::private_release_case::candidate_physical_selector_supported(SELECTOR));
}

#[test]
fn proc_unix_absence_compares_complete_endpoint_fields() {
    let header = b"Num RefCount Protocol Flags Type St Inode Path\n";
    let row =
        b"00000001: 00000001 00000000 00000000 0001 01 42 @other-memcordon-private-unix-name\n";
    let mut inventory = header.to_vec();
    inventory.extend_from_slice(row);
    assert!(proc_unix_endpoint_absent(&inventory, "@memcordon-private-unix-name").unwrap());
    assert!(!proc_unix_endpoint_absent(&inventory, "@other-memcordon-private-unix-name").unwrap());
    inventory.extend_from_slice(
        b"00000002: 00000001 00000000 00000000 0001 01 43 @other spaced endpoint\n",
    );
    assert!(proc_unix_endpoint_absent(&inventory, "@spaced endpoint").unwrap());
    assert!(!proc_unix_endpoint_absent(&inventory, "@other spaced endpoint").unwrap());
    inventory.pop();
    assert!(proc_unix_endpoint_absent(&inventory, "@memcordon-private-unix-name").is_err());
}

#[test]
fn unix_supervisor_absence_requires_same_target_namespace_and_ack() {
    let challenge = [0x51; 32];
    let target = ProcessIdentityV4 {
        pid: 3401,
        start_time: 501,
    };
    let snapshot = UnixAbsenceSnapshotV1 {
        network_namespace_inode: 701,
        mount_namespace_inode: 702,
        target_root_inode: 703,
        proc_unix_sha256: hash_bytes(b"Num RefCount Protocol Flags Type St Inode Path\n"),
        pathname_absent: true,
        abstract_absent: true,
    };
    let mut evidence = UnixIntentSupervisorAbsenceV1 {
        target: target.clone(),
        challenge_sha256: hash_bytes(&challenge),
        before_release: snapshot.clone(),
        after_denials_before_ack: snapshot,
        ack_sha256: observer_ack_digest(&challenge),
    };
    evidence.verify_binding(&challenge, &target, 701).unwrap();
    evidence.after_denials_before_ack.network_namespace_inode = 999;
    assert!(evidence.verify_binding(&challenge, &target, 701).is_err());
    evidence.after_denials_before_ack.network_namespace_inode = 701;
    evidence.after_denials_before_ack.abstract_absent = false;
    assert!(evidence.verify_binding(&challenge, &target, 701).is_err());
    evidence.after_denials_before_ack.abstract_absent = true;
    evidence.ack_sha256 = hash_bytes(b"wrong-ack");
    assert!(evidence.verify_binding(&challenge, &target, 701).is_err());
}

#[test]
fn unix_ci_ack_requires_exact_gate_and_independent_absence() {
    let challenge = [0x72; 32];
    let result_key = hash_bytes(b"result");
    let gate_sha256 = hash_bytes(b"gate");
    let snapshot = UnixAbsenceSnapshotV1 {
        network_namespace_inode: 701,
        mount_namespace_inode: 702,
        target_root_inode: 703,
        proc_unix_sha256: hash_bytes(b"before"),
        pathname_absent: true,
        abstract_absent: true,
    };
    let witness = UnixIntentSupervisorAbsenceV1 {
        target: ProcessIdentityV4 {
            pid: 3401,
            start_time: 501,
        },
        challenge_sha256: hash_bytes(&challenge),
        before_release: snapshot.clone(),
        after_denials_before_ack: snapshot.clone(),
        ack_sha256: observer_ack_digest(&challenge),
    };
    let bytes = ack_bytes_for_test(&result_key, &challenge, &gate_sha256, snapshot.clone());
    verify_ack_for_test(&bytes, &result_key, &challenge, &witness, &gate_sha256).unwrap();
    assert!(
        verify_ack_for_test(
            &bytes,
            &result_key,
            &challenge,
            &witness,
            &hash_bytes(b"other-gate"),
        )
        .is_err()
    );
    let mut wrong = snapshot;
    wrong.abstract_absent = false;
    let bytes = ack_bytes_for_test(&result_key, &challenge, &gate_sha256, wrong);
    assert!(verify_ack_for_test(&bytes, &result_key, &challenge, &witness, &gate_sha256).is_err());
}
