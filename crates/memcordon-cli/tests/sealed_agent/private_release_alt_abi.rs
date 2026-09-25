#![cfg(target_os = "linux")]

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};

use crate::linux::network_filter::{NativeAbi, compile_initial_closed_filter};
use crate::linux::private_attempt::ProcessIdentityV4;
use crate::linux::private_release_alt_abi::{
    I386AlternateAbiSubwitnessV1, SELECTOR, i386_response_digest_for_test, ready_digest_for_test,
};

#[test]
fn alternate_abi_selector_remains_closed_without_aarch32_proof() {
    assert!(!crate::linux::private_release_case::candidate_physical_selector_supported(SELECTOR));
}

#[test]
fn x32_ready_binding_separates_branches_challenges_filter_and_process() {
    let challenge = [0x42; 32];
    let filter = hash_bytes(b"reviewed-x64-filter");
    let native = ready_digest_for_test(false, &challenge, &filter, 1234);
    assert_ne!(
        native,
        ready_digest_for_test(true, &challenge, &filter, 1234)
    );
    assert_ne!(
        native,
        ready_digest_for_test(false, &[0x43; 32], &filter, 1234)
    );
    assert_ne!(
        native,
        ready_digest_for_test(false, &challenge, &hash_bytes(b"other-filter"), 1234)
    );
    assert_ne!(
        native,
        ready_digest_for_test(false, &challenge, &filter, 1235)
    );
    assert_ne!(native, DiagnosticSha256::from_bytes([0; 32]));
}

#[test]
fn reviewed_x64_filter_kills_the_x32_marked_getpid_entry() {
    let program = compile_initial_closed_filter(NativeAbi::X86_64);
    // The reviewed first branch checks the AUDIT_ARCH; the next two words
    // test the x32 syscall bit and return SECCOMP_RET_KILL_PROCESS.
    assert_eq!(program[4].code, 0x45); // BPF_JMP | BPF_JSET | BPF_K
    assert_eq!(program[4].k, 0x4000_0000);
    assert_eq!(program[5].code, 0x06); // BPF_RET | BPF_K
    assert_eq!(program[5].k, 0x8000_0000);
}

#[test]
fn i386_control_and_kill_binding_rejects_swapped_or_non_sigsys_evidence() {
    let challenge = [0x51; 32];
    let filter = hash_bytes(b"reviewed-x64-filter");
    let mut witness = I386AlternateAbiSubwitnessV1 {
        challenge_sha256: hash_bytes(&challenge),
        filter_sha256: filter.clone(),
        outer_control: ProcessIdentityV4 {
            pid: 1201,
            start_time: 91,
        },
        outer_control_response_sha256: i386_response_digest_for_test(&challenge, &filter, 1201),
        filtered: ProcessIdentityV4 {
            pid: 1202,
            start_time: 92,
        },
        filtered_signal: libc::SIGSYS,
    };
    witness.verify_binding(&challenge, &filter).unwrap();
    assert!(witness.verify_binding(&[0x52; 32], &filter).is_err());
    witness.filtered_signal = libc::SIGILL;
    assert!(witness.verify_binding(&challenge, &filter).is_err());
    witness.filtered_signal = libc::SIGSYS;
    witness.filtered = witness.outer_control.clone();
    assert!(witness.verify_binding(&challenge, &filter).is_err());
}
