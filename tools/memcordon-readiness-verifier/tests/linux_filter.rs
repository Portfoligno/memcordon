//! Structural decoder vectors only; these do not claim native compilation or attachment.
use memcordon_readiness_verifier::*;
use sha2::{Digest, Sha256};

fn digest(program: &[Instruction]) -> String {
    let mut bytes = Vec::new();
    for word in program {
        bytes.extend(word.code.to_le_bytes());
        bytes.extend([word.jt, word.jf]);
        bytes.extend(word.k.to_le_bytes());
    }
    hex::encode(Sha256::digest(bytes))
}
fn vector(abi: &str, arch: u32, socket: u32, pair: u32) -> FilterVector {
    let program = frozen_linux_filter_program(abi).unwrap();
    let cases: [(&str, u32, [u32; 3], u32); 8] = [
        ("tcp-positive", socket, [2, 1, 0], 0x7fff0000),
        ("unix-positive", socket, [1, 1, 0], 0x7fff0000),
        ("unix-pair-positive", pair, [1, 1, 0], 0x7fff0000),
        ("udp-denied", socket, [2, 2, 0], 0x5005d),
        ("unix-protocol-denied", socket, [1, 1, 1], 0x5005d),
        ("ipv6", socket, [10, 1, 0], 0x50061),
        ("raw", socket, [2, 3, 0], 0x5005d),
        ("inet-pair", pair, [2, 1, 0], 0x50061),
    ];
    let mut observations = cases[..5]
        .iter()
        .map(|(case, number, args, result)| FilterObservation {
            case: (*case).into(),
            architecture: arch,
            syscall: *number,
            arguments: args.map(u64::from),
            actual_bpf_return: *result,
        })
        .collect::<Vec<_>>();
    observations.push(FilterObservation {
        case: "wrong-architecture".into(),
        architecture: arch ^ 1,
        syscall: socket,
        arguments: [2, 1, 0],
        actual_bpf_return: 0x80000000,
    });
    FilterVector {
        abi: abi.into(),
        program_sha256: digest(&program),
        program,
        observations,
    }
}
#[test]
fn independently_reconstructed_gnu_program_matches_audited_comparison_words() {
    // These comparison pins came from a host-only pure operational compiler
    // extraction with selected GNU aliases; they claim no kernel attachment.
    for (abi, length, sha) in [
        (
            "x86_64",
            748,
            "685124754773052438afe6c87debf548ce56bcb90976fa7ede8b72dc7e5e1a73",
        ),
        (
            "aarch64",
            668,
            "f5fa0fca0556b9c4063d3b11cf5e97cc8f99963404d7d45fc6be36e99d12dff6",
        ),
    ] {
        let program = frozen_linux_filter_program(abi).unwrap();
        assert_eq!(program.len(), length, "{abi} complete instruction count");
        assert_eq!(
            digest(&program),
            sha,
            "{abi} complete independent instruction catalogue"
        );
    }
}
#[test]
fn structural_filter_decoder_rejects_rehashed_decision_and_inventory_mutations() {
    let key = CaseKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: None,
        evidence_class: EvidenceClass::NativeComponentRegression,
        family: "L-VER-01".into(),
        scenario: "filter-x64".into(),
    };
    let receipt = LinuxFilterReceipt {
        format: "memcordon.linux-filter-component".into(),
        revision: 1,
        run_id: "1".into(),
        recipe_id: "native-linux-x64".into(),
        test_name: "native_private_tcp::mixed_filter_vectors_emit_actual_component_receipts".into(),
        native_target: key.target.clone(),
        executable_sha256: "11".repeat(32),
        challenge_sha256: "22".repeat(32),
        operation: "mixed-filter-compiler-bpf-vectors".into(),
        vectors: vec![
            vector("x86_64", 0xc000003e, 41, 53),
            vector("aarch64", 0xc00000b7, 198, 199),
        ],
    };
    validate_linux_filter_receipt(&receipt, &key).unwrap();
    let mut changed = receipt.clone();
    changed.vectors[0].program[11].k = 0x7fff0001;
    changed.vectors[0].program_sha256 = digest(&changed.vectors[0].program);
    assert!(validate_linux_filter_receipt(&changed, &key).is_err());
    let mut changed = receipt.clone();
    changed.vectors.pop();
    assert!(validate_linux_filter_receipt(&changed, &key).is_err());
    let mut changed = receipt.clone();
    changed.vectors[0].observations.pop();
    assert!(validate_linux_filter_receipt(&changed, &key).is_err());
    let mut changed = receipt.clone();
    changed.vectors[0].program[0].code = 0xffff;
    changed.vectors[0].program_sha256 = digest(&changed.vectors[0].program);
    assert!(validate_linux_filter_receipt(&changed, &key).is_err());
    let mut changed = receipt.clone();
    // An unobserved syscall allowance leaves all socket probes unchanged.
    let last = changed.vectors[0].program.len() - 1;
    changed.vectors[0].program.splice(
        last..last,
        [
            Instruction {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: 999,
            },
            Instruction {
                code: 6,
                jt: 0,
                jf: 0,
                k: 0x7fff0000,
            },
        ],
    );
    changed.vectors[0].program_sha256 = digest(&changed.vectors[0].program);
    assert!(
        validate_linux_filter_receipt(&changed, &key).is_err(),
        "rehashed unobserved syscall authority cannot bypass complete catalogue"
    );
}
