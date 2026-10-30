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
    for (case, syscall, arguments, actual_bpf_return) in [
        (
            "seqpacket-pair-positive",
            pair,
            [1, 5 | 0x80000, 0],
            0x7fff0000,
        ),
        ("named-seqpacket-denied", socket, [1, 5, 0], 0x5005d),
        ("seqpacket-protocol-denied", pair, [1, 5, 1], 0x5005d),
    ] {
        observations.push(FilterObservation {
            case: case.into(),
            architecture: arch,
            syscall,
            arguments,
            actual_bpf_return,
        });
    }
    FilterVector {
        profile: "linux-private-workload-v1".into(),
        abi: abi.into(),
        program_sha256: digest(&program),
        program,
        observations,
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
        test_name: "native_current_filter::current_filter_vectors_emit_actual_component_receipts"
            .into(),
        native_target: key.target.clone(),
        executable_sha256: "11".repeat(32),
        challenge_sha256: "22".repeat(32),
        operation: "current-filter-compiler-bpf-vectors".into(),
        vectors: vec![
            vector("x86_64", 0xc000003e, 41, 53),
            vector("aarch64", 0xc00000b7, 198, 199),
        ],
    };
    validate_linux_filter_receipt(&receipt, &key).unwrap();
    for abi in 0..2 {
        for mutation in 0..4 {
            let mut changed = receipt.clone();
            let index = changed.vectors[abi]
                .observations
                .iter()
                .position(|item| item.case == "seqpacket-pair-positive")
                .unwrap();
            match mutation {
                0 => {
                    changed.vectors[abi].observations[index].case =
                        "seqpacket-pair-positive-or-denied".into()
                }
                1 => changed.vectors[abi].observations[index].case = "unknown-positive".into(),
                2 => changed.vectors[abi].observations[index].actual_bpf_return = 0x5005d,
                _ => {
                    changed.vectors[abi].observations[index] =
                        changed.vectors[abi].observations[0].clone()
                }
            }
            assert!(validate_linux_filter_receipt(&changed, &key).is_err());
        }
    }
    let mut changed = receipt.clone();
    changed.vectors[0].profile = "unsupported-profile".into();
    assert!(
        validate_linux_filter_receipt(&changed, &key).is_err(),
        "another profile cannot substitute for the sole current program"
    );
    let mut changed = receipt.clone();
    changed.vectors[1].program = receipt.vectors[0].program.clone();
    changed.vectors[1].program_sha256 = digest(&changed.vectors[1].program);
    assert!(
        validate_linux_filter_receipt(&changed, &key).is_err(),
        "another ABI program cannot substitute for the selected architecture"
    );
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
