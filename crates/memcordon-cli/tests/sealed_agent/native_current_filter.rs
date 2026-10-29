#![cfg(target_os = "linux")]
use crate::linux::network_filter::{NativeAbi, filter_instruction_digest, validate_program};
fn evaluate_filter<const N: usize>(
    instructions: &[libc::sock_filter],
    architecture: u32,
    number: u32,
    arguments: [u64; N],
) -> u32 {
    let mut accumulator = 0_u32;
    let mut position = 0_usize;
    for _ in 0..instructions.len() {
        let instruction = &instructions[position];
        let advance = match instruction.code {
            0x20 => {
                accumulator = match instruction.k {
                    0 => number,
                    4 => architecture,
                    16 => arguments[0] as u32,
                    20 => (arguments[0] >> 32) as u32,
                    24 => arguments[1] as u32,
                    28 => (arguments[1] >> 32) as u32,
                    32 => arguments[2] as u32,
                    36 => (arguments[2] >> 32) as u32,
                    40 => arguments.get(3).copied().unwrap_or(0) as u32,
                    44 => (arguments.get(3).copied().unwrap_or(0) >> 32) as u32,
                    other => panic!("unexpected seccomp-data offset {other}"),
                };
                1
            }
            0x15 => {
                1 + usize::from(if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                })
            }
            0x45 => {
                1 + usize::from(if accumulator & instruction.k != 0 {
                    instruction.jt
                } else {
                    instruction.jf
                })
            }
            0x05 => 1 + instruction.k as usize,
            0x54 => {
                accumulator &= instruction.k;
                1
            }
            0x06 => return instruction.k,
            other => panic!("unexpected BPF opcode {other}"),
        };
        position += advance;
        assert!(position < instructions.len(), "filter jump escaped program");
    }
    panic!("filter did not return")
}

/// Emits compiler vectors from this measured native operational harness. These
/// are BPF evaluations, not claims that a foreign ABI was attached to the kernel.
#[test]
#[ignore = "requires an explicitly owned native component receipt directory"]
fn current_filter_vectors_emit_actual_component_receipts() {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    fn hexadecimal(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut result, "{byte:02x}").unwrap();
        }
        result
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        run_id: String,
        recipe_id: String,
        native_target: String,
        artifact_root: std::path::PathBuf,
        artifact_prefix: String,
        challenge: Vec<u8>,
    }
    let mut input_bytes = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut input_bytes)
        .unwrap();
    assert!(input_bytes.len() <= 65536);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&input_bytes).unwrap();
    let input: Input = serde_json::from_slice(&input_bytes).unwrap();
    assert!(!input.run_id.is_empty() && !input.recipe_id.is_empty());
    assert_eq!(input.challenge.len(), 32);
    let native_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        _ => panic!("unsupported native filter component target"),
    };
    assert_eq!(input.native_target, native_target);
    assert!(input.artifact_root.is_absolute() && input.artifact_root.is_dir());
    assert!(
        !input.artifact_prefix.is_empty()
            && !input.artifact_prefix.contains(['\\', ':'])
            && input
                .artifact_prefix
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
    );
    let mut executable = Vec::new();
    std::fs::File::open(std::env::current_exe().unwrap())
        .unwrap()
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut executable)
        .unwrap();
    assert!(executable.len() <= 512 * 1024 * 1024);
    let mut vectors = Vec::new();
    for (abi, name, architecture, socket, socketpair) in [
        (NativeAbi::X86_64, "x86_64", 0xc000_003e_u32, 41_u32, 53_u32),
        (
            NativeAbi::Aarch64,
            "aarch64",
            0xc000_00b7_u32,
            198_u32,
            199_u32,
        ),
    ] {
        let program = crate::linux::network_filter::compile_mixed_seqpacket_filter(abi);
        let profile = "linux-private-workload-v1";
        validate_program(&program).unwrap();
        let cases = [
            (
                "tcp-positive",
                architecture,
                socket,
                [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0],
                0x7fff_0000_u32,
            ),
            (
                "unix-positive",
                architecture,
                socket,
                [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0],
                0x7fff_0000,
            ),
            (
                "unix-pair-positive",
                architecture,
                socketpair,
                [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0],
                0x7fff_0000,
            ),
            (
                "seqpacket-pair-positive",
                architecture,
                socketpair,
                [
                    libc::AF_UNIX as u64,
                    (libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC) as u64,
                    0,
                ],
                0x7fff_0000,
            ),
            (
                "named-seqpacket-denied",
                architecture,
                socket,
                [libc::AF_UNIX as u64, libc::SOCK_SEQPACKET as u64, 0],
                0x0005_0000 | libc::EPROTONOSUPPORT as u32,
            ),
            (
                "seqpacket-protocol-denied",
                architecture,
                socketpair,
                [libc::AF_UNIX as u64, libc::SOCK_SEQPACKET as u64, 1],
                0x0005_0000 | libc::EPROTONOSUPPORT as u32,
            ),
            (
                "wrong-architecture",
                architecture ^ 1,
                socket,
                [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0],
                0x8000_0000,
            ),
            (
                "udp-denied",
                architecture,
                socket,
                [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0],
                0x0005_0000 | libc::EPROTONOSUPPORT as u32,
            ),
            (
                "unix-protocol-denied",
                architecture,
                socket,
                [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 1],
                0x0005_0000 | libc::EPROTONOSUPPORT as u32,
            ),
        ];
        let observations = cases.into_iter().map(|(case, arch, number, arguments, expected)| {
            let actual = evaluate_filter(&program, arch, number, arguments);
            assert_eq!(actual, expected, "{name}/{case}");
            serde_json::json!({"case":case,"architecture":arch,"syscall":number,"arguments":arguments,"actual_bpf_return":actual})
        }).collect::<Vec<_>>();
        let instructions = program
            .iter()
            .map(|word| serde_json::json!({"code":word.code,"jt":word.jt,"jf":word.jf,"k":word.k}))
            .collect::<Vec<_>>();
        vectors.push(serde_json::json!({"abi":name,"profile":profile,"program":instructions,"program_sha256":hexadecimal(&filter_instruction_digest(&program).unwrap()),"observations":observations}));
    }
    let receipt = serde_json::json!({"format":"memcordon.linux-filter-component","revision":1,
        "run_id":input.run_id,"recipe_id":input.recipe_id,"test_name":"native_current_filter::current_filter_vectors_emit_actual_component_receipts",
        "native_target":native_target,"executable_sha256":hexadecimal(&Sha256::digest(executable)),
        "challenge_sha256":hexadecimal(&Sha256::digest(input.challenge)),"operation":"current-filter-compiler-bpf-vectors","vectors":vectors});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(input.artifact_root.join("filter-native-receipt.json"))
        .unwrap();
    file.write_all(&serde_json::to_vec(&receipt).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    std::fs::File::open(&input.artifact_root)
        .unwrap()
        .sync_all()
        .unwrap();
}
