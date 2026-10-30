#![cfg(target_os = "linux")]
use crate::linux::network_filter::{NativeAbi, validate_program};
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

/// Independent BPF vectors for both supported ABIs.
#[test]
fn current_filter_vectors_match_profile() {
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
        for (case, arch, number, arguments, expected) in cases {
            let actual = evaluate_filter(&program, arch, number, arguments);
            assert_eq!(actual, expected, "{name}/{case}");
        }
    }
}
