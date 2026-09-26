#![cfg(target_os = "linux")]

use crate::linux::attempt::AttemptRecord;
use crate::linux::entrypoint::{
    EntrypointObjectIdentity, VerifiedEntrypoint, seal_ticket_for_test,
};
use crate::linux::execution_identity::resolve_target_identity;
use crate::linux::launch::{pin_private_prelaunch_authority, private_cleanup_guard_gate_for_test};
use crate::linux::network_filter::{
    NativeAbi, compile_initial_closed_filter, filter_instruction_digest,
    install_gated_private_filter, unconditional_catalogue, validate_program,
};
use crate::linux::network_netlink::{
    loopback_index, parse_datagram, verify_loopback_addresses, verify_loopback_routes,
};
use crate::linux::network_profile::{PrivatePortPolicy, parse_private_port_policy};
use crate::linux::private_target::{
    MAX_FAILURE_DETAIL_BYTES, PrivateControlObservation, PrivateExecArguments, PrivateGateEvent,
    PrivateGateProgress, PrivateReadyObservation, decode_private_control_packet,
    encode_private_failure_packet_for_test, exact_private_authorization_packet,
    pin_private_network_namespace, private_network_owner_for_test,
};
use crate::request::{
    CallerExecutionEnvelopeV2, DeadlineScope, FileIdentity, LaunchPolicyV2, LaunchRequestV2,
    Lifetime, NamespaceIdentity, NetworkLaunchRequestV4, SwapLimit,
};
use memcordon_core::workload_contract::{
    AuthorizationRef, ContractVersionTwo, ExecutionIdentityRefV2, ExecutionIdentityRequestV2,
    LogicalId, Nonce128, PolicyEpoch, WorkloadContractV2,
};
use memcordon_core::workload_registry_v2::{
    ApprovedEntrypointV2, LinuxExecutionIdentityV2, ProfileKindV2,
};
use memcordon_core::{BoundedText, BoundedVec};
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

fn eligible_caller() -> CallerExecutionEnvelopeV2 {
    let namespace = NamespaceIdentity {
        device: 1,
        inode: 1,
    };
    let file = FileIdentity {
        device: 1,
        inode: 1,
    };
    CallerExecutionEnvelopeV2 {
        pid: 100,
        process_start_time: 1,
        uid: 1000,
        gid: 1000,
        supplementary_groups: vec![1000],
        no_new_privs: true,
        capability_bounding_set: 0,
        mount_namespace_identity: namespace,
        pid_namespace_identity: namespace,
        user_namespace_identity: namespace,
        network_namespace_identity: namespace,
        ipc_namespace_identity: namespace,
        uts_namespace_identity: namespace,
        time_namespace_identity: namespace,
        current_directory_identity: file,
        root_identity: file,
    }
}

#[test]
fn preserve_caller_private_identity_requires_nonroot_nnp_and_empty_bounding_set() {
    let mut caller = eligible_caller();
    let request = ExecutionIdentityRequestV2::PreserveCaller;
    let selected = resolve_target_identity(&request, None, &caller, 0, 0).unwrap();
    assert_eq!(selected.uid(), 1000);
    assert_eq!(selected.gid(), 1000);
    assert_eq!(selected.groups(), &[1000]);
    assert!(!selected.delegated());

    caller.no_new_privs = false;
    assert!(resolve_target_identity(&request, None, &caller, 0, 0).is_err());
    caller.no_new_privs = true;
    caller.capability_bounding_set = 1;
    assert!(resolve_target_identity(&request, None, &caller, 0, 0).is_err());
    caller.capability_bounding_set = 0;
    caller.uid = 0;
    assert!(resolve_target_identity(&request, None, &caller, 0, 0).is_err());
}

#[test]
fn delegated_private_identity_requires_a_matching_administrator_record() {
    let request = ExecutionIdentityRequestV2::AdministratorProfile {
        reference: ExecutionIdentityRefV2 {
            id: LogicalId::new("candidate".into()).unwrap(),
            semantic_digest: memcordon_core::workload_codec::hash_bytes(b"candidate"),
        },
    };
    assert!(resolve_target_identity(&request, None, &eligible_caller(), 0, 0).is_err());
}

fn granted_private_identity() -> LinuxExecutionIdentityV2 {
    let mut entrypoints = BoundedVec::default();
    entrypoints
        .try_push(ApprovedEntrypointV2 {
            id: LogicalId::new("candidate-elf".into()).unwrap(),
            absolute_path: BoundedText::new("/opt/memcordon/candidate-elf").unwrap(),
            sha256: memcordon_core::workload_codec::hash_bytes(b"candidate-elf"),
            size: NonZeroU64::new(4096).unwrap(),
        })
        .unwrap();
    let mut identity = LinuxExecutionIdentityV2 {
        reference: ExecutionIdentityRefV2 {
            id: LogicalId::new("candidate".into()).unwrap(),
            semantic_digest: memcordon_core::workload_codec::hash_bytes(b"placeholder"),
        },
        enabled: true,
        uid: NonZeroU32::new(2000).unwrap(),
        gid: NonZeroU32::new(2000).unwrap(),
        supplementary_groups: BoundedVec::default(),
        entrypoints,
    };
    identity.reference.semantic_digest = identity.semantic_digest().unwrap();
    identity
}

fn private_request(identity: ExecutionIdentityRequestV2, program: &[u8]) -> NetworkLaunchRequestV4 {
    let digest = memcordon_core::workload_codec::hash_bytes(b"private-plan");
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    NetworkLaunchRequestV4 {
        contract: WorkloadContractV2 {
            schema_version: ContractVersionTwo::default(),
            workload_plan_digest: digest.clone(),
            authorized_profile: profile.reference(),
            authorization: AuthorizationRef {
                grant_id: LogicalId::new("private-grant".into()).unwrap(),
                grant_revision: NonZeroU64::MIN,
                approved_plan_digest: digest.clone(),
            },
            ceiling: profile.ceiling(),
            requirements: BoundedVec::default(),
            endpoints: BoundedVec::default(),
            expected_epoch: PolicyEpoch {
                service_instance: Nonce128([3; 16]),
                revision: NonZeroU64::MIN,
            },
            execution_identity: identity,
        },
        registry_digest: digest.clone(),
        qualification_digest: digest,
        expected_plan: None,
        launch: LaunchRequestV2 {
            restart_attempt: 0,
            workload_contract: None,
            program: program.to_vec(),
            arguments: Vec::new(),
            environment: Vec::new(),
            policy: LaunchPolicyV2 {
                memory_limit_bytes: None,
                swap_limit: SwapLimit::Host,
                absolute_deadline_millis: None,
                deadline_scope: DeadlineScope::Attempt,
                lifetime: Lifetime::Command,
                poll_interval_millis: 100,
                signal_grace_millis: 100,
                command_exit_grace_millis: 100,
                limit_grace_millis: 100,
            },
            descriptors: Vec::new(),
        },
    }
}

#[test]
fn private_prelaunch_rejects_ungranted_program_before_target_allocation() {
    let identity = granted_private_identity();
    let request = private_request(
        ExecutionIdentityRequestV2::AdministratorProfile {
            reference: identity.reference.clone(),
        },
        b"/opt/memcordon/other-elf",
    );
    let root = std::fs::File::open("/").unwrap();
    let rejection = pin_private_prelaunch_authority(
        &request,
        Some(&identity),
        &eligible_caller(),
        root.as_fd(),
        0,
        0,
    )
    .unwrap_err();
    assert!(rejection.contains("program is not granted"));
}

#[test]
fn private_prelaunch_does_not_infer_elf_authority_from_preserved_caller() {
    let root = std::fs::File::open("/").unwrap();
    let request = private_request(
        ExecutionIdentityRequestV2::PreserveCaller,
        b"/opt/memcordon/candidate-elf",
    );
    let rejection =
        pin_private_prelaunch_authority(&request, None, &eligible_caller(), root.as_fd(), 0, 0)
            .unwrap_err();
    assert!(rejection.contains("entrypoint authority unavailable"));
}

#[test]
fn private_exec_abi_preserves_structured_argv_and_environment_bytes() {
    let mut request = private_request(
        ExecutionIdentityRequestV2::PreserveCaller,
        b"/opt/memcordon/candidate-elf",
    );
    request.launch.arguments = vec![b"--port".to_vec(), b"0".to_vec()];
    request.launch.environment = vec![(b"RUST_LOG".to_vec(), b"info=detail".to_vec())];
    let prepared = PrivateExecArguments::from_request(&request).unwrap();
    let argv: Vec<_> = prepared
        .argv()
        .iter()
        .map(|value| value.as_bytes())
        .collect();
    let environment: Vec<_> = prepared
        .environment()
        .iter()
        .map(|value| value.as_bytes())
        .collect();
    assert_eq!(
        argv,
        [
            b"/opt/memcordon/candidate-elf".as_slice(),
            b"--port".as_slice(),
            b"0".as_slice(),
        ]
    );
    assert_eq!(environment, [b"RUST_LOG=info=detail".as_slice()]);

    request.launch.arguments.push(b"bad\0argument".to_vec());
    assert!(PrivateExecArguments::from_request(&request).is_err());
    request.launch.arguments.pop();
    request.launch.environment = vec![(b"BAD=NAME".to_vec(), b"value".to_vec())];
    assert!(PrivateExecArguments::from_request(&request).is_err());
}

#[test]
fn private_gate_rejects_authorization_or_arming_before_native_filter() {
    let mut progress = PrivateGateProgress::gated();
    assert!(
        progress
            .advance(PrivateGateEvent::AuthorizationReceived)
            .is_err()
    );
    assert!(progress.advance(PrivateGateEvent::ExecArmed).is_err());
    progress.advance(PrivateGateEvent::FilterInstalled).unwrap();
    assert!(progress.advance(PrivateGateEvent::ExecArmed).is_err());
    progress.advance(PrivateGateEvent::ReadyReported).unwrap();
    progress
        .advance(PrivateGateEvent::AuthorizationReceived)
        .unwrap();
    progress.advance(PrivateGateEvent::ExecArmed).unwrap();
    assert!(progress.advance(PrivateGateEvent::ExecArmed).is_err());
}

#[test]
fn private_authorization_packet_is_exact() {
    assert!(exact_private_authorization_packet(&[1]));
    for packet in [b"".as_slice(), b"\0", b"\x01\0", b"\x01\x01"] {
        assert!(!exact_private_authorization_packet(packet));
    }
}

#[test]
fn private_ready_record_is_closed_and_binds_abi_filter_digest() {
    let mut ready = [0_u8; 39];
    ready[..4].copy_from_slice(&[2, 3, 1, 0]);
    ready[4] = 1;
    ready[5..7].copy_from_slice(&27_u16.to_be_bytes());
    ready[7..].fill(0xa5);
    assert_eq!(
        decode_private_control_packet(&ready).unwrap(),
        PrivateControlObservation::Ready(PrivateReadyObservation {
            native_abi: NativeAbi::X86_64,
            instruction_count: 27,
            filter_digest: [0xa5; 32],
            precreated_sendmsg_errno: None,
        })
    );
    ready[4] = 3;
    assert!(decode_private_control_packet(&ready).is_err());
    ready[4] = 1;
    ready[5..7].fill(0);
    assert!(decode_private_control_packet(&ready).is_err());
    assert!(decode_private_control_packet(&ready[..ready.len() - 1]).is_err());
    assert!(decode_private_control_packet(&[2, 2, 0, 0]).is_err());
    let mut probe_ready = [0_u8; 43];
    probe_ready[..4].copy_from_slice(&[2, 3, 1, 1]);
    probe_ready[4] = 1;
    probe_ready[5..7].copy_from_slice(&27_u16.to_be_bytes());
    probe_ready[7..39].fill(0xa5);
    probe_ready[39..43].copy_from_slice(&libc::EPERM.to_le_bytes());
    assert_eq!(
        decode_private_control_packet(&probe_ready).unwrap(),
        PrivateControlObservation::Ready(PrivateReadyObservation {
            native_abi: NativeAbi::X86_64,
            instruction_count: 27,
            filter_digest: [0xa5; 32],
            precreated_sendmsg_errno: Some(libc::EPERM),
        })
    );
    probe_ready[39..43].copy_from_slice(&libc::EACCES.to_le_bytes());
    assert!(decode_private_control_packet(&probe_ready).is_err());
    let failure = encode_private_failure_packet_for_test(3, "seccomp native install: EPERM");
    assert_eq!(
        decode_private_control_packet(&failure).unwrap(),
        PrivateControlObservation::Failed {
            phase: 3,
            detail: "seccomp native install: EPERM".into(),
        }
    );
    let mut truncated = failure;
    truncated.pop();
    assert!(decode_private_control_packet(&truncated).is_err());
    let oversized =
        encode_private_failure_packet_for_test(3, &"x".repeat(MAX_FAILURE_DETAIL_BYTES + 1));
    assert_eq!(
        decode_private_control_packet(&oversized).unwrap(),
        PrivateControlObservation::Failed {
            phase: 3,
            detail: "native failure detail exceeded protocol bound".into(),
        }
    );
}

#[test]
fn private_elf_rebind_rejects_an_unowned_fd4_claim() {
    let file = std::fs::File::open("/").unwrap();
    // SAFETY: F_DUPFD_CLOEXEC duplicates a live descriptor into a slot >=5.
    let duplicate = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    assert!(duplicate >= 5);
    // SAFETY: successful fcntl returned a unique owned descriptor.
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let ticket = seal_ticket_for_test(EntrypointObjectIdentity {
        device: 0,
        inode: 0,
        size: 0,
        sha256: [0; 32],
    });
    assert!(VerifiedEntrypoint::from_sealed_slot(duplicate, ticket).is_err());
}

#[test]
#[ignore = "requires the native Linux pidfd and namespace filesystem"]
fn private_namespace_owner_rejects_the_provider_namespace() {
    let pid = unsafe { libc::getpid() };
    // SAFETY: pidfd_open receives the known current PID and zero flags.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    assert!(raw >= 0);
    // SAFETY: successful pidfd_open returned a uniquely owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let metadata = std::fs::metadata("/proc/self/ns/net").unwrap();
    let current = NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    assert!(pin_private_network_namespace(pid, pidfd.as_fd(), current, current).is_err());
}

#[test]
fn private_cleanup_cannot_disarm_while_network_owner_is_live() {
    let directory = tempfile::TempDir::new().unwrap();
    let record = AttemptRecord::create_for_test(
        directory.path(),
        "0123456789abcdef0123456789abcdef".into(),
        unsafe { libc::getpid() },
    )
    .unwrap();
    let descriptor: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
    let owner = private_network_owner_for_test(
        descriptor,
        NamespaceIdentity {
            device: 1,
            inode: 2,
        },
    );
    assert_eq!(
        private_cleanup_guard_gate_for_test(record, owner),
        (false, true)
    );
}

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

#[test]
fn initial_closed_filter_checks_architecture_x32_and_socket_scalars() {
    const ALLOW: u32 = 0x7fff_0000;
    const KILL: u32 = 0x8000_0000;
    const ERRNO: u32 = 0x0005_0000;
    for (abi, arch, socket, socketpair, clone) in [
        (NativeAbi::X86_64, 0xc000_003e, 41, 53, 56),
        (NativeAbi::Aarch64, 0xc000_00b7, 198, 199, 220),
    ] {
        let filter = compile_initial_closed_filter(abi);
        assert_eq!(validate_program(&filter), Ok(()));
        let tcp = [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0];
        assert_eq!(evaluate_filter(&filter, arch, socket, tcp), ALLOW);
        assert_eq!(
            evaluate_filter(
                &filter,
                arch,
                socket,
                [
                    tcp[0],
                    (libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u64,
                    0,
                ],
            ),
            ALLOW
        );
        assert_eq!(
            evaluate_filter(
                &filter,
                arch,
                socket,
                [tcp[0], tcp[1], libc::IPPROTO_TCP as u64]
            ),
            ALLOW
        );
        assert_eq!(evaluate_filter(&filter, arch ^ 1, socket, tcp), KILL);
        assert_eq!(
            evaluate_filter(&filter, arch, socketpair, [0; 3]),
            ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            evaluate_filter(&filter, arch, 435, [0; 3]),
            ERRNO | libc::ENOSYS as u32
        );
        for allowed_flags in [
            libc::SIGCHLD as u64,
            (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64,
            (libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64,
        ] {
            assert_eq!(
                evaluate_filter(&filter, arch, clone, [allowed_flags, 0, 0]),
                ALLOW
            );
        }
        for denied_flags in [
            libc::CLONE_NEWNET as u64,
            libc::CLONE_PARENT as u64,
            libc::CLONE_THREAD as u64,
            (libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD | libc::SIGCHLD) as u64,
            libc::SIGKILL as u64,
            (libc::SIGCHLD as u64) | (1_u64 << 32),
        ] {
            assert_eq!(
                evaluate_filter(&filter, arch, clone, [denied_flags, 0, 0]),
                ERRNO | libc::EPERM as u32
            );
        }
        assert_eq!(
            evaluate_filter(&filter, arch, socket, [libc::AF_UNIX as u64, tcp[1], 0]),
            ERRNO | libc::EAFNOSUPPORT as u32
        );
        assert_eq!(
            evaluate_filter(&filter, arch, socket, [tcp[0], libc::SOCK_DGRAM as u64, 0]),
            ERRNO | libc::EPROTONOSUPPORT as u32
        );
        assert_eq!(
            evaluate_filter(&filter, arch, socket, [tcp[0] | (1_u64 << 32), tcp[1], 0]),
            ERRNO | libc::EAFNOSUPPORT as u32
        );
        assert_eq!(
            evaluate_filter(&filter, arch, socket, [tcp[0], tcp[1] | (1_u64 << 32), 0]),
            ERRNO | libc::EPROTONOSUPPORT as u32
        );
        assert_eq!(
            evaluate_filter(&filter, arch, socket, [tcp[0], tcp[1], 1_u64 << 32]),
            ERRNO | libc::EPROTONOSUPPORT as u32
        );
        assert_eq!(
            evaluate_filter(&filter, arch, 9999, [0; 3]),
            ERRNO | libc::EPERM as u32
        );
        if abi == NativeAbi::X86_64 {
            assert_eq!(
                evaluate_filter(&filter, arch, 0x4000_0000 | socket, tcp),
                KILL
            );
        }
    }
}

#[test]
fn initial_filter_rejects_out_of_bounds_jump_mutation() {
    let mut filter = compile_initial_closed_filter(NativeAbi::X86_64);
    filter[1].jt = u8::MAX;
    assert!(validate_program(&filter).is_err());
    filter.resize_with(4097, || libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff_0000,
    });
    assert!(validate_program(&filter).is_err());
}

#[test]
fn initial_closed_filter_limits_fcntl_and_ioctl_scalars() {
    const ALLOW: u32 = 0x7fff_0000;
    const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
    for (abi, arch, fcntl, ioctl) in [
        (NativeAbi::X86_64, 0xc000_003e, 72, 16),
        (NativeAbi::Aarch64, 0xc000_00b7, 25, 29),
    ] {
        let filter = compile_initial_closed_filter(abi);
        for command in [libc::F_GETFD, libc::F_DUPFD_CLOEXEC, libc::F_OFD_GETLK] {
            assert_eq!(
                evaluate_filter(&filter, arch, fcntl, [3, command as u64, 0]),
                ALLOW
            );
        }
        for argument in [0_u64, libc::FD_CLOEXEC as u64] {
            assert_eq!(
                evaluate_filter(&filter, arch, fcntl, [3, libc::F_SETFD as u64, argument]),
                ALLOW
            );
        }
        assert_eq!(
            evaluate_filter(
                &filter,
                arch,
                fcntl,
                [
                    3,
                    libc::F_SETFL as u64,
                    (libc::O_APPEND | libc::O_NONBLOCK) as u64
                ],
            ),
            ALLOW
        );
        for arguments in [
            [3, libc::F_SETFD as u64, 2],
            [3, libc::F_SETFL as u64, libc::O_ASYNC as u64],
            [3, libc::F_SETFD as u64, 1_u64 << 32],
            [3, (libc::F_SETFD as u64) | (1_u64 << 32), 0],
            [3, u32::MAX as u64, 0],
        ] {
            assert_eq!(evaluate_filter(&filter, arch, fcntl, arguments), DENY);
        }
        for command in [
            libc::FIONBIO,
            libc::FIONREAD,
            libc::TCGETS,
            libc::TIOCGWINSZ,
        ] {
            assert_eq!(
                evaluate_filter(&filter, arch, ioctl, [3, command, 0]),
                ALLOW
            );
        }
        for command in [u32::MAX as u64, libc::FIONBIO | (1_u64 << 32)] {
            assert_eq!(evaluate_filter(&filter, arch, ioctl, [3, command, 0]), DENY);
        }
    }
}

#[test]
fn initial_closed_filter_limits_socket_option_pairs() {
    const ALLOW: u32 = 0x7fff_0000;
    const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
    for (abi, arch, get_option, set_option) in [
        (NativeAbi::X86_64, 0xc000_003e, 55, 54),
        (NativeAbi::Aarch64, 0xc000_00b7, 209, 208),
    ] {
        let filter = compile_initial_closed_filter(abi);
        for (number, level, option) in [
            (get_option, libc::SOL_SOCKET, libc::SO_ERROR),
            (get_option, libc::SOL_SOCKET, libc::SO_REUSEADDR),
            (set_option, libc::SOL_SOCKET, libc::SO_REUSEADDR),
            (get_option, libc::IPPROTO_TCP, libc::TCP_NODELAY),
            (set_option, libc::IPPROTO_TCP, libc::TCP_NODELAY),
        ] {
            assert_eq!(
                evaluate_filter(&filter, arch, number, [3, level as u64, option as u64]),
                ALLOW
            );
        }
        for (number, level, option) in [
            (set_option, libc::SOL_SOCKET, libc::SO_ERROR),
            (set_option, libc::SOL_SOCKET, libc::SO_REUSEPORT),
            (get_option, libc::IPPROTO_TCP, libc::SO_DOMAIN),
            (set_option, libc::IPPROTO_TCP, libc::SO_REUSEADDR),
        ] {
            assert_eq!(
                evaluate_filter(&filter, arch, number, [3, level as u64, option as u64]),
                DENY
            );
        }
        for arguments in [
            [
                3,
                libc::SOL_SOCKET as u64 | (1_u64 << 32),
                libc::SO_REUSEADDR as u64,
            ],
            [
                3,
                libc::SOL_SOCKET as u64,
                libc::SO_REUSEADDR as u64 | (1_u64 << 32),
            ],
            [3, u32::MAX as u64, libc::SO_REUSEADDR as u64],
        ] {
            assert_eq!(evaluate_filter(&filter, arch, get_option, arguments), DENY);
        }
    }
}

#[test]
fn initial_closed_filter_limits_process_control_scalars() {
    const ALLOW: u32 = 0x7fff_0000;
    const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
    for (abi, arch, prctl, prlimit64, arch_prctl) in [
        (NativeAbi::X86_64, 0xc000_003e, 157, 302, Some(158)),
        (NativeAbi::Aarch64, 0xc000_00b7, 167, 261, None),
    ] {
        let filter = compile_initial_closed_filter(abi);
        for command in [
            libc::PR_GET_NO_NEW_PRIVS,
            libc::PR_GET_DUMPABLE,
            libc::PR_GET_NAME,
            libc::PR_SET_NAME,
            libc::PR_GET_SECCOMP,
            libc::PR_GET_SECUREBITS,
            libc::PR_GET_TIMERSLACK,
        ] {
            assert_eq!(
                evaluate_filter(&filter, arch, prctl, [command as u64, 0, 0]),
                ALLOW
            );
        }
        for command in [
            libc::PR_SET_NO_NEW_PRIVS as u64,
            libc::PR_SET_SECCOMP as u64,
            libc::PR_SET_SECUREBITS as u64,
            (libc::PR_GET_SECUREBITS as u64) | (1_u64 << 32),
            (libc::PR_GET_DUMPABLE as u64) | (1_u64 << 32),
        ] {
            assert_eq!(evaluate_filter(&filter, arch, prctl, [command, 0, 0]), DENY);
        }
        assert_eq!(evaluate_filter(&filter, arch, prlimit64, [0; 3]), ALLOW);
        for pid in [1_u64, 1_u64 << 32, u64::MAX] {
            assert_eq!(evaluate_filter(&filter, arch, prlimit64, [pid, 0, 0]), DENY);
        }
        if let Some(number) = arch_prctl {
            for command in [0x1002_u64, 0x1003] {
                assert_eq!(
                    evaluate_filter(&filter, arch, number, [command, 0, 0]),
                    ALLOW
                );
            }
            for command in [0x1001_u64, 0x1004, 0x1002 | (1_u64 << 32)] {
                assert_eq!(
                    evaluate_filter(&filter, arch, number, [command, 0, 0]),
                    DENY
                );
            }
        } else {
            assert_eq!(evaluate_filter(&filter, arch, 158, [0x1002, 0, 0]), DENY);
        }
    }
}

#[test]
fn initial_closed_filter_limits_descriptor_and_event_flags() {
    const ALLOW: u32 = 0x7fff_0000;
    const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
    for (abi, arch, numbers) in [
        (
            NativeAbi::X86_64,
            0xc000_003e,
            [288, 293, 292, 290, 291, 289, 283],
        ),
        (
            NativeAbi::Aarch64,
            0xc000_00b7,
            [242, 59, 24, 19, 20, 74, 85],
        ),
    ] {
        let filter = compile_initial_closed_filter(abi);
        for (number, index, allowed_flags) in [
            (
                numbers[0],
                3,
                (libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u64,
            ),
            (numbers[1], 1, (libc::O_CLOEXEC | libc::O_NONBLOCK) as u64),
            (numbers[2], 2, libc::O_CLOEXEC as u64),
            (
                numbers[3],
                1,
                (libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) as u64,
            ),
            (numbers[4], 0, libc::EPOLL_CLOEXEC as u64),
            (
                numbers[5],
                3,
                (libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) as u64,
            ),
            (
                numbers[6],
                1,
                (libc::TFD_CLOEXEC | libc::TFD_NONBLOCK) as u64,
            ),
        ] {
            let mut arguments = [0_u64; 4];
            assert_eq!(evaluate_filter(&filter, arch, number, arguments), ALLOW);
            arguments[index] = allowed_flags;
            assert_eq!(evaluate_filter(&filter, arch, number, arguments), ALLOW);
            arguments[index] = 1_u64 << 30;
            assert_eq!(evaluate_filter(&filter, arch, number, arguments), DENY);
            arguments[index] = allowed_flags | (1_u64 << 32);
            assert_eq!(evaluate_filter(&filter, arch, number, arguments), DENY);
        }
        assert_eq!(
            evaluate_filter(
                &filter,
                arch,
                numbers[3],
                [0, libc::EFD_SEMAPHORE as u64, 0, 0]
            ),
            DENY
        );
    }
}

#[test]
fn initial_closed_filter_uses_exact_native_unconditional_catalogues() {
    const ALLOW: u32 = 0x7fff_0000;
    const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
    for (abi, arch, count, permitted, forbidden) in [
        (
            NativeAbi::X86_64,
            0xc000_003e,
            179,
            [
                ("read", 0),
                ("openat", 257),
                ("execveat", 322),
                ("bind", 49),
            ],
            [46, 47, 308, 321, 425, 438],
        ),
        (
            NativeAbi::Aarch64,
            0xc000_00b7,
            146,
            [
                ("read", 63),
                ("openat", 56),
                ("execveat", 281),
                ("bind", 200),
            ],
            [211, 212, 268, 280, 425, 438],
        ),
    ] {
        let catalogue = unconditional_catalogue(abi);
        assert_eq!(catalogue.len(), count);
        let unique_numbers: std::collections::BTreeSet<_> =
            catalogue.iter().map(|(_, number)| *number).collect();
        assert_eq!(unique_numbers.len(), catalogue.len());
        for (name, number) in permitted {
            assert!(catalogue.contains(&(name, number)));
        }
        for name in [
            "socket",
            "clone",
            "fcntl",
            "ioctl",
            "getsockopt",
            "setsockopt",
            "prctl",
            "prlimit64",
            "accept4",
            "pipe2",
            "dup3",
            "eventfd2",
            "epoll_create1",
            "signalfd4",
            "timerfd_create",
        ] {
            assert!(!catalogue.iter().any(|(item, _)| *item == name));
        }
        let filter = compile_initial_closed_filter(abi);
        for (_, number) in permitted {
            assert_eq!(evaluate_filter(&filter, arch, number, [0; 3]), ALLOW);
        }
        for number in forbidden {
            assert_eq!(evaluate_filter(&filter, arch, number, [0; 3]), DENY);
        }
    }
}

#[test]
fn compiled_filter_digest_binds_exact_native_instruction_words() {
    let x64 = compile_initial_closed_filter(NativeAbi::X86_64);
    let arm64 = compile_initial_closed_filter(NativeAbi::Aarch64);
    let x64_digest = filter_instruction_digest(&x64).unwrap();
    assert_eq!(x64_digest, filter_instruction_digest(&x64).unwrap());
    assert_ne!(x64_digest, filter_instruction_digest(&arm64).unwrap());

    let mut independently_encoded = Vec::with_capacity(x64.len() * 8);
    for instruction in &x64 {
        independently_encoded.extend_from_slice(&instruction.code.to_le_bytes());
        independently_encoded.extend_from_slice(&[instruction.jt, instruction.jf]);
        independently_encoded.extend_from_slice(&instruction.k.to_le_bytes());
    }
    assert_eq!(&independently_encoded[..8], &[0x20, 0, 0, 0, 4, 0, 0, 0]);
    let independently_hashed: [u8; 32] =
        <sha2::Sha256 as sha2::Digest>::digest(&independently_encoded).into();
    assert_eq!(x64_digest, independently_hashed);

    let mut mutated = x64;
    mutated[1].k ^= 1;
    assert_ne!(x64_digest, filter_instruction_digest(&mutated).unwrap());
    assert!(filter_instruction_digest(&[]).is_err());
}

#[test]
fn native_filter_install_rejects_mismatched_authority_before_attachment() {
    #[cfg(target_arch = "x86_64")]
    let (native, foreign) = (NativeAbi::X86_64, NativeAbi::Aarch64);
    #[cfg(target_arch = "aarch64")]
    let (native, foreign) = (NativeAbi::Aarch64, NativeAbi::X86_64);
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        assert!(install_gated_private_filter(foreign, [0; 32]).is_err());
        assert!(install_gated_private_filter(native, [0; 32]).is_err());
    }
}

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let length = 4 + value.len();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(length as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize((length + 3) & !3, 0);
    bytes
}

fn loopback_link() -> Vec<u8> {
    let mut bytes = vec![libc::AF_UNSPEC as u8, 0];
    bytes.extend_from_slice(&libc::ARPHRD_LOOPBACK.to_ne_bytes());
    bytes.extend_from_slice(&1_i32.to_ne_bytes());
    bytes.extend_from_slice(&((libc::IFF_LOOPBACK | libc::IFF_UP) as u32).to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&attribute(libc::IFLA_IFNAME, b"lo\0"));
    bytes
}

fn loopback_address() -> Vec<u8> {
    let mut bytes = vec![libc::AF_INET as u8, 8, 0, libc::RT_SCOPE_HOST];
    bytes.extend_from_slice(&1_u32.to_ne_bytes());
    bytes.extend_from_slice(&attribute(libc::IFA_ADDRESS, &[127, 0, 0, 1]));
    bytes.extend_from_slice(&attribute(libc::IFA_LOCAL, &[127, 0, 0, 1]));
    bytes
}

fn loopback_route(prefix: u8, kind: u8, destination: [u8; 4]) -> Vec<u8> {
    let mut bytes = vec![
        libc::AF_INET as u8,
        prefix,
        0,
        0,
        libc::RT_TABLE_LOCAL,
        libc::RTPROT_KERNEL,
        if kind == libc::RTN_LOCAL {
            libc::RT_SCOPE_HOST
        } else {
            libc::RT_SCOPE_LINK
        },
        kind,
    ];
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&attribute(libc::RTA_DST, &destination));
    bytes.extend_from_slice(&attribute(libc::RTA_OIF, &1_u32.to_ne_bytes()));
    bytes.extend_from_slice(&attribute(libc::RTA_PREFSRC, &[127, 0, 0, 1]));
    bytes
}

#[test]
fn private_topology_rejects_hidden_links_addresses_and_routes() {
    let link = loopback_link();
    let address = loopback_address();
    let routes = vec![
        loopback_route(8, libc::RTN_LOCAL, [127, 0, 0, 0]),
        loopback_route(32, libc::RTN_LOCAL, [127, 0, 0, 1]),
        loopback_route(32, libc::RTN_BROADCAST, [127, 255, 255, 255]),
    ];
    assert_eq!(loopback_index(std::slice::from_ref(&link), true), Ok(1));
    assert_eq!(
        verify_loopback_addresses(std::slice::from_ref(&address), 1),
        Ok(true)
    );
    assert_eq!(verify_loopback_routes(&routes, 1), Ok(()));
    assert!(loopback_index(&[link.clone(), link], true).is_err());

    let mut ipv6 = address;
    ipv6[0] = libc::AF_INET6 as u8;
    assert!(verify_loopback_addresses(&[ipv6], 1).is_err());

    let mut external_routes = routes.clone();
    external_routes[0][1] = 0;
    assert!(verify_loopback_routes(&external_routes, 1).is_err());
    let mut unicast_routes = routes.clone();
    unicast_routes[0][4] = libc::RT_TABLE_MAIN;
    unicast_routes[0][6] = libc::RT_SCOPE_LINK;
    unicast_routes[0][7] = libc::RTN_UNICAST;
    assert!(verify_loopback_routes(&unicast_routes, 1).is_err());
    assert!(verify_loopback_routes(&routes[..2], 1).is_err());
}

#[test]
fn netlink_datagram_rejects_stale_or_interrupted_messages() {
    let sequence = 7_u32;
    let recipient_port_id = 19_u32;
    let mut packet = Vec::new();
    packet.extend_from_slice(&20_u32.to_ne_bytes());
    packet.extend_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
    packet.extend_from_slice(&0_u16.to_ne_bytes());
    packet.extend_from_slice(&sequence.to_ne_bytes());
    packet.extend_from_slice(&recipient_port_id.to_ne_bytes());
    packet.extend_from_slice(&0_i32.to_ne_bytes());
    assert_eq!(
        parse_datagram(&packet, sequence, recipient_port_id)
            .unwrap()
            .len(),
        1
    );
    assert!(parse_datagram(&packet, sequence + 1, recipient_port_id).is_err());
    assert!(parse_datagram(&packet, sequence, recipient_port_id + 1).is_err());
    packet[6..8].copy_from_slice(&(libc::NLM_F_DUMP_INTR as u16).to_ne_bytes());
    assert!(parse_datagram(&packet, sequence, recipient_port_id).is_err());
    packet[6..8].copy_from_slice(&0_u16.to_ne_bytes());
    packet[0..4].copy_from_slice(&21_u32.to_ne_bytes());
    assert!(parse_datagram(&packet, sequence, recipient_port_id).is_err());
}

#[test]
fn private_port_policy_requires_exact_namespace_local_readback() {
    let expected = parse_private_port_policy("0\n", "32768\t60999\n", "\n").unwrap();
    assert_eq!(expected, PrivatePortPolicy::REQUIRED);
    for (start, range, reserved) in [
        ("1\n", "32768 60999\n", "\n"),
        ("0\n", "32767 60999\n", "\n"),
        ("0\n", "32768 61000\n", "\n"),
        ("0\n", "32768 60999\n", "1234\n"),
    ] {
        assert_ne!(
            parse_private_port_policy(start, range, reserved).unwrap(),
            PrivatePortPolicy::REQUIRED
        );
    }
}

#[test]
fn private_port_policy_parser_rejects_malformed_or_oversized_numbers() {
    for (start, range) in [
        ("-1", "32768 60999"),
        ("65536", "32768 60999"),
        ("0", "0 60999"),
        ("0", "60999 32768"),
        ("0", "32768"),
        ("0", "32768 60999 61000"),
        ("0", "32768 65536"),
    ] {
        assert!(parse_private_port_policy(start, range, "\n").is_err());
    }
}
