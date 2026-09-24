#![cfg(target_os = "linux")]

use crate::linux::network_profile::{PrivateNetworkSetup, PrivatePortPolicy};
use crate::linux::private_namespace_init::{
    PrivateNamespaceStartupObservation, PrivateNamespaceStartupPhase,
    decode_private_namespace_startup, encode_private_namespace_startup, parse_target_parent_pid,
    private_namespace_startup_channel,
};
use crate::linux::private_target::private_network_owner_for_test;
use crate::request::NamespaceIdentity;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

fn ready() -> PrivateNamespaceStartupObservation {
    PrivateNamespaceStartupObservation::TargetForked {
        namespace: NamespaceIdentity {
            device: 42,
            inode: 43,
        },
        network: PrivateNetworkSetup {
            port_policy: PrivatePortPolicy::REQUIRED,
            loopback_index: 1,
            address_count: 1,
            route_count: 2,
        },
    }
}

#[test]
fn v2_startup_codec_requires_exact_native_readback_and_namespace_owner() {
    let observation = ready();
    let packet = encode_private_namespace_startup(&observation).unwrap();
    assert_eq!(
        decode_private_namespace_startup(&packet).unwrap(),
        observation
    );
    let owner = private_network_owner_for_test(
        std::fs::File::open("/dev/null").unwrap().into(),
        NamespaceIdentity {
            device: 42,
            inode: 43,
        },
    );
    observation.validate_ready(&owner).unwrap();
    let wrong_owner = private_network_owner_for_test(
        owner.as_fd().try_clone_to_owned().unwrap(),
        NamespaceIdentity {
            device: 42,
            inode: 44,
        },
    );
    assert!(observation.validate_ready(&wrong_owner).is_err());

    let mut bad = packet.clone();
    bad[0] = 1;
    assert!(decode_private_namespace_startup(&bad).is_err());
    let mut bad = packet.clone();
    bad[24] = 2;
    assert!(decode_private_namespace_startup(&bad).is_err());
    let mut bad = packet.clone();
    bad[32] = 2;
    assert!(decode_private_namespace_startup(&bad).is_err());
    let mut bad = packet.clone();
    bad.push(0);
    assert!(decode_private_namespace_startup(&bad).is_err());
    assert!(decode_private_namespace_startup(&packet[..packet.len() - 1]).is_err());
}

#[test]
fn v2_startup_failure_preserves_bounded_native_detail() {
    let observation = PrivateNamespaceStartupObservation::Failed {
        phase: PrivateNamespaceStartupPhase::NamespaceSetup,
        detail: "NETLINK_ROUTE readback did not match".into(),
    };
    let packet = encode_private_namespace_startup(&observation).unwrap();
    assert_eq!(
        decode_private_namespace_startup(&packet).unwrap(),
        observation
    );
    let mut bad = packet.clone();
    bad[2] = 255;
    assert!(decode_private_namespace_startup(&bad).is_err());
    let mut bad = packet.clone();
    bad[5] = 255;
    assert!(decode_private_namespace_startup(&bad).is_err());
    let mut bad = packet.clone();
    bad[6] = 255;
    assert!(decode_private_namespace_startup(&bad).is_err());
    let oversized = PrivateNamespaceStartupObservation::Failed {
        phase: PrivateNamespaceStartupPhase::TargetFork,
        detail: "x".repeat(513),
    };
    let decoded =
        decode_private_namespace_startup(&encode_private_namespace_startup(&oversized).unwrap())
            .unwrap();
    assert!(
        matches!(decoded, PrivateNamespaceStartupObservation::Failed { detail, .. } if detail.contains("exceeded protocol bound"))
    );
}

#[test]
fn v2_startup_channel_binds_sender_pid_and_rejects_truncated_packet() {
    let (provider, init) = private_namespace_startup_channel().unwrap();
    // SAFETY: pidfd_open targets this live test process and returns one new fd.
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
    assert!(raw_pidfd >= 0);
    // SAFETY: successful pidfd_open returned a uniquely owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    assert!(init.report(&ready(), None).is_err());
    init.report(&ready(), Some(pidfd.as_fd())).unwrap();
    let received = provider
        .receive(
            std::process::id() as libc::pid_t,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(received.observation, ready());
    assert_eq!(
        received.target_host_pid().unwrap(),
        std::process::id() as libc::pid_t
    );

    init.report(&ready(), Some(pidfd.as_fd())).unwrap();
    assert!(
        provider
            .receive(-1, Instant::now() + Duration::from_secs(1))
            .unwrap_err()
            .contains("sender")
    );

    let oversized = [0_u8; 1024];
    // SAFETY: send reads the exact initialized byte array from a live socket.
    assert_eq!(
        unsafe {
            libc::send(
                init.as_fd().as_raw_fd(),
                oversized.as_ptr().cast(),
                oversized.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        oversized.len() as isize
    );
    assert!(
        provider
            .receive(
                std::process::id() as libc::pid_t,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap_err()
            .contains("truncated")
    );
}

#[test]
fn v2_startup_channel_rejects_ready_without_target_pidfd() {
    let (provider, init) = private_namespace_startup_channel().unwrap();
    let record = encode_private_namespace_startup(&ready()).unwrap();
    // SAFETY: send reads the complete initialized record from a live socket.
    assert_eq!(
        unsafe {
            libc::send(
                init.as_fd().as_raw_fd(),
                record.as_ptr().cast(),
                record.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        record.len() as isize
    );
    assert!(
        provider
            .receive(
                std::process::id() as libc::pid_t,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err()
            .contains("pidfd")
    );
}

#[test]
fn v2_startup_channel_accepts_native_failure_without_target_pidfd() {
    let (provider, init) = private_namespace_startup_channel().unwrap();
    let failure = PrivateNamespaceStartupObservation::Failed {
        phase: PrivateNamespaceStartupPhase::NamespaceSetup,
        detail: "loopback NETLINK_ROUTE readback failed".into(),
    };
    init.report(&failure, None).unwrap();
    let received = provider
        .receive(
            std::process::id() as libc::pid_t,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(received.observation, failure);
    assert!(received.target_pidfd.is_none());
    assert!(received.target_host_pid().is_err());
}

#[test]
fn target_parent_readback_rejects_missing_ambiguous_or_nonpositive_parent() {
    assert_eq!(
        parse_target_parent_pid("Name:\tchild\nPPid:\t42\n").unwrap(),
        42
    );
    assert!(parse_target_parent_pid("Name:\tchild\n").is_err());
    assert!(parse_target_parent_pid("PPid:\t42\nPPid:\t43\n").is_err());
    assert!(parse_target_parent_pid("PPid:\t0\n").is_err());
    assert!(parse_target_parent_pid("PPid:\tnan\n").is_err());
}
