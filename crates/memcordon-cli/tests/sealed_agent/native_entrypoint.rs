use std::num::NonZeroU64;
use std::os::fd::AsFd;

use memcordon_core::workload_contract::LogicalId;
use memcordon_core::workload_registry_v2::ApprovedEntrypointV2;
use memcordon_core::{BoundedText, DiagnosticSha256};

use crate::linux::entrypoint::{EntrypointObjectIdentity, open_verified_entrypoint, validate_elf};

fn approved(path: &str) -> ApprovedEntrypointV2 {
    ApprovedEntrypointV2 {
        id: LogicalId::new("adapter".into()).unwrap(),
        absolute_path: BoundedText::new(path).unwrap(),
        sha256: DiagnosticSha256::from_bytes([7; 32]),
        size: NonZeroU64::new(64).unwrap(),
    }
}

#[test]
fn entrypoint_identity_binds_held_object_and_content() {
    let identity = EntrypointObjectIdentity {
        device: 3,
        inode: 5,
        size: 7,
        sha256: [11; 32],
    };
    assert_ne!(identity.device, identity.inode);
    assert_eq!(identity.sha256, [11; 32]);
}

#[test]
fn rejects_script_and_foreign_elf_before_content_authority() {
    let mut header = [0_u8; 64];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    header[16] = 2;
    header[20] = 1;
    let native_machine: u16 = if cfg!(target_arch = "x86_64") {
        62
    } else {
        183
    };
    header[18..20].copy_from_slice(&native_machine.to_le_bytes());
    assert!(validate_elf(&header).is_ok());
    header[18..20].copy_from_slice(&0_u16.to_le_bytes());
    assert!(validate_elf(&header).is_err());
    header[18..20].copy_from_slice(&native_machine.to_le_bytes());
    header[..4].copy_from_slice(b"#!/b");
    assert!(validate_elf(&header).is_err());
}

#[test]
fn rejects_unprotected_ancestor_even_with_approved_content_digest() {
    let root = std::fs::File::open("/").unwrap();
    let failure = open_verified_entrypoint(
        root.as_fd(),
        &approved("/tmp/memcordon-preexisting-caller-path"),
    )
    .unwrap_err();
    assert!(
        failure.contains("ancestor is not root-controlled"),
        "{failure}"
    );
}

#[test]
fn rejects_non_normalized_entrypoint_path() {
    let root = std::fs::File::open("/").unwrap();
    let failure =
        open_verified_entrypoint(root.as_fd(), &approved("/var/../usr/bin/true")).unwrap_err();
    assert!(
        failure.contains("absolute normalized file path"),
        "{failure}"
    );
}
