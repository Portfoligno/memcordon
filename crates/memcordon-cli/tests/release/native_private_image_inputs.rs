#![cfg(target_os = "linux")]

use crate::linux::entrypoint::{
    EntrypointObjectIdentity, VerifiedEntrypoint, install_protected_entrypoint,
    open_verified_entrypoint,
};
use memcordon_core::workload_contract::LogicalId;
use memcordon_core::workload_registry_v2::ApprovedEntrypointV2;
use memcordon_core::{BoundedText, workload_codec::hash_bytes};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Write};
use std::num::NonZeroU64;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

struct ImageRoot {
    directory: tempfile::TempDir,
    root: File,
    bytes: Vec<u8>,
}

impl ImageRoot {
    fn new() -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0, "requires actual root");
        let directory = tempfile::Builder::new()
            .prefix("memcordon-native-image-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(directory.path().join("images")).unwrap();
        fs::set_permissions(
            directory.path().join("images"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let root = File::open(directory.path()).unwrap();
        // Use a complete real native dynamic image, not a handcrafted ELF header.
        let bytes = fs::read("/bin/echo").unwrap();
        assert!(bytes.starts_with(b"\x7fELF"));
        assert_eq!(bytes[4], 2);
        let phoff = usize::try_from(u64::from_le_bytes(bytes[32..40].try_into().unwrap())).unwrap();
        let phsize = usize::from(u16::from_le_bytes(bytes[54..56].try_into().unwrap()));
        let phcount = usize::from(u16::from_le_bytes(bytes[56..58].try_into().unwrap()));
        assert!(
            (0..phcount).any(|index| {
                let offset = phoff
                    .checked_add(index.checked_mul(phsize).unwrap())
                    .unwrap();
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) == 3
            }),
            "positive control must have a real PT_INTERP dynamic loader"
        );
        Self {
            directory,
            root,
            bytes,
        }
    }

    fn approved(&self, name: &str, bytes: &[u8]) -> ApprovedEntrypointV2 {
        ApprovedEntrypointV2 {
            id: LogicalId::new(name.into()).unwrap(),
            absolute_path: BoundedText::new(Path::new("/images").join(name).to_str().unwrap())
                .unwrap(),
            sha256: hash_bytes(bytes),
            size: NonZeroU64::new(bytes.len().try_into().unwrap()).unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join("images").join(name)
    }

    fn install(&self, name: &str) -> (ApprovedEntrypointV2, EntrypointObjectIdentity) {
        let approved = self.approved(name, &self.bytes);
        let identity = install_protected_entrypoint(
            self.root.as_fd(),
            &approved,
            &mut Cursor::new(&self.bytes),
        )
        .unwrap();
        let held = self.open(&approved).unwrap();
        assert_eq!(held.identity(), identity);
        assert_eq!(identity.sha256, *approved.sha256.bytes());
        (approved, identity)
    }

    fn open(&self, approved: &ApprovedEntrypointV2) -> Result<VerifiedEntrypoint, String> {
        open_verified_entrypoint(self.root.as_fd(), approved)
    }
}

#[test]
#[ignore = "requires Linux root and actual protected native ELF installation"]
fn native_private_image_install_uses_fresh_inode_despite_writable_alias() {
    let image = ImageRoot::new();
    let old = image.path("old-alias");
    let mut alias = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&old)
        .unwrap();
    alias.write_all(&image.bytes).unwrap();
    alias.sync_all().unwrap();
    let old_identity = alias.metadata().unwrap();
    // chmod cannot revoke a writable open-file description retained beforehand.
    fs::set_permissions(&old, fs::Permissions::from_mode(0o555)).unwrap();
    let untrusted = image.approved("old-alias", &image.bytes);
    assert!(
        image.open(&untrusted).is_err(),
        "preexisting inode has no trusted creation binding"
    );
    assert!(
        install_protected_entrypoint(
            image.root.as_fd(),
            &untrusted,
            &mut Cursor::new(&image.bytes)
        )
        .is_err(),
        "installer must not bless an existing inode"
    );
    let (approved, installed) = image.install("fresh-copy");
    assert_ne!(
        (installed.device, installed.inode),
        (old_identity.dev(), old_identity.ino())
    );
    alias.write_all_at(b"broken", 0).unwrap();
    alias.sync_all().unwrap();
    assert_ne!(fs::read(&old).unwrap(), image.bytes);
    assert_eq!(fs::read(image.path("fresh-copy")).unwrap(), image.bytes);
    assert_eq!(image.open(&approved).unwrap().identity(), installed);
}

#[test]
#[ignore = "requires Linux root and actual protected native ELF installation"]
fn native_private_image_rejects_script_and_foreign_abi() {
    let image = ImageRoot::new();
    image.install("native-dynamic-positive");
    let script = b"#!/bin/sh\nexit 0\n";
    let approved = image.approved("script", script);
    assert!(
        install_protected_entrypoint(image.root.as_fd(), &approved, &mut Cursor::new(script))
            .is_err()
    );
    assert!(
        !image.path("script").exists(),
        "rejected image cannot be published"
    );
    let mut foreign = image.bytes.clone();
    let machine: u16 = if cfg!(target_arch = "x86_64") {
        183
    } else {
        62
    };
    foreign[18..20].copy_from_slice(&machine.to_le_bytes());
    let approved = image.approved("foreign-abi", &foreign);
    assert!(
        install_protected_entrypoint(image.root.as_fd(), &approved, &mut Cursor::new(foreign))
            .is_err()
    );
    assert!(!image.path("foreign-abi").exists());
}

#[test]
#[ignore = "requires Linux root, native xattrs and protected ELF installation"]
fn native_private_image_rejects_setid_filecap_and_writable_metadata() {
    let image = ImageRoot::new();
    for (name, mode) in [("setuid", 0o4555), ("setgid", 0o2555), ("writable", 0o575)] {
        let (approved, _) = image.install(name);
        fs::set_permissions(image.path(name), fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            image.open(&approved).is_err(),
            "unsafe mode was accepted: {name}"
        );
    }
    let (approved, _) = image.install("filecap");
    let path = CString::new(image.path("filecap").as_os_str().as_bytes()).unwrap();
    // Linux vfs_cap_data revision 2: effective CAP_NET_BIND_SERVICE.
    let words = [0x0200_0001_u32, 1_u32 << 10, 0, 0, 0];
    let capability: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    assert_eq!(
        unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"security.capability".as_ptr(),
                capability.as_ptr().cast(),
                capability.len(),
                0,
            )
        },
        0,
        "native filecap setup failed: {}",
        std::io::Error::last_os_error()
    );
    assert!(
        image.open(&approved).is_err(),
        "actual file capability was accepted"
    );
}

#[test]
#[ignore = "requires Linux root and protected ELF installation"]
fn native_private_image_rejects_ancestor_symlink_and_inode_substitution() {
    let image = ImageRoot::new();
    let (approved, _) = image.install("ancestor");
    fs::set_permissions(
        image.directory.path().join("images"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(image.open(&approved).is_err());
    fs::set_permissions(
        image.directory.path().join("images"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(image.open(&approved).is_ok());
    let (approved, identity) = image.install("substitute");
    let held = image.open(&approved).unwrap();
    let old = image.path("held-original");
    fs::rename(image.path("substitute"), &old).unwrap();
    symlink(&old, image.path("substitute")).unwrap();
    assert!(image.open(&approved).is_err());
    fs::remove_file(image.path("substitute")).unwrap();
    fs::write(image.path("substitute"), &image.bytes).unwrap();
    fs::set_permissions(image.path("substitute"), fs::Permissions::from_mode(0o555)).unwrap();
    assert!(
        image.open(&approved).is_err(),
        "same bytes on a different inode do not match creation binding"
    );
    assert_eq!(
        held.identity(),
        identity,
        "held original does not switch to replacement path"
    );
    let native = File::open(&old).unwrap().metadata().unwrap();
    assert_eq!(
        (native.dev(), native.ino()),
        (identity.device, identity.inode)
    );
}

#[test]
#[ignore = "requires Linux root and protected ELF installation"]
fn native_private_image_rejects_digest_length_and_hardlink_substitution() {
    let image = ImageRoot::new();
    let (approved, _) = image.install("bound");
    let mut changed_hash = approved.clone();
    changed_hash.sha256 = hash_bytes(b"different measured image");
    assert!(image.open(&changed_hash).is_err());
    let mut changed_length = approved.clone();
    changed_length.size = NonZeroU64::new(approved.size.get() + 1).unwrap();
    assert!(image.open(&changed_length).is_err());
    fs::hard_link(image.path("bound"), image.path("hardlink")).unwrap();
    assert!(
        image.open(&approved).is_err(),
        "actual extra inode alias was accepted"
    );
    fs::remove_file(image.path("hardlink")).unwrap();
    assert!(image.open(&approved).is_ok());
    let writer = OpenOptions::new()
        .write(true)
        .open(image.path("bound"))
        .unwrap();
    writer.write_all_at(b"X", u64::from(64_u32)).unwrap();
    writer.sync_all().unwrap();
    assert!(
        image.open(&approved).is_err(),
        "same-length content substitution was accepted"
    );
}
