#![cfg(unix)]

#[path = "../src/release/linux_image_custody.rs"]
mod custody;

use custody::{CustodyPool, PositionalReader, Role};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct FixtureDirectory(std::path::PathBuf);

impl FixtureDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = Path::new("/tmp").join(format!(
            "memcordon-image-custody-{}-{timestamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        // Only this successfully exclusively created test directory is owned.
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn repeated_deep_inventory_references_share_the_original_physical_owners() {
    let root = FixtureDirectory::new();
    let mut directories = vec![root.path().to_owned()];
    for component in ["original-image", "lib", "native", "selected"] {
        let path = directories.last().unwrap().join(component);
        std::fs::create_dir(&path).unwrap();
        directories.push(path);
    }
    let paths: Vec<_> = (0..24)
        .map(|index| {
            let path = directories.last().unwrap().join(index.to_string());
            std::fs::write(&path, b"actual original member").unwrap();
            path
        })
        .collect();
    let mut pool = CustodyPool::default();
    let mut logical_chains = Vec::new();
    let mut logical_files = Vec::new();
    for _ in 0..6 {
        for path in &paths {
            let chain: Vec<_> = directories
                .iter()
                .map(|directory| {
                    pool.admit(
                        Role::AdministrativeDirectory,
                        directory,
                        File::open(directory).unwrap(),
                    )
                    .unwrap()
                })
                .collect();
            assert_eq!(chain.len(), directories.len());
            for (directory, owner) in directories.iter().zip(&chain) {
                let current = std::fs::metadata(directory).unwrap();
                let original = owner.metadata().unwrap();
                assert_eq!(
                    (original.dev(), original.ino()),
                    (current.dev(), current.ino())
                );
            }
            logical_chains.push(chain);
            logical_files.push(
                pool.admit(Role::AdministrativeFile, path, File::open(path).unwrap())
                    .unwrap(),
            );
        }
    }
    assert_eq!(pool.owner_count(), directories.len() + paths.len());
    for chain in &logical_chains {
        for (first, repeated) in logical_chains[0].iter().zip(chain) {
            assert!(
                Arc::ptr_eq(first, repeated),
                "same original File object, not duplicated descriptors"
            );
        }
    }
    for repeated in logical_files.chunks(paths.len()) {
        for (first, repeated) in logical_files.iter().zip(repeated) {
            assert!(Arc::ptr_eq(first, repeated));
        }
    }
    // A report's ordered logical witnesses survive dropping the interning
    // table, and retain their exact original objects until their own retirement.
    let final_owner = Arc::clone(&logical_files[0]);
    let weak = Arc::downgrade(&final_owner);
    drop(pool);
    drop(logical_chains);
    drop(logical_files);
    let mut bytes = Vec::new();
    PositionalReader::new(&final_owner)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"actual original member");
    assert!(weak.upgrade().is_some());
    drop(final_owner);
    assert!(weak.upgrade().is_none());
}

#[test]
fn replacement_is_refused_without_refreshing_original_directory_or_file_custody() {
    let root = FixtureDirectory::new();
    let directory = root.path().join("selected");
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("member.bin");
    std::fs::write(&path, b"same bytes").unwrap();
    let mut pool = CustodyPool::default();
    let original_directory = pool
        .admit(
            Role::EvidenceDirectory,
            &directory,
            File::open(&directory).unwrap(),
        )
        .unwrap();
    let original_file = pool
        .admit(Role::AdministrativeFile, &path, File::open(&path).unwrap())
        .unwrap();
    let moved = root.path().join("original-selected");
    std::fs::rename(&directory, &moved).unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&path, b"same bytes").unwrap();
    assert!(
        pool.admit(
            Role::EvidenceDirectory,
            &directory,
            File::open(&directory).unwrap()
        )
        .is_err()
    );
    assert!(
        pool.admit(Role::AdministrativeFile, &path, File::open(&path).unwrap())
            .is_err()
    );
    assert_eq!(pool.owner_count(), 2);
    assert_eq!(
        original_directory.metadata().unwrap().ino(),
        std::fs::metadata(&moved).unwrap().ino()
    );
    assert_eq!(
        original_file.metadata().unwrap().ino(),
        std::fs::metadata(moved.join("member.bin")).unwrap().ino()
    );
    let mut bytes = Vec::new();
    PositionalReader::new(&original_file)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"same bytes");
}

#[test]
fn role_and_native_type_remain_independent_of_same_path_or_inode() {
    let root = FixtureDirectory::new();
    let path = root.path().join("member.bin");
    std::fs::write(&path, b"independently admitted role").unwrap();
    let mut pool = CustodyPool::default();
    let admin = pool
        .admit(Role::AdministrativeFile, &path, File::open(&path).unwrap())
        .unwrap();
    let repeated = pool
        .admit(Role::AdministrativeFile, &path, File::open(&path).unwrap())
        .unwrap();
    assert!(Arc::ptr_eq(&admin, &repeated));
    assert_eq!(pool.owner_count(), 1);
    assert!(
        pool.admit(
            Role::AdministrativeDirectory,
            &path,
            File::open(&path).unwrap()
        )
        .is_err()
    );
    assert!(
        pool.admit(
            Role::AdministrativeFile,
            root.path(),
            File::open(root.path()).unwrap()
        )
        .is_err()
    );
    let admin_directory = pool
        .admit(
            Role::AdministrativeDirectory,
            root.path(),
            File::open(root.path()).unwrap(),
        )
        .unwrap();
    let evidence_directory = pool
        .admit(
            Role::EvidenceDirectory,
            root.path(),
            File::open(root.path()).unwrap(),
        )
        .unwrap();
    assert!(!Arc::ptr_eq(&admin_directory, &evidence_directory));
    assert_eq!(pool.owner_count(), 3);
}

#[test]
fn pool_refuses_nonabsolute_or_aliased_original_paths() {
    let root = FixtureDirectory::new();
    let path = root.path().join("member.bin");
    std::fs::write(&path, b"original").unwrap();
    let mut pool = CustodyPool::default();
    for alias in [
        Path::new("member.bin").to_owned(),
        root.path().join(".").join("member.bin"),
        root.path().join("child").join("..").join("member.bin"),
    ] {
        assert_eq!(
            pool.admit(Role::AdministrativeFile, &alias, File::open(&path).unwrap())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(pool.owner_count(), 0);
}

#[test]
fn independent_positional_reads_reobserve_mutated_members_without_shared_offset_or_hash_cache() {
    let root = FixtureDirectory::new();
    let path = root.path().join("member.bin");
    let original = b"original complete bytes";
    std::fs::write(&path, original).unwrap();
    let mut pool = CustodyPool::default();
    let owner = pool
        .admit(Role::AdministrativeFile, &path, File::open(&path).unwrap())
        .unwrap();
    let mut cursor = owner.as_ref();
    cursor.seek(SeekFrom::Start(3)).unwrap();
    let mut first = PositionalReader::new(&owner);
    let mut second = PositionalReader::new(&owner);
    let mut prefix = [0; 2];
    first.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix, original[..prefix.len()]);
    let mut complete = Vec::new();
    second.read_to_end(&mut complete).unwrap();
    assert_eq!(complete, original);
    let mut rest = Vec::new();
    first.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, original[prefix.len()..]);
    assert_eq!(cursor.stream_position().unwrap(), 3);
    let changed = b"intentional staged mutation with different length";
    std::fs::write(&path, changed).unwrap();
    let reused = pool
        .admit(Role::AdministrativeFile, &path, File::open(&path).unwrap())
        .unwrap();
    assert!(Arc::ptr_eq(&owner, &reused));
    complete.clear();
    PositionalReader::new(&reused)
        .read_to_end(&mut complete)
        .unwrap();
    assert_eq!(complete, changed);
    assert_ne!(complete, original);
    assert_eq!(pool.owner_count(), 1);
}
