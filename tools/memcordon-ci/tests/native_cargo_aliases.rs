#[path = "../src/release/native_cargo_aliases.rs"]
mod native_cargo_aliases;

use native_cargo_aliases::{ClosedInventory, SourceState};
use std::path::PathBuf;

fn state(links: u64) -> SourceState {
    SourceState {
        device: 1,
        inode: 2,
        links,
        length: 64,
        modified: (3, 4),
        changed: (5, 6),
    }
}

fn graph() -> Vec<(PathBuf, SourceState)> {
    [
        "component-package-admin/materialized/fixture-build/debug/fixture",
        "component-package-admin/materialized/fixture-build/debug/deps/fixture-hash",
    ]
    .into_iter()
    .map(|path| (path.into(), state(2)))
    .collect()
}

#[test]
fn complete_cargo_alias_graph_preserves_every_original_path() {
    let entries = graph();
    let held = ClosedInventory::acquire(entries.clone()).unwrap();
    for (path, identity) in &entries {
        assert_eq!(held.source(path).unwrap(), identity);
    }
    held.verify(entries).unwrap();
    ClosedInventory::acquire(vec![("authority.json".into(), state(1))]).unwrap();
}

#[test]
fn external_or_authority_aliases_and_inventory_mutations_are_refused() {
    let entries = graph();
    assert!(ClosedInventory::acquire(vec![entries[0].clone()]).is_err());
    let mut outside = entries.clone();
    outside[1].0 = "authority.json".into();
    assert!(ClosedInventory::acquire(outside).is_err());
    let mut duplicate = entries.clone();
    duplicate[1].0 = duplicate[0].0.clone();
    assert!(ClosedInventory::acquire(duplicate).is_err());
    let held = ClosedInventory::acquire(entries.clone()).unwrap();
    for field in ["inode", "length", "mtime", "ctime", "links", "path"] {
        let mut changed = entries.clone();
        match field {
            "inode" => changed[1].1.inode += 1,
            "length" => changed[1].1.length += 1,
            "mtime" => changed[1].1.modified.1 += 1,
            "ctime" => changed[1].1.changed.1 += 1,
            "links" => changed[1].1.links += 1,
            "path" => {
                changed[1].0 = "component-package-admin/materialized/fixture-build/replaced".into()
            }
            _ => unreachable!(),
        }
        assert!(held.verify(changed).is_err(), "{field}");
    }
    assert!(ClosedInventory::acquire(vec![("../escape".into(), state(1))]).is_err());
    let mut sibling = graph();
    sibling[1].0 = "component-package-admin/materialized/fixture-build-sibling/alias".into();
    assert!(ClosedInventory::acquire(sibling).is_err());
    let exact_bound = (0..8192)
        .map(|index| {
            let mut identity = state(1);
            identity.inode = index + 1;
            (format!("entry-{index}").into(), identity)
        })
        .collect();
    ClosedInventory::acquire(exact_bound).unwrap();
    assert!(
        ClosedInventory::acquire(
            (0..8193)
                .map(|index| (format!("entry-{index}").into(), state(1)))
                .collect()
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn actual_cargo_hard_links_require_complete_inventory_and_unchanged_sources() {
    use std::os::unix::fs::MetadataExt;
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    std::fs::write(&first, b"original compiler evidence").unwrap();
    std::fs::hard_link(&first, &second).unwrap();
    let snapshot = || {
        [
            (
                &first,
                "component-package-admin/materialized/fixture-build/debug/fixture",
            ),
            (
                &second,
                "component-package-admin/materialized/fixture-build/debug/deps/fixture-hash",
            ),
        ]
        .into_iter()
        .map(|(path, relative)| {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            (
                relative.into(),
                SourceState {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    links: metadata.nlink(),
                    length: metadata.len(),
                    modified: (metadata.mtime(), metadata.mtime_nsec()),
                    changed: (metadata.ctime(), metadata.ctime_nsec()),
                },
            )
        })
        .collect()
    };
    let held = ClosedInventory::acquire(snapshot()).unwrap();
    held.verify(snapshot()).unwrap();
    let external = directory.path().join("external");
    std::fs::hard_link(&first, &external).unwrap();
    assert!(held.verify(snapshot()).is_err());
    std::fs::remove_file(external).unwrap();
    std::fs::write(&second, b"changed compiler evidence").unwrap();
    assert!(held.verify(snapshot()).is_err());
}
