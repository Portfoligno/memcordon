use memcordon_core::DiagnosticSha256;
use memcordon_core::runtime_image_census::{
    RuntimeImageCensusIdentityV1, RuntimeImageCensusMemberV1, RuntimeImageCensusObjectV1,
    RuntimeImageCensusV1,
};
use memcordon_core::workload_contract_v3::RootRelativePath;
use memcordon_core::workload_registry_v3::RuntimeImageDefinitionV1;

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn identity(inode: u64, mode: u32, length: u64) -> RuntimeImageCensusIdentityV1 {
    RuntimeImageCensusIdentityV1 {
        device: 17,
        inode,
        uid: 0,
        gid: 0,
        mode,
        nlink: if mode & 0o170000 == 0o040000 { 2 } else { 1 },
        length,
    }
}

fn fixture() -> (
    RuntimeImageDefinitionV1,
    DiagnosticSha256,
    RuntimeImageCensusV1,
) {
    let definition: RuntimeImageDefinitionV1 = serde_json::from_value(serde_json::json!({
        "format": "memcordon.runtime-image", "revision": 1,
        "image_id": "census-fixture", "target": "x86_64-unknown-linux-gnu",
        "entries": [
            {"kind":"regular", "path":"bin/program", "sha256":digest(1), "size":7, "executable":true},
            {"kind":"regular", "path":"data/config", "sha256":digest(2), "size":3, "executable":false},
            {"kind":"symlink", "path":"links/config", "target":"data/config"}
        ],
        "entrypoints":[{"id":"main", "path":"bin/program"}],
        "library_directories":[], "startup_environment":[]
    })).unwrap();
    definition.validate().unwrap();
    let raw_digest = digest(3);
    let members = [
        (
            ".memcordon-image.json",
            identity(3, 0o100444, 512),
            RuntimeImageCensusObjectV1::Regular {
                sha256: raw_digest.clone(),
                capability_absent: true,
            },
        ),
        (
            "bin",
            identity(4, 0o040555, 0),
            RuntimeImageCensusObjectV1::Directory,
        ),
        (
            "bin/program",
            identity(5, 0o100555, 7),
            RuntimeImageCensusObjectV1::Regular {
                sha256: digest(1),
                capability_absent: true,
            },
        ),
        (
            "data",
            identity(6, 0o040555, 0),
            RuntimeImageCensusObjectV1::Directory,
        ),
        (
            "data/config",
            identity(7, 0o100444, 3),
            RuntimeImageCensusObjectV1::Regular {
                sha256: digest(2),
                capability_absent: true,
            },
        ),
        (
            "links",
            identity(8, 0o040555, 0),
            RuntimeImageCensusObjectV1::Directory,
        ),
        (
            "links/config",
            identity(9, 0o120777, 14),
            RuntimeImageCensusObjectV1::Symlink {
                target: "../data/config".into(),
            },
        ),
    ]
    .into_iter()
    .map(|(path, identity, object)| RuntimeImageCensusMemberV1 {
        path: RootRelativePath::new(path.into()).unwrap(),
        identity,
        object,
    })
    .collect();
    let census = RuntimeImageCensusV1 {
        format: "memcordon.runtime-image-census".into(),
        revision: 1,
        reference: definition.reference().unwrap(),
        target: definition.target.clone(),
        definition_sha256: raw_digest.clone(),
        cutoff_unix_millis: 1234,
        store: identity(1, 0o040700, 0),
        root: identity(2, 0o040555, 0),
        members,
    };
    (definition, raw_digest, census)
}

#[test]
fn complete_manifest_projection_roundtrips_with_implicit_directories_and_rebuilt_link() {
    let (definition, raw_digest, census) = fixture();
    census
        .validate_for_definition(&definition, &raw_digest)
        .unwrap();
    let decoded: RuntimeImageCensusV1 =
        serde_json::from_slice(&serde_json::to_vec(&census).unwrap()).unwrap();
    assert_eq!(decoded, census);
    decoded
        .validate_for_definition(&definition, &raw_digest)
        .unwrap();
}

#[test]
fn census_rejects_incomplete_extra_reordered_or_aliased_inventory() {
    let (definition, raw_digest, census) = fixture();
    for mutation in 0..8 {
        let mut altered = census.clone();
        match mutation {
            0 => {
                altered.members.remove(3);
            }
            1 => {
                altered.members.push(RuntimeImageCensusMemberV1 {
                    path: RootRelativePath::new("input-socket".into()).unwrap(),
                    identity: identity(10, 0o140600, 0),
                    object: RuntimeImageCensusObjectV1::Directory,
                });
            }
            2 => altered.members.swap(1, 2),
            3 => altered.members[4].identity.inode = altered.members[2].identity.inode,
            4 => altered.members[1].identity.inode = altered.root.inode,
            5 => altered.root.inode = altered.store.inode,
            6 => altered.members[4].path = RootRelativePath::new("input-socket".into()).unwrap(),
            7 => altered.members[4].identity.device += 1,
            _ => unreachable!(),
        }
        assert!(
            altered
                .validate_for_definition(&definition, &raw_digest)
                .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn census_rejects_foreign_binding_unprotected_bytes_and_changed_link() {
    let (definition, raw_digest, census) = fixture();
    for mutation in 0..16 {
        let mut altered = census.clone();
        match mutation {
            0 => altered.revision += 1,
            1 => altered.target = "aarch64-unknown-linux-gnu".into(),
            2 => altered.definition_sha256 = digest(4),
            3 => altered.cutoff_unix_millis = 0,
            4 => altered.store.mode |= 0o020,
            5 => altered.root.uid = 1000,
            6 => altered.members[1].identity.mode |= 0o002,
            7 => altered.members[2].identity.uid = 1000,
            8 => altered.members[2].identity.mode = 0o100755,
            9 => altered.members[2].identity.length += 1,
            10 => altered.members[2].identity.nlink = 2,
            11 => {
                altered.members[2].object = RuntimeImageCensusObjectV1::Regular {
                    sha256: digest(4),
                    capability_absent: true,
                }
            }
            12 => {
                altered.members[2].object = RuntimeImageCensusObjectV1::Regular {
                    sha256: digest(1),
                    capability_absent: false,
                }
            }
            13 => {
                altered.members[6].object = RuntimeImageCensusObjectV1::Symlink {
                    target: "../../source/input-socket".into(),
                }
            }
            14 => {
                altered.members[0].object = RuntimeImageCensusObjectV1::Regular {
                    sha256: digest(4),
                    capability_absent: true,
                }
            }
            15 => altered.members[6].identity.mode = 0o140600,
            _ => unreachable!(),
        }
        assert!(
            altered
                .validate_for_definition(&definition, &raw_digest)
                .is_err(),
            "mutation {mutation}"
        );
    }
    assert!(
        census
            .validate_for_definition(&definition, &digest(4))
            .is_err()
    );
    let mut foreign = definition;
    foreign.target = "aarch64-unknown-linux-gnu".into();
    assert!(
        census
            .validate_for_definition(&foreign, &raw_digest)
            .is_err()
    );
}
