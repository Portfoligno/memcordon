#![cfg(feature = "test-support")]
use memcordon_platform::windows_private_fixture_binding::{
    DIRECTORY_QUERY_ACCESS, DirectoryExpectation, DirectoryReference, DirectoryRole,
    DirectoryTransfer, MAX_DIRECTORY_REFERENCES, PrivateFixtureAncestor, PrivateFixtureBinding,
    validate_declaration,
};
use std::path::PathBuf;

fn fixture() -> (PrivateFixtureBinding, Vec<PathBuf>) {
    let root = if cfg!(windows) {
        PathBuf::from("C:\\")
    } else {
        PathBuf::from("/")
    };
    let parent = root.join("owned");
    let directory = |path| PrivateFixtureAncestor {
        path,
        volume_serial: 7,
        file_index: 11,
        attributes: 0x10,
    };
    let fixture = parent.join("fixture.exe");
    let binding = PrivateFixtureBinding {
        revision: 2,
        fixture: fixture.clone(),
        volume_serial: 7,
        file_index: 42,
        attributes: 0x20,
        links: 1,
        bytes: 1234,
        sha256: "ab".repeat(32),
        native_path_utf16: r"\Device\Volume\owned\fixture.exe".encode_utf16().collect(),
        ancestors: vec![
            PrivateFixtureAncestor {
                file_index: 1,
                ..directory(root.clone())
            },
            directory(parent.clone()),
        ],
        local_directory: directory(parent.join("fixture.exe.local")),
        output_ancestors: vec![
            PrivateFixtureAncestor {
                file_index: 1,
                ..directory(root.clone())
            },
            PrivateFixtureAncestor {
                file_index: 13,
                ..directory(root.join("output"))
            },
        ],
    };
    let paths = vec![fixture, parent.join("fixture.exe.local/provider.dll")];
    (binding, paths)
}

#[test]
fn declarations_are_bounded_data_and_require_the_exact_experiment_target_set() {
    let (binding, paths) = fixture();
    binding.validate(&paths).unwrap();
    validate_declaration(true, &paths, Some(&binding)).unwrap();
    validate_declaration(false, &[], None).unwrap();
    assert!(validate_declaration(true, &paths, None).is_err());
    assert!(validate_declaration(false, &paths, Some(&binding)).is_err());
    assert!(validate_declaration(false, &paths, None).is_err());
    let mut reordered = paths.clone();
    reordered.swap(0, 1);
    assert!(binding.validate(&reordered).is_err());
    for target in [
        paths[1].join("nested.dll"),
        paths[0].with_file_name("other.exe"),
        PathBuf::from("relative.dll"),
    ] {
        let mut changed = paths.clone();
        changed[1] = target;
        assert!(binding.validate(&changed).is_err());
    }
    let mut duplicate = paths.clone();
    duplicate.push(paths[1].clone());
    assert!(binding.validate(&duplicate).is_err());
    let bytes = serde_json::to_vec(&binding).unwrap();
    let parsed: PrivateFixtureBinding = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed, binding);
    let mut extra = serde_json::to_value(&binding).unwrap();
    extra["custody"] = true.into();
    assert!(serde_json::from_value::<PrivateFixtureBinding>(extra).is_err());
}

#[test]
fn malformed_identity_content_and_ancestry_cannot_enter_the_native_verifier() {
    let (original, paths) = fixture();
    for changed in [
        {
            let mut value = original.clone();
            value.revision = 1;
            value
        },
        {
            let mut value = original.clone();
            value.sha256 = "x".repeat(64);
            value
        },
        {
            let mut value = original.clone();
            value.bytes = 0;
            value
        },
        {
            let mut value = original.clone();
            value.links = 2;
            value
        },
        {
            let mut value = original.clone();
            value.attributes |= 0x400;
            value
        },
        {
            let mut value = original.clone();
            value.attributes |= 0x10;
            value
        },
        {
            let mut value = original.clone();
            value.native_path_utf16.push(0);
            value
        },
        {
            let mut value = original.clone();
            value.native_path_utf16 = vec![92; 2049];
            value
        },
        {
            let mut value = original.clone();
            value.ancestors.reverse();
            value
        },
        {
            let mut value = original.clone();
            value.ancestors[1].attributes |= 0x400;
            value
        },
        {
            let mut value = original.clone();
            value.ancestors[1].attributes = 0x20;
            value
        },
        {
            let mut value = original.clone();
            value.ancestors[1].path = paths[1].clone();
            value
        },
        {
            let mut value = original.clone();
            value.local_directory.path = paths[0].clone();
            value
        },
    ] {
        assert!(changed.validate(&paths).is_err());
    }
    // A well-formed identity/content substitution remains data: only actual
    // native handle/mapping comparisons may reject it or issue a capability.
    let mut substituted = original;
    substituted.file_index += 1;
    substituted.sha256 = "cd".repeat(32);
    substituted.validate(&paths).unwrap();
}

#[test]
fn output_chain_is_exact_root_first_and_separated_by_object_identity() {
    let (binding, _) = fixture();
    let output = binding.output_ancestors.last().unwrap().path.clone();
    binding.validate_output(&output).unwrap();
    for case in 0..6 {
        let mut changed = binding.clone();
        match case {
            0 => changed.output_ancestors.reverse(),
            1 => changed.output_ancestors.clear(),
            2 => changed.output_ancestors.last_mut().unwrap().attributes |= 0x400,
            3 => changed.output_ancestors.last_mut().unwrap().attributes = 0x20,
            4 => {
                changed.output_ancestors.last_mut().unwrap().file_index =
                    binding.local_directory.file_index
            }
            _ => changed.output_ancestors.last_mut().unwrap().path = output.join("different"),
        }
        assert!(changed.validate_output(&output).is_err(), "case {case}");
    }
    let mut changed = binding.clone();
    changed.output_ancestors.last_mut().unwrap().file_index =
        binding.ancestors.last().unwrap().file_index;
    assert!(changed.validate_output(&output).is_err());
    let digest = binding.directory_expectation().unwrap().manifest_sha256;
    let mut old = binding.clone();
    old.revision = 1;
    assert!(old.directory_expectation().is_err());
    let mut oversized = binding.clone();
    oversized.output_ancestors = vec![binding.output_ancestors[0].clone(); 65];
    assert!(oversized.directory_expectation().is_err());
    changed.output_ancestors.last_mut().unwrap().file_index = 999;
    assert_ne!(
        changed.directory_expectation().unwrap().manifest_sha256,
        digest
    );
}

#[test]
fn directory_transport_is_finite_ordered_distinct_and_metadata_only_data() {
    let expected = DirectoryExpectation {
        manifest_sha256: [7; 32],
        input_count: 64,
        output_count: 64,
    };
    let transfer = DirectoryTransfer {
        version: 1,
        manifest_sha256: expected.manifest_sha256,
        references: expected
            .roles()
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(slot, (role, index))| DirectoryReference {
                role,
                index,
                handle: 0x100 + slot as u64 * 4,
                access_mask: DIRECTORY_QUERY_ACCESS,
            })
            .collect(),
    };
    assert_eq!(transfer.references.len(), MAX_DIRECTORY_REFERENCES);
    assert_eq!(transfer.references[64].role, DirectoryRole::LocalDirectory);
    transfer.validate(&expected).unwrap();
    for case in 0..9 {
        let mut changed = transfer.clone();
        match case {
            0 => changed.references[0].access_mask |= 1,
            1 => changed.references[0].access_mask |= 0x100000,
            2 => changed.references[0].handle = 0,
            3 => changed.references[0].handle = u64::MAX - 1,
            4 => changed.references[1].handle = changed.references[0].handle,
            5 => changed.references.swap(0, 1),
            6 => {
                changed.references.pop();
            }
            7 => changed.manifest_sha256[0] ^= 1,
            _ => changed.version = 2,
        }
        assert!(changed.validate(&expected).is_err(), "case {case}");
    }
    for input_count in [0, 65] {
        assert!(
            DirectoryExpectation {
                input_count,
                ..expected.clone()
            }
            .validate()
            .is_err()
        );
    }
}
