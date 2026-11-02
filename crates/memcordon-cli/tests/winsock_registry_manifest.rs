use memcordon_platform::windows_registry_manifest as registry;
use registry::{Key, Manifest, Root, ValueRecord, View};

fn name(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn fixture() -> Manifest {
    Manifest {
        version: registry::VERSION,
        view: View::Native,
        keys: vec![
            Key {
                root: Root::Winsock2Parameters,
                path: vec![],
                class: vec![0x03b1, 0xd800],
                values: vec![
                    ValueRecord {
                        name: vec![],
                        kind: 0,
                        bytes: vec![],
                    },
                    ValueRecord {
                        name: name("Current_Protocol_Catalog"),
                        kind: 1,
                        bytes: vec![0, 0xd8, 0, 0, 255, 0],
                    },
                ],
            },
            Key {
                root: Root::Winsock2Parameters,
                path: vec![name("Protocol_Catalog9")],
                class: vec![],
                values: vec![ValueRecord {
                    name: name("Num_Catalog_Entries"),
                    kind: 4,
                    bytes: 1u32.to_le_bytes().to_vec(),
                }],
            },
            Key {
                root: Root::WinsockParameters,
                path: vec![],
                class: vec![],
                values: vec![],
            },
        ],
    }
}

#[test]
fn exact_native_names_types_bytes_and_empty_default_survive_canonical_roundtrip() {
    let original = fixture();
    let bytes = serde_json::to_vec(&original).unwrap();
    let decoded: Manifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.keys[0].class, [0x03b1, 0xd800]);
    let digest = original.digest().unwrap();
    let mut reordered = decoded.clone();
    reordered.keys[0].values.reverse();
    reordered.keys.reverse();
    assert_eq!(reordered.digest().unwrap(), digest);
    assert_eq!(decoded.keys[0].values[0].name, Vec::<u16>::new());
    assert!(decoded.keys[0].values[0].bytes.is_empty());
    assert_eq!(decoded.keys[0].values[1].bytes, [0, 0xd8, 0, 0, 255, 0]);
    let declaration = original.declaration().unwrap();
    declaration.validate().unwrap();
    assert_eq!(declaration.sha256, digest);
    assert_eq!(declaration.view, View::Native);
}

#[test]
fn source_mutations_and_length_ambiguous_values_cannot_keep_the_sealed_digest() {
    let original = fixture();
    let expected = original.digest().unwrap();
    for mutation in 0..5 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.keys[0].values[1].bytes[0] ^= 1,
            1 => changed.keys[0].values[1].kind = 3,
            2 => changed.keys[0].values[1].name.push(0xd800),
            3 => changed.keys[1].path[0].push(b'x' as u16),
            4 => changed.keys[0].class.push(b'x' as u16),
            _ => unreachable!(),
        }
        assert_ne!(changed.digest().unwrap(), expected);
    }
    let mut first = fixture();
    first.keys[0].values[1].name = name("ab");
    first.keys[0].values[1].bytes = b"c".to_vec();
    let mut second = first.clone();
    second.keys[0].values[1].name = name("a");
    second.keys[0].values[1].bytes = b"bc".to_vec();
    assert_ne!(first.digest().unwrap(), second.digest().unwrap());
}

#[test]
fn incomplete_duplicated_or_unbounded_trees_fail_before_sealing() {
    for mutation in 0..12 {
        let mut bad = fixture();
        match mutation {
            0 => {
                bad.keys.remove(0);
            }
            1 => bad.keys.push(bad.keys[0].clone()),
            2 => bad.keys[1].path.push(name("missing-parent")),
            3 => bad.keys[1].path = vec![name("deep"); registry::MAX_DEPTH + 1],
            4 => bad.keys[1].path[0].push(0),
            5 => bad.keys[1].path[0].push(b'\\' as u16),
            6 => {
                let duplicate = bad.keys[0].values[0].clone();
                bad.keys[0].values.push(duplicate);
            }
            7 => bad.keys[0].values[1].kind = 12,
            8 => bad.keys[0].values[1].name.push(0),
            9 => bad.keys[0].values[1].bytes = vec![0; registry::MAX_VALUE_BYTES + 1],
            10 => bad.keys[0].class.push(0),
            11 => bad.keys[0].class = vec![b'x' as u16; 256],
            _ => unreachable!(),
        }
        assert!(bad.digest().is_err(), "mutation {mutation}");
    }
    let mut many = fixture();
    many.keys[0].values = (0..=registry::MAX_VALUES)
        .map(|index| ValueRecord {
            name: name(&index.to_string()),
            kind: 0,
            bytes: vec![],
        })
        .collect();
    assert!(many.validate().is_err());
    let mut large = fixture();
    large.keys[0].values = (0..5)
        .map(|index| ValueRecord {
            name: name(&index.to_string()),
            kind: 3,
            bytes: vec![0; registry::MAX_VALUE_BYTES],
        })
        .collect();
    assert!(large.validate().is_err());
    let mut future = fixture().declaration().unwrap();
    future.version += 1;
    assert!(future.validate().is_err());
    let mut json = serde_json::to_value(fixture()).unwrap();
    json["view"] = "wow64-32".into();
    assert!(serde_json::from_value::<Manifest>(json).is_err());
}

fn forest() -> Manifest {
    Manifest {
        version: registry::VERSION,
        view: View::Native,
        keys: Root::ALL
            .into_iter()
            .map(|root| Key {
                root,
                path: vec![],
                class: vec![],
                values: vec![],
            })
            .collect(),
    }
}

#[test]
fn both_fixed_roots_are_mandatory_and_parent_closure_never_crosses_roots() {
    forest().validate().unwrap();
    for root in Root::ALL {
        let mut missing = forest();
        missing.keys.retain(|key| key.root != root);
        assert!(missing.validate().is_err());
    }
    let mut same_relative_path = fixture();
    let mut sibling = same_relative_path.keys[1].clone();
    sibling.root = Root::WinsockParameters;
    same_relative_path.keys.push(sibling);
    same_relative_path.validate().unwrap();
    let mut wrong_parent = same_relative_path.clone();
    wrong_parent
        .keys
        .last_mut()
        .unwrap()
        .path
        .push(name("leaf"));
    assert!(wrong_parent.validate().is_err());
    let mut duplicate = same_relative_path.clone();
    duplicate.keys.push(duplicate.keys[3].clone());
    assert!(duplicate.validate().is_err());
    let mut unknown = serde_json::to_value(forest()).unwrap();
    unknown["keys"][0]["root"] = "arbitrary-service-parameters".into();
    assert!(serde_json::from_value::<Manifest>(unknown).is_err());
    let mut absent = serde_json::to_value(forest()).unwrap();
    absent["keys"][0].as_object_mut().unwrap().remove("root");
    assert!(serde_json::from_value::<Manifest>(absent).is_err());
}

#[test]
fn roots_are_digest_bound_and_legacy_single_root_declarations_are_refused() {
    let original = fixture();
    let digest = original.digest().unwrap();
    let mut swapped = original.clone();
    for key in &mut swapped.keys {
        key.root = match key.root {
            Root::Winsock2Parameters => Root::WinsockParameters,
            Root::WinsockParameters => Root::Winsock2Parameters,
        };
    }
    assert_ne!(swapped.digest().unwrap(), digest);
    let mut moved = original.clone();
    moved.keys[1].root = Root::WinsockParameters;
    assert_ne!(moved.digest().unwrap(), digest);
    let mut changed = original.clone();
    changed.keys[2].values.push(ValueRecord {
        name: vec![],
        kind: 3,
        bytes: vec![1],
    });
    assert_ne!(changed.digest().unwrap(), digest);
    let mut declaration = original.declaration().unwrap();
    assert_eq!(declaration.version, 2);
    declaration.version = 1;
    assert!(declaration.validate().is_err());
    let mut legacy = original;
    legacy.version = 1;
    assert!(legacy.digest().is_err());
    let encoded = serde_json::to_value(forest()).unwrap();
    assert_eq!(encoded["keys"][0]["root"], "winsock2-parameters");
    assert_eq!(encoded["keys"][1]["root"], "winsock-parameters");
}

#[test]
fn forest_key_and_value_limits_are_shared_not_doubled_per_root() {
    let mut keys = forest();
    for index in 0..registry::MAX_KEYS - Root::ALL.len() {
        keys.keys.push(Key {
            root: Root::ALL[index % Root::ALL.len()],
            path: vec![name(&index.to_string())],
            class: vec![],
            values: vec![],
        });
    }
    keys.validate().unwrap();
    keys.keys.push(Key {
        root: Root::WinsockParameters,
        path: vec![name("one-too-many")],
        class: vec![],
        values: vec![],
    });
    assert!(keys.validate().is_err());

    let mut values = forest();
    for (index, key) in values.keys.iter_mut().enumerate() {
        key.values = (0..registry::MAX_VALUES / 2)
            .map(|value| ValueRecord {
                name: name(&format!("{index}-{value}")),
                kind: 0,
                bytes: vec![],
            })
            .collect();
    }
    values.validate().unwrap();
    values.keys[1].values.push(ValueRecord {
        name: name("one-too-many"),
        kind: 0,
        bytes: vec![],
    });
    assert!(values.validate().is_err());
}

#[test]
fn forest_byte_budget_charges_both_roots_and_accepts_only_the_exact_shared_extent() {
    let mut value = forest();
    for key in &mut value.keys {
        key.values = (0..2)
            .map(|index| ValueRecord {
                name: vec![b'a' as u16 + index],
                kind: 3,
                bytes: vec![0; registry::MAX_VALUE_BYTES],
            })
            .collect();
    }
    // Two root tags plus four one-unit native names consume ten bytes.
    let metadata = Root::ALL.len() + 4 * size_of::<u16>();
    value.keys[1].values[1]
        .bytes
        .truncate(registry::MAX_VALUE_BYTES - metadata);
    value.validate().unwrap();
    value.keys[1].values[1].bytes.push(0);
    assert!(value.validate().is_err());
}
