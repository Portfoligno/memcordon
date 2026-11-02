use memcordon_platform::windows_registry_manifest as registry;
use registry::{Key, Manifest, Root, TransportPresence, TransportRoot, ValueRecord, View};

fn name(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn transport_value(services: &[&str]) -> ValueRecord {
    let mut units = Vec::new();
    for service in services {
        units.extend(name(service));
        units.push(0);
    }
    units.push(0);
    ValueRecord {
        name: name("Transports"),
        kind: 7,
        bytes: units.into_iter().flat_map(u16::to_le_bytes).collect(),
    }
}
fn fixture() -> Manifest {
    Manifest {
        version: registry::VERSION,
        view: View::Native,
        migration_providers: TransportPresence::Absent { lstatus: 2 },
        transports: vec![],
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
                values: vec![transport_value(&[])],
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
        migration_providers: TransportPresence::Absent { lstatus: 2 },
        transports: vec![],
        keys: Root::ALL
            .into_iter()
            .map(|root| Key {
                root: root.clone(),
                path: vec![],
                class: vec![],
                values: if root == Root::WinsockParameters {
                    vec![transport_value(&[])]
                } else {
                    vec![]
                },
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
        key.root = match &key.root {
            Root::Winsock2Parameters => Root::WinsockParameters,
            Root::WinsockParameters => Root::Winsock2Parameters,
            other => other.clone(),
        };
    }
    assert!(
        swapped.digest().is_err(),
        "discovery cannot move to the other root"
    );
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
    assert_eq!(declaration.version, 4);
    declaration.version = 3;
    assert!(declaration.validate().is_err());
    declaration.version = 2;
    assert!(declaration.validate().is_err());
    declaration.version = 1;
    assert!(declaration.validate().is_err());
    let mut legacy = original;
    legacy.version = 2;
    assert!(legacy.digest().is_err());
    let encoded = serde_json::to_value(forest()).unwrap();
    assert_eq!(encoded["keys"][0]["root"], "winsock2-parameters");
    assert_eq!(encoded["keys"][1]["root"], "winsock-parameters");
}

#[test]
fn forest_key_and_value_limits_are_shared_not_doubled_per_root() {
    let mut keys = forest();
    for index in 0..registry::MAX_KEYS - Root::ALL.len() - 1 {
        keys.keys.push(Key {
            root: Root::ALL[index % Root::ALL.len()].clone(),
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
        let count = registry::MAX_VALUES / 2 - key.values.len();
        key.values.extend(
            (0..count)
                .map(|value| ValueRecord {
                    name: name(&format!("{index}-{value}")),
                    kind: 0,
                    bytes: vec![],
                })
                .collect::<Vec<_>>(),
        );
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
        key.values.extend(
            (0..2)
                .map(|index| ValueRecord {
                    name: vec![b'a' as u16 + index],
                    kind: 3,
                    bytes: vec![0; registry::MAX_VALUE_BYTES],
                })
                .collect::<Vec<_>>(),
        );
    }
    // Root tags, four payload names and the exact empty Transports value.
    let metadata = 6 + Root::ALL.len() + 4 * size_of::<u16>() + name("Transports").len() * 2 + 2;
    value.keys[1].values[2]
        .bytes
        .truncate(registry::MAX_VALUE_BYTES - metadata);
    value.validate().unwrap();
    value.keys[1].values[2].bytes.push(0);
    assert!(value.validate().is_err());
}

fn transport_forest() -> Manifest {
    let mut value = forest();
    value.keys[1].values[0] = transport_value(&["Alpha", "Beta", "Alpha"]);
    value.transports = vec![
        TransportRoot {
            service: name("Alpha"),
            presence: TransportPresence::Present,
        },
        TransportRoot {
            service: name("Beta"),
            presence: TransportPresence::Absent { lstatus: 2 },
        },
    ];
    value.keys.push(Key {
        root: Root::TransportWinsock {
            service: name("Alpha"),
        },
        path: vec![],
        class: vec![],
        values: vec![ValueRecord {
            name: vec![],
            kind: 3,
            bytes: vec![1, 0, 255],
        }],
    });
    value
}

#[test]
fn native_multi_sz_requires_real_terminators_and_preserves_exact_components() {
    assert!(
        registry::parse_transports(&transport_value(&[]))
            .unwrap()
            .is_empty()
    );
    let original = transport_value(&["Beta", "Alpha", "Beta"]);
    assert_eq!(
        registry::parse_transports(&original).unwrap(),
        vec![name("Alpha"), name("Beta")]
    );
    let mut padded = original.clone();
    padded.bytes.extend([0, 0, 0, 0]);
    assert_eq!(
        registry::parse_transports(&padded).unwrap(),
        registry::parse_transports(&original).unwrap()
    );
    let mut native = transport_value(&["Alpha"]);
    native.bytes.splice(0..2, 0xd800u16.to_le_bytes());
    assert_eq!(
        registry::parse_transports(&native).unwrap()[0][0],
        0xd800,
        "no lossy Unicode conversion"
    );
    for mutation in 0..8 {
        let mut bad = original.clone();
        match mutation {
            0 => {
                bad.bytes.pop();
            }
            1 => {
                bad.bytes.truncate(bad.bytes.len() - 2);
            }
            2 => bad.bytes.extend(1u16.to_le_bytes()),
            3 => bad.kind = 1,
            4 => bad.bytes.clear(),
            5 => bad = transport_value(&["escape\\child"]),
            6 => bad = transport_value(&["escape/child"]),
            7 => bad = transport_value(&[&"x".repeat(256)]),
            _ => unreachable!(),
        }
        assert!(
            registry::parse_transports(&bad).is_err(),
            "mutation {mutation}"
        );
    }
    let mut aliases = transport_value(&["Alpha", "alpha"]);
    assert_eq!(
        registry::parse_transports(&aliases).unwrap().len(),
        2,
        "native ordinal alias checks must not be guessed by Unicode folding"
    );
    aliases.name = name("tRaNsPoRtS");
    let mut value = forest();
    value.keys[1].values[0] = aliases;
    assert_eq!(registry::transport_services(&value.keys).unwrap().len(), 2);
    value.keys[1].values.push(transport_value(&[]));
    assert!(registry::transport_services(&value.keys).is_err());
}

#[test]
fn transport_presence_is_exact_source_closure_not_optional_missing_data() {
    let original = transport_forest();
    original.validate().unwrap();
    let roundtrip: Manifest =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(roundtrip, original);
    assert_eq!(
        original.keys[1].values[0].bytes,
        transport_value(&["Alpha", "Beta", "Alpha"]).bytes
    );
    assert_eq!(
        Root::TransportWinsock {
            service: name("Alpha")
        }
        .path(),
        name("System\\CurrentControlSet\\Services\\Alpha\\Parameters\\Winsock")
    );
    for mutation in 0..9 {
        let mut bad = original.clone();
        match mutation {
            0 => {
                bad.transports.pop();
            }
            1 => bad.transports[1].service = name("Unlisted"),
            2 => bad.transports[1].presence = TransportPresence::Absent { lstatus: 5 },
            3 => {
                bad.keys[2].root = Root::TransportWinsock {
                    service: name("Beta"),
                }
            }
            4 => {
                bad.keys.pop();
            }
            5 => bad.keys[1].values[0] = transport_value(&["Alpha"]),
            6 => bad.transports.push(bad.transports[0].clone()),
            7 => bad.keys[2].path = vec![name("missing-parent")],
            8 => bad.transports[0].service = name("escape\\elsewhere"),
            _ => unreachable!(),
        }
        assert!(bad.digest().is_err(), "mutation {mutation}");
    }
    let mut unknown = serde_json::to_value(original).unwrap();
    unknown["keys"][2]["root"]["transport-winsock"]["unrecognized"] = true.into();
    assert!(serde_json::from_value::<Manifest>(unknown).is_err());
}

#[test]
fn canonical_transport_digest_binds_raw_discovery_presence_and_contents() {
    let original = transport_forest();
    let digest = original.digest().unwrap();
    let mut reordered = original.clone();
    reordered.transports.reverse();
    reordered.keys.reverse();
    assert_eq!(reordered.digest().unwrap(), digest);
    let mut raw_order = original.clone();
    raw_order.keys[1].values[0] = transport_value(&["Beta", "Alpha", "Alpha"]);
    assert_ne!(
        raw_order.digest().unwrap(),
        digest,
        "raw source list is not normalized"
    );
    let mut absent = original.clone();
    absent.transports[0].presence = TransportPresence::Absent { lstatus: 2 };
    absent.keys.pop();
    assert_ne!(absent.digest().unwrap(), digest);
    let mut content = original.clone();
    content.keys[2].values[0].bytes.push(2);
    assert_ne!(content.digest().unwrap(), digest);
    let mut source_missing = original;
    source_missing.keys[1].values.clear();
    assert!(
        source_missing.validate().is_err(),
        "missing discovery value is not an empty list"
    );
}

#[test]
fn absent_transport_inventory_and_memberships_share_existing_limits() {
    let mut value = transport_forest();
    for index in 0..registry::MAX_KEYS - value.keys.len() - 2 {
        value.keys.push(Key {
            root: Root::Winsock2Parameters,
            path: vec![name(&index.to_string())],
            class: vec![],
            values: vec![],
        });
    }
    value.validate().unwrap();
    value.keys.push(Key {
        root: Root::Winsock2Parameters,
        path: vec![name("one-too-many")],
        class: vec![],
        values: vec![],
    });
    assert!(value.validate().is_err());
    let names = (0..registry::MAX_KEYS)
        .map(|index| format!("Service{index}"))
        .collect::<Vec<_>>();
    let names = names.iter().map(String::as_str).collect::<Vec<_>>();
    assert!(registry::parse_transports(&transport_value(&names)).is_err());
}

#[test]
fn optional_migration_root_requires_explicit_witnessed_presence_and_never_fabricates_keys() {
    let absent = forest();
    absent.validate().unwrap();
    let mut present = absent.clone();
    present.migration_providers = TransportPresence::Present;
    assert!(present.validate().is_err());
    present.keys.push(Key {
        root: Root::WinsockMigrationProviders,
        path: vec![],
        class: vec![0xd800],
        values: vec![],
    });
    present.validate().unwrap();
    assert_ne!(present.digest().unwrap(), absent.digest().unwrap());
    let mut contents = present.clone();
    contents.keys.last_mut().unwrap().values.push(ValueRecord {
        name: name("actual-native-provider"),
        kind: 3,
        bytes: vec![1, 0, 255],
    });
    assert_ne!(contents.digest().unwrap(), present.digest().unwrap());
    let mut reordered = contents.clone();
    reordered.keys.reverse();
    assert_eq!(reordered.digest().unwrap(), contents.digest().unwrap());
    assert_eq!(
        Root::WinsockMigrationProviders.path(),
        name("System\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers")
    );
    for status in [3, 5, 0] {
        let mut bad = absent.clone();
        bad.migration_providers = TransportPresence::Absent { lstatus: status };
        assert!(bad.validate().is_err());
    }
    let mut contradictory = present.clone();
    contradictory.migration_providers = TransportPresence::Absent { lstatus: 2 };
    assert!(contradictory.validate().is_err());
    let mut duplicate = present.clone();
    duplicate.keys.push(present.keys.last().unwrap().clone());
    assert!(duplicate.validate().is_err());
    let mut wire = serde_json::to_value(absent).unwrap();
    wire.as_object_mut().unwrap().remove("migration_providers");
    assert!(serde_json::from_value::<Manifest>(wire).is_err());
}

#[test]
fn migration_presence_consumes_one_inventory_slot_whether_present_or_absent() {
    let mut absent = forest();
    for index in 0..registry::MAX_KEYS - 3 {
        absent.keys.push(Key {
            root: Root::Winsock2Parameters,
            path: vec![name(&index.to_string())],
            class: vec![],
            values: vec![],
        });
    }
    absent.validate().unwrap();
    let mut present = absent.clone();
    present.migration_providers = TransportPresence::Present;
    present.keys.push(Key {
        root: Root::WinsockMigrationProviders,
        path: vec![],
        class: vec![],
        values: vec![],
    });
    present.validate().unwrap();
    for value in [&mut absent, &mut present] {
        value.keys.push(Key {
            root: Root::Winsock2Parameters,
            path: vec![name("one-too-many")],
            class: vec![],
            values: vec![],
        });
        assert!(value.validate().is_err());
    }
}
