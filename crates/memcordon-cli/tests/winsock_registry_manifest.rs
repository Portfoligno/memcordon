#[path = "../src/bin/consumer_readiness_windows/winsock_registry_manifest.rs"]
mod registry;
use registry::{Key, Manifest, ValueRecord, View};

fn name(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn fixture() -> Manifest {
    Manifest {
        version: 1,
        view: View::Native,
        keys: vec![
            Key {
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
                path: vec![name("Protocol_Catalog9")],
                class: vec![],
                values: vec![ValueRecord {
                    name: name("Num_Catalog_Entries"),
                    kind: 4,
                    bytes: 1u32.to_le_bytes().to_vec(),
                }],
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
