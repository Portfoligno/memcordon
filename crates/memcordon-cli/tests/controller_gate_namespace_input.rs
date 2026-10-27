#[path = "../src/bin/consumer_readiness_windows/controller_gate_access_input.rs"]
mod input;
use input::namespace as namespace_input;
use input::namespace::{self, Proof};
#[path = "../src/bin/consumer_readiness_windows/controller_gate_namespace_directory.rs"]
mod directory;
use directory::Counted;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn fixture() -> (input::Input, Vec<u16>, Vec<u8>) {
    let mut descriptor = vec![0; 20];
    descriptor[0] = 1;
    descriptor[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    descriptor[4..8].copy_from_slice(&20_u32.to_le_bytes());
    descriptor[8..12].copy_from_slice(&20_u32.to_le_bytes());
    descriptor[16..20].copy_from_slice(&32_u32.to_le_bytes());
    descriptor.extend([1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    descriptor.extend([2, 0, 8, 0, 0, 0, 0, 0]);
    let name = wide("Local\\owned-event");
    let challenge = b"original-namespace-challenge".to_vec();
    let mut value = input::Input {
        revision: 1,
        descriptor_sha256: input::sha256(&descriptor),
        descriptor,
        name_utf16_sha256: input::name_sha256(&name),
        challenge_sha256: input::sha256(&challenge),
        work_cutoff_qpc: 100,
        qpc_frequency: 10,
        namespace: None,
    };
    let components = vec![wide("enumerated-directory"), wide("owned-event")];
    value.namespace = Some(Proof {
        revision: 1,
        path_sha256: namespace::path_sha256(&components).unwrap(),
        components,
        challenge_sha256: value.challenge_sha256.clone(),
        name_utf16_sha256: value.name_utf16_sha256.clone(),
        descriptor_sha256: value.descriptor_sha256.clone(),
        work_cutoff_qpc: value.work_cutoff_qpc,
        qpc_frequency: value.qpc_frequency,
        controller_same_original: true,
        controller_absolute_same_original: true,
        complete: true,
    });
    (value, name, challenge)
}

#[test]
fn optional_proof_binds_original_path_clock_name_challenge_and_descriptor() {
    let (value, name, challenge) = fixture();
    value.validate(&name, &challenge).unwrap();
    assert_eq!(
        namespace::rooted_path(&value.namespace.as_ref().unwrap().components).unwrap(),
        wide("\\enumerated-directory\\owned-event")
    );
    let mut absent = value.clone();
    absent.namespace = None;
    absent.validate(&name, &challenge).unwrap();
    let encoded = serde_json::to_value(&absent).unwrap();
    assert!(encoded.get("namespace").is_none());
    let decoded: input::Input = serde_json::from_value(encoded).unwrap();
    assert!(decoded.namespace.is_none());
    let mut candidates = Vec::new();
    for field in ["revision", "work_cutoff_qpc", "qpc_frequency"] {
        let mut encoded = serde_json::to_value(&value).unwrap();
        encoded["namespace"][field] = serde_json::json!(999);
        candidates.push(serde_json::from_value::<input::Input>(encoded).unwrap());
    }
    for field in [
        "path_sha256",
        "challenge_sha256",
        "name_utf16_sha256",
        "descriptor_sha256",
    ] {
        let mut encoded = serde_json::to_value(&value).unwrap();
        encoded["namespace"][field] =
            serde_json::json!(input::sha256(b"different original binding"));
        candidates.push(serde_json::from_value::<input::Input>(encoded).unwrap());
    }
    for field in [
        "complete",
        "controller_same_original",
        "controller_absolute_same_original",
    ] {
        let mut encoded = serde_json::to_value(&value).unwrap();
        encoded["namespace"][field] = serde_json::json!(false);
        candidates.push(serde_json::from_value::<input::Input>(encoded).unwrap());
    }
    for candidate in candidates {
        assert!(candidate.validate(&name, &challenge).is_err());
    }
    let mut changed_leaf = value.clone();
    let proof = changed_leaf.namespace.as_mut().unwrap();
    *proof.components.last_mut().unwrap() = wide("different-event");
    proof.path_sha256 = namespace::path_sha256(&proof.components).unwrap();
    assert!(changed_leaf.validate(&name, &challenge).is_err());
    let mut encoded = serde_json::to_value(&value).unwrap();
    encoded["namespace"]["unqualified_extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<input::Input>(encoded).is_err());
}

#[test]
fn path_components_depth_and_storage_are_closed_without_guessed_mapping() {
    let (value, _, _) = fixture();
    let original = value.namespace.unwrap();
    assert_eq!(original.event_leaf().unwrap(), wide("owned-event"));
    let mut empty = original.clone();
    empty.components.clear();
    assert!(empty.event_leaf().is_err());
    let mut oversized_leaf = original.clone();
    *oversized_leaf.components.last_mut().unwrap() =
        vec![u16::from(b'x'); namespace::MAX_PATH_BYTES / size_of::<u16>()];
    assert!(oversized_leaf.event_leaf().is_err());
    for value in [
        vec![],
        wide("."),
        wide(".."),
        wide("one/two"),
        wide("one\\two"),
        vec![0],
    ] {
        let mut proof = original.clone();
        *proof.components.last_mut().unwrap() = value.clone();
        assert!(proof.event_leaf().is_err());
        assert!(namespace::rooted_path(&[value]).is_err());
    }
    assert!(namespace::rooted_path(&vec![wide("d"); namespace::MAX_COMPONENTS]).is_ok());
    assert!(namespace::rooted_path(&vec![wide("d"); namespace::MAX_COMPONENTS + 1]).is_err());
    assert!(
        namespace::rooted_path(&[vec![
            u16::from(b'x');
            namespace::MAX_PATH_BYTES / size_of::<u16>()
        ]])
        .is_err()
    );
}

fn native_buffer() -> (Vec<u8>, usize, Counted, Counted, usize) {
    let header = size_of::<u64>() * 4;
    let base = 0x1000usize;
    let mut bytes = vec![0; header];
    let mut append = |text: &str| {
        let address = base + bytes.len();
        let units = wide(text);
        let length = u16::try_from(units.len() * size_of::<u16>()).unwrap();
        bytes.extend(units.into_iter().chain(Some(0)).flat_map(u16::to_le_bytes));
        Counted {
            length,
            maximum_length: length + u16::try_from(size_of::<u16>()).unwrap(),
            address,
        }
    };
    let name = append("owned-event");
    let kind = append("Event");
    (bytes, base, name, kind, header)
}

#[test]
fn detailed_parser_refusals_preserve_exact_closed_predicate_without_addresses() {
    let (bytes, base, name, kind, header) = native_buffer();
    let cases = [
        (
            Counted {
                address: base - 2,
                ..name
            },
            "pointer-before-buffer",
        ),
        (Counted { length: 0, ..name }, "empty-length"),
        (
            Counted {
                length: name.maximum_length + 2,
                ..name
            },
            "length-exceeds-maximum",
        ),
        (
            Counted {
                length: name.length - 1,
                ..name
            },
            "odd-length",
        ),
        (
            Counted {
                maximum_length: name.maximum_length + 1,
                ..name
            },
            "odd-maximum",
        ),
        (
            Counted {
                address: name.address + 1,
                ..name
            },
            "address-misaligned",
        ),
        (
            Counted {
                address: base,
                ..name
            },
            "overlaps-header",
        ),
        (
            Counted {
                maximum_length: u16::MAX - 1,
                ..name
            },
            "outside-returned-buffer",
        ),
    ];
    for (bad, reason) in cases {
        for (left, right, field) in [(bad, kind, "name"), (name, bad, "kind")] {
            let failure = directory::entry_detailed(&bytes, base, left, right, header).unwrap_err();
            assert_eq!(failure.field, field);
            assert_eq!(failure.reason, reason);
            assert_eq!(failure.length, Some(bad.length));
            assert_eq!(failure.relative_offset, bad.address.checked_sub(base));
            let encoded = serde_json::to_value(&failure).unwrap();
            assert!(encoded.get("address").is_none());
            assert!(directory::entry(&bytes, base, left, right, header).is_err());
        }
    }
    for (data, address, size, field, reason) in [
        (&bytes[..], base, 0, "header", "empty-header"),
        (
            &bytes[..],
            base,
            bytes.len() + 1,
            "header",
            "outside-returned-buffer",
        ),
        (&bytes[..], base + 1, header, "buffer", "base-misaligned"),
        (
            &bytes[..],
            usize::MAX - 1,
            header,
            "buffer",
            "base-extent-overflow",
        ),
    ] {
        let failure = directory::entry_detailed(data, address, name, kind, size).unwrap_err();
        assert_eq!((failure.field, failure.reason), (field, reason));
    }
    let oversized = vec![0; directory::MAX_BUFFER_BYTES + 1];
    assert_eq!(
        directory::entry_detailed(&oversized, base, name, kind, header)
            .unwrap_err()
            .reason,
        "allocation-bound"
    );
    let overflow = directory::entry_detailed(
        &bytes,
        0,
        Counted {
            address: usize::MAX - 1,
            ..name
        },
        kind,
        header,
    )
    .unwrap_err();
    assert_eq!(overflow.reason, "extent-overflow");
    assert!(overflow.checked_extent.is_none());
    for (text, reason) in [
        ("\0", "component-nul"),
        ("/", "component-slash"),
        ("\\", "component-backslash"),
        (".", "component-dot"),
        ("..", "component-dot-dot"),
    ] {
        let mut changed = bytes.clone();
        let units = wide(text);
        let start = name.address - base;
        for (index, unit) in units.iter().enumerate() {
            let offset = start + index * size_of::<u16>();
            changed[offset..offset + size_of::<u16>()].copy_from_slice(&unit.to_le_bytes());
        }
        let bad = Counted {
            length: u16::try_from(units.len() * size_of::<u16>()).unwrap(),
            ..name
        };
        assert_eq!(
            directory::entry_detailed(&changed, base, bad, kind, header)
                .unwrap()
                .classify(&units)
                .unwrap_err()
                .get_ref()
                .unwrap()
                .downcast_ref::<directory::ParseFailure>()
                .unwrap()
                .reason,
            reason
        );
    }
    let wrapped =
        directory::entry(&bytes, base, Counted { length: 0, ..name }, kind, header).unwrap_err();
    assert_eq!(wrapped.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        wrapped
            .get_ref()
            .unwrap()
            .downcast_ref::<directory::ParseFailure>()
            .unwrap()
            .reason,
        "empty-length"
    );
}

#[test]
fn counted_native_strings_are_copied_only_from_complete_aligned_owned_extents() {
    let (bytes, base, name, kind, header) = native_buffer();
    let entry = directory::entry(&bytes, base, name, kind, header).unwrap();
    assert_eq!(entry.name, wide("owned-event"));
    assert_eq!(entry.kind, wide("Event"));
    for bad in [
        Counted {
            length: name.length + 1,
            ..name
        },
        Counted {
            maximum_length: name.maximum_length + 1,
            ..name
        },
        Counted {
            length: name.maximum_length + 2,
            ..name
        },
        Counted {
            address: name.address + 1,
            ..name
        },
        Counted {
            address: base,
            ..name
        },
        Counted {
            address: usize::MAX - 1,
            ..name
        },
        Counted { length: 0, ..name },
        Counted { address: 0, ..name },
    ] {
        assert!(directory::entry(&bytes, base, bad, kind, header).is_err());
    }
    assert!(directory::entry(&bytes[..bytes.len() - 1], base, name, kind, header).is_err());
    assert!(directory::entry(&bytes, base, name, kind, 0).is_err());
    assert!(directory::entry(&bytes, usize::MAX - 1, name, kind, header).is_err());
    let mut huge = bytes.clone();
    huge.resize(directory::MAX_BUFFER_BYTES + 1, 0);
    assert!(directory::entry(&huge, base, name, kind, header).is_err());
    for unit in [0, u16::from(b'/'), u16::from(b'\\')] {
        let mut altered = bytes.clone();
        altered[header..header + size_of::<u16>()].copy_from_slice(&unit.to_le_bytes());
        let entry = directory::entry(&altered, base, name, kind, header).unwrap();
        assert!(entry.classify(&entry.name).is_err());
    }
}

fn counted_entry(name: &[u16], kind: &[u16]) -> (Vec<u8>, usize, Counted, Counted, usize) {
    let base = 0x1000;
    let header = size_of::<u64>() * 4;
    let mut bytes = vec![0; header];
    let mut append = |units: &[u16]| {
        let address = base + bytes.len();
        let length = u16::try_from(std::mem::size_of_val(units)).unwrap();
        bytes.extend(
            units
                .iter()
                .copied()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes),
        );
        Counted {
            length,
            maximum_length: length + u16::try_from(size_of::<u16>()).unwrap(),
            address,
        }
    };
    let name = append(name);
    let kind = append(kind);
    (bytes, base, name, kind, header)
}

#[test]
fn observed_arm_irrelevant_kind_with_slash_name_is_not_a_namespace_path() {
    // Reproduce the observed native extents, without claiming the unretained
    // original text: header32, name110/max112 at64, kind12/max14 at176.
    let header = size_of::<u64>() * 4;
    let base = 0x1000;
    let mut bytes = vec![0; 190];
    let mut name_units = vec![u16::from(b'x'); 110 / size_of::<u16>()];
    name_units[0] = u16::from(b'/');
    let kind_units = wide("Mutant");
    for (offset, units) in [(64, name_units.as_slice()), (176, kind_units.as_slice())] {
        for (ordinal, unit) in units.iter().enumerate() {
            let start = offset + ordinal * size_of::<u16>();
            bytes[start..start + size_of::<u16>()].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let name = Counted {
        length: 110,
        maximum_length: 112,
        address: base + 64,
    };
    let kind = Counted {
        length: 12,
        maximum_length: 14,
        address: base + 176,
    };
    let ignored = directory::entry(&bytes, base, name, kind, header).unwrap();
    assert_eq!(ignored.name, name_units);
    assert_eq!(
        ignored.classify(&wide("owned-event")).unwrap(),
        directory::EntryClass::Ignored
    );
    let (next, next_base, next_name, next_kind, next_header) = native_buffer();
    let selected = directory::entry(&next, next_base, next_name, next_kind, next_header).unwrap();
    assert_eq!(
        selected.classify(&wide("owned-event")).unwrap(),
        directory::EntryClass::SelectedEvent
    );
    for (bad_name, bad_kind, field) in [
        (
            Counted {
                length: 111,
                ..name
            },
            kind,
            "name",
        ),
        (
            name,
            Counted {
                maximum_length: 16,
                ..kind
            },
            "kind",
        ),
        (
            Counted {
                address: base,
                ..name
            },
            kind,
            "name",
        ),
        (
            name,
            Counted {
                address: kind.address + 1,
                ..kind
            },
            "kind",
        ),
    ] {
        let error =
            directory::entry_detailed(&bytes, base, bad_name, bad_kind, header).unwrap_err();
        assert_eq!(error.field, field);
    }
}

#[test]
fn path_policy_applies_only_to_exact_directory_or_matching_event_after_both_spans() {
    for text in ["/", "\\", ".", "..", "\0"] {
        let leaf = wide(text);
        for kind_text in ["Directory", "Event"] {
            let kind_units = wide(kind_text);
            let (bytes, base, name, kind, header) = counted_entry(&leaf, &kind_units);
            let entry = directory::entry(&bytes, base, name, kind, header).unwrap();
            assert!(
                entry.classify(&leaf).is_err(),
                "accepted path-bearing {kind_text}/{text:?}"
            );
            if kind_text == "Event" {
                assert_eq!(
                    entry.classify(&wide("owned-event")).unwrap(),
                    directory::EntryClass::Ignored
                );
            }
        }
        for unrelated in ["Mutant", "event", "DirectoryOther", "\0", "/"] {
            let (bytes, base, name, kind, header) = counted_entry(&leaf, &wide(unrelated));
            assert_eq!(
                directory::entry(&bytes, base, name, kind, header)
                    .unwrap()
                    .classify(&leaf)
                    .unwrap(),
                directory::EntryClass::Ignored
            );
        }
    }
    for (kind_text, expected) in [
        ("Directory", directory::EntryClass::Directory),
        ("Event", directory::EntryClass::SelectedEvent),
        ("event", directory::EntryClass::Ignored),
        ("Mutant", directory::EntryClass::Ignored),
    ] {
        let (bytes, base, name, kind, header) =
            counted_entry(&wide("owned-event"), &wide(kind_text));
        assert_eq!(
            directory::entry(&bytes, base, name, kind, header)
                .unwrap()
                .classify(&wide("owned-event"))
                .unwrap(),
            expected
        );
    }
    // A path-policy error in name must not hide the malformed kind span.
    let (bytes, base, name, kind, header) = counted_entry(&wide("/"), &wide("Directory"));
    assert_eq!(
        directory::entry_detailed(&bytes, base, name, Counted { length: 1, ..kind }, header)
            .unwrap_err()
            .field,
        "kind"
    );
}
