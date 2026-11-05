use memcordon_ci::windows_pe_manifest::{RECORD_BYTES, inventory};
use sha2::{Digest, Sha256};

#[derive(Clone)]
enum Name {
    Id(u16),
    Text(Vec<u16>),
}
fn word(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn dword(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn allocate(resource: &mut Vec<u8>, size: usize) -> usize {
    let at = (resource.len() + 3) & !3;
    resource.resize(at + size, 0);
    at
}
fn fixture(pe64: bool, names: &[(Name, usize)], payload: &[u8]) -> Vec<u8> {
    let mut resource = vec![0; 24];
    word(&mut resource, 14, 1);
    dword(&mut resource, 16, 24);
    let named = names
        .iter()
        .filter(|(name, _)| matches!(name, Name::Text(_)))
        .count();
    let type_dir = allocate(&mut resource, 16 + names.len() * 8);
    dword(&mut resource, 20, 0x80000000 | type_dir as u32);
    word(&mut resource, type_dir + 12, named as u16);
    word(&mut resource, type_dir + 14, (names.len() - named) as u16);
    let mut data_entries = Vec::new();
    for (index, (name, languages)) in names.iter().enumerate() {
        let encoded = match name {
            Name::Id(id) => u32::from(*id),
            Name::Text(units) => {
                let at = allocate(&mut resource, 2 + units.len() * 2);
                word(&mut resource, at, units.len() as u16);
                for (i, unit) in units.iter().enumerate() {
                    word(&mut resource, at + 2 + i * 2, *unit);
                }
                0x80000000 | at as u32
            }
        };
        let language_dir = allocate(&mut resource, 16 + languages * 8);
        dword(&mut resource, type_dir + 16 + index * 8, encoded);
        dword(
            &mut resource,
            type_dir + 20 + index * 8,
            0x80000000 | language_dir as u32,
        );
        word(&mut resource, language_dir + 14, *languages as u16);
        for language in 0..*languages {
            let data = allocate(&mut resource, 16);
            dword(
                &mut resource,
                language_dir + 16 + language * 8,
                language as u32,
            );
            dword(&mut resource, language_dir + 20 + language * 8, data as u32);
            data_entries.push(data);
        }
    }
    let payload_offset = (resource.len() + 511) & !511;
    resource.resize(payload_offset + payload.len(), 0);
    resource[payload_offset..].copy_from_slice(payload);
    for data in data_entries {
        dword(&mut resource, data, 0x1000 + payload_offset as u32);
        dword(&mut resource, data + 4, payload.len() as u32);
        dword(&mut resource, data + 8, 65001);
    }
    let raw_size = (resource.len() + 511) & !511;
    resource.resize(raw_size, 0);
    let mut bytes = vec![0; 512 + raw_size];
    bytes[..2].copy_from_slice(b"MZ");
    dword(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    word(&mut bytes, 0x84, if pe64 { 0x8664 } else { 0x14c });
    word(&mut bytes, 0x86, 1);
    word(&mut bytes, 0x94, if pe64 { 240 } else { 224 });
    word(&mut bytes, 0x96, 0x2022);
    let optional = 0x98;
    word(&mut bytes, optional, if pe64 { 0x20b } else { 0x10b });
    dword(&mut bytes, optional + 32, 4096);
    dword(&mut bytes, optional + 36, 512);
    word(&mut bytes, optional + 40, 6);
    dword(
        &mut bytes,
        optional + 56,
        ((0x1000 + raw_size + 4095) & !4095) as u32,
    );
    dword(&mut bytes, optional + 60, 512);
    word(&mut bytes, optional + 68, 3);
    let dirs = optional + if pe64 { 112 } else { 96 };
    dword(&mut bytes, dirs - 4, 16);
    dword(&mut bytes, dirs + 16, 0x1000);
    dword(&mut bytes, dirs + 20, raw_size as u32);
    let section = optional + if pe64 { 240 } else { 224 };
    bytes[section..section + 5].copy_from_slice(b".rsrc");
    dword(&mut bytes, section + 8, raw_size as u32);
    dword(&mut bytes, section + 12, 0x1000);
    dword(&mut bytes, section + 16, raw_size as u32);
    dword(&mut bytes, section + 20, 512);
    dword(&mut bytes, section + 36, 0x40000040);
    bytes[512..].copy_from_slice(&resource);
    bytes
}
fn absent(pe64: bool) -> Vec<u8> {
    let mut bytes = fixture(pe64, &[], b"");
    let dirs = 0x98 + if pe64 { 112 } else { 96 };
    dword(&mut bytes, dirs + 16, 0);
    dword(&mut bytes, dirs + 20, 0);
    bytes
}
#[test]
fn pe32_and_both_native_machine_images_distinguish_checked_absence_and_presence() {
    for pe64 in [false, true] {
        let image = absent(pe64);
        let result = inventory(&image);
        assert_eq!(result["status"], "complete_no_manifest");
        assert_eq!(result["parser_complete"], true);
        assert_eq!(
            result["image_sha256"],
            serde_json::json!(<[u8; 32]>::from(Sha256::digest(&image)))
        );
    }
    let mut arm = absent(true);
    word(&mut arm, 0x84, 0xaa64);
    assert_eq!(inventory(&arm)["status"], "complete_no_manifest");
    let payload = b"owned manifest bytes are never exported";
    let image = fixture(
        true,
        &[
            (Name::Text("custom".encode_utf16().collect()), 2),
            (Name::Id(1), 1),
        ],
        payload,
    );
    let result = inventory(&image);
    assert_eq!(result["status"], "manifest_present");
    assert_eq!(result["manifests"].as_array().unwrap().len(), 3);
    assert_eq!(result["manifests"][2]["application_id_1"], true);
    assert_eq!(
        result["manifests"][0]["sha256"],
        serde_json::json!(<[u8; 32]>::from(Sha256::digest(payload)))
    );
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains(std::str::from_utf8(payload).unwrap())
    );
    assert_eq!(result["acceptance_authority"], false);
    assert_eq!(result["loader_eligibility_proved"], false);
}
#[test]
fn malformed_mapping_trees_and_partial_inputs_never_establish_absence() {
    let image = fixture(true, &[(Name::Id(1), 1)], b"bytes");
    for length in [0, 63, 127, 150, image.len() - 1] {
        assert_eq!(inventory(&image[..length])["status"], "incomplete");
    }
    let mut cycle = image.clone();
    dword(&mut cycle, 512 + 20, 0x80000000);
    assert_eq!(
        inventory(&cycle)["failure"],
        "resource-cycle-or-directory-alias"
    );
    let mut depth = image.clone();
    dword(&mut depth, 512 + 20, 24);
    assert_eq!(inventory(&depth)["failure"], "resource-depth");
    let mut duplicate = fixture(true, &[(Name::Id(1), 1), (Name::Id(1), 1)], b"x");
    assert_eq!(inventory(&duplicate)["failure"], "duplicate-resource-entry");
    dword(&mut duplicate, 0x98 + 112 + 20, u32::MAX);
    assert_eq!(inventory(&duplicate)["status"], "incomplete");
    let malformed = fixture(true, &[(Name::Text(vec![0xd800]), 1)], b"x");
    assert_eq!(inventory(&malformed)["failure"], "resource-name");
    let empty = fixture(true, &[(Name::Id(1), 0), (Name::Id(2), 1)], b"x");
    assert_eq!(inventory(&empty)["failure"], "empty-manifest-tree");
    let mut overlap = absent(true);
    word(&mut overlap, 0x86, 2);
    let section = 0x98 + 240;
    let copy = overlap[section..section + 40].to_vec();
    overlap[section + 40..section + 80].copy_from_slice(&copy);
    assert_eq!(inventory(&overlap)["failure"], "ambiguous-rva");
}
#[test]
fn finite_entry_leaf_payload_and_serialized_bounds_are_inconclusive() {
    let entries = fixture(true, &[(Name::Id(1), 1024)], b"x");
    assert_eq!(inventory(&entries)["failure"], "resource-entry-bound");
    let leaves = fixture(true, &[(Name::Id(1), 65)], b"x");
    assert_eq!(inventory(&leaves)["failure"], "manifest-leaf-bound");
    let payload = fixture(true, &[(Name::Id(1), 64)], &vec![b'x'; 20000]);
    assert_eq!(inventory(&payload)["failure"], "manifest-payload-bound");
    let output = fixture(true, &[(Name::Text(vec![0x4e00; 128]), 64)], b"x");
    let result = inventory(&output);
    assert_eq!(result["status"], "incomplete");
    assert_eq!(result["failure"], "inventory-output-bound");
    assert!(serde_json::to_vec(&result).unwrap().len() <= RECORD_BYTES);
    assert!(result["manifests_omitted_for_bound"].as_u64().unwrap() > 0);
}
