#[path = "../src/bin/consumer_readiness_windows/controller_gate_access_input.rs"]
mod input;
use input::Input;
fn fixture() -> (Input, Vec<u16>, Vec<u8>) {
    let owner = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let rc = [1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0];
    let mut ace = vec![0, 0, 0, 0];
    ace.extend(0x0010_0000_u32.to_le_bytes());
    ace.extend(rc);
    let size = ace.len() as u16;
    ace[2..4].copy_from_slice(&size.to_le_bytes());
    let mut acl = vec![2, 0, 0, 0, 1, 0, 0, 0];
    acl.extend(ace);
    let size = acl.len() as u16;
    acl[2..4].copy_from_slice(&size.to_le_bytes());
    let mut descriptor = vec![0; 20];
    descriptor[0] = 1;
    descriptor[2..4].copy_from_slice(&0x9004_u16.to_le_bytes());
    for field in [4, 8] {
        let offset = descriptor.len() as u32;
        descriptor[field..field + size_of::<u32>()].copy_from_slice(&offset.to_le_bytes());
        descriptor.extend(owner);
    }
    let offset = descriptor.len() as u32;
    descriptor[16..20].copy_from_slice(&offset.to_le_bytes());
    descriptor.extend(acl);
    let name = "Local\\owned-fixture-gate"
        .encode_utf16()
        .collect::<Vec<_>>();
    let challenge = b"original-challenge".to_vec();
    (
        Input {
            revision: 1,
            descriptor_sha256: input::sha256(&descriptor),
            descriptor,
            name_utf16_sha256: input::name_sha256(&name),
            challenge_sha256: input::sha256(&challenge),
            work_cutoff_qpc: 100,
            qpc_frequency: 10,
            namespace: None,
        },
        name,
        challenge,
    )
}
#[test]
fn exact_bounded_snapshot_requires_original_name_challenge_and_bytes() {
    let (value, name, challenge) = fixture();
    value.validate(&name, &challenge).unwrap();
    assert!(value.validate(&[b'x' as u16], &challenge).is_err());
    assert!(value.validate(&name, b"another").is_err());
    let mut altered = value.clone();
    altered.descriptor[0] = 0;
    assert!(altered.validate(&name, &challenge).is_err());
    let mut altered = value.clone();
    altered.qpc_frequency = 0;
    assert!(altered.validate(&name, &challenge).is_err());
    let mut json = serde_json::to_value(&value).unwrap();
    json["unrecognized"] = true.into();
    assert!(serde_json::from_value::<Input>(json).is_err());
}
#[test]
fn coherent_hash_never_hides_malformed_descriptor_extents() {
    let (value, name, challenge) = fixture();
    for change in 0..7 {
        let mut bad = value.clone();
        match change {
            0 => bad.descriptor.truncate(19),
            1 => bad.descriptor[4..8].copy_from_slice(&u32::MAX.to_le_bytes()),
            2 => bad.descriptor[16..20].copy_from_slice(&1_u32.to_le_bytes()),
            3 => bad.descriptor[20 + 1] = u8::MAX,
            4 => {
                let at = u32::from_le_bytes(bad.descriptor[16..20].try_into().unwrap()) as usize;
                bad.descriptor[at + 4..at + 6].copy_from_slice(&u16::MAX.to_le_bytes());
            }
            5 => bad.descriptor.resize(input::DESCRIPTOR_BOUND + 1, 0),
            _ => bad.descriptor[12..16].copy_from_slice(&20_u32.to_le_bytes()),
        }
        bad.descriptor_sha256 = input::sha256(&bad.descriptor);
        assert!(
            bad.validate(&name, &challenge).is_err(),
            "accepted malformed case{change}"
        );
    }
}
