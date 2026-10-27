#[path = "../src/bin/consumer_readiness_windows/fixture_default_dacl.rs"]
mod fixture;

use std::io::ErrorKind;

const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_READ_EXECUTE: u32 = 0xa000_0000;
const ACL_HEADER_BYTES: usize = 8;

fn sid(authority: [u8; 6], sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, u8::try_from(sub_authorities.len()).unwrap()];
    bytes.extend_from_slice(&authority);
    for value in sub_authorities {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn ace(kind: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = u16::try_from(std::mem::size_of::<u32>() * 2 + sid.len()).unwrap();
    let mut bytes = vec![kind, flags];
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = u16::try_from(ACL_HEADER_BYTES + aces.iter().map(Vec::len).sum::<usize>()).unwrap();
    let count = u16::try_from(aces.len()).unwrap();
    let mut bytes = vec![2, 0];
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes
}

fn ordinary_sample() -> Vec<u8> {
    let nt_authority = [0, 0, 0, 0, 0, 5];
    let builtin_administrators = sid(nt_authority, &[32, 544]);
    let local_system = sid(nt_authority, &[18]);
    let original_logon = sid(nt_authority, &[5, 0, 764577]);
    acl(&[
        ace(0, 0, GENERIC_ALL, &builtin_administrators),
        ace(0, 0, GENERIC_ALL, &local_system),
        ace(0, 0, GENERIC_READ_EXECUTE, &original_logon),
    ])
}

fn refused(raw: &[u8]) {
    assert_eq!(
        fixture::plan(Some(raw)).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}

#[test]
fn original_three_aces_are_preserved_with_only_explicit_rc_generic_all_appended() {
    let original = ordinary_sample();
    let immutable = original.clone();
    let planned = fixture::plan(Some(&original)).unwrap();
    let restricted_code = sid([0, 0, 0, 0, 0, 5], &[12]);
    assert_eq!(restricted_code, fixture::RESTRICTED_CODE_SID);
    let expected_delta = ace(0, 0, GENERIC_ALL, &restricted_code);
    assert_eq!(original.len(), 80);
    assert_eq!(planned.len(), 100);
    assert_eq!(
        &planned[ACL_HEADER_BYTES..original.len()],
        &original[ACL_HEADER_BYTES..]
    );
    assert_eq!(&planned[original.len()..], expected_delta);
    assert_eq!(&planned[..2], &original[..2]);
    assert_eq!(
        &planned[6..ACL_HEADER_BYTES],
        &original[6..ACL_HEADER_BYTES]
    );
    assert_eq!(
        usize::from(u16::from_le_bytes([planned[2], planned[3]])),
        original.len() + expected_delta.len()
    );
    assert_eq!(
        u16::from_le_bytes([planned[4], planned[5]]),
        u16::from_le_bytes([original[4], original[5]]) + 1
    );
    assert_eq!(original, immutable);
    assert_eq!(fixture::plan(Some(&planned)).unwrap(), planned);
}

#[test]
fn supported_ordinary_deny_and_inheritance_bytes_keep_their_original_order() {
    let ordinary = sid([0, 0, 0, 0, 0, 5], &[18]);
    let deny = ace(1, 0, 2, &ordinary);
    let inherited_allow = ace(0, 0x13, GENERIC_READ_EXECUTE, &ordinary);
    let source = acl(&[deny.clone(), inherited_allow.clone()]);
    let planned = fixture::plan(Some(&source)).unwrap();
    assert_eq!(
        &planned[ACL_HEADER_BYTES..ACL_HEADER_BYTES + deny.len()],
        deny
    );
    assert_eq!(
        &planned[ACL_HEADER_BYTES + deny.len()..source.len()],
        inherited_allow
    );
    assert_eq!(fixture::plan(Some(&planned)).unwrap(), planned);
}

#[test]
fn conflicting_rc_masks_denials_inheritance_and_duplicates_refuse_without_editing_source() {
    for (kind, flags, mask) in [
        (1, 0, GENERIC_ALL),
        (0, 0x10, GENERIC_ALL),
        (0, 1, GENERIC_ALL),
        (0, 8, GENERIC_ALL),
        (0, 0, 0),
        (0, 0, GENERIC_READ_EXECUTE),
        (0, 0, GENERIC_ALL | 1),
    ] {
        let source = acl(&[ace(kind, flags, mask, fixture::RESTRICTED_CODE_SID)]);
        let original = source.clone();
        refused(&source);
        assert_eq!(source, original);
    }
    let exact = ace(0, 0, GENERIC_ALL, fixture::RESTRICTED_CODE_SID);
    refused(&acl(&[exact.clone(), exact]));
}

#[test]
fn null_headers_unknown_ace_forms_and_inconsistent_sizes_refuse() {
    assert_eq!(
        fixture::plan(None).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    let source = ordinary_sample();
    for prefix in 0..source.len() {
        refused(&source[..prefix]);
    }
    for (offset, value) in [
        (0, 4),
        (1, 1),
        (6, 1),
        (7, 1),
        (2, 0),
        (4, 0),
        (ACL_HEADER_BYTES, 2),
        (ACL_HEADER_BYTES, 5),
        (ACL_HEADER_BYTES + 1, 0x20),
        (ACL_HEADER_BYTES + 2, 0),
        (ACL_HEADER_BYTES + 2, 23),
    ] {
        let mut changed = source.clone();
        changed[offset] = value;
        refused(&changed);
    }
    let mut padded = source.clone();
    padded.extend_from_slice(&[0; std::mem::size_of::<u32>()]);
    let padded_size = u16::try_from(padded.len()).unwrap();
    padded[2..4].copy_from_slice(&padded_size.to_le_bytes());
    refused(&padded);
    refused(&vec![0; fixture::MAX_ACL_BYTES + 1]);
}

#[test]
fn malformed_sid_revision_count_and_trailing_sid_data_are_not_supported() {
    let valid_sid = sid([0, 0, 0, 0, 0, 5], &[18]);
    for (index, value) in [(0, 2), (1, 0), (1, 16)] {
        let mut malformed = valid_sid.clone();
        malformed[index] = value;
        refused(&acl(&[ace(0, 0, GENERIC_ALL, &malformed)]));
    }
    let mut extra = valid_sid.clone();
    extra.extend_from_slice(&[0; std::mem::size_of::<u32>()]);
    refused(&acl(&[ace(0, 0, GENERIC_ALL, &extra)]));
}

#[test]
fn original_ace_bound_is_enforced_before_append_and_idempotent_at_the_bound() {
    let ordinary = sid([0, 0, 0, 0, 0, 5], &[18]);
    let existing = ace(0, 0, GENERIC_ALL, &ordinary);
    refused(&acl(&vec![existing.clone(); fixture::MAX_ACES]));
    refused(&acl(&vec![existing.clone(); fixture::MAX_ACES + 1]));
    let mut full = vec![existing; fixture::MAX_ACES - 1];
    full.push(ace(0, 0, GENERIC_ALL, fixture::RESTRICTED_CODE_SID));
    let full = acl(&full);
    assert_eq!(fixture::plan(Some(&full)).unwrap(), full);
}
