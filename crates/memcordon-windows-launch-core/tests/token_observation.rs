use memcordon_core::WindowsCallerTokenEnvelopeV1;
use memcordon_windows_launch_core::*;
use sha2::{Digest, Sha256};

fn envelope(
    normal: &[SidAttributesV1],
    restricted: &[SidAttributesV1],
    privileges: &[PrivilegeAttributesV1],
) -> WindowsCallerTokenEnvelopeV1 {
    WindowsCallerTokenEnvelopeV1 {
        user_sid: "S-1-5-18".into(),
        owner_sid: "S-1-5-32-544".into(),
        primary_group_sid: "S-1-5-18".into(),
        groups_sha256: sid_attributes_digest(normal).unwrap(),
        restricted_sids_sha256: sid_attributes_digest(restricted).unwrap(),
        privileges_sha256: privilege_attributes_digest(privileges).unwrap(),
        integrity_level: "S-1-16-12288".into(),
        mandatory_policy: u32::MAX,
        session_id: u32::MAX,
        elevation_type: 2,
        elevated: true,
        virtualization_allowed: false,
        virtualization_enabled: false,
        ui_access: false,
        appcontainer: false,
        authentication_id: u64::MAX,
        token_type: 1,
        impersonation_level: 0,
    }
}
fn build(
    normal: Vec<SidAttributesV1>,
    restricted: Vec<SidAttributesV1>,
    privileges: Vec<PrivilegeAttributesV1>,
) -> Result<TokenObservationV1, ObservationUnavailable> {
    let stats = TokenStatisticsObservationV1 {
        token_id: u64::MAX,
        modified_id: u64::MAX - 1,
        expiration_time: i64::MIN,
        dynamic_charged: u32::MAX,
        dynamic_available: u32::MAX,
        group_count: normal.len() as u32,
        privilege_count: privileges.len() as u32,
    };
    TokenObservationV1::from_parts(
        envelope(&normal, &restricted, &privileges),
        u32::MAX,
        stats,
        normal,
        restricted,
        privileges,
    )
}
fn pair(sid: &str, attributes: u32) -> SidAttributesV1 {
    SidAttributesV1 {
        sid: sid.into(),
        attributes,
    }
}

#[test]
fn canonical_digests_match_original_length_prefixed_le_records_and_preserve_duplicates() {
    let first = pair("S-1-5-18", 4);
    assert_eq!(
        sid_attributes_digest(std::slice::from_ref(&first)).unwrap(),
        hex::encode(Sha256::digest(b"\x0c\0\0\0S-1-5-18\x04\0\0\0"))
    );
    let privilege = PrivilegeAttributesV1 {
        luid_high: -1,
        luid_low: 7,
        attributes: 2,
    };
    assert_eq!(
        privilege_attributes_digest(std::slice::from_ref(&privilege)).unwrap(),
        hex::encode(Sha256::digest([
            12, 0, 0, 0, 255, 255, 255, 255, 7, 0, 0, 0, 2, 0, 0, 0
        ]))
    );
    let records = vec![
        pair("S-1-5-32-544", 16),
        first.clone(),
        first.clone(),
        pair("S-1-5-18", 0),
    ];
    let mut reversed = records.clone();
    reversed.reverse();
    assert_eq!(
        sid_attributes_digest(&records),
        sid_attributes_digest(&reversed)
    );
    let mut dropped = records.clone();
    dropped.remove(1);
    assert_ne!(
        sid_attributes_digest(&records),
        sid_attributes_digest(&dropped)
    );
    for flags in [0, 16, u32::MAX] {
        assert_ne!(
            sid_attributes_digest(std::slice::from_ref(&first)),
            sid_attributes_digest(&[pair("S-1-5-18", flags)])
        );
    }
    assert!(
        sid_attributes_digest(&vec![first; TOKEN_OBSERVATION_ENTRY_BOUND + 1]).is_ok(),
        "production digest has no diagnostic count cap"
    );
}

#[test]
fn complete_owned_observation_roundtrips_full_width_context_and_refuses_correspondence_changes() {
    let normal = vec![
        pair("S-1-5-32-544", 16),
        pair("S-1-5-18", 0),
        pair("S-1-5-18", 0),
    ];
    let restricted = vec![pair("S-1-5-12", 4)];
    let value = build(
        normal.clone(),
        restricted,
        vec![PrivilegeAttributesV1 {
            luid_high: i32::MIN,
            luid_low: u32::MAX,
            attributes: u32::MAX,
        }],
    )
    .unwrap();
    assert_eq!(value.normal_groups.len(), normal.len());
    assert_eq!(value.user_attributes, u32::MAX);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(bytes.len() <= TOKEN_OBSERVATION_BYTE_BOUND);
    let decoded: TokenObservationV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, value);
    decoded.validate().unwrap();
    let mut changed = value.clone();
    changed.normal_groups[0].attributes ^= 4;
    assert!(changed.validate().is_err());
    let mut changed = value.clone();
    changed.normal_groups.remove(0);
    assert!(changed.validate().is_err());
    let mut changed = value.clone();
    std::mem::swap(&mut changed.normal_groups, &mut changed.restricted_sids);
    assert!(changed.validate().is_err());
    let mut changed = value.clone();
    changed.normal_groups.reverse();
    assert_eq!(
        changed.validate(),
        Err(ObservationUnavailable::NonCanonical)
    );
    let mut changed = value.clone();
    changed.statistics.privilege_count = 0;
    assert_eq!(
        changed.validate(),
        Err(ObservationUnavailable::CountMismatch)
    );
    let mut changed = value.clone();
    changed.privileges[0].attributes ^= 1;
    assert_eq!(
        changed.validate(),
        Err(ObservationUnavailable::DigestMismatch)
    );
    let mut json = serde_json::to_value(&value).unwrap();
    json["extra"] = true.into();
    assert!(serde_json::from_value::<TokenObservationV1>(json).is_err());
}

#[test]
fn diagnostic_bounds_are_independent_all_or_unavailable_not_truncated() {
    assert_eq!(
        build(
            vec![pair("S-1-5-18", 4); TOKEN_OBSERVATION_ENTRY_BOUND + 1],
            vec![],
            vec![]
        ),
        Err(ObservationUnavailable::CountBound)
    );
    assert_eq!(
        build(
            vec![pair("S-1-5-21-1234567890-1234567890-1234567890-1001", 4); 200],
            vec![],
            vec![]
        ),
        Err(ObservationUnavailable::SizeBound)
    );
    for bad in [
        "",
        "S-2-5-18",
        "S-1-05-18",
        "S-1-5-018",
        "S-1-5-4294967296",
        "S-1-281474976710656-1",
        "S-1-5-18\0",
    ] {
        assert_eq!(
            build(vec![pair(bad, 4)], vec![], vec![]),
            Err(ObservationUnavailable::InvalidSid)
        );
    }
    let mut value = build(vec![], vec![], vec![]).unwrap();
    value.envelope.groups_sha256 = "wrong".into();
    assert_eq!(
        value.validate(),
        Err(ObservationUnavailable::DigestMismatch)
    );
}
