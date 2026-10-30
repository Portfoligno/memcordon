#[path = "private/fixture_namespace_directory_policy.rs"]
pub mod policy;
use policy::*;

#[test]
fn policy_binding_requires_observed_identity_and_all_bracketed_inputs() {
    let stable = BindingFacts {
        root_same: Some(true),
        child_same: Some(true),
        sd_equal: Some(true),
        label_equal: Some(true),
        token_equal: Some(true),
        requested_token_matches: true,
    };
    assert!(stable_binding(&stable));
    for index in 0..5 {
        for changed in [Some(false), None] {
            let mut candidate = stable;
            *match index {
                0 => &mut candidate.root_same,
                1 => &mut candidate.child_same,
                2 => &mut candidate.sd_equal,
                3 => &mut candidate.label_equal,
                _ => &mut candidate.token_equal,
            } = changed;
            assert!(
                !stable_binding(&candidate),
                "identity, changed policy or unavailable input cannot qualify the explanation"
            );
        }
    }
    assert!(!stable_binding(&BindingFacts {
        requested_token_matches: false,
        ..stable
    }));
    assert!(!stable_binding(&BindingFacts::default()));
}

fn identity(rid: u32) -> Vec<u8> {
    let mut sid = vec![1, 1, 0, 0, 0, 0, 0, 5];
    sid.extend(rid.to_le_bytes());
    sid
}
fn ace(kind: u8, flags: u8, mask: u32, rid: u32) -> Vec<u8> {
    let sid = identity(rid);
    let mut bytes = vec![kind, flags];
    bytes.extend(u16::try_from(8 + sid.len()).unwrap().to_le_bytes());
    bytes.extend(mask.to_le_bytes());
    bytes.extend(sid);
    bytes
}
fn acl_bytes(aces: &[Vec<u8>]) -> Vec<u8> {
    let length = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = vec![2, 0];
    bytes.extend(u16::try_from(length).unwrap().to_le_bytes());
    bytes.extend(u16::try_from(aces.len()).unwrap().to_le_bytes());
    bytes.extend([0, 0]);
    for ace in aces {
        bytes.extend(ace);
    }
    bytes
}
fn descriptor(aces: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend(identity(21));
    bytes[8..12].copy_from_slice(&32u32.to_le_bytes());
    bytes.extend(identity(32));
    bytes[16..20].copy_from_slice(&44u32.to_le_bytes());
    bytes.extend(acl_bytes(aces));
    bytes
}
fn subject() -> Subject {
    Subject {
        user: SidEntry {
            sid: "S-1-5-21".into(),
            attributes: 0,
        },
        groups: vec![SidEntry {
            sid: "S-1-5-32".into(),
            attributes: 4,
        }],
        restricted: vec![SidEntry {
            sid: "S-1-5-12".into(),
            attributes: 0,
        }],
    }
}
#[test]
fn ordered_normal_and_restricted_passes_explain_each_requested_bit_separately() {
    let bytes = descriptor(&[ace(0, 0, 15, 21), ace(0, 0, 2, 12)]);
    let sd = decode_descriptor(&bytes).unwrap();
    let result = explain(&sd, &subject(), 15);
    assert_eq!(sd.owner.as_deref(), Some("S-1-5-21"));
    assert!(
        result
            .normal
            .iter()
            .all(|value| matches!(value.decision, Decision::Allowed { ace: Some(0) }))
    );
    assert_eq!(
        result.restricted[1].decision,
        Decision::Allowed { ace: Some(1) }
    );
    for index in [0, 2, 3] {
        assert_eq!(
            result.restricted[index].decision,
            Decision::Denied { ace: None }
        );
    }
    assert!(result.diagnostic_only && !result.acceptance_authority);
    let allow_first =
        decode_descriptor(&descriptor(&[ace(0, 0, 1, 21), ace(1, 0, 1, 21)])).unwrap();
    assert_eq!(
        explain(&allow_first, &subject(), 1).normal[0].decision,
        Decision::Allowed { ace: Some(0) }
    );
    let deny_first = decode_descriptor(&descriptor(&[ace(1, 0, 1, 21), ace(0, 0, 1, 21)])).unwrap();
    assert_eq!(
        explain(&deny_first, &subject(), 1).normal[0].decision,
        Decision::Denied { ace: Some(0) }
    );
}
#[test]
fn deny_only_disabled_inherit_only_and_unsupported_aces_never_fabricate_grants() {
    let sd = decode_descriptor(&descriptor(&[ace(0, 0, 15, 32)])).unwrap();
    let mut token = subject();
    token.groups[0].attributes = 0x10;
    assert_eq!(
        explain(&sd, &token, 1).normal[0].decision,
        Decision::Denied { ace: None }
    );
    token.groups[0].attributes = 0;
    assert_eq!(
        explain(&sd, &token, 1).normal[0].decision,
        Decision::Denied { ace: None }
    );
    let sd = decode_descriptor(&descriptor(&[ace(1, 0, 1, 32), ace(0, 0, 1, 21)])).unwrap();
    token.groups[0].attributes = 0x10;
    assert_eq!(
        explain(&sd, &token, 1).normal[0].decision,
        Decision::Denied { ace: Some(0) }
    );
    let sd = decode_descriptor(&descriptor(&[ace(1, 8, 15, 21), ace(0, 0, 15, 21)])).unwrap();
    assert!(matches!(
        explain(&sd, &token, 1).normal[0].decision,
        Decision::Allowed { ace: Some(1) }
    ));
    let mut owner_rights = ace(0, 0, 15, 4);
    owner_rights[15] = 3;
    for unsupported in [
        ace(9, 0, 15, 21),
        ace(0, 0, 0x80000000, 21),
        ace(0, 0x80, 15, 21),
        owner_rights,
        ace(0, 0, 15, 10),
    ] {
        let sd = decode_descriptor(&descriptor(&[ace(0, 0, 15, 21), unsupported])).unwrap();
        assert!(matches!(
            explain(&sd, &token, 1).normal[0].decision,
            Decision::Unresolved { .. }
        ));
    }
}
#[test]
fn null_empty_and_absent_dacl_remain_distinct_and_restriction_absence_is_explicit() {
    let mut bytes = descriptor(&[]);
    let empty = decode_descriptor(&bytes).unwrap();
    assert_eq!(
        explain(&empty, &subject(), 1).normal[0].decision,
        Decision::Denied { ace: None }
    );
    bytes[16..20].fill(0);
    let null = decode_descriptor(&bytes).unwrap();
    assert_eq!(null.dacl, Acl::Null);
    assert_eq!(
        explain(&null, &subject(), 1).restricted[0].decision,
        Decision::Allowed { ace: None }
    );
    bytes[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
    let absent = decode_descriptor(&bytes).unwrap();
    assert_eq!(absent.dacl, Acl::Absent);
    let mut token = subject();
    token.restricted.clear();
    assert_eq!(
        explain(&absent, &token, 1).restricted[0].decision,
        Decision::NotApplicable
    );
    assert!(matches!(
        explain(&absent, &token, 0x100000).normal[0].decision,
        Decision::Unresolved { .. }
    ));
}
#[test]
fn malformed_self_relative_sid_acl_and_ace_extents_are_rejected() {
    let bytes = descriptor(&[ace(0, 0, 15, 21)]);
    for index in 0..6 {
        let mut malformed = bytes.clone();
        match index {
            0 => malformed[2..4].fill(0),
            1 => malformed[4..8].copy_from_slice(&u32::MAX.to_le_bytes()),
            2 => malformed[21] = 16,
            3 => malformed[46..48].copy_from_slice(&4u16.to_le_bytes()),
            4 => malformed[54..56].copy_from_slice(&u16::MAX.to_le_bytes()),
            _ => malformed.truncate(malformed.len() - 1),
        }
        assert!(decode_descriptor(&malformed).is_err());
    }
    assert_eq!(
        decode_descriptor(&vec![0; MAX_SD_BYTES + 1]),
        Err(PolicyError::Bound)
    );
    let sd = decode_descriptor(&bytes).unwrap();
    let Acl::Present { aces, .. } = sd.dacl else {
        panic!("fixture ACL");
    };
    assert_eq!(aces[0].raw_hex, "000014000f000000010100000000000515000000");
}
#[test]
fn mandatory_label_absence_unavailability_and_mic_inputs_are_never_conflated() {
    let sd = decode_descriptor(&descriptor(&[])).unwrap();
    assert_eq!(mandatory_label(Some(&sd)), Label::DefaultMedium);
    assert_eq!(mandatory_label(None), Label::Unavailable);
    let facts = mic_facts(&mandatory_label(None), "S-1-16-4096", 1);
    assert_eq!(facts.token_lower_than_object, None);
    let facts = mic_facts(&Label::DefaultMedium, "S-1-16-4096", 1);
    assert_eq!(facts.token_lower_than_object, Some(true));
    assert_eq!(facts.object_label_mask, Some(1));
    let mut bytes = descriptor(&[]);
    let offset = bytes.len();
    let mut label = ace(17, 0, 1, 0x3000);
    label[15] = 16;
    bytes[2..4].copy_from_slice(&0x8014u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
    bytes.extend(acl_bytes(&[label]));
    let sd = decode_descriptor(&bytes).unwrap();
    assert!(matches!(
        mandatory_label(Some(&sd)),
        Label::Observed {
            integrity_rid: 0x3000,
            mask: 1,
            ..
        }
    ));
    let facts = mic_facts(&mandatory_label(Some(&sd)), "S-1-16-8192", 1);
    assert_eq!(facts.token_lower_than_object, Some(true));
    assert_eq!(facts.token_mandatory_policy, 1);
}
