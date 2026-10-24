use memcordon_windows_loader_lab::selected_policy as snapshot;

// Encoded Windows self-relative descriptor fixtures. They exercise the same
// selected-policy parser as live readback, without claiming native execution.
#[derive(Clone)]
struct Fixture {
    owner: Vec<u8>,
    group: Vec<u8>,
    dacl: Option<Vec<u8>>,
    label: Option<Vec<u8>>,
    control: u16,
    resource_manager: u8,
}

fn sid(authority: u8, subauthorities: &[u32]) -> Vec<u8> {
    let mut bytes = vec![
        1,
        u8::try_from(subauthorities.len()).unwrap(),
        0,
        0,
        0,
        0,
        0,
        authority,
    ];
    for value in subauthorities {
        bytes.extend(value.to_le_bytes());
    }
    bytes
}

fn ace(kind: u8, flags: u8, mask: u32, trustee: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, flags];
    bytes.extend(u16::try_from(8 + trustee.len()).unwrap().to_le_bytes());
    bytes.extend(mask.to_le_bytes());
    bytes.extend(trustee);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
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

impl Fixture {
    fn selected() -> Self {
        Self {
            owner: sid(5, &[18]),
            group: sid(5, &[32, 544]),
            dacl: Some(acl(&[
                ace(0, 0, 0xf016f, &sid(3, &[4])),
                ace(0, 0, 0xf016f, &sid(5, &[18])),
            ])),
            label: Some(acl(&[ace(17, 0, 1, &sid(16, &[8192]))])),
            control: 0xb014,
            resource_manager: 0,
        }
    }

    fn bytes(&self, order: [usize; 4]) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[0] = 1;
        bytes[1] = self.resource_manager;
        bytes[2..4].copy_from_slice(&self.control.to_le_bytes());
        let components = [
            Some(self.owner.as_slice()),
            Some(self.group.as_slice()),
            self.label.as_deref(),
            self.dacl.as_deref(),
        ];
        for index in order {
            if let Some(component) = components[index] {
                while bytes.len() % 4 != 0 {
                    bytes.push(0);
                }
                let offset = u32::try_from(bytes.len()).unwrap();
                let field = 4 + index * size_of::<u32>();
                bytes[field..field + size_of::<u32>()].copy_from_slice(&offset.to_le_bytes());
                bytes.extend(component);
            }
        }
        bytes
    }
}

fn same(expected: &Fixture, actual: &Fixture) -> bool {
    let expected = snapshot::capture(&expected.bytes([0, 1, 2, 3])).unwrap();
    let actual = snapshot::capture(&actual.bytes([0, 1, 2, 3])).unwrap();
    snapshot::compare(&expected, &actual).is_ok()
}

#[test]
fn reordered_component_storage_and_unused_acl_tail_preserve_selected_policy() {
    let fixture = Fixture::selected();
    let expected = snapshot::capture(&fixture.bytes([0, 1, 2, 3])).unwrap();
    let reordered = snapshot::capture(&fixture.bytes([3, 2, 1, 0])).unwrap();
    assert_ne!(expected.raw_sha256, reordered.raw_sha256);
    snapshot::compare(&expected, &reordered).unwrap();
    let mut padded = fixture.clone();
    let dacl = padded.dacl.as_mut().unwrap();
    dacl.extend([0xa5; 4]);
    let length = u16::try_from(dacl.len()).unwrap();
    dacl[2..4].copy_from_slice(&length.to_le_bytes());
    assert!(same(&fixture, &padded));
}

#[test]
fn owner_group_ordered_ace_and_label_changes_are_not_layout_equivalence() {
    let fixture = Fixture::selected();
    let owner_rights = sid(3, &[4]);
    let system = sid(5, &[18]);
    for (kind, flags, mask, trustee) in [
        (1, 0, 0xf016f, owner_rights.clone()),
        (0, 0x10, 0xf016f, owner_rights.clone()),
        (0, 0, 0xf016e, owner_rights.clone()),
        (0, 0, 0xf016f, sid(1, &[0])),
    ] {
        let mut changed = fixture.clone();
        changed.dacl = Some(acl(&[
            ace(kind, flags, mask, &trustee),
            ace(0, 0, 0xf016f, &system),
        ]));
        assert!(
            !same(&fixture, &changed),
            "accepted changed ACE kind/flags/mask/trustee"
        );
    }
    let mut changed = fixture.clone();
    changed.owner = sid(5, &[19]);
    assert!(!same(&fixture, &changed));
    changed = fixture.clone();
    changed.group = sid(5, &[32, 545]);
    assert!(!same(&fixture, &changed));
    changed = fixture.clone();
    changed.dacl = Some(acl(&[
        ace(0, 0, 0xf016f, &system),
        ace(0, 0, 0xf016f, &owner_rights),
    ]));
    assert!(!same(&fixture, &changed), "ACE order must remain exact");
    for (mask, label) in [(2, 8192), (1, 12288)] {
        changed = fixture.clone();
        changed.label = Some(acl(&[ace(17, 0, mask, &sid(16, &[label]))]));
        assert!(
            !same(&fixture, &changed),
            "accepted changed mandatory label/policy"
        );
    }
}

#[test]
fn protection_defaulting_inheritance_revision_and_acl_presence_remain_exact() {
    let fixture = Fixture::selected();
    for flag in [
        0x1, 0x2, 0x8, 0x20, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000,
    ] {
        let mut changed = fixture.clone();
        changed.control ^= flag;
        assert!(
            !same(&fixture, &changed),
            "accepted changed control bit {flag:#x}"
        );
    }
    let mut changed = fixture.clone();
    changed.dacl.as_mut().unwrap()[0] = 4;
    assert!(!same(&fixture, &changed), "ACL revision must remain exact");
    let mut null = fixture.clone();
    null.dacl = None;
    let mut absent = null.clone();
    absent.control &= !(0x4 | 0x1000);
    let mut empty = fixture.clone();
    empty.dacl = Some(acl(&[]));
    for changed in [&null, &absent, &empty] {
        assert!(!same(&fixture, changed));
    }
    assert!(!same(&null, &absent));
    assert!(!same(&null, &empty));
    assert!(!same(&absent, &empty));
    let mut null_label = fixture.clone();
    null_label.label = None;
    let mut absent_label = null_label.clone();
    absent_label.control &= !(0x10 | 0x2000);
    let mut empty_label = fixture.clone();
    empty_label.label = Some(acl(&[]));
    for changed in [&null_label, &absent_label, &empty_label] {
        assert!(!same(&fixture, changed));
    }
    assert!(!same(&null_label, &absent_label));
    assert!(!same(&null_label, &empty_label));
    assert!(!same(&absent_label, &empty_label));
    let mut rm_expected = fixture.clone();
    rm_expected.control |= 0x4000;
    let mut rm_changed = rm_expected.clone();
    rm_changed.resource_manager = 1;
    assert!(
        !same(&rm_expected, &rm_changed),
        "resource-manager header must remain exact"
    );
}

#[test]
fn unsupported_ace_and_truncated_descriptor_fail_closed() {
    let mut fixture = Fixture::selected();
    fixture.dacl = Some(acl(&[ace(2, 0, 0xf016f, &sid(5, &[18]))]));
    assert!(snapshot::capture(&fixture.bytes([0, 1, 2, 3])).is_err());
    let bytes = Fixture::selected().bytes([0, 1, 2, 3]);
    assert!(snapshot::capture(&bytes[..bytes.len() - 1]).is_err());
    let mut absolute = bytes;
    absolute[3] &= !0x80;
    assert!(snapshot::capture(&absolute).is_err());
}

#[test]
fn desktop_resultant_transition_is_explicit_forward_only_and_station_stays_strict() {
    use snapshot::DesktopResult;
    let expected_fixture = Fixture::selected();
    let expected = snapshot::capture(&expected_fixture.bytes([0, 1, 2, 3])).unwrap();
    let exact_repacked = snapshot::capture(&expected_fixture.bytes([3, 2, 1, 0])).unwrap();
    assert_eq!(
        snapshot::compare_desktop_resultant(&expected, &exact_repacked).unwrap(),
        DesktopResult::Exact
    );
    let mut actual_fixture = expected_fixture.clone();
    actual_fixture.control |= 0x800;
    let actual = snapshot::capture(&actual_fixture.bytes([3, 2, 1, 0])).unwrap();
    let expected_raw = expected.raw_sha256.clone();
    let actual_raw = actual.raw_sha256.clone();
    assert_eq!(
        snapshot::compare_desktop_resultant(&expected, &actual).unwrap(),
        DesktopResult::DesktopSaclAutoInherited
    );
    assert!(
        snapshot::compare(&expected, &actual).is_err(),
        "station/strict comparison must still reject the bit"
    );
    assert!(
        snapshot::compare_desktop_resultant(&actual, &expected).is_err(),
        "reverse transition cannot qualify"
    );
    assert!(
        snapshot::compare_desktop_resultant(&actual, &actual).is_err(),
        "already-auto-inherited creation policy must not qualify even exactly"
    );
    assert_eq!(expected.raw_sha256, expected_raw);
    assert_eq!(actual.raw_sha256, actual_raw);
}

#[test]
fn desktop_resultant_requires_protected_present_unrequested_single_label_policy() {
    let valid = Fixture::selected();
    let expected = snapshot::capture(&valid.bytes([0, 1, 2, 3])).unwrap();
    for flag in [0x200, 0x800, 0x2000] {
        let mut invalid_creation = valid.clone();
        invalid_creation.control ^= flag;
        let invalid = snapshot::capture(&invalid_creation.bytes([0, 1, 2, 3])).unwrap();
        assert!(
            snapshot::compare_desktop_resultant(&invalid, &invalid).is_err(),
            "accepted invalid creation control {flag:#x}"
        );
    }
    for label in [
        None,
        Some(acl(&[])),
        Some(acl(&[
            ace(17, 0, 1, &sid(16, &[8192])),
            ace(17, 0, 1, &sid(16, &[8192])),
        ])),
    ] {
        let mut invalid = valid.clone();
        invalid.label = label;
        let invalid_source = snapshot::capture(&invalid.bytes([0, 1, 2, 3])).unwrap();
        assert!(snapshot::compare_desktop_resultant(&invalid_source, &invalid_source).is_err());
        invalid.control |= 0x800;
        let invalid_actual = snapshot::capture(&invalid.bytes([0, 1, 2, 3])).unwrap();
        assert!(snapshot::compare_desktop_resultant(&expected, &invalid_actual).is_err());
    }
    let mut absent = valid.clone();
    absent.control &= !(0x10 | 0x2000);
    absent.label = None;
    let absent_source = snapshot::capture(&absent.bytes([0, 1, 2, 3])).unwrap();
    assert!(snapshot::compare_desktop_resultant(&absent_source, &absent_source).is_err());
    absent.control |= 0x800;
    assert!(
        snapshot::compare_desktop_resultant(
            &expected,
            &snapshot::capture(&absent.bytes([0, 1, 2, 3])).unwrap()
        )
        .is_err()
    );
    for flag in [0x200, 0x2000, 0x400, 0x1000] {
        let mut invalid_actual = valid.clone();
        invalid_actual.control |= 0x800;
        invalid_actual.control ^= flag;
        assert!(
            snapshot::compare_desktop_resultant(
                &expected,
                &snapshot::capture(&invalid_actual.bytes([0, 1, 2, 3])).unwrap()
            )
            .is_err(),
            "accepted combined control change {flag:#x}"
        );
    }
}

#[test]
fn startup_probe_uses_selected_creation_and_pins_the_held_resultant() {
    use memcordon_windows_loader_lab::startup_probe_contract::verify_observed_policy;
    use snapshot::{ComparisonOutcome, Domain};
    let creation = Fixture::selected();
    let selected = snapshot::capture(&creation.bytes([0, 1, 2, 3])).unwrap();
    let mut resultant = creation;
    resultant.control |= 0x800;
    let held = snapshot::capture(&resultant.bytes([3, 2, 1, 0])).unwrap();
    let reread = snapshot::capture(&resultant.bytes([3, 2, 1, 0])).unwrap();
    assert_eq!(
        verify_observed_policy(Domain::Desktop, &selected, &held, &reread)
            .unwrap()
            .comparison,
        ComparisonOutcome::DesktopSaclAutoInherited
    );
    assert!(verify_observed_policy(Domain::Desktop, &held, &held, &reread).is_err());
    // An equally valid but differently packed resultant is still a changed
    // held observation and must not qualify for the diagnostic identity.
    let repacked = snapshot::capture(&resultant.bytes([0, 1, 2, 3])).unwrap();
    snapshot::verify_and_fingerprint(Domain::Desktop, &selected, &repacked).unwrap();
    assert!(verify_observed_policy(Domain::Desktop, &selected, &held, &repacked).is_err());
}

#[test]
fn desktop_resultant_bit_cannot_conceal_any_other_selected_policy_change() {
    let valid = Fixture::selected();
    let expected = snapshot::capture(&valid.bytes([0, 1, 2, 3])).unwrap();
    let mut changes = Vec::new();
    let mut changed = valid.clone();
    changed.owner = sid(5, &[19]);
    changes.push(changed);
    let mut changed = valid.clone();
    changed.group = sid(5, &[32, 545]);
    changes.push(changed);
    let mut changed = valid.clone();
    changed.resource_manager = 1;
    changes.push(changed);
    let mut changed = valid.clone();
    changed.dacl.as_mut().unwrap()[0] = 4;
    changes.push(changed);
    let owner_rights = sid(3, &[4]);
    let system = sid(5, &[18]);
    for (kind, flags, mask, trustee) in [
        (1, 0, 0xf016f, owner_rights.clone()),
        (0, 0x10, 0xf016f, owner_rights.clone()),
        (0, 0, 0xf016e, owner_rights.clone()),
        (0, 0, 0xf016f, sid(1, &[0])),
    ] {
        let mut changed = valid.clone();
        changed.dacl = Some(acl(&[
            ace(kind, flags, mask, &trustee),
            ace(0, 0, 0xf016f, &system),
        ]));
        changes.push(changed);
    }
    let mut changed = valid.clone();
    changed.dacl = Some(acl(&[
        ace(0, 0, 0xf016f, &system),
        ace(0, 0, 0xf016f, &owner_rights),
    ]));
    changes.push(changed);
    for (flags, mask, label) in [(0x10, 1, 8192), (0, 2, 8192), (0, 1, 12288)] {
        let mut changed = valid.clone();
        changed.label = Some(acl(&[ace(17, flags, mask, &sid(16, &[label]))]));
        changes.push(changed);
    }
    let mut changed = valid.clone();
    changed.label.as_mut().unwrap()[0] = 4;
    changes.push(changed);
    for (index, mut changed) in changes.into_iter().enumerate() {
        changed.control |= 0x800;
        let actual = snapshot::capture(&changed.bytes([3, 2, 1, 0])).unwrap();
        assert!(
            snapshot::compare_desktop_resultant(&expected, &actual).is_err(),
            "accepted policy drift case {index}"
        );
    }
}

#[test]
fn verified_fingerprints_bind_domain_selection_and_admitted_observed_policy() {
    use snapshot::{ComparisonOutcome, Domain};
    let fixture = Fixture::selected();
    let expected = snapshot::capture(&fixture.bytes([0, 1, 2, 3])).unwrap();
    let observed = snapshot::capture(&fixture.bytes([3, 2, 1, 0])).unwrap();
    let station = snapshot::verify_and_fingerprint(Domain::Station, &expected, &observed).unwrap();
    assert_eq!(
        station.fingerprint,
        snapshot::expected_fingerprint(Domain::Station, &expected).unwrap()
    );
    assert_ne!(expected.raw_sha256, observed.raw_sha256);
    snapshot::validate_verified(Domain::Station, &expected, &station).unwrap();
    assert_ne!(
        station.fingerprint.sha256,
        snapshot::expected_fingerprint(Domain::Desktop, &expected)
            .unwrap()
            .sha256
    );
    let mut resultant = fixture.clone();
    resultant.control |= 0x800;
    let actual = snapshot::capture(&resultant.bytes([3, 2, 1, 0])).unwrap();
    let desktop = snapshot::verify_and_fingerprint(Domain::Desktop, &expected, &actual).unwrap();
    assert_eq!(
        desktop.comparison,
        ComparisonOutcome::DesktopSaclAutoInherited
    );
    assert_eq!(desktop.observed_control, resultant.control);
    assert_eq!(
        desktop.fingerprint,
        snapshot::expected_fingerprint(Domain::Desktop, &expected).unwrap()
    );
    snapshot::validate_verified(Domain::Desktop, &expected, &desktop).unwrap();
    assert!(snapshot::verify_and_fingerprint(Domain::Station, &expected, &actual).is_err());
    let mut wrong = fixture;
    wrong.owner = sid(5, &[19]);
    let wrong = snapshot::capture(&wrong.bytes([0, 1, 2, 3])).unwrap();
    assert!(
        snapshot::verify_and_fingerprint(Domain::Station, &expected, &wrong).is_err(),
        "cannot emit expected digest for unverified observed policy"
    );
    assert!(
        snapshot::validate_verified(Domain::Station, &wrong, &station).is_err(),
        "cannot replay a valid fingerprint for another expected policy"
    );
}

#[test]
fn gate_fingerprints_cover_only_explicit_owner_group_dacl_selection() {
    use snapshot::Domain;
    let mut gate = Fixture::selected();
    gate.label = None;
    gate.control &= !(0x10 | 0x20 | 0x200 | 0x800 | 0x2000);
    let expected = snapshot::capture_selected(&gate.bytes([0, 1, 2, 3]), 0x7).unwrap();
    let mut materialized = Fixture::selected();
    materialized.label = Some(acl(&[ace(17, 0, 2, &sid(16, &[12288]))]));
    materialized.control |= 0x800;
    let actual = snapshot::capture_selected(&materialized.bytes([3, 2, 1, 0]), 0x7).unwrap();
    let verified = snapshot::verify_and_fingerprint(Domain::Gate, &expected, &actual).unwrap();
    assert_eq!(verified.fingerprint.selection, 0x7);
    assert_eq!(verified.observed_control, gate.control);
    snapshot::validate_verified(Domain::Gate, &expected, &verified).unwrap();
    assert_ne!(expected.raw_sha256, actual.raw_sha256);
    assert!(snapshot::expected_fingerprint(Domain::Station, &expected).is_err());
    assert!(
        snapshot::expected_fingerprint(
            Domain::Gate,
            &snapshot::capture(&materialized.bytes([0, 1, 2, 3])).unwrap()
        )
        .is_err()
    );
    for changed in ["owner", "group", "mask", "control"] {
        let mut actual = gate.clone();
        match changed {
            "owner" => actual.owner = sid(5, &[19]),
            "group" => actual.group = sid(5, &[32, 545]),
            "mask" => {
                actual.dacl = Some(acl(&[
                    ace(0, 0, 0xf016e, &sid(3, &[4])),
                    ace(0, 0, 0xf016f, &sid(5, &[18])),
                ]))
            }
            "control" => actual.control ^= 0x1000,
            _ => unreachable!(),
        }
        let actual = snapshot::capture_selected(&actual.bytes([0, 1, 2, 3]), 0x7).unwrap();
        assert!(
            snapshot::verify_and_fingerprint(Domain::Gate, &expected, &actual).is_err(),
            "gate accepted changed {changed}"
        );
    }
    let mut bad_offset = gate.bytes([0, 1, 2, 3]);
    bad_offset[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        snapshot::capture_selected(&bad_offset, 0x7).is_err(),
        "unselected SACL offset must still be bounded before native pointer inspection"
    );
}

#[test]
fn parent_validation_rejects_forged_fingerprint_context_and_resultant_claims() {
    use snapshot::{ComparisonOutcome, Domain};
    let fixture = Fixture::selected();
    let expected = snapshot::capture(&fixture.bytes([0, 1, 2, 3])).unwrap();
    let station = snapshot::verify_and_fingerprint(Domain::Station, &expected, &expected).unwrap();
    for field in [
        "schema",
        "selection",
        "domain",
        "digest",
        "outcome",
        "control",
    ] {
        let mut forged = station.clone();
        match field {
            "schema" => forged.fingerprint.schema_version = 2,
            "selection" => forged.fingerprint.selection = 0x7,
            "domain" => forged.fingerprint.domain = Domain::Desktop,
            "digest" => forged.fingerprint.sha256 = "00".repeat(32),
            "outcome" => forged.comparison = ComparisonOutcome::DesktopSaclAutoInherited,
            "control" => forged.observed_control ^= 0x1000,
            _ => unreachable!(),
        }
        assert!(
            snapshot::validate_verified(Domain::Station, &expected, &forged).is_err(),
            "accepted forged {field}"
        );
    }
    let mut actual = fixture;
    actual.control |= 0x800;
    let actual = snapshot::capture(&actual.bytes([0, 1, 2, 3])).unwrap();
    let admitted = snapshot::verify_and_fingerprint(Domain::Desktop, &expected, &actual).unwrap();
    let mut forged = admitted.clone();
    forged.comparison = ComparisonOutcome::Exact;
    assert!(snapshot::validate_verified(Domain::Desktop, &expected, &forged).is_err());
    let mut forged = admitted;
    forged.observed_control &= !0x800;
    assert!(snapshot::validate_verified(Domain::Desktop, &expected, &forged).is_err());
}
