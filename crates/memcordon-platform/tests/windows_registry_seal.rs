#![cfg(feature = "test-support")]
use memcordon_platform::windows_registry_seal::{
    ReadAce, read_trustees, validate_read_acl, validate_sid,
};

fn sid(authority: u8, subauthorities: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, subauthorities.len() as u8, 0, 0, 0, 0, 0, authority];
    for value in subauthorities {
        bytes.extend(value.to_le_bytes());
    }
    bytes
}
fn acl(user: &[u8]) -> Vec<ReadAce> {
    let mut trustees = vec![user.to_vec(), sid(3, &[4]), sid(5, &[12]), sid(5, &[18])];
    trustees.sort();
    trustees.dedup();
    trustees
        .into_iter()
        .map(|sid| ReadAce {
            kind: 0,
            flags: 0,
            mask: 0x20019,
            sid,
        })
        .collect()
}

#[test]
fn intended_user_and_both_access_checks_have_exact_read_grants() {
    let user = sid(5, &[21, 111, 222, 333, 1001]);
    let mut actual = acl(&user);
    validate_read_acl(&user, &actual).unwrap();
    actual.reverse();
    validate_read_acl(&user, &actual).unwrap();
    let system = sid(5, &[18]);
    validate_read_acl(&system, &acl(&system)).unwrap();
    let generated = read_trustees(&system).unwrap();
    assert_eq!(generated.len(), 3);
    assert!(generated.contains(&sid(3, &[4])));
    assert!(generated.contains(&sid(5, &[12])));
    assert!(generated.contains(&system));
    // An unrelated same-domain user cannot substitute for the captured user.
    assert!(validate_read_acl(&sid(5, &[21, 111, 222, 333, 1002]), &actual).is_err());
}

#[test]
fn seal_rejects_mutation_extra_identity_missing_and_nonallow_aces() {
    let user = sid(5, &[21, 111, 222, 333, 1001]);
    let baseline = acl(&user);
    for index in 0..baseline.len() {
        for mask in [
            0x20019 | 2,
            0x20019 | 4,
            0x20019 | 0x10000,
            0x20019 | 0x40000,
            0x20019 | 0x80000,
            0x20019 & !1,
        ] {
            let mut bad = baseline.clone();
            bad[index].mask = mask;
            assert!(validate_read_acl(&user, &bad).is_err());
        }
        for kind in [1, 5, 6, 17, 255] {
            let mut bad = baseline.clone();
            bad[index].kind = kind;
            assert!(validate_read_acl(&user, &bad).is_err());
        }
        for flags in [1, 2, 8, 16, 128] {
            let mut bad = baseline.clone();
            bad[index].flags = flags;
            assert!(validate_read_acl(&user, &bad).is_err());
        }
        let mut missing = baseline.clone();
        missing.remove(index);
        assert!(validate_read_acl(&user, &missing).is_err());
    }
    let mut duplicate = baseline.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(validate_read_acl(&user, &duplicate).is_err());
    let mut everyone = baseline.clone();
    everyone[0].sid = sid(1, &[0]);
    assert!(validate_read_acl(&user, &everyone).is_err());
    let mut extra = baseline.clone();
    extra.push(ReadAce {
        kind: 0,
        flags: 0,
        mask: 0x20019,
        sid: sid(5, &[32, 544]),
    });
    assert!(validate_read_acl(&user, &extra).is_err());
}

#[test]
fn sid_shape_is_bounded_exact_and_not_a_string_identity() {
    let valid = sid(5, &[21, 111, 222, 333, 1001]);
    validate_sid(&valid).unwrap();
    for length in 0..valid.len() {
        assert!(validate_sid(&valid[..length]).is_err());
    }
    let mut longer = valid.clone();
    longer.push(0);
    assert!(validate_sid(&longer).is_err());
    let mut revision = valid.clone();
    revision[0] = 2;
    assert!(validate_sid(&revision).is_err());
    let mut too_many = vec![0; 8 + 16 * 4];
    too_many[0] = 1;
    too_many[1] = 16;
    assert!(validate_sid(&too_many).is_err());
    assert!(validate_sid(b"S-1-5-21-111-222-333-1001").is_err());
    let mut bad_acl = acl(&valid);
    bad_acl[0].sid = longer;
    assert!(validate_read_acl(&valid, &bad_acl).is_err());
}
