#[path = "private/fixture_namespace_acl.rs"]
mod namespace_acl;
#[path = "../src/bin/consumer_readiness_windows/fixture_default_dacl.rs"]
mod policy;

fn user_acl() -> Vec<u8> {
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let ace_size = 8 + sid.len();
    let total = 8 + ace_size;
    let mut raw = vec![2, 0];
    raw.extend_from_slice(&(total as u16).to_le_bytes());
    raw.extend_from_slice(&1u16.to_le_bytes());
    raw.extend_from_slice(&[0, 0, 0, 0]);
    raw.extend_from_slice(&(ace_size as u16).to_le_bytes());
    raw.extend_from_slice(&0x1000_0000u32.to_le_bytes());
    raw.extend_from_slice(&sid);
    raw
}

#[test]
fn namespace_admits_exact_user_and_rc_without_inheritance() {
    let original = user_acl();
    let retained = original.clone();
    let result = namespace_acl::plan(&original).unwrap();
    namespace_acl::validate(&result, namespace_acl::user_sid(&original).unwrap()).unwrap();
    assert_eq!(original, retained);
    assert_eq!(result[4..6], 2u16.to_le_bytes());
    assert_eq!(
        result.len(),
        original.len() + 8 + policy::RESTRICTED_CODE_SID.len()
    );
}

#[test]
fn namespace_rejects_inheritance_extra_grants_and_wrong_user() {
    let original = user_acl();
    let user = namespace_acl::user_sid(&original).unwrap();
    let good = namespace_acl::plan(&original).unwrap();
    let first_size = usize::from(u16::from_le_bytes([good[10], good[11]]));
    let second = 8 + first_size;
    for flag in [1, 2, 4, 8, 16] {
        let mut bad = good.clone();
        bad[9] = flag;
        assert!(namespace_acl::validate(&bad, user).is_err());
        let mut bad_rc = good.clone();
        bad_rc[second + 1] = flag;
        assert!(namespace_acl::validate(&bad_rc, user).is_err());
        let mut bad_source = original.clone();
        bad_source[9] = flag;
        assert!(namespace_acl::plan(&bad_source).is_err());
    }
    let mut wrong = user.to_vec();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(namespace_acl::validate(&good, &wrong).is_err());
    let mut deny = original.clone();
    deny[8] = 1;
    assert!(namespace_acl::plan(&deny).is_err());
    assert!(namespace_acl::plan(&good).is_err());
    let mut extra = good.clone();
    extra.extend_from_slice(&good[8..second]);
    let length = u16::try_from(extra.len()).unwrap();
    extra[2..4].copy_from_slice(&length.to_le_bytes());
    extra[4..6].copy_from_slice(&3u16.to_le_bytes());
    assert!(namespace_acl::validate(&extra, user).is_err());
    for end in 0..original.len() {
        assert!(namespace_acl::plan(&original[..end]).is_err());
    }
}
