#[path = "../src/bin/consumer_readiness_windows/matched_control_security_components.rs"]
pub mod components;
use components::*;
use sha2::{Digest, Sha256};

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[test]
fn native_component_addresses_and_lengths_cannot_escape_exact_owned_bytes() {
    let base = 4096;
    let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    assert_eq!(component_offset(base, bytes.len(), base), Ok(0));
    assert_eq!(
        component_offset(base, bytes.len(), base + bytes.len() - 1),
        Ok(bytes.len() - 1)
    );
    for pointer in [base - 1, base + bytes.len(), usize::MAX] {
        assert_eq!(
            component_offset(base, bytes.len(), pointer),
            Err(Stage::ComponentBounds)
        );
    }
    assert!(component_offset(base, 0, base).is_err());
    assert_eq!(
        component_offset(usize::MAX - 1, 3, usize::MAX),
        Err(Stage::ComponentBounds)
    );
    for (offset, length) in [
        (0, 0),
        (bytes.len(), 1),
        (bytes.len() + 1, 1),
        (usize::MAX, 2),
        (2, usize::MAX),
    ] {
        assert_eq!(
            component_bytes(&bytes, offset, length),
            Err(Stage::ComponentBounds)
        );
    }
    assert_eq!(component_bytes(&bytes, 4, 5).unwrap(), &[5, 6, 7, 8, 9]);
}

#[test]
fn component_hashes_distinguish_used_and_free_bytes_without_padding_or_mutation() {
    // The last physical allocation bytes are outside the captured exact extent.
    let storage = [
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 250, 251, 252, 253,
    ];
    let exact = &storage[..12];
    let original = hash(exact);
    let used = component_bytes(exact, 4, 4).unwrap();
    let total = component_bytes(exact, 4, 8).unwrap();
    assert_eq!(hash(used), hash(&[15, 16, 17, 18]));
    assert_eq!(hash(total), hash(&[15, 16, 17, 18, 19, 20, 21, 22]));
    assert_ne!(hash(used), hash(total));
    assert!(component_bytes(exact, 4, 9).is_err());
    assert_ne!(hash(exact), hash(&storage));
    assert_eq!(hash(exact), original);
}

#[test]
fn absent_and_null_acl_never_claim_undefined_defaulted_or_observed_bytes() {
    let absent = serde_json::to_value(Acl::Absent {}).unwrap();
    let null = serde_json::to_value(Acl::Null { defaulted: true }).unwrap();
    let empty = serde_json::to_value(Acl::Observed {
        defaulted: false,
        ace_count: 0,
        bytes_in_use: 8,
        bytes_free: 0,
        used_sha256: hash(&[0; 8]),
        total_sha256: hash(&[0; 8]),
    })
    .unwrap();
    assert_eq!(absent["state"], "absent");
    assert!(absent.get("defaulted").is_none());
    assert!(absent.get("used_sha256").is_none());
    assert_eq!(null["state"], "null");
    assert_eq!(null["defaulted"], true);
    assert!(null.get("bytes_in_use").is_none());
    assert_eq!(empty["state"], "observed");
    assert_eq!(empty["ace_count"], 0);
    let owner = serde_json::to_value(Sid::Absent {}).unwrap();
    assert!(owner.get("defaulted").is_none());
    assert!(owner.get("sha256").is_none());
    let mut invalid = absent;
    invalid["defaulted"] = true.into();
    assert!(serde_json::from_value::<Acl>(invalid).is_err());
    let mut invalid_owner = owner;
    invalid_owner["defaulted"] = true.into();
    assert!(serde_json::from_value::<Sid>(invalid_owner).is_err());
}

#[test]
fn fixed_three_role_fingerprints_are_bounded_closed_and_contain_no_raw_security() {
    let sid = Sid::Observed {
        defaulted: true,
        bytes: 12,
        sha256: [255; 32],
    };
    let acl = Acl::Observed {
        defaulted: true,
        ace_count: 0,
        bytes_in_use: 8,
        bytes_free: 16,
        used_sha256: [255; 32],
        total_sha256: [255; 32],
    };
    let rows = [Role::Stdin, Role::Stdout, Role::Stderr].map(|role| Row {
        role,
        security_information: 23,
        full_bytes: 144,
        full_sha256: [255; 32],
        components: Components::Observed(Box::new(ObservedComponents {
            revision: 1,
            control: 0x8004,
            native_bytes: 144,
            owner: sid.clone(),
            group: sid.clone(),
            dacl: acl.clone(),
            label_sacl_subset: acl.clone(),
        })),
    });
    let wire = serde_json::to_vec(&rows).unwrap();
    assert!(wire.len() < MAX_SIDECAR_BYTES);
    assert_eq!(serde_json::from_slice::<[Row; 3]>(&wire).unwrap(), rows);
    let value = serde_json::to_value(&rows).unwrap();
    for row in value.as_array().unwrap() {
        assert_eq!(row["security_information"], 23);
        let observed = row["components"].as_object().unwrap();
        assert!(observed.contains_key("label_sacl_subset"));
        for forbidden in [
            "sacl",
            "raw_sid",
            "raw_sd",
            "environment",
            "handle",
            "creator",
        ] {
            assert!(!observed.contains_key(forbidden));
        }
    }
    let mut extra = serde_json::to_value(&rows[0]).unwrap();
    extra["raw_descriptor"] = vec![1, 2, 3].into();
    assert!(serde_json::from_value::<Row>(extra).is_err());
}

#[test]
fn unavailable_native_error_is_not_a_zero_or_an_observed_component() {
    let unknown = Components::unavailable(Stage::ValidatorUnavailable, None);
    let zero = Components::unavailable(Stage::Owner, Some(0));
    assert_ne!(unknown, zero);
    let unknown = serde_json::to_value(unknown).unwrap();
    let zero = serde_json::to_value(zero).unwrap();
    assert!(unknown["native_win32_error"].is_null());
    assert_eq!(zero["native_win32_error"], 0);
    assert!(unknown.get("owner").is_none());
    assert!(unknown.get("control").is_none());
    assert!(serde_json::to_vec(&unknown).unwrap().len() < 512);
}
