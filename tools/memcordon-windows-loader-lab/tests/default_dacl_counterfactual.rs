use memcordon_windows_loader_lab::{
    default_dacl_counterfactual::*, startup_probe_contract::describe_default_dacl,
};
use serde_json::{Value, json};

fn capture(raw: Option<&[u8]>) -> Value {
    json!({"captured":true,"facts":describe_default_dacl(raw).unwrap()})
}

fn acl() -> Vec<u8> {
    let mut raw = vec![2, 0, 0, 0, 2, 0, 0, 0];
    for subauthority in [18_u32, 19] {
        let mut ace = vec![0, 0, 0, 0];
        ace.extend_from_slice(&0x000f_01ff_u32.to_le_bytes());
        ace.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5]);
        ace.extend_from_slice(&subauthority.to_le_bytes());
        let size = u16::try_from(ace.len()).unwrap();
        ace[2..4].copy_from_slice(&size.to_le_bytes());
        raw.extend_from_slice(&ace);
    }
    let size = u16::try_from(raw.len()).unwrap();
    raw[2..4].copy_from_slice(&size.to_le_bytes());
    raw
}

fn restricting() -> Value {
    json!({"captured":true,"facts":{"complete":true,"entries":[{"sid":"S-1-5-12","attributes":4,"enabled":true,"deny_only":false}]}})
}

#[test]
fn only_exact_appended_noninherited_rc_allow_is_admitted() {
    let raw = acl();
    let source = capture(Some(&raw));
    let restricting = restricting();
    let expected = expected_acl(&source, &restricting).unwrap();
    let changed = capture(Some(&expected));
    verify_delta(&source, &source, &restricting, &changed).unwrap();
    let ace = &changed["facts"]["aces"][2];
    assert_eq!(ace["type"], 0);
    assert_eq!(ace["flags"], 0);
    assert_eq!(ace["mask"], 0x1000_0000_u32);
    assert_eq!(ace["sid"], "S-1-5-12");
    let first = source["facts"]["aces"][0]["raw_hex"].as_str().unwrap();
    let first = hex::decode(first).unwrap();
    let header = raw.len() - first.len() * source["facts"]["aces"].as_array().unwrap().len();
    let mut reordered = expected.clone();
    let second = header + first.len();
    let saved = reordered[header..second].to_vec();
    reordered.copy_within(second..second + first.len(), header);
    reordered[second..second + first.len()].copy_from_slice(&saved);
    assert!(verify_delta(&source, &source, &restricting, &capture(Some(&reordered))).is_err());
    let mut extra_change = expected.clone();
    extra_change[header + size_of::<u32>()] ^= 1;
    assert!(
        verify_delta(
            &source,
            &source,
            &restricting,
            &capture(Some(&extra_change))
        )
        .is_err()
    );
    assert!(verify_delta(&source, &changed, &restricting, &changed).is_err());
}

#[test]
fn unsupported_source_shapes_or_restrictions_never_enable_intervention() {
    let raw = acl();
    let valid = capture(Some(&raw));
    for source in [
        capture(None),
        capture(Some(&[2, 0, 8, 0, 0, 0, 0, 0])),
        json!({"captured":false}),
        json!({"captured":true,"facts":{}}),
    ] {
        assert!(expected_acl(&source, &restricting()).is_err());
    }
    let first_header = size_of::<u16>() * 4;
    for (offset, value) in [
        (first_header, 1),
        (first_header, 255),
        (first_header + 1, 0x10),
    ] {
        let mut changed = raw.clone();
        changed[offset] = value;
        assert!(expected_acl(&capture(Some(&changed)), &restricting()).is_err());
    }
    let mut truncated = valid.clone();
    truncated["facts"]["raw_hex"] = json!(hex::encode(&raw[..raw.len() - 1]));
    assert!(expected_acl(&truncated, &restricting()).is_err());
    for (field, value) in [
        ("sid", json!("S-1-5-18")),
        ("enabled", json!(false)),
        ("deny_only", json!(true)),
        ("attributes", json!(0)),
    ] {
        let mut changed = restricting();
        changed["facts"]["entries"][0][field] = value;
        assert!(expected_acl(&valid, &changed).is_err());
    }
    let mut extra = restricting();
    let entry = extra["facts"]["entries"][0].clone();
    extra["facts"]["entries"]
        .as_array_mut()
        .unwrap()
        .push(entry);
    assert!(expected_acl(&valid, &extra).is_err());
    let mut overflow = valid;
    overflow["facts"]["raw_hex"] = json!(hex::encode(vec![
        0;
        memcordon_windows_loader_lab::startup_probe_contract::DEFAULT_DACL_BYTES
            + 1
    ]));
    assert!(expected_acl(&overflow, &restricting()).is_err());
}

#[test]
fn baseline_gate_requires_natural_failure_and_settled_unmodified_ownership() {
    let baseline = BaselineEvidence {
        work_exit: Some(0xc0000142),
        natural_exit: true,
        fixture_entry: false,
        native_retirement_complete: true,
        pending_debug_event: false,
        event_omissions: 0,
        stream_omissions: 0,
        source_default_acl_equal: Some(true),
        original_work_deadline_live: true,
    };
    assert!(eligible_baseline(baseline));
    for changed in [
        BaselineEvidence {
            natural_exit: false,
            ..baseline
        },
        BaselineEvidence {
            fixture_entry: true,
            ..baseline
        },
        BaselineEvidence {
            native_retirement_complete: false,
            ..baseline
        },
        BaselineEvidence {
            pending_debug_event: true,
            ..baseline
        },
        BaselineEvidence {
            event_omissions: 1,
            ..baseline
        },
        BaselineEvidence {
            stream_omissions: 1,
            ..baseline
        },
        BaselineEvidence {
            source_default_acl_equal: None,
            ..baseline
        },
        BaselineEvidence {
            source_default_acl_equal: Some(false),
            ..baseline
        },
        BaselineEvidence {
            original_work_deadline_live: false,
            ..baseline
        },
        BaselineEvidence {
            work_exit: Some(0),
            ..baseline
        },
    ] {
        assert!(!eligible_baseline(changed));
    }
    assert_eq!(
        interpret_changed(true, None, true, true, false, false),
        Interpretation::BoundFixtureEntry
    );
    assert_eq!(
        interpret_changed(false, Some(0xc0000142), false, true, false, false),
        Interpretation::SameNaturalInitializationFailure
    );
    for (entry, exit) in [(true, None), (false, Some(0xc0000142))] {
        assert_eq!(
            interpret_changed(entry, exit, false, true, false, true),
            Interpretation::Inconclusive,
            "late entry/terminal evidence must not establish a controlled outcome"
        );
    }
    for (forced, retired, omitted, expired) in [
        (true, true, false, false),
        (false, false, false, false),
        (false, true, true, false),
        (false, true, false, true),
    ] {
        assert_eq!(
            interpret_changed(false, Some(0xc0000142), forced, retired, omitted, expired),
            Interpretation::Inconclusive
        );
    }
}

#[test]
fn entry_requires_complete_original_challenge_and_fresh_target_pid() {
    let event =
        json!({"sequence":0,"stage":"started","pid":123,"ordinal":null,"value":b"bound-challenge"});
    let frame = |value: &Value| {
        let bytes = serde_json::to_vec(value).unwrap();
        let mut framed = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
        framed.extend(bytes);
        framed
    };
    let bytes = frame(&event);
    assert!(bound_entry(&bytes, 123, b"bound-challenge", bytes.len()).unwrap());
    assert!(
        !bound_entry(
            &bytes[..bytes.len() - 1],
            123,
            b"bound-challenge",
            bytes.len()
        )
        .unwrap()
    );
    for (field, value) in [
        ("pid", json!(124)),
        ("sequence", json!(1)),
        ("stage", json!("controller-released")),
        ("value", json!(b"wrong-challenge")),
    ] {
        let mut changed = event.clone();
        changed[field] = value;
        assert!(bound_entry(&frame(&changed), 123, b"bound-challenge", 4096).is_err());
    }
    assert!(bound_entry(&bytes, 123, b"bound-challenge", bytes.len() - 1).is_err());
}

#[test]
fn only_new_token_identity_and_modified_counter_are_excluded_from_security_comparison() {
    let source = json!({"security":{"envelope":{"session_id":2,"token_type":1},"groups":["original"]},"statistics":{"token_id":1,"modified_id":2,"expiration":3,"group_count":1,"token_type":1,"impersonation_level":null}});
    let mut duplicate = source.clone();
    duplicate["statistics"]["token_id"] = json!(4);
    duplicate["statistics"]["modified_id"] = json!(5);
    assert!(unchanged_security(&source, &duplicate));
    duplicate["statistics"]["expiration"] = json!(6);
    assert!(!unchanged_security(&source, &duplicate));
    duplicate = source.clone();
    duplicate["security"]["groups"] = json!(["changed"]);
    assert!(!unchanged_security(&source, &duplicate));
    assert!(!unchanged_security(&json!({}), &json!({})));
}

#[test]
fn token_statistics_require_applicable_type_and_level() {
    let primary = json!({"security":{"envelope":{"token_type":1}},"statistics":{"token_id":1,"modified_id":2,"token_type":1,"impersonation_level":null}});
    assert!(unchanged_security(&primary, &primary));
    for (kind, level) in [
        (1, json!(0)),
        (3, Value::Null),
        (2, Value::Null),
        (2, json!(4)),
        (2, json!(-1)),
    ] {
        let mut invalid = primary.clone();
        invalid["statistics"]["token_type"] = json!(kind);
        invalid["security"]["envelope"]["token_type"] = json!(kind);
        invalid["statistics"]["impersonation_level"] = level;
        assert!(!unchanged_security(&invalid, &invalid));
    }
    let mut impersonation = primary.clone();
    impersonation["statistics"]["token_type"] = json!(2);
    impersonation["security"]["envelope"]["token_type"] = json!(2);
    impersonation["statistics"]["impersonation_level"] = json!(2);
    assert!(unchanged_security(&impersonation, &impersonation));
    let mut changed = impersonation.clone();
    changed["statistics"]["impersonation_level"] = json!(1);
    assert!(!unchanged_security(&impersonation, &changed));
    changed = primary.clone();
    changed["statistics"]["token_type"] = json!(2);
    assert!(!unchanged_security(&changed, &changed));
}

#[test]
fn preintervention_refusal_retains_bounded_cause_without_claiming_mutation() {
    let source = json!({"security":{"envelope":{"token_type":1}},"statistics":{"token_id":1,"modified_id":2,"token_type":1,"impersonation_level":null,"expiration":1},"default_dacl":capture(Some(&acl()))});
    let mut duplicate = source.clone();
    duplicate["statistics"]["expiration"] = json!(2);
    let evidence = duplicate_refusal(&source, &duplicate);
    assert_eq!(evidence["security_equal"], false);
    assert_eq!(evidence["default_acl_equal"], true);
    assert_eq!(evidence["differing_fields"].as_array().unwrap().len(), 1);
    assert_eq!(evidence["differing_fields"][0]["section"], "statistics");
    assert_eq!(evidence["differing_fields"][0]["field"], "expiration");
    assert_eq!(evidence["differing_fields"][0]["source"]["value"], 1);
    assert_eq!(evidence["differing_fields"][0]["duplicate"]["value"], 2);
    assert_eq!(evidence["acl_set_attempted"], false);
    assert_eq!(evidence["changed_target_started"], false);
    assert_eq!(evidence["source"]["snapshot_omitted"], true);
    assert_eq!(
        evidence["source_acl"]["raw_hex"],
        source["default_dacl"]["facts"]["raw_hex"]
    );
    duplicate = source.clone();
    duplicate["default_dacl"] = capture(None);
    let evidence = duplicate_refusal(&source, &duplicate);
    assert_eq!(evidence["security_equal"], true);
    assert_eq!(evidence["default_acl_equal"], false);
    let oversized =
        vec![0_u8; memcordon_windows_loader_lab::startup_probe_contract::DEFAULT_DACL_BYTES + 1];
    duplicate["default_dacl"]["facts"]["raw_hex"] = json!(hex::encode(oversized));
    let evidence = duplicate_refusal(&source, &duplicate);
    assert_eq!(evidence["duplicate_acl"]["raw_omitted"], true);
    assert!(evidence["duplicate_acl"]["raw_hex"].is_null());
    assert!(serde_json::to_vec(&evidence).unwrap().len() < 64 * 1024);
}
