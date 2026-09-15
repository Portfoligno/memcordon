use memcordon_ci::reparse_diagnostic::describe;

const APP_EXEC_LINK: u32 = 0x8000_001b;

fn frame(tag: u32, payload: &[u8]) -> Vec<u8> {
    [
        tag.to_le_bytes().as_slice(),
        u16::try_from(payload.len())
            .unwrap()
            .to_le_bytes()
            .as_slice(),
        0_u16.to_le_bytes().as_slice(),
        payload,
    ]
    .concat()
}

fn alias_payload(version: u32, fields: &[&str]) -> Vec<u8> {
    let mut payload = version.to_le_bytes().to_vec();
    for field in fields {
        for unit in field.encode_utf16().chain(std::iter::once(0)) {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
    }
    payload
}

#[test]
fn app_alias_diagnostics_preserve_exact_payload_and_escape_control_characters() {
    let payload = alias_payload(
        3,
        &[
            "Package",
            "App\nentry",
            "C:\\Program Files\\工具\\app.exe",
            "0",
        ],
    );
    let description = describe(&frame(APP_EXEC_LINK, &payload)).unwrap();
    assert!(description.contains("8000001b"), "{description}");
    assert!(description.contains("version=3"), "{description}");
    assert!(
        description.contains(&hex::encode(&payload)),
        "{description}"
    );
    assert!(description.contains("App\\nentry"), "{description}");
    assert_eq!(description.lines().count(), 1);
}

#[test]
fn unknown_tags_versions_and_unpaired_utf16_remain_lossless_diagnostic_evidence() {
    let opaque = [0, 255, 17, 0];
    let unknown = describe(&frame(0x8000_1234, &opaque)).unwrap();
    assert!(unknown.contains("80001234"), "{unknown}");
    assert!(unknown.contains(&hex::encode(opaque)), "{unknown}");
    let future = alias_payload(99, &["future package"]);
    let description = describe(&frame(APP_EXEC_LINK, &future)).unwrap();
    assert!(description.contains("version=99"), "{description}");
    assert!(description.contains(&hex::encode(&future)), "{description}");
    let mut surrogate = 3_u32.to_le_bytes().to_vec();
    for unit in [0xd800_u16, 0] {
        surrogate.extend_from_slice(&unit.to_le_bytes());
    }
    let description = describe(&frame(APP_EXEC_LINK, &surrogate)).unwrap();
    assert!(description.contains("fields_utf16="), "{description}");
    assert!(
        description.contains(&hex::encode(&surrogate)),
        "{description}"
    );
    assert!(!description.contains('\u{fffd}'), "{description}");
}

#[test]
fn malformed_headers_and_alias_strings_fail_without_panicking() {
    let complete = frame(APP_EXEC_LINK, &alias_payload(3, &["package"]));
    let header_length = frame(APP_EXEC_LINK, &[]).len();
    for length in 0..header_length {
        assert!(describe(&complete[..length]).is_err());
    }
    let mut truncated = complete.clone();
    truncated.pop();
    assert!(describe(&truncated).is_err());
    let mut trailing = complete;
    trailing.push(0);
    assert!(describe(&trailing).is_err());
    for payload in [
        vec![],
        vec![0],
        3_u32.to_le_bytes().to_vec(),
        [3_u32.to_le_bytes().as_slice(), &[1]].concat(),
        [3_u32.to_le_bytes().as_slice(), &1_u16.to_le_bytes()].concat(),
    ] {
        assert!(
            describe(&frame(APP_EXEC_LINK, &payload)).is_err(),
            "{payload:?}"
        );
    }
    assert!(describe(&frame(0x8000_1234, &vec![0; 16 * 1024])).is_err());
}

#[test]
fn retargeting_payload_changes_evidence_even_with_identical_alias_metadata() {
    let first = alias_payload(3, &["Package", "App", "C:\\First\\app.exe", "0"]);
    let second = alias_payload(3, &["Package", "App", "C:\\Other\\app.exe", "0"]);
    assert_ne!(
        describe(&frame(APP_EXEC_LINK, &first)).unwrap(),
        describe(&frame(APP_EXEC_LINK, &second)).unwrap()
    );
}
