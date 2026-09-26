use memcordon_ci::private_source_carrier::{encode_source_carrier, parse_source_carrier};
use std::collections::BTreeMap;

#[test]
fn source_carrier_preserves_exact_sorted_original_bytes() {
    let raw = BTreeMap::from([
        ("interval/a/capture.bin".into(), vec![1, 2, 3]),
        ("interval/a/stdout.raw".into(), Vec::new()),
    ]);
    let packed = encode_source_carrier(&raw).unwrap();
    assert_eq!(parse_source_carrier(&packed).unwrap(), raw);
    let mut changed = packed.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(parse_source_carrier(&changed).is_err());
    let mut tail = packed;
    tail.push(0);
    assert!(parse_source_carrier(&tail).is_err());
}

#[test]
fn source_carrier_rejects_cycles_and_unbounded_metadata_before_allocation() {
    for path in [
        "case/source-carrier.v1.bin",
        "case/replay-bundle.v1.bin",
        "../escape",
        "case/origin-commitment.v1.json",
    ] {
        assert!(encode_source_carrier(&BTreeMap::from([(path.into(), vec![1])])).is_err());
    }
    let mut bytes = b"MCSC\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_source_carrier(&bytes).is_err());
    assert!(
        encode_source_carrier(&BTreeMap::from([(
            "case/checkpoint.json".into(),
            Vec::new()
        )]))
        .is_err()
    );
}

#[test]
fn held_binary_carrier_preserves_original_bytes_and_requires_origin_image() {
    use memcordon_ci::private_public_live::HeldPublicTargetSamplesV1;
    use memcordon_ci::private_source_carrier::{decode_held_source, encode_held_source};
    use memcordon_core::workload_codec::hash_bytes;
    let image = vec![0, 255, 128, 1];
    let sample = HeldPublicTargetSamplesV1 {
        schema_version: 1,
        pid: 17,
        start_time_ticks: 42,
        begin_monotonic_ns: 100,
        end_monotonic_ns: 101,
        executable_sha256: hash_bytes(&image),
        executable_device: 1,
        executable_inode: 2,
        tasks: Vec::new(),
        leaves: BTreeMap::from([
            ("image.raw".into(), image.clone()),
            (
                "status.raw".into(),
                b"original uninterpreted raw bytes\n".to_vec(),
            ),
        ]),
    };
    let path = "candidate-c-v3/observer/images/pinned.raw";
    let packed = encode_held_source(&sample, path.into()).unwrap();
    let actual = decode_held_source(&packed, |expected| {
        assert_eq!(expected, path);
        Ok(image.clone())
    })
    .unwrap();
    assert_eq!(actual, sample);
    assert!(decode_held_source(&packed, |_| Ok(vec![9])).is_err());
    let mut changed = packed;
    *changed.last_mut().unwrap() ^= 1;
    assert!(decode_held_source(&changed, |_| Ok(image.clone())).is_err());
}
