use memcordon_readiness_verifier::{NativeArguments, current::byte_effects::*};

#[test]
fn raw_effects_reject_cross_stream_mixing_and_incomplete_files() {
    let bytes = (u8::MIN..=u8::MAX).collect::<Vec<_>>();
    let reverse = bytes.iter().copied().rev().collect::<Vec<_>>();
    verify_raw_streams("binary-streams", &bytes, &bytes, &reverse).unwrap();
    verify_raw_streams_expected("binary-streams", &bytes, &bytes, &bytes, &bytes).unwrap();
    assert!(verify_raw_streams("binary-streams", &bytes, &bytes, &bytes).is_err());
    assert!(
        verify_raw_streams(
            "binary-streams",
            &bytes,
            &bytes[..bytes.len() - 1],
            &reverse
        )
        .is_err()
    );
    assert!(verify_raw_streams("bounded-large-output", &bytes, &bytes, &reverse).is_err());
    verify_binary_file(&bytes, &bytes).unwrap();
    assert!(verify_binary_file(&bytes, &reverse).is_err());
    verify_raw_streams("empty-input", &[], &[], &[]).unwrap();
    assert!(verify_raw_streams("empty-input", &[], b"unexpected", &[]).is_err());
}

#[test]
fn raw_native_argv_preserves_empty_whitespace_quotes_and_unix_non_utf8() {
    let argv = NativeArguments::UnixBytes(vec![
        b"fixture".to_vec(),
        vec![],
        b"space and\ttab".to_vec(),
        b"literal\"quote\\".to_vec(),
        vec![u8::MAX],
    ]);
    verify_native_argv(&argv, &argv, "native-argv").unwrap();
    let changed = NativeArguments::UnixBytes(vec![b"fixture".to_vec(), b"normalized".to_vec()]);
    assert!(verify_native_argv(&argv, &changed, "native-argv").is_err());
}
