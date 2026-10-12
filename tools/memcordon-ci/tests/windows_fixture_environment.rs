#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/fixture_environment.rs"]
mod fixture_environment;

#[test]
fn explicit_system_prerequisite_is_exact_and_never_ambient() {
    let root: Vec<u16> = r"C:\Windows".encode_utf16().collect();
    let entries = fixture_environment::from_system(&root, 12).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, "=C:".encode_utf16().collect::<Vec<_>>());
    assert_eq!(entries[0].value, "C:\\".encode_utf16().collect::<Vec<_>>());
    assert_eq!(
        entries[1].name,
        "PROCESSOR_ARCHITECTURE".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(entries[1].value, "ARM64".encode_utf16().collect::<Vec<_>>());
    assert_eq!(
        entries[2].name,
        "SystemRoot".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(entries[2].value, root);
    let block = memcordon_core::encode_windows_environment_block(&entries).unwrap();
    assert_eq!(
        block,
        "=C:=C:\\\0PROCESSOR_ARCHITECTURE=ARM64\0SystemRoot=C:\\Windows\0\0"
            .encode_utf16()
            .collect::<Vec<_>>()
    );
    for invalid in [
        "",
        "relative",
        r"\\server\Windows",
        r"%SystemRoot%\Windows",
        "C:\\Win\0dows",
        "C:\\Windows=bad",
    ] {
        assert!(
            fixture_environment::from_system(&invalid.encode_utf16().collect::<Vec<_>>(), 12)
                .is_err(),
            "accepted {invalid:?}"
        );
    }
    assert!(fixture_environment::from_system(&vec![b'C' as u16; 2048], 12).is_err());
    assert_eq!(
        fixture_environment::from_system(&root, 9).unwrap()[1].value,
        "AMD64".encode_utf16().collect::<Vec<_>>()
    );
    for unsupported in [0, 5, 6, u16::MAX] {
        assert!(fixture_environment::from_system(&root, unsupported).is_err());
    }
    let lower =
        fixture_environment::from_system(&r"d:\Windows".encode_utf16().collect::<Vec<_>>(), 9)
            .unwrap();
    assert_eq!(lower[0].name, "=D:".encode_utf16().collect::<Vec<_>>());
    assert_eq!(lower[0].value, "D:\\".encode_utf16().collect::<Vec<_>>());
}
