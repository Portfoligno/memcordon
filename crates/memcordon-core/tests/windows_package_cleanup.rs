use memcordon_core::{
    WINDOWS_PRIVATE_PROTOCOL_VERSION, WINDOWS_PUBLIC_PROTOCOL_VERSION,
    WindowsControlRequestStatusV1, WindowsLauncherRequestV1, WindowsLauncherResponseV1,
    WindowsProviderRequestV1,
};

#[test]
fn package_cleanup_deadline_is_preserved_across_public_and_private_protocols() {
    let public = WindowsProviderRequestV1::PackageCleanup {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        challenge: "cleanup-challenge".to_owned(),
        deadline_millis: 12_345,
    };
    let public_json = serde_json::to_vec(&public).unwrap();
    assert_eq!(
        serde_json::from_slice::<WindowsProviderRequestV1>(&public_json).unwrap(),
        public
    );

    let private = WindowsLauncherRequestV1::PackageCleanup {
        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        deadline_millis: 12_345,
    };
    let private_json = serde_json::to_vec(&private).unwrap();
    assert_eq!(
        serde_json::from_slice::<WindowsLauncherRequestV1>(&private_json).unwrap(),
        private
    );
}

#[test]
fn launcher_package_cleanup_reports_typed_retained_state() {
    let response = WindowsLauncherResponseV1::PackageCleanup {
        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        status: WindowsControlRequestStatusV1::Active,
        attempts_empty: Some(false),
        detail: "MCSEALED-WINDOWS-PACKAGE-ACTIVE: guardian receipt pending".to_owned(),
    };
    let json = serde_json::to_vec(&response).unwrap();
    let decoded = serde_json::from_slice::<WindowsLauncherResponseV1>(&json).unwrap();
    assert!(matches!(
        decoded,
        WindowsLauncherResponseV1::PackageCleanup {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            status: WindowsControlRequestStatusV1::Active,
            attempts_empty: Some(false),
            detail,
        } if detail.contains("guardian receipt pending")
    ));
}
