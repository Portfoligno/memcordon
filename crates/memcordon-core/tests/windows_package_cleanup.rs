use memcordon_core::{
    WINDOWS_PRIVATE_PROTOCOL_VERSION, WINDOWS_PUBLIC_PROTOCOL_VERSION,
    WindowsControlRequestStatusV1, WindowsLauncherRequestV1, WindowsLauncherResponseV1,
    WindowsPackageCleanupOutcomeV1, WindowsProviderRequestV1, WindowsProviderResponseV1,
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
        terminal_outboxes: Some(2),
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
            terminal_outboxes: Some(2),
            detail,
        } if detail.contains("guardian receipt pending")
    ));
}

#[test]
fn package_cleanup_accepts_authenticated_inventory_and_explicit_failure() {
    use WindowsControlRequestStatusV1::{Active, Failed, Ready};

    for (status, attempts_empty, terminal_outboxes) in [
        (Ready, Some(true), Some(0)),
        (Active, Some(false), Some(0)),
        (Active, Some(false), Some(3)),
        (Failed, None, None),
        (Failed, Some(false), None),
        (Failed, Some(false), Some(3)),
        (Failed, Some(true), Some(0)),
    ] {
        let outcome = WindowsPackageCleanupOutcomeV1 {
            status,
            attempts_empty,
            terminal_outboxes,
            detail: "authenticated launcher cleanup evidence".to_owned(),
        };
        assert!(outcome.validate().is_ok(), "{outcome:?}");
    }
}

#[test]
fn package_cleanup_rejects_missing_or_contradictory_success_evidence() {
    use WindowsControlRequestStatusV1::{Active, Failed, Ready};

    for (status, attempts_empty, terminal_outboxes) in [
        (Ready, None, None),
        (Ready, Some(true), None),
        (Ready, Some(true), Some(1)),
        (Ready, Some(false), Some(0)),
        (Ready, None, Some(0)),
        (Active, Some(false), None),
        (Active, None, Some(1)),
        (Active, Some(true), Some(0)),
        (Active, Some(true), Some(1)),
        (Failed, Some(true), Some(1)),
    ] {
        let outcome = WindowsPackageCleanupOutcomeV1 {
            status,
            attempts_empty,
            terminal_outboxes,
            detail: "contradictory launcher cleanup evidence".to_owned(),
        };
        assert!(outcome.validate().is_err(), "{outcome:?}");
    }
}

#[test]
fn package_cleanup_inventory_survives_private_and_bound_public_serialization() {
    use WindowsControlRequestStatusV1::{Active, Failed, Ready};

    for (status, attempts_empty, terminal_outboxes, detail) in [
        (Ready, Some(true), Some(0), "launcher state is empty"),
        (
            Active,
            Some(false),
            Some(2),
            "durable terminal acknowledgement pending",
        ),
        (
            Failed,
            Some(false),
            None,
            "authenticated terminal inventory read failed",
        ),
    ] {
        let private = WindowsLauncherResponseV1::PackageCleanup {
            schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
            status,
            attempts_empty,
            terminal_outboxes,
            detail: detail.to_owned(),
        };
        let encoded = serde_json::to_vec(&private).unwrap();
        let decoded = serde_json::from_slice::<WindowsLauncherResponseV1>(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&private).unwrap()
        );

        let WindowsLauncherResponseV1::PackageCleanup {
            status: forwarded_status,
            attempts_empty: forwarded_empty,
            terminal_outboxes: forwarded_inventory,
            detail: forwarded_detail,
            ..
        } = decoded
        else {
            panic!("cleanup response changed kind");
        };
        let public = WindowsProviderResponseV1::PackageCleanupResult {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            challenge: "bound-package-cleanup-challenge".to_owned(),
            status: forwarded_status,
            attempts_empty: forwarded_empty,
            terminal_outboxes: forwarded_inventory,
            detail: forwarded_detail,
        };
        let encoded = serde_json::to_vec(&public).unwrap();
        let decoded = serde_json::from_slice::<WindowsProviderResponseV1>(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&public).unwrap()
        );
        assert!(matches!(
            decoded,
            WindowsProviderResponseV1::PackageCleanupResult {
                schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                challenge,
                status: actual_status,
                attempts_empty: actual_empty,
                terminal_outboxes: actual_inventory,
                detail: actual_detail,
            } if challenge == "bound-package-cleanup-challenge"
                && actual_status == status
                && actual_empty == attempts_empty
                && actual_inventory == terminal_outboxes
                && actual_detail == detail
        ));
    }
}
