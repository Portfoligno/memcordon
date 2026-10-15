use memcordon_core::*;

fn site() -> WindowsControlWorkerSiteV1 {
    WindowsControlWorkerSiteV1 {
        format: "memcordon.windows-component-control-worker-site".into(),
        revision: 1,
        attempt_id: "ab".repeat(32),
        nonce: "original-launch".into(),
        request_sha256: "cd".repeat(32),
        fault: WindowsSealedFault::ControlWorkerKilledAfterAuthorization,
        process: WindowsProcessIdentityV1 {
            process_id: 7,
            creation_time_100ns: 134365042738576637,
        },
        thread: WindowsWorkerThreadIdentityV1 {
            thread_id: 11,
            creation_time_100ns: 134365042738576639,
        },
        target_pid: 13,
        target_authorization_observed: true,
    }
}

#[test]
fn control_site_binds_original_request_and_preserves_native_births() {
    let original = site();
    let binds = |value: &WindowsControlWorkerSiteV1| {
        value.binds(
            &original.attempt_id,
            &original.nonce,
            &original.request_sha256,
            original.fault,
            original.target_pid,
        )
    };
    assert!(binds(&original));
    let bytes = serde_json::to_vec(&original).unwrap();
    let decoded: WindowsControlWorkerSiteV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.process.creation_time_100ns, 134365042738576637);
    for field in [
        "attempt",
        "nonce",
        "request",
        "fault",
        "target",
        "process",
        "thread",
        "birth",
        "authorized",
    ] {
        let mut changed = original.clone();
        match field {
            "attempt" => changed.attempt_id = "ef".repeat(32),
            "nonce" => changed.nonce.push('x'),
            "request" => changed.request_sha256 = "ef".repeat(32),
            "fault" => changed.fault = WindowsSealedFault::FrontendKilledAfterAuthorization,
            "target" => changed.target_pid += 1,
            "process" => changed.process.process_id = 0,
            "thread" => changed.thread.thread_id = 0,
            "birth" => changed.process.creation_time_100ns = 0,
            "authorized" => changed.target_authorization_observed = false,
            _ => unreachable!(),
        }
        assert_ne!(changed, original);
        assert!(!binds(&changed), "accepted {field}");
    }
}

#[test]
fn ordinary_authorization_omits_site_and_support_site_roundtrips() {
    let site = site();
    let mut frame = WindowsProviderResponseV3::TargetAuthorized {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        attempt_id: site.attempt_id.clone(),
        nonce: site.nonce.clone(),
        request_sha256: site.request_sha256.clone(),
        child_pid: site.target_pid,
        control_site: None,
    };
    let bytes = serde_json::to_vec(&frame).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("control_site").is_none());
    if let WindowsProviderResponseV3::TargetAuthorized { control_site, .. } = &mut frame {
        *control_site = Some(Box::new(site));
    }
    let bytes = serde_json::to_vec(&frame).unwrap();
    let decoded: WindowsProviderResponseV3 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
}

#[test]
fn control_release_requires_exact_support_selection_and_original_authorization() {
    for fault in [
        WindowsSealedFault::ControlWorkerKilledAfterAuthorization,
        WindowsSealedFault::ControlServiceKilledAfterAuthorization,
    ] {
        let original = site();
        let release = WindowsProviderRequestV3::CertificationControlReleased {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            attempt_id: original.attempt_id.clone(),
            nonce: original.nonce.clone(),
            request_sha256: original.request_sha256.clone(),
            fault,
            target_pid: original.target_pid,
        };
        let binds = |value: &WindowsProviderRequestV3| {
            value.control_release_binds(
                &original.attempt_id,
                &original.nonce,
                &original.request_sha256,
                fault,
                original.target_pid,
            )
        };
        assert!(binds(&release));
        let value = serde_json::to_value(&release).unwrap();
        assert_eq!(value["message"], "certification-control-released");
        for (field, changed) in [
            ("schema_version", serde_json::json!(1)),
            ("attempt_id", serde_json::json!("ef".repeat(32))),
            ("nonce", serde_json::json!("foreign")),
            ("request_sha256", serde_json::json!("ef".repeat(32))),
            (
                "fault",
                serde_json::json!("frontend-killed-after-authorization"),
            ),
            ("target_pid", serde_json::json!(14)),
        ] {
            let mut changed_value = value.clone();
            changed_value[field] = changed;
            let decoded = serde_json::from_value(changed_value).unwrap();
            assert!(!binds(&decoded), "accepted foreign {field}");
        }
        assert!(!binds(&WindowsProviderRequestV3::Probe {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION
        }));
        assert!(!release.control_release_binds(
            &original.attempt_id,
            &original.nonce,
            &original.request_sha256,
            WindowsSealedFault::FrontendKilledAfterAuthorization,
            original.target_pid
        ));
        for field in ["nonce", "target_pid", "fault"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<WindowsProviderRequestV3>(missing).is_err());
        }
        let mut unknown = value.clone();
        unknown["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WindowsProviderRequestV3>(unknown).is_err());
    }
}
