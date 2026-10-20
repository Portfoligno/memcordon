use memcordon_windows_launch_core::{
    DesktopBindingV1, ExactHandleListV1, PreparedEnvironmentIdentityV1, ProductionLoaderPlan,
    ProductionLoaderPlanInputV1, ProductionLoaderPlanV1, ProductionLoaderPlanV2,
    TargetTokenIdentityV1, build_package_loader_plan, build_package_loader_plan_v2,
};

fn input() -> ProductionLoaderPlanInputV1 {
    let digest = "ab".repeat(32);
    ProductionLoaderPlanInputV1 {
        executable_path_utf16: "C:\\MemCordon\\bootstrap.exe".encode_utf16().collect(),
        executable_sha256: digest.clone(),
        command_line_sha256: digest.clone(),
        environment: PreparedEnvironmentIdentityV1 {
            encoding: "utf-16le-double-nul".into(),
            byte_len: 42,
            sha256: digest.clone(),
        },
        current_directory_sha256: digest.clone(),
        desktop: DesktopBindingV1 {
            exact_name: "MemCordon\\Qualification".into(),
            security_descriptor_sha256: digest.clone(),
            window_station_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
            desktop_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        },
        process_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        thread_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        job_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        loader_ready_pipe_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        target_token: TargetTokenIdentityV1 {
            envelope_sha256: digest,
            authentication_id: 7,
            session_id: 0,
        },
        inherited_handles: ExactHandleListV1::none(),
        job_at_creation: true,
    }
}

#[test]
fn consoleless_policy_is_versioned_and_digest_bound() {
    let legacy = build_package_loader_plan(input()).unwrap();
    let consoleless = build_package_loader_plan_v2(input()).unwrap();
    assert_eq!(legacy.creation_flags(), 0x80404);
    assert_eq!(consoleless.creation_flags(), 0x8040c);
    assert_ne!(
        legacy.launch_plan_sha256(),
        consoleless.launch_plan_sha256()
    );
    let old = serde_json::to_value(&legacy).unwrap();
    let new = serde_json::to_value(&consoleless).unwrap();
    assert_eq!(old["schema_version"], 1);
    assert_eq!(new["schema_version"], 2);
    assert_eq!(
        serde_json::from_value::<ProductionLoaderPlanV1>(old.clone()).unwrap(),
        legacy
    );
    assert_eq!(
        serde_json::from_value::<ProductionLoaderPlanV2>(new.clone()).unwrap(),
        consoleless
    );
    assert!(serde_json::from_value::<ProductionLoaderPlanV1>(new).is_err());
    assert!(serde_json::from_value::<ProductionLoaderPlanV2>(old).is_err());
}

#[test]
fn consoleless_parser_rejects_policy_and_digest_substitution() {
    let plan = build_package_loader_plan_v2(input()).unwrap();
    let original = serde_json::to_value(plan).unwrap();
    for (field, value) in [
        ("schema_version", serde_json::json!(1)),
        ("creation_flags", serde_json::json!(0x80404)),
        ("creation_flags", serde_json::json!(0x8040d)),
        ("launch_plan_sha256", serde_json::json!("cd".repeat(32))),
        ("executable_sha256", serde_json::json!("cd".repeat(32))),
    ] {
        let mut altered = original.clone();
        altered[field] = value;
        assert!(
            serde_json::from_value::<ProductionLoaderPlanV2>(altered).is_err(),
            "{field}"
        );
    }
}

#[test]
fn unsupported_plan_versions_never_construct_or_deserialize() {
    assert!(ProductionLoaderPlan::<0>::new(input()).is_err());
    assert!(ProductionLoaderPlan::<3>::new(input()).is_err());
    let value = serde_json::to_value(build_package_loader_plan_v2(input()).unwrap()).unwrap();
    assert!(serde_json::from_value::<ProductionLoaderPlan<0>>(value.clone()).is_err());
    assert!(serde_json::from_value::<ProductionLoaderPlan<3>>(value).is_err());
}
