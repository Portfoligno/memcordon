use memcordon_readiness_verifier::current::{ReadinessManifestV2, validate_manifest};

const CURRENT: &[u8] = include_bytes!("../../../ci/consumer-readiness-v2.toml");

fn changed(change: impl FnOnce(&mut ReadinessManifestV2)) -> Vec<u8> {
    let mut manifest: ReadinessManifestV2 =
        toml::from_str(std::str::from_utf8(CURRENT).unwrap()).unwrap();
    change(&mut manifest);
    toml::to_string(&manifest).unwrap().into_bytes()
}

#[test]
fn only_current_format_and_exact_inventory_are_accepted() {
    let current = validate_manifest(CURRENT).unwrap();
    assert!(validate_manifest(b"format='unsupported'\nrevision=99\n").is_err());
    assert!(current.iter().any(|case| {
        case.family == "L-ISO-06" && case.scenario == "same-sandbox-uid-cross-attempt"
    }));
    assert!(
        current
            .iter()
            .all(|case| { case.family != "L-ID-02" && case.family != "L-ID-03" })
    );
}

#[test]
fn revision_numbers_cannot_substitute_for_wire_format_identity() {
    let wrong_format = changed(|manifest| {
        manifest.linux.request.format = "unsupported-request".into();
    });
    assert!(validate_manifest(&wrong_format).is_err());
    let old_result = changed(|manifest| manifest.windows.result.revision = 1);
    assert!(validate_manifest(&old_result).is_err());
    let old_profile = changed(|manifest| {
        manifest.linux.runtime_profile = "linux-tcp4-unix-private-v2".into();
    });
    assert!(validate_manifest(&old_profile).is_err());
}

#[test]
fn omitted_duplicate_and_retired_cases_fail_independent_anchors() {
    let omitted = changed(|manifest| {
        manifest.cases.retain(|case| case.family != "C-OWNER");
    });
    assert!(validate_manifest(&omitted).is_err());
    let duplicate = changed(|manifest| manifest.cases.push(manifest.cases[0].clone()));
    assert!(validate_manifest(&duplicate).is_err());
    let retired = changed(|manifest| {
        let case = manifest
            .cases
            .iter_mut()
            .find(|case| case.family == "C-ADMISSION")
            .unwrap();
        case.scenarios.push("unsupported-current-scenario".into());
    });
    assert!(validate_manifest(&retired).is_err());
}

#[test]
fn native_cleanup_cannot_use_empty_or_foreign_platform_inventory() {
    use memcordon_readiness_verifier::current::{
        NativeResourceObservationV2, NativeResourceV2::*, validate_native_inventory,
    };
    let target = "aarch64-unknown-linux-gnu";
    assert!(validate_native_inventory(target, &[]).is_err());
    let mut observations = [
        LinuxAggregate,
        LinuxTarget,
        LinuxNamespaceInit,
        LinuxGuardian,
        LinuxRelays,
        LinuxControlHandles,
        LinuxRootReferences,
        LinuxStaging,
        LinuxFootprint,
    ]
    .into_iter()
    .map(|resource| NativeResourceObservationV2 {
        resource,
        settled: true,
        evidence: "target/channel/native-retirement.json".into(),
    })
    .collect::<Vec<_>>();
    validate_native_inventory(target, &observations).unwrap();
    assert!(validate_native_inventory("aarch64-pc-windows-msvc", &observations).is_err());
    observations[0].evidence = "../unowned.json".into();
    assert!(validate_native_inventory(target, &observations).is_err());
    observations[0].evidence = "target/channel/native-retirement.json".into();
    observations[1].settled = false;
    assert!(validate_native_inventory(target, &observations).is_err());
}
