#[path = "private/fixture_namespace_module_bundle.rs"]
mod bundle;
#[path = "private/fixture_namespace_primary_protocol.rs"]
#[allow(dead_code)]
mod protocol;

use protocol::{
    ApiSetObservation, ApiSetResolution, ApiSetStage, ModuleLocation, ModuleProvenance, ModuleRole,
};
use std::time::{Duration, Instant};

fn provenance() -> ModuleProvenance {
    ModuleProvenance::Present {
        started_qpc: 1,
        finished_qpc: 2,
        diagnostic_only: true,
        acceptance_authority: false,
        import_matches_resolved: true,
        api_set_resolution: ApiSetResolution {
            contract: protocol::API_SET_CONTRACT.into(),
            symbol: protocol::API_SET_SYMBOL.into(),
            resolution_method: protocol::API_SET_METHOD.into(),
            observation: ApiSetObservation::Unavailable {
                stage: ApiSetStage::LoadContract,
                raw_error: Some(126),
                deadline: false,
            },
        },
        modules: [
            ModuleRole::ImportAddress,
            ModuleRole::Kernel32ExportTable,
            ModuleRole::ResolvedExport,
            ModuleRole::NtOpenEvent,
        ]
        .into_iter()
        .map(|role| ModuleLocation {
            role,
            base: 4096,
            address: 4096,
            rva: 0,
            path_utf16: "C:\\Windows\\System32\\image.dll".encode_utf16().collect(),
        })
        .collect(),
    }
}

fn with_resolved_contract() -> ModuleProvenance {
    let mut value = provenance();
    let ModuleProvenance::Present {
        modules,
        api_set_resolution,
        ..
    } = &mut value
    else {
        unreachable!()
    };
    let mut host = modules[0].clone();
    host.role = ModuleRole::ApiSetOpenEvent;
    modules.push(host);
    api_set_resolution.observation = ApiSetObservation::Resolved {
        same_as_original_thunk: true,
    };
    value
}

#[test]
fn five_roles_keep_four_distinct_file_and_existing_byte_bounds() {
    let mut value = with_resolved_contract();
    let grouped = bundle::groups(&value).unwrap();
    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped[0].1.len(), 5);
    let ModuleProvenance::Present {
        modules,
        import_matches_resolved,
        api_set_resolution,
        ..
    } = &mut value
    else {
        unreachable!()
    };
    *import_matches_resolved = false;
    api_set_resolution.observation = ApiSetObservation::Resolved {
        same_as_original_thunk: false,
    };
    for (index, module) in modules.iter_mut().enumerate() {
        let ordinal = index.min(3);
        module.base = 4096 * (ordinal as u64 + 1);
        module.address = module.base;
        module.path_utf16 = format!("C:\\Windows\\System32\\image-{ordinal}.dll")
            .encode_utf16()
            .collect();
    }
    assert_eq!(bundle::groups(&value).unwrap().len(), 4);
    let ModuleProvenance::Present { modules, .. } = &mut value else {
        unreachable!()
    };
    modules[4].base = 24576;
    modules[4].address = 24576;
    modules[4].path_utf16 = "C:\\Windows\\System32\\fifth.dll".encode_utf16().collect();
    assert!(value.validate().is_ok());
    assert_eq!(
        bundle::groups(&value).unwrap_err().to_string(),
        "distinct module file bound"
    );
    assert_eq!(bundle::TOTAL_LIMIT, 4 * bundle::IMAGE_LIMIT);
}

#[test]
fn optional_resolution_timeout_retains_facts_without_source_reads() {
    let mut value = provenance();
    assert!(bundle::source_reads_permitted(&value, 3).unwrap());
    assert!(bundle::source_reads_permitted(&value, 2).is_err());
    let ModuleProvenance::Present {
        api_set_resolution, ..
    } = &mut value
    else {
        unreachable!()
    };
    api_set_resolution.observation = ApiSetObservation::Unavailable {
        stage: ApiSetStage::ResolveExport,
        raw_error: Some(1460),
        deadline: true,
    };
    assert!(!bundle::source_reads_permitted(&value, 2).unwrap());
    assert!(bundle::source_reads_permitted(&value, 1).is_err());
    assert_eq!(
        serde_json::to_value(&value).unwrap()["api_set_resolution"]["observation"]["raw_error"],
        1460
    );
}

#[test]
fn identical_module_paths_preserve_all_roles_without_duplicate_copies() {
    let groups = bundle::groups(&provenance()).unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].1.len(), 4);
    let mut value = provenance();
    let ModuleProvenance::Present { modules, .. } = &mut value else {
        unreachable!()
    };
    modules[3].path_utf16 = "D:\\other.dll".encode_utf16().collect();
    modules[3].base = 8192;
    modules[3].address = 8192;
    assert_eq!(bundle::groups(&value).unwrap().len(), 2);
}

#[test]
fn malformed_records_never_reach_disk_selection() {
    for mutation in 0..4 {
        let mut value = provenance();
        let ModuleProvenance::Present { modules, .. } = &mut value else {
            unreachable!()
        };
        match mutation {
            0 => modules[0].path_utf16.push(0),
            1 => modules[0].path_utf16 = vec![0xd800],
            2 => modules[0].rva = 1,
            _ => modules[0].role = ModuleRole::NtOpenEvent,
        }
        assert!(bundle::groups(&value).is_err());
    }
}

#[test]
fn image_and_total_bounds_do_not_renew_original_cutoff() {
    let deadline = Instant::now() + Duration::from_secs(1);
    assert!(
        bundle::check_budget(
            bundle::IMAGE_LIMIT,
            bundle::TOTAL_LIMIT - bundle::IMAGE_LIMIT,
            deadline
        )
        .is_ok()
    );
    assert!(bundle::check_budget(bundle::IMAGE_LIMIT + 1, 0, deadline).is_err());
    assert!(bundle::check_budget(1, bundle::TOTAL_LIMIT, deadline).is_err());
    assert!(bundle::check_budget(1, u64::MAX, deadline).is_err());
    assert_eq!(
        bundle::check_budget(0, 0, Instant::now())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
}

#[test]
fn partial_changed_and_expired_copy_never_claims_complete_bytes() {
    let before = serde_json::json!({"id":1,"size":8,"write":2});
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut entry = bundle::unavailable_entry(&[], &[]);
    for (after, copied, cutoff) in [
        (serde_json::json!({"id":2,"size":8,"write":2}), 8, deadline),
        (before.clone(), 7, deadline),
        (before.clone(), 8, Instant::now()),
    ] {
        let result =
            bundle::completed_bytes(&before, &after, 8, copied, cutoff, "module-0.bin", "digest");
        assert!(result.is_err());
        entry["errors"] = serde_json::json!([result.unwrap_err().to_string()]);
        assert!(entry["bytes"].is_null());
    }
    entry["bytes"] =
        bundle::completed_bytes(&before, &before, 8, 8, deadline, "module-0.bin", "digest")
            .unwrap();
    assert_eq!(entry["bytes"]["length"], 8);
}
