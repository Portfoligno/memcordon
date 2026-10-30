use memcordon_ci::windows_native_removal::*;
use std::path::{Path, PathBuf};
fn fixture() -> (RemovalReceipt, Vec<PathBuf>, Vec<String>, Vec<Vec<u16>>) {
    let paths = vec![
        PathBuf::from("owned/agent.exe"),
        PathBuf::from("owned/runtime.json"),
    ];
    let services = vec!["guardian".to_owned(), "control".to_owned()];
    let images = image_names([
        Path::new("owned/Agent.EXE"),
        Path::new("owned/Worker.exe"),
        Path::new("owned/Bootstrap.exe"),
    ])
    .unwrap();
    let receipt = RemovalReceipt {
        format: "memcordon.windows-native-removal".into(),
        revision: 2,
        provider_generation: "selected".into(),
        absent_services: services.clone(),
        absent_paths: paths.clone(),
        fixture_processes_absent: true,
        installed_image_processes_absent: true,
        native_component_census: ComponentCensus {
            api: CENSUS_API.into(),
            entries_observed: 141,
            terminal_native_code: 18,
            required_image_names_utf16: images.clone(),
            matching_processes: Vec::new(),
        },
        service_observations: services
            .iter()
            .map(|service_name| ServiceAbsence {
                service_name: service_name.clone(),
                api: "OpenServiceW".into(),
                native_domain: "win32".into(),
                native_code: 1060,
            })
            .collect(),
        path_observations: paths
            .iter()
            .map(|path| PathAbsence {
                path: path.clone(),
                native_domain: "win32".into(),
                native_code: 2,
            })
            .collect(),
    };
    (receipt, paths, services, images)
}
#[test]
fn actual_revision2_census_object_roundtrips_and_matches_exact_selected_images() {
    let (receipt, paths, services, images) = fixture();
    let parsed: RemovalReceipt =
        serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
    parsed
        .validate("selected", &paths, &services, &images)
        .unwrap();
    assert_eq!(
        serde_json::to_value(&parsed).unwrap()["native_component_census"]["entries_observed"],
        141
    );
    assert_eq!(
        image_names([Path::new("owned/AGENT.exe"), Path::new("owned/agent.EXE")]).unwrap(),
        vec!["agent.exe".encode_utf16().collect::<Vec<_>>()]
    );
    assert!(image_names([Path::new("owned/à.exe")]).is_err());
}
#[test]
fn census_and_all_original_absence_generation_guards_remain_strict() {
    for mutation in 0..17 {
        let (mut receipt, paths, services, images) = fixture();
        match mutation {
            0 => receipt.revision = 1,
            1 => receipt.provider_generation = "foreign".into(),
            2 => receipt.native_component_census.api = "other".into(),
            3 => receipt.native_component_census.terminal_native_code = 0,
            4 => receipt.native_component_census.entries_observed = MAX_PROCESS_ENTRIES + 1,
            5 => {
                receipt
                    .native_component_census
                    .required_image_names_utf16
                    .pop();
            }
            6 => receipt
                .native_component_census
                .required_image_names_utf16
                .push("foreign.exe".encode_utf16().collect()),
            7 => {
                receipt.native_component_census.required_image_names_utf16[1] =
                    receipt.native_component_census.required_image_names_utf16[0].clone()
            }
            8 => receipt
                .native_component_census
                .required_image_names_utf16
                .swap(0, 1),
            9 => receipt.service_observations[0].native_code = 5,
            10 => receipt.path_observations[0].native_code = 5,
            11 => receipt.fixture_processes_absent = false,
            12 => receipt.installed_image_processes_absent = false,
            13 => receipt.absent_paths[0] = PathBuf::from("foreign"),
            14 => receipt.absent_services.swap(0, 1),
            15 => receipt.service_observations[0].api = "other".into(),
            _ => receipt.path_observations[0].native_domain = "other".into(),
        }
        assert!(
            receipt
                .validate("selected", &paths, &services, &images)
                .is_err(),
            "mutation{mutation}"
        );
    }
}
#[test]
fn old_string_wrong_types_unknown_fields_and_nonempty_matches_are_not_coerced() {
    for mutation in 0..6 {
        let (receipt, _, _, _) = fixture();
        let mut value = serde_json::to_value(receipt).unwrap();
        match mutation {
            0 => {
                value["native_component_census"] =
                    serde_json::json!("owned-package-image-names-no-live-candidate")
            }
            1 => value["native_component_census"]["entries_observed"] = serde_json::json!(-1),
            2 => {
                value["native_component_census"]["matching_processes"] =
                    serde_json::json!([{"pid":7}])
            }
            3 => value["native_component_census"]["unexpected"] = serde_json::json!(true),
            4 => value["unexpected"] = serde_json::json!(true),
            _ => {
                value["native_component_census"]["required_image_names_utf16"][0][0] =
                    serde_json::json!(65536)
            }
        }
        assert!(serde_json::from_value::<RemovalReceipt>(value).is_err());
    }
}
