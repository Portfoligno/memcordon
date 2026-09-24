use std::collections::BTreeMap;

use memcordon_ci::config::{self, Release};
use memcordon_core::runtime_manifest::{
    NativeProviderProtocols, RuntimeManifestV2, SealedRuntimeV2,
};

fn markdown_table(document: &str, heading: &str) -> BTreeMap<String, String> {
    let table = document
        .split_once(heading)
        .expect("documented table heading must exist")
        .1;
    table
        .lines()
        .take_while(|line| line.starts_with("| "))
        .map(|line| {
            let cells = line
                .strip_prefix("| ")
                .and_then(|line| line.strip_suffix(" |"))
                .expect("table row must have enclosing pipes")
                .split_once(" | ")
                .expect("table row must have exactly two cells");
            (cells.0.to_owned(), cells.1.to_owned())
        })
        .collect()
}

fn release() -> Release {
    toml::from_str(include_str!("../../../ci/release.toml"))
        .expect("release configuration must parse")
}

#[test]
fn reference_runtime_inventory_matches_release_configuration() {
    let documented = markdown_table(
        include_str!("../../../docs/reference.md"),
        "| Target | Runtime components |\n| --- | --- |\n",
    );
    let configured: BTreeMap<_, _> = release()
        .assets
        .target
        .into_iter()
        .map(|target| {
            (
                target.id,
                target
                    .executable
                    .into_iter()
                    .map(|component| component.archive_path)
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        })
        .collect();
    assert_eq!(documented, configured);
}

#[test]
fn workload_v1_version_matrix_matches_frozen_runtime_and_release() {
    let documented = markdown_table(
        include_str!("../../../docs/spec-workload-contract-v1.md"),
        "| Surface | Implemented revision |\n| --- | --- |\n",
    );
    let linux = RuntimeManifestV2::linux(String::new(), String::new(), String::new(), vec![]);
    let windows = RuntimeManifestV2::windows(String::new(), String::new(), String::new(), vec![]);
    let SealedRuntimeV2::Included {
        native_protocols:
            NativeProviderProtocols::Linux {
                provider_contract,
                launch_wire,
            },
        execution_report_schema,
        plan_report_schema,
        doctor_report_schema,
        workload_contract_schema,
        ..
    } = linux.sealed
    else {
        panic!("Linux V1 runtime shape changed");
    };
    let SealedRuntimeV2::Included {
        native_protocols:
            NativeProviderProtocols::Windows {
                public_wire,
                private_wire,
                ..
            },
        ..
    } = windows.sealed
    else {
        panic!("Windows V1 runtime shape changed");
    };
    assert_eq!(
        documented["Execution / plan / doctor report"],
        format!("{execution_report_schema} / {plan_report_schema} / {doctor_report_schema}")
    );
    assert_eq!(
        documented["Workload contract and profile semantics"],
        workload_contract_schema.to_string()
    );
    assert_eq!(
        documented["Generic provider contract / Linux launch wire"],
        format!("{provider_contract} / {launch_wire}")
    );
    assert_eq!(
        documented["Windows public / private wire"],
        format!("{public_wire} / {private_wire}")
    );
    assert_eq!(
        documented["Runtime manifest"],
        linux.schema_version.to_string()
    );
    assert_eq!(
        documented["Release configuration / release manifest"],
        format!("{0} / {0}", config::RELEASE_SCHEMA_VERSION)
    );
}
