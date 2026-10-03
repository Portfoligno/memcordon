use std::collections::BTreeMap;

use memcordon_ci::config::{self, Release};
use memcordon_core::runtime_manifest::{
    NativeProviderProtocols, RuntimeComponentRecord, RuntimeManifest, SealedRuntime,
};

fn markdown_table(document: &str, heading: &str) -> BTreeMap<String, String> {
    let lines: Vec<_> = document.lines().collect();
    let heading: Vec<_> = heading.lines().collect();
    assert!(
        !heading.is_empty(),
        "documented table heading must not be empty"
    );
    let start = lines
        .windows(heading.len())
        .position(|candidate| candidate == heading)
        .expect("documented table heading must exist")
        + heading.len();
    lines[start..]
        .iter()
        .copied()
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

#[test]
fn markdown_tables_preserve_exact_cells_across_checkout_line_endings() {
    let document = "intro\n| Target | Runtime components |\n| --- | --- |\n| linux | agent, launcher |\n| windows | agent.exe |\n\ntrailer\n";
    let heading = "| Target | Runtime components |\n| --- | --- |\n";
    let expected = BTreeMap::from([
        ("linux".into(), "agent, launcher".into()),
        ("windows".into(), "agent.exe".into()),
    ]);
    assert_eq!(markdown_table(document, heading), expected);
    assert_eq!(
        markdown_table(&document.replace('\n', "\r\n"), heading),
        expected
    );
    assert_eq!(
        markdown_table(document, &heading.replace('\n', "\r\n")),
        expected
    );
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
fn workload_version_matrix_matches_named_runtime_and_release() {
    let documented = markdown_table(
        include_str!("../../../docs/spec-workload-contract-v1.md"),
        "| Surface | Implemented revision |\n| --- | --- |\n",
    );
    let manifest = |windows: bool| {
        let asset = release()
            .assets
            .target
            .into_iter()
            .find(|asset| asset.id == if windows { "windows-x64" } else { "linux-x64" })
            .unwrap();
        let components = asset
            .executable
            .into_iter()
            .map(|component| RuntimeComponentRecord {
                id: match component.role {
                    memcordon_core::runtime_manifest::RuntimeComponentRole::PublicCli => {
                        "public-cli"
                    }
                    memcordon_core::runtime_manifest::RuntimeComponentRole::SealedAgent => {
                        "sealed-agent"
                    }
                    memcordon_core::runtime_manifest::RuntimeComponentRole::Arm32AbiHelper => {
                        "arm32-abi-helper"
                    }
                    memcordon_core::runtime_manifest::RuntimeComponentRole::DesktopBootstrap => {
                        "desktop-bootstrap"
                    }
                    memcordon_core::runtime_manifest::RuntimeComponentRole::SessionBroker => {
                        "session-broker"
                    }
                }
                .into(),
                path: component.archive_path,
                role: component.role,
                size: 1,
                mode: component.mode,
                sha256: String::from(memcordon_core::DiagnosticSha256::from_bytes([7; 32])),
            })
            .collect();
        if windows {
            RuntimeManifest::windows(
                "1.0.0".into(),
                "a".repeat(40),
                asset.rust_target,
                components,
            )
        } else {
            RuntimeManifest::linux(
                "1.0.0".into(),
                "a".repeat(40),
                asset.rust_target,
                components,
            )
        }
        .unwrap()
    };
    let linux = manifest(false);
    let windows = manifest(true);
    let SealedRuntime::Included {
        native_protocols:
            NativeProviderProtocols::Linux {
                provider_contract,
                launch_wire,
            },
        workload_contract_schema,
        ..
    } = linux.sealed
    else {
        panic!("Linux V1 runtime shape changed");
    };
    let SealedRuntime::Included {
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
        "memcordon.result / memcordon.plan / memcordon.capabilities revision 1"
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
        format!("{} revision {}", linux.format, linux.revision)
    );
    assert_eq!(
        documented["Release configuration / release manifest"],
        format!("{0} / {0}", config::RELEASE_SCHEMA_VERSION)
    );
}
