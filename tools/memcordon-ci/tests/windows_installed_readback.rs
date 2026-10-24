use memcordon_ci::{
    release::{artifacts, target, windows_component_readback},
    windows_causal_acceptance::InstalledChannel,
    windows_installed_cases::{InstalledWindowsPayload, SelectedArtifact},
};
use memcordon_core::runtime_manifest::{RuntimeComponentRole as Role, RuntimeManifest};
use std::{fs, path::PathBuf};

struct Fixture {
    _root: tempfile::TempDir,
    retained: PathBuf,
    installed: PathBuf,
    current: InstalledWindowsPayload,
    binaries: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let retained = root.path().join("selected-current-payload");
        let installed = root.path().join("installed-provider");
        fs::create_dir(&retained).unwrap();
        fs::create_dir(&installed).unwrap();
        let target = "aarch64-pc-windows-msvc";
        let source = "0123456789012345678901234567890123456789";
        let version = "0.5.8-dev";
        let mut records = Vec::new();
        let mut selected = Vec::new();
        let mut providers = Vec::new();
        let mut binaries = Vec::new();
        for (binary, role) in [
            ("memcordon", Role::PublicCli),
            ("memcordon-sealed-agent", Role::SealedAgent),
            ("memcordon-target-desktop-bootstrap", Role::DesktopBootstrap),
            ("memcordon-session-broker", Role::SessionBroker),
        ] {
            let name = format!("{binary}.exe");
            // This observer measures bytes and layout; no executable is launched.
            let bytes = binary.as_bytes();
            fs::write(retained.join(&name), bytes).unwrap();
            let artifact = SelectedArtifact {
                path: retained.join(&name),
                sha256: artifacts::checksum(bytes),
            };
            if role != Role::PublicCli {
                fs::write(installed.join(&name), bytes).unwrap();
                providers.push(SelectedArtifact {
                    path: installed.join(&name),
                    sha256: artifact.sha256.clone(),
                });
            }
            records.push(target::runtime_component(role, name, bytes));
            selected.push(artifact);
            binaries.push(binary.to_owned());
        }
        let manifest =
            RuntimeManifest::windows(version.into(), source.into(), target.into(), records)
                .unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(retained.join("runtime-manifest.json"), &bytes).unwrap();
        fs::write(installed.join("runtime-manifest.json"), &bytes).unwrap();
        let fixture = SelectedArtifact {
            path: retained.join("fixture.exe"),
            sha256: artifacts::checksum(b"independent fixture"),
        };
        fs::write(&fixture.path, b"independent fixture").unwrap();
        let current = InstalledWindowsPayload {
            channel: InstalledChannel::NativeBundle,
            source_commit: source.into(),
            version: version.into(),
            target: target.into(),
            artifacts: selected.clone(),
            cli: selected[0].clone(),
            agent: selected[1].clone(),
            components: selected,
            installed_components: providers.clone(),
            fixture,
            workload_diagnostic: None,
            installed_agent: providers[0].clone(),
            installed_manifest: SelectedArtifact {
                path: installed.join("runtime-manifest.json"),
                sha256: artifacts::checksum(&bytes),
            },
            provider: manifest.public_binding(&bytes).unwrap(),
            output_directory: root.path().join("output"),
        };
        Self {
            _root: root,
            retained,
            installed,
            current,
            binaries,
        }
    }

    fn observe(&self) -> memcordon_ci::Result<Vec<serde_json::Value>> {
        windows_component_readback::observe(
            &self.current,
            &self.installed,
            &self.retained,
            &self.binaries,
            &self.current.target,
        )
    }
}

#[test]
fn retained_client_and_only_three_installed_providers_supply_all_four_records() {
    let fixture = Fixture::new();
    assert!(!fixture.installed.join("memcordon.exe").exists());
    let records = fixture.observe().unwrap();
    assert_eq!(records.len(), 4);
    for (record, binary) in records.iter().zip(&fixture.binaries) {
        let expected = if binary == "memcordon" {
            &fixture.current.cli
        } else {
            fixture
                .current
                .installed_components
                .iter()
                .find(|artifact| artifact.path == fixture.installed.join(format!("{binary}.exe")))
                .unwrap()
        };
        assert_eq!(record["binary"], *binary);
        assert_eq!(
            record["path"],
            serde_json::to_value(&expected.path).unwrap()
        );
        assert_eq!(record["sha256"], expected.sha256);
    }
}

#[test]
fn fresh_equal_reads_cannot_replace_prior_selected_hashes() {
    let fixture = Fixture::new();
    fs::write(
        &fixture.current.cli.path,
        b"changed client at same actual and retained path",
    )
    .unwrap();
    let error = fixture.observe().unwrap_err().to_string();
    assert!(
        error.contains("PublicCli") && error.contains("memcordon.exe"),
        "{error}"
    );
    let fixture = Fixture::new();
    fs::write(&fixture.current.agent.path, b"jointly changed provider").unwrap();
    fs::write(
        &fixture.current.installed_agent.path,
        b"jointly changed provider",
    )
    .unwrap();
    assert!(fixture.observe().is_err());
    let mut fixture = Fixture::new();
    fixture.current.cli.sha256 = artifacts::checksum(b"different selected hash");
    fixture.current.components[0].sha256 = fixture.current.cli.sha256.clone();
    assert!(fixture.observe().is_err());
}

#[test]
fn missing_provider_preserves_component_path_and_io_error_context() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.current.installed_agent.path).unwrap();
    let error = fixture.observe().unwrap_err().to_string();
    assert!(
        error.contains("actual role=SealedAgent") && error.contains("memcordon-sealed-agent.exe"),
        "{error}"
    );
    assert!(error.contains("os error"), "{error}");
}

#[test]
fn ambiguous_inventory_outside_paths_and_foreign_bindings_fail_closed() {
    for mutation in 0..8 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => {
                fixture.current.installed_components.pop();
            }
            1 => {
                fixture.current.installed_components[1] =
                    fixture.current.installed_components[0].clone();
            }
            2 => {
                fixture.current.installed_components[0].path =
                    fixture.retained.join("memcordon-sealed-agent.exe");
            }
            3 => {
                fixture.current.components[1] = fixture.current.components[0].clone();
            }
            4 => {
                fixture.binaries[1] = fixture.binaries[0].clone();
            }
            5 => {
                fixture.current.source_commit = "fedcba9876543210fedcba9876543210fedcba98".into();
            }
            6 => {
                fixture.current.installed_manifest.sha256 =
                    artifacts::checksum(b"foreign manifest");
            }
            7 => {
                fixture.binaries[1] = "unexpected-provider".into();
            }
            _ => unreachable!(),
        }
        assert!(fixture.observe().is_err(), "mutation {mutation} accepted");
    }
}
