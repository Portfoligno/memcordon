use memcordon_ci::{CiError, Result, release, windows_installed_cases, windows_readiness_adapter};
use memcordon_core::{
    BoundedText, DiagnosticSha256, PublicProviderBindingV1, WindowsRecoveryInventoryV1,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[path = "../src/release/original_windows_recovery_receipt.rs"]
mod contract;

struct Fixture {
    summary: windows_readiness_adapter::RecoveryCleanup,
    directory: PathBuf,
    cli: windows_installed_cases::SelectedArtifact,
    provider: PublicProviderBindingV1,
    agent_hash: String,
    manifest_hash: String,
    files: BTreeMap<PathBuf, Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let directory = PathBuf::from("owned/cleanup-0/recovery");
        let cli = windows_installed_cases::SelectedArtifact {
            path: PathBuf::from("owned/memcordon.exe"),
            sha256: "a".repeat(64),
        };
        let provider = PublicProviderBindingV1 {
            generation: BoundedText::new("selected-generation").unwrap(),
            source_commit: BoundedText::new(&"b".repeat(40)).unwrap(),
            runtime_manifest_sha256: DiagnosticSha256::from_bytes([2; 32]),
        };
        let agent_hash = "c".repeat(64);
        let manifest_hash = String::from(provider.runtime_manifest_sha256.clone());
        let config = json!({"service_type":16,"start_type":3,"error_control":1,"binary_path_utf16":r"C:\owned\memcordon-sealed-agent.exe".encode_utf16().collect::<Vec<_>>(),"service_start_name_utf16":"LocalSystem".encode_utf16().collect::<Vec<_>>()});
        let mut config_bytes = Vec::new();
        for key in ["service_type", "start_type", "error_control"] {
            config_bytes.extend((config[key].as_u64().unwrap() as u32).to_le_bytes());
        }
        for key in ["binary_path_utf16", "service_start_name_utf16"] {
            let units: Vec<u16> = serde_json::from_value(config[key].clone()).unwrap();
            config_bytes.extend((units.len() as u64).to_le_bytes());
            for unit in units {
                config_bytes.extend(unit.to_le_bytes());
            }
        }
        let config_hash = release::artifacts::checksum(&config_bytes);
        let guardian = json!({"format":"memcordon.windows-native-guardian-quiescence","revision":1,"image_sha256":agent_hash,"runtime_manifest_sha256":manifest_hash,"slots":(0..8).map(|index|json!({"service_name":format!("MemCordonSealedGuardian-{index:03}"),"current_state":1,"process_id":0,"configuration":config,"configuration_sha256":config_hash})).collect::<Vec<_>>()});
        let inventory = WindowsRecoveryInventoryV1 {
            schema_version: 1,
            challenge: "d".repeat(64),
            provider_generation: provider.generation.as_str().into(),
            current_boot_identity: "observed-boot".into(),
            executing: 0,
            incomplete_proof: 0,
            unacknowledged_outboxes: 0,
            ack_retirement_in_progress: 0,
            completed_tombstones: 2,
            active_admissions: 0,
            quarantined: 0,
        };
        let argv = ["windows-recover", "converge", "30000"]
            .map(|value| value.encode_utf16().collect::<Vec<_>>());
        let invocation = json!({"format":"memcordon.windows-native-recovery-invocation","revision":1,"cli":cli,"provider":provider,"cwd":directory,"environment_cleared":true,"command_budget_millis":30100,"argv_utf16":argv});
        let mut files = BTreeMap::new();
        for (name, bytes) in [
            (
                "recovery-invocation.json",
                serde_json::to_vec(&invocation).unwrap(),
            ),
            (
                "recovery.stdout.bin",
                serde_json::to_vec(&inventory).unwrap(),
            ),
            ("recovery.stderr.bin", Vec::new()),
            (
                "guardian-quiescence.json",
                serde_json::to_vec(&guardian).unwrap(),
            ),
        ] {
            files.insert(directory.join(name), bytes);
        }
        let artifacts = files
            .iter()
            .map(|(path, bytes)| windows_installed_cases::SelectedArtifact {
                path: path.clone(),
                sha256: release::artifacts::checksum(bytes),
            })
            .collect();
        Self {
            summary: windows_readiness_adapter::RecoveryCleanup {
                output_directory: directory.clone(),
                artifacts,
                native_status: Some(0),
                deadline_exhausted: false,
                recovery: Ok(()),
                native_quiescence: Ok(()),
            },
            directory,
            cli,
            provider,
            agent_hash,
            manifest_hash,
            files,
        }
    }
    fn validate(&self) -> Result<()> {
        contract::validate(
            &self.summary,
            &contract::ExpectedRecovery {
                directory: &self.directory,
                cli: &self.cli,
                provider: &self.provider,
                agent_sha256: &self.agent_hash,
                manifest_sha256: &self.manifest_hash,
            },
            |path| {
                self.files
                    .get(path)
                    .cloned()
                    .ok_or_else(|| CiError::Message("fixture custody unavailable".into()))
            },
        )
    }
    fn edit(&mut self, name: &str, mutate: impl FnOnce(&mut Value)) {
        let path = self.directory.join(name);
        let mut value = serde_json::from_slice(&self.files[&path]).unwrap();
        mutate(&mut value);
        let bytes = serde_json::to_vec(&value).unwrap();
        self.summary
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.path == path)
            .unwrap()
            .sha256 = release::artifacts::checksum(&bytes);
        self.files.insert(path, bytes);
    }
}

#[test]
fn complete_four_artifact_disk_receipt_uses_the_same_contract_for_initial_and_recovered_settlement()
{
    let fixture = Fixture::new();
    fixture.validate().unwrap();
    let retained = serde_json::to_vec(&fixture.summary).unwrap();
    let parsed: windows_readiness_adapter::RecoveryCleanup =
        serde_json::from_slice(&retained).unwrap();
    assert_eq!(parsed.artifacts.len(), 4);
    assert!(parsed.artifacts.iter().all(|artifact|artifact.path.file_name()!=Some(std::ffi::OsStr::new("cleanup.json"))));
    let mut recovered = fixture;
    recovered.summary = parsed;
    recovered.validate().unwrap();
}
#[test]
fn recovery_artifact_set_remains_exact_unique_contained_and_hash_bound() {
    for mutation in 0..6 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => fixture.summary.artifacts.retain(|artifact| {
                artifact.path.file_name() != Some(std::ffi::OsStr::new("guardian-quiescence.json"))
            }),
            1 => fixture
                .summary
                .artifacts
                .push(fixture.summary.artifacts[0].clone()),
            2 => fixture.summary.artifacts[1] = fixture.summary.artifacts[0].clone(),
            3 => {
                fixture.summary.artifacts[0].path =
                    Path::new("foreign").join("guardian-quiescence.json")
            }
            4 => fixture.summary.artifacts[0].path = fixture.directory.join("unexpected.json"),
            _ => fixture.summary.artifacts[0].sha256 = "0".repeat(64),
        }
        assert!(fixture.validate().is_err());
    }
    let mut fixture = Fixture::new();
    fixture
        .files
        .get_mut(&fixture.directory.join("recovery.stderr.bin"))
        .unwrap()
        .extend(b"changed");
    assert!(fixture.validate().is_err());
}
#[test]
fn guardian_quiescence_requires_selected_runtime_all_eight_slots_and_actual_stopped_configuration()
{
    for mutation in 0..9 {
        let mut fixture = Fixture::new();
        fixture.edit("guardian-quiescence.json", |value| match mutation {
            0 => value["image_sha256"] = json!("f".repeat(64)),
            1 => value["runtime_manifest_sha256"] = json!("e".repeat(64)),
            2 => {
                value["slots"].as_array_mut().unwrap().pop();
            }
            3 => value["slots"][1] = value["slots"][0].clone(),
            4 => value["slots"][0]["service_name"] = json!("unselected-guardian"),
            5 => value["slots"][0]["current_state"] = json!(4),
            6 => value["slots"][0]["process_id"] = json!(123),
            7 => value["slots"][0]["configuration"]["start_type"] = json!(2),
            _ => value["slots"][0]["configuration_sha256"] = json!("d".repeat(64)),
        });
        // Hashes are refreshed above: failures exercise actual receipt semantics.
        assert!(fixture.validate().is_err());
    }
}
#[test]
fn successful_summary_still_requires_native_success_quiescence_and_original_deadline_directory() {
    for mutation in 0..6 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => fixture.summary.native_status = None,
            1 => fixture.summary.native_status = Some(1),
            2 => fixture.summary.deadline_exhausted = true,
            3 => fixture.summary.recovery = Err("recovery failed".into()),
            4 => fixture.summary.native_quiescence = Err("guardian remains live".into()),
            _ => fixture.summary.output_directory = PathBuf::from("escaped/recovery"),
        }
        assert!(fixture.validate().is_err());
    }
}
#[test]
fn original_invocation_provider_budget_and_zero_recovery_authority_remain_mandatory() {
    for mutation in 0..7 {
        let mut fixture = Fixture::new();
        fixture.edit("recovery-invocation.json", |value| match mutation {
            0 => value["cli"]["sha256"] = json!("f".repeat(64)),
            1 => value["provider"]["generation"] = json!("foreign-generation"),
            2 => value["cwd"] = json!("foreign"),
            3 => value["environment_cleared"] = json!(false),
            4 => value["command_budget_millis"] = json!(60001),
            5 => value["argv_utf16"][0] = json!("other-command".encode_utf16().collect::<Vec<_>>()),
            _ => value["argv_utf16"][2] = json!("30001".encode_utf16().collect::<Vec<_>>()),
        });
        assert!(fixture.validate().is_err());
    }
    for field in [
        "provider_generation",
        "executing",
        "incomplete_proof",
        "unacknowledged_outboxes",
        "ack_retirement_in_progress",
        "active_admissions",
        "quarantined",
    ] {
        let mut fixture = Fixture::new();
        fixture.edit("recovery.stdout.bin", |value| {
            value[field] = if field == "provider_generation" {
                json!("foreign")
            } else {
                json!(1)
            }
        });
        assert!(fixture.validate().is_err());
    }
}
