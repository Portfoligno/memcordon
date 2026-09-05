use std::ffi::OsString;
use std::fs;
use std::path::Path;

use memcordon_core::{WindowsLoaderQualificationOutcomeV2, WindowsQualificationReceiptV1};
use memcordon_windows_launch_core::ProductionLoaderPlanV1;
use serde::de::DeserializeOwned;

use crate::{CiError, Result};

const ARTIFACT_NAMES: [&str; 3] = [
    "production-loader-plan-v1.json",
    "qualification.json",
    "production-loader-result-v2.json",
];

#[derive(Debug)]
pub struct ReadyWindowsQualificationArtifacts {
    pub receipt: WindowsQualificationReceiptV1,
    pub plan: ProductionLoaderPlanV1,
}

pub fn windows_ephemeral_install_arguments(directory: &Path) -> [OsString; 5] {
    [
        OsString::from("package"),
        OsString::from("install"),
        OsString::from("--ephemeral-ci"),
        OsString::from("--qualification-artifact-directory"),
        directory.as_os_str().to_os_string(),
    ]
}

pub fn prepare_windows_qualification_artifact_directory(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory).map_err(|error| {
        CiError::Message(format!(
            "Windows package-channel qualification artifact directory is unavailable at {}: {error}",
            directory.display()
        ))
    })?;
    for name in ARTIFACT_NAMES {
        let path = directory.join(name);
        if path.exists() {
            fs::remove_file(&path).map_err(|error| {
                CiError::Message(format!(
                    "Windows package-channel stale qualification artifact could not be removed at {}: {error}",
                    path.display()
                ))
            })?;
        }
    }
    Ok(())
}

pub fn read_ready_windows_qualification_artifacts(
    directory: &Path,
) -> Result<ReadyWindowsQualificationArtifacts> {
    let outcome: WindowsLoaderQualificationOutcomeV2 =
        read_json(directory, "production-loader-result-v2.json")?;
    let receipt: WindowsQualificationReceiptV1 = read_json(directory, "qualification.json")?;
    let plan: ProductionLoaderPlanV1 = read_json(directory, "production-loader-plan-v1.json")?;

    if !outcome.is_consistent() {
        return Err(CiError::Message(
            "Windows qualification loader outcome is inconsistent".to_owned(),
        ));
    }
    let WindowsLoaderQualificationOutcomeV2::Ready(ready) = &outcome else {
        return Err(CiError::Message(
            "Windows qualification install exported a failed loader outcome".to_owned(),
        ));
    };
    if outcome.launch_plan_json().is_some() {
        return Err(CiError::Message(
            "Windows qualification loader outcome retained an inline plan instead of its detached artifact"
                .to_owned(),
        ));
    }
    if !receipt.qualified || !receipt.is_consistent() {
        return Err(CiError::Message(
            "Windows qualification receipt is incomplete or inconsistent".to_owned(),
        ));
    }
    let WindowsLoaderQualificationOutcomeV2::Ready(receipt_ready) = &receipt.loader_qualification
    else {
        return Err(CiError::Message(
            "Windows qualification receipt has a failed loader outcome".to_owned(),
        ));
    };
    let receipt_plan_json = receipt_ready.launch_plan_json.as_deref().ok_or_else(|| {
        CiError::Message(
            "Windows qualification receipt is missing its inline loader plan".to_owned(),
        )
    })?;
    let receipt_plan: ProductionLoaderPlanV1 =
        serde_json::from_str(receipt_plan_json).map_err(|error| {
            CiError::Message(format!(
                "Windows qualification receipt has an invalid inline loader plan: {error}"
            ))
        })?;
    if receipt_plan.launch_plan_sha256() != receipt_ready.launch_plan_sha256 || receipt_plan != plan
    {
        return Err(CiError::Message(
            "Windows qualification receipt and detached loader plans differ".to_owned(),
        ));
    }
    let mut normalized_receipt_outcome = receipt.loader_qualification.clone();
    normalized_receipt_outcome.clear_launch_plan_json();
    if normalized_receipt_outcome != outcome {
        return Err(CiError::Message(
            "Windows qualification normalized receipt and detached loader outcome differ"
                .to_owned(),
        ));
    }
    if plan.launch_plan_sha256() != ready.launch_plan_sha256 {
        return Err(CiError::Message(
            "Windows qualification loader plan and outcome digests differ".to_owned(),
        ));
    }

    Ok(ReadyWindowsQualificationArtifacts { receipt, plan })
}

fn read_json<T>(directory: &Path, name: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let path = directory.join(name);
    let bytes = fs::read(&path).map_err(|error| {
        CiError::Message(format!(
            "Windows package-channel qualification artifact is unavailable at {}: {error}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CiError::Message(format!(
            "Windows package-channel qualification artifact is invalid at {}: {error}",
            path.display()
        ))
    })
}
