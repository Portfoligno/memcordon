//! Independent current request preparation refusal checks.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::VerificationResult;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn verify_observed(
    evidence: &CaseEvidenceV2,
    input: &Value,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if ![
        ("C-ADMISSION", "unsupported-profile"),
        ("C-ADMISSION", "malformed-request"),
        ("C-ADMISSION", "unsupported-format"),
        ("C-ADMISSION", "identity-override-rejected"),
        ("L-VER-01", "unknown-request-variant"),
        ("L-VER-01", "duplicate-request"),
        ("L-VER-01", "result-format-mismatch"),
        ("L-VER-01", "unsupported-provider-version"),
        ("L-VER-01", "corrupted-binding"),
    ]
    .contains(&(evidence.key.family.as_str(), evidence.key.scenario.as_str()))
    {
        return Err("unknown current request refusal".into());
    }
    let provider_negative = matches!(
        evidence.key.scenario.as_str(),
        "unsupported-provider-version" | "corrupted-binding"
    );
    super::linux_component_lifecycle::closed(
        input,
        &[
            "format",
            "revision",
            "run_id",
            "key",
            "request",
            "caller_uid",
            "caller_gid",
        ],
    )?;
    if input["format"] != "memcordon.linux-current-refusal-input"
        || input["revision"] != 1
        || input["run_id"] != evidence.run_id
        || input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || input["request"].as_str() != evidence.request.as_deref()
        || (!provider_negative && evidence.raw_result.is_some())
        || evidence.attempt_observation.is_some()
    {
        return Err("refusal input fabricated a released/native result".into());
    }
    let request = resolver(
        evidence
            .request
            .as_deref()
            .ok_or("refused request bytes absent")?,
    )?;
    match evidence.key.scenario.as_str() {
        "malformed-request" | "duplicate-request" => {
            if request != br#"{"format":"memcordon.workload-request","revision":1,"revision":1}"#
                || crate::validate_json_document(&request).is_ok()
            {
                return Err(
                    "duplicate-key request refusal did not reach original malformed bytes".into(),
                );
            }
        }
        scenario => {
            let value = crate::validate_json_document(&request)?;
            match scenario {
                "unsupported-format"
                    if value
                        == serde_json::json!({"format":"unsupported-request","revision":255}) => {}
                "unsupported-profile"
                    if value["format"] == "memcordon.workload-request"
                        && value["revision"] == 1
                        && value["runtime"]["kind"] == "linux-private"
                        && value["runtime"]["profile"] == "unsupported-profile" => {}
                "identity-override-rejected"
                    if value["format"] == "memcordon.workload-request"
                        && value["revision"] == 1
                        && value["runtime"]["kind"] == "linux-private"
                        && value["runtime"]["profile"] == "linux-private-workload-v1"
                        && value["runtime"]["uid"] == 0 => {}
                "unknown-request-variant"
                    if value["format"] == "memcordon.workload-request"
                        && value["revision"] == 1
                        && value["runtime"]["kind"] == "unsupported-runtime" => {}
                "result-format-mismatch" | "unsupported-provider-version" | "corrupted-binding" => {
                    super::linux::request_digest(&request)?;
                }
                _ => return Err("request refusal operands do not match selected negative".into()),
            }
        }
    }
    let native = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
    let mut fields = vec![
        "format",
        "revision",
        "run_id",
        "lease_id",
        "scenario",
        "process",
        "cli_sha256",
        "caller_uid",
        "caller_gid",
        "native_status",
        "raw_wait_status",
        "report_absent",
        "before",
        "after",
        "request",
    ];
    if provider_negative {
        fields.push("provider_fixture");
    }
    super::linux_component_lifecycle::closed(&native, &fields)?;
    let expected_roots = [
        "/var/lib/memcordon/workload-attempts",
        "/var/lib/memcordon/workload-inputs",
        "/var/lib/memcordon/workload-resources",
        "/sys/fs/cgroup/memcordon-sealed",
    ];
    if native["format"] != "memcordon.linux-current-request-refusal"
        || native["revision"] != 1
        || native["run_id"] != evidence.run_id
        || native["lease_id"].as_str() != evidence.lease_id.as_deref()
        || native["scenario"] != evidence.key.scenario
        || native["request"].as_str() != evidence.request.as_deref()
        || native["native_status"] != if provider_negative { 125 } else { 2 }
        || native["raw_wait_status"] != if provider_negative { 32000 } else { 512 }
        || (!provider_negative && native["report_absent"] != true)
        || native["before"] != native["after"]
        || native["before"].as_array().is_none_or(|paths| {
            paths.len() != 4
                || paths
                    .iter()
                    .zip(expected_roots)
                    .any(|(path, expected)| path["path"] != expected)
        })
        || native["process"]["pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
        || native["process"]["birth"].as_u64().is_none()
        || native["caller_uid"] != input["caller_uid"]
        || native["caller_gid"] != input["caller_gid"]
        || input["caller_uid"].as_u64().is_none_or(|uid| uid == 0)
        || native["cli_sha256"] != evidence.fixture_sha256
        || hex::encode(Sha256::digest(resolver(&evidence.fixture)?)) != evidence.fixture_sha256
    {
        return Err("actual ordinary request refusal/unchanged allocation facts differ".into());
    }
    if provider_negative {
        let fixture = &native["provider_fixture"];
        let original_bytes: Vec<u8> = serde_json::from_value(fixture["original_bytes"].clone())
            .map_err(|error| error.to_string())?;
        let bad_bytes: Vec<u8> = serde_json::from_value(fixture["bad_bytes"].clone())
            .map_err(|error| error.to_string())?;
        let original = crate::validate_json_document(&original_bytes)?;
        let mut bad = crate::validate_json_document(&bad_bytes)?;
        if fixture["format"] != "memcordon.linux-current-provider-fixture"
            || fixture["revision"] != 1
            || fixture["scenario"] != evidence.key.scenario
            || fixture["restored"] != true
            || original["format"] != "memcordon.runtime-manifest"
            || original["revision"] != 2
            || original["source_commit"] != evidence.source_commit
            || fixture["provider"]["runtime_manifest_sha256"]
                != hex::encode(Sha256::digest(&original_bytes))
            || fixture["original"]["inode"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || fixture["bad"]["inode"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || fixture["original"]["uid"] != 0
            || fixture["bad"]["uid"] != 0
        {
            return Err(
                "current provider negative lost exact descriptor/native restoration binding".into(),
            );
        }
        if evidence.key.scenario == "unsupported-provider-version" {
            if bad["revision"] != 255 {
                return Err("provider negative did not use unsupported current version".into());
            }
            bad["revision"] = 2.into();
        } else {
            let old = original["components"]
                .as_array()
                .ok_or("original current provider components absent")?;
            let altered = bad["components"]
                .as_array_mut()
                .ok_or("changed current provider components absent")?;
            if old.len() != altered.len() {
                return Err("binding negative changed current component inventory".into());
            }
            let mut changed = 0;
            for (actual, expected) in altered.iter_mut().zip(old) {
                if expected["role"] == "sealed-agent" {
                    if actual["sha256"] != "0".repeat(64) {
                        return Err("binding negative component commitment unchanged".into());
                    }
                    actual["sha256"] = expected["sha256"].clone();
                    changed += 1;
                }
            }
            if changed != 1 {
                return Err("binding negative provider role absent/duplicated".into());
            }
        }
        if bad != original {
            return Err("provider negative changed unrelated descriptor facts".into());
        }
        if let Some(path) = &evidence.raw_result {
            let result = crate::validate_json_document(&resolver(path)?)?;
            if native["report_absent"] != false
                || result["format"] != "memcordon.result"
                || result["revision"] != 3
                || result["release"] != "not-released"
                || result["runtime"]["kind"] != "preparation-failed"
                || !result["outcome"]["native_termination"].is_null()
                || !result["workload_attempt"].is_null()
            {
                return Err("unsupported provider invented allocated target evidence".into());
            }
        } else if native["report_absent"] != true {
            return Err("provider refusal lost actual emitted report".into());
        }
    }
    let invocation = crate::validate_json_document(&resolver(&evidence.invocation)?)?;
    super::linux_component_lifecycle::closed(
        &invocation,
        &[
            "format",
            "revision",
            "program",
            "request",
            "bundle_sha256",
            "report",
            "memory",
            "deadline",
            "sealed",
            "report_format",
        ],
    )?;
    let report_format = if evidence.key.scenario == "result-format-mismatch" {
        "standard"
    } else {
        "result-v3"
    };
    let diagnostic = if evidence.key.scenario == "result-format-mismatch" {
        "MCUSAGE-WORKLOAD-REPORT-FORMAT"
    } else {
        "MCUSAGE-WORKLOAD-REQUEST"
    };
    if invocation["format"] != "memcordon.linux-current-refusal-invocation"
        || invocation["revision"] != 1
        || invocation["request"].as_str() != evidence.request.as_deref()
        || invocation["sealed"] != true
        || invocation["report_format"] != report_format
        || invocation["memory"] != "+128MiB"
        || invocation["deadline"] != "+10s"
    {
        return Err("actual refused invocation boundary differs".into());
    }
    let stderr = resolver(&evidence.stderr)?;
    let detail = std::str::from_utf8(&stderr).map_err(|error| error.to_string())?;
    if (!provider_negative && !detail.contains(diagnostic))
        || (provider_negative
            && (detail.contains("MCUSAGE")
                || !detail.contains(if evidence.key.scenario == "unsupported-provider-version" {
                    "manifest"
                } else {
                    "component"
                })))
        || !resolver(&evidence.stdout)?.is_empty()
    {
        return Err("current preparation refusal lost original diagnostic".into());
    }
    Ok(())
}

pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let components = product
        .components
        .iter()
        .filter(|component| component.role == "cli")
        .collect::<Vec<_>>();
    if components.len() != 1 || components[0].installed_sha256 != evidence.fixture_sha256 {
        return Err("request parser is not exact selected CLI image".into());
    }
    verify_observed(evidence, input, resolver)
}
