//! Data-only retention of an already observed current Linux invocation.
use super::linux_current_installed::{CallerImages, CurrentLinuxCase};
use crate::{CiError, Result, readiness_identity::SourceIdentity};
use memcordon_readiness_verifier::current::CaseEvidenceV2;
use std::collections::BTreeMap;

pub struct CapturedCase {
    pub evidence: CaseEvidenceV2,
    pub input: serde_json::Value,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// This function acquires no native owners and assigns no passing state.
pub fn capture(
    case: &CurrentLinuxCase,
    identity: &SourceIdentity,
    lease_id: &str,
    fixture_source: &str,
    images: &CallerImages,
    prefix: &str,
    extra: serde_json::Value,
) -> Result<CapturedCase> {
    let mut files = BTreeMap::new();
    let mut write = |name: &str, bytes: Vec<u8>| {
        let path = format!("{prefix}/{name}");
        files.insert(path.clone(), bytes);
        path
    };
    let request = write("request.json", serde_json::to_vec(&case.request)?);
    let result = case
        .result
        .as_ref()
        .map(|value| serde_json::to_vec(value).map(|bytes| write("result.json", bytes)))
        .transpose()?;
    let recovery = case
        .recovery
        .as_ref()
        .map(|bytes| write("recovery.json", bytes.clone()));
    let locator = write("attempt.json", serde_json::to_vec(&case.locator)?);
    let stdout = write("stdout.bin", case.stdout.clone());
    let stderr = write("stderr.bin", case.stderr.clone());
    let native = write("native.json", serde_json::to_vec(&case.controller)?);
    let retirement = write("retirement.json", serde_json::to_vec(&case.retirement)?);
    let prepared = write("prepared.json", case.prepared.clone());
    let start = write("start.json", case.start.clone());
    let prepared_ack = case
        .prepared_ack
        .as_ref()
        .map(|bytes| write("prepared-ack.json", bytes.clone()));
    let binary: Vec<u8> = if case.key.scenario == "empty-input" {
        Vec::new()
    } else {
        (u8::MIN..=u8::MAX).collect()
    };
    let input = serde_json::json!({"format":"memcordon.consumer-readiness.input","revision":2,"run_id":identity.run_id,"challenge":case.challenge,"key":case.key,"request":request,"start":start,"prepared":prepared,"prepared_ack":prepared_ack,"binary":binary,"stderr_binary":binary,"deadline_millis":case.deadline_millis,"memory_bytes":case.memory_bytes,"lifetime":case.lifetime,"target_argv":memcordon_readiness_verifier::NativeArguments::UnixBytes(case.arguments.clone())});
    let input_bytes = serde_json::to_vec(&input)?;
    let input_sha256 = super::artifacts::checksum(&input_bytes);
    let input_path = write("input.json", input_bytes);
    let invocation = match &case.result {
        Some(result) => write("invocation.json", serde_json::to_vec(&result.invocation)?),
        None => start,
    };
    let fixture_bytes = std::fs::read(images.runtime_source.join("bin/owned-readiness"))?;
    let fixture_sha256 = super::artifacts::checksum(&fixture_bytes);
    let fixture = write("fixture.bin", fixture_bytes);
    let semantic = write(
        "semantic.json",
        serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.current-fixture-semantic-source","revision":1,"challenge":case.challenge,"stdout":stdout,"native":native,"extra":extra}),
        )?,
    );
    let mut outputs = Vec::new();
    for (path, bytes) in &case.outputs {
        outputs.push(write(&format!("outputs/{}", path.as_str()), bytes.clone()));
    }
    if !prefix.is_empty()
        && prefix
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
    {
        Ok(CapturedCase {
            evidence: CaseEvidenceV2 {
                format: "memcordon.consumer-readiness.case".into(),
                revision: 2,
                key: case.key.clone(),
                run_id: identity.run_id.clone(),
                source_commit: identity.source_commit.clone(),
                source_tree_sha256: identity.source_tree_sha256.clone(),
                lease_id: Some(lease_id.into()),
                fixture,
                fixture_source: fixture_source.into(),
                fixture_sha256,
                fixture_source_sha256: identity.source_tree_sha256.clone(),
                input: input_path,
                input_sha256,
                invocation,
                request: Some(request),
                raw_result: result,
                attempt_observation: Some(locator),
                authenticated_terminal: None,
                recovery,
                stdout,
                stderr,
                outputs,
                native_observation: native,
                retirement,
                semantic_observation: semantic,
                component_recipe_id: None,
            },
            input,
            files,
        })
    } else {
        Err(CiError::Message(
            "current case capture prefix invalid".into(),
        ))
    }
}
