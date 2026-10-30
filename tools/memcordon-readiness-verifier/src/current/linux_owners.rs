//! Independent current installed owner/intervention evidence joins.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::{ComponentBuild, EvidenceClass, VerificationResult};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerReceipt {
    format: String,
    revision: u32,
    key: crate::CaseKey,
    run_id: String,
    facet: String,
    snapshot: String,
    captures: BTreeMap<String, String>,
    previous: BTreeMap<String, String>,
    restart: Option<String>,
}

pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: Option<&ProductObservationV2>,
    build: Option<&ComponentBuild>,
    version: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let facet = match (evidence.key.family.as_str(), evidence.key.scenario.as_str()) {
        ("C-LIFETIME", "frontend-loss") => "lost-terminal-response",
        ("C-LIFETIME", "guardian-loss") => "released-guardian-loss",
        ("C-LIFETIME", "service-loss") => "released-service-loss",
        ("C-LIFETIME", "worker-loss") => "released-worker-loss",
        ("C-LIFETIME", "recovery") => "repeated-recovery",
        (
            "C-OWNER",
            "foreign-inspect"
            | "foreign-cancel"
            | "foreign-recover"
            | "stale-attempt"
            | "request-substitution",
        ) => "release-barrier",
        ("C-CANCEL", "service-restart-fresh-request") => "release-barrier",
        ("L-LIFE-02", "frontend-release") => "lost-terminal-response",
        ("L-LIFE-02", "worker-release") => "released-worker-loss",
        ("L-LIFE-02", "guardian-release") => "released-guardian-loss",
        ("L-LIFE-02", "control-release") => "released-control-loss",
        ("L-LIFE-02", "frontend-drain") => "drain-frontend",
        ("L-LIFE-02", "worker-drain") => "drain-worker",
        ("L-LIFE-02", "guardian-drain") => "drain-guardian",
        ("L-LIFE-02", "control-drain") => "drain-control",
        ("C-CANCEL", "during-drain") => "controlled-drain-cancel",
        ("C-CANCEL", "before-preparation") => "before-preparation",
        (
            "L-LIFE-02",
            "frontend-allocation"
            | "worker-allocation"
            | "guardian-allocation"
            | "control-allocation",
        ) => "allocation",
        _ => return Err(
            "current installed owner intervention oracle is incomplete for this required scenario"
                .into(),
        ),
    };
    let receipt: OwnerReceipt = crate::wire::decode(&resolve(&evidence.semantic_observation)?)?;
    if receipt.format != "memcordon.current-installed-owner"
        || receipt.revision != 1
        || receipt.key != evidence.key
        || receipt.run_id != evidence.run_id
        || receipt.facet != facet
        || evidence.key.evidence_class != EvidenceClass::InstalledProduct
        || evidence.key.channel.is_none()
        || (facet == "lost-terminal-response" && evidence.raw_result.is_some())
        || evidence.component_recipe_id.is_some()
        || build.is_some()
        || input
            != &json!({"format":"memcordon.current-owner-input","revision":1,"key":evidence.key,"run_id":evidence.run_id,"facet":facet})
    {
        return Err(
            "current installed owner source, actual intervention or optional result differs".into(),
        );
    }
    if let Some(product) = product
        && (product.key.target != evidence.key.target
            || Some(&product.key.channel) != evidence.key.channel.as_ref()
            || product.source_commit != evidence.source_commit
            || product.source_tree_sha256 != evidence.source_tree_sha256
            || product.version != version
            || evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str()))
    {
        return Err("owner intervention belongs to another selected product".into());
    }
    if crate::sha256(&resolve(&evidence.fixture)?) != evidence.fixture_sha256
        || crate::sha256(&resolve(&evidence.fixture_source)?) != evidence.source_tree_sha256
    {
        return Err("current owner fixture or selected source archive substituted".into());
    }
    let snapshot_bytes = resolve(&receipt.snapshot)?;
    let snapshot: Value = crate::wire::decode(&snapshot_bytes)?;
    let request: Value = crate::wire::decode(&resolve(
        evidence.request.as_deref().ok_or("owner request absent")?,
    )?)?;
    if snapshot["format"] != "memcordon.workload-snapshot"
        || snapshot["revision"] != 1
        || snapshot["target"] != evidence.key.target
        || request["runtime"]["inputs"]["runtime_digest"] != crate::sha256(&snapshot_bytes)
        || !snapshot["entries"].as_array().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["kind"] == "regular"
                    && entry["path"] == "bin/owned-readiness"
                    && entry["executable"] == true
                    && entry["sha256"] == evidence.fixture_sha256
            })
        })
    {
        return Err(
            "original streamed runtime does not contain the actual selected owner fixture".into(),
        );
    }
    if facet == "before-preparation" {
        if !receipt.previous.is_empty() || receipt.restart.is_some() {
            return Err("preparation cancellation borrowed a native attempt lifetime".into());
        }
        return verify_before_preparation(evidence, &receipt.captures, version, resolve);
    }
    for (field, leaf) in [
        (&evidence.invocation, "start.json"),
        (&evidence.native_observation, "held-before.json"),
        (
            &evidence.retirement,
            if facet == "allocation" {
                "phase-action.json"
            } else {
                "action.json"
            },
        ),
        (&evidence.stdout, "stdout.bin"),
        (&evidence.stderr, "stderr.bin"),
    ] {
        if receipt.captures.get(leaf) != Some(field) {
            return Err("current owner common artifact reference substituted".into());
        }
    }
    let mut native_captures = receipt.captures.clone();
    if facet == "allocation" {
        if !receipt.previous.is_empty() || receipt.restart.is_some() {
            return Err("allocation phase borrowed another operation lifetime".into());
        }
        return verify_allocation(evidence, &receipt.captures, version, resolve);
    }
    if evidence.key.family == "C-OWNER" {
        verify_peer(evidence, &receipt.captures, version, resolve)?;
        for name in [
            "owner-intervention.json",
            "owner-input.json",
            "owner-response.json",
            "owner-probe.bin",
            "owner-preparation.json",
            "owner-stdout.bin",
            "owner-stderr.bin",
        ] {
            native_captures.remove(name);
        }
        if evidence.raw_result.is_none() || evidence.recovery.is_some() {
            return Err(
                "foreign owner refusal must preserve the original successful victim result".into(),
            );
        }
    }
    if evidence.key.scenario == "service-restart-fresh-request" {
        verify_restart(evidence, &receipt, version, resolve)?;
    } else if !receipt.previous.is_empty() || receipt.restart.is_some() {
        return Err("current owner case substituted another operation lifetime".into());
    }
    let native_facet = if facet.starts_with("drain-") || facet == "controlled-drain-cancel" {
        verify_drain(evidence, &receipt.captures, resolve)?;
        for name in [
            "drain-phase.json",
            "drain-readback.json",
            "drain-record.json",
        ] {
            native_captures.remove(name);
        }
        match facet {
            "drain-frontend" => "lost-terminal-response",
            "drain-worker" => "released-worker-loss",
            "drain-guardian" => "released-guardian-loss",
            "drain-control" => "released-control-loss",
            _ => "controlled-drain-cancel",
        }
    } else {
        facet
    };
    super::linux_component_lifecycle::verify_observations(
        evidence,
        native_facet,
        &evidence.source_commit,
        &evidence.key.target,
        version,
        &native_captures,
        resolve,
    )
}

fn verify_before_preparation(
    evidence: &CaseEvidenceV2,
    captures: &BTreeMap<String, String>,
    version: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let raw = |name: &str| -> VerificationResult<Vec<u8>> {
        resolve(
            captures
                .get(name)
                .ok_or_else(|| format!("actual input-open cancellation capture absent: {name}"))?,
        )
    };
    let document = |name: &str| -> VerificationResult<Value> { crate::wire::decode(&raw(name)?) };
    if evidence.attempt_observation.is_some()
        || evidence.authenticated_terminal.is_some()
        || evidence.recovery.is_some()
        || !evidence.outputs.is_empty()
    {
        return Err(
            "before-preparation cancellation invented a native attempt/result/output".into(),
        );
    }
    for (path, name) in [
        (&evidence.invocation, "invocation.json"),
        (&evidence.native_observation, "namespace-proof.json"),
        (&evidence.retirement, "action.json"),
        (&evidence.stdout, "stdout.bin"),
        (&evidence.stderr, "stderr.bin"),
    ] {
        if captures.get(name) != Some(path) {
            return Err("before-preparation actual artifact references differ".into());
        }
    }
    let invocation = document("invocation.json")?;
    let action = document("action.json")?;
    let original = document("original-frontend.json")?;
    let intent = document("creation-intent.json")?;
    let bundle = document("bundle-held.json")?;
    let namespaces = document("namespace-proof.json")?;
    let wait = document("frontend-wait.json")?;
    let request = document("request.json")?;
    let digest = super::linux::request_digest(&raw("request.json")?)?;
    let manifest = document("provider-manifest.json")?;
    if invocation["format"] != "memcordon.current-preparation-invocation"
        || invocation["revision"] != 1
        || invocation["report_format"] != "result-v3"
        || invocation["request_sha256"] != digest
        || invocation["entrypoint"] != "owned-readiness"
        || invocation["deadline_token"] != "+30s"
        || invocation["lifetime"] != "command"
        || manifest["format"] != "memcordon.runtime-manifest"
        || manifest["revision"] != 2
        || manifest["source_commit"] != evidence.source_commit
        || manifest["version"] != version
        || manifest["target"] != evidence.key.target
        || manifest["sealed"]["profile"] != "linux-private-workload-v1"
        || invocation["provider"]["source_commit"] != evidence.source_commit
        || invocation["provider"]["runtime_manifest_sha256"]
            != crate::sha256(&raw("provider-manifest.json")?)
    {
        return Err(
            "before-preparation actor did not select the actual current request/CLI/provider"
                .into(),
        );
    }
    let memory = invocation["memory_bytes"]
        .as_u64()
        .ok_or("before-preparation configured memory absent")?;
    super::linux_component_lifecycle::validate_snapshot_budget(
        &document("runtime-snapshot.json")?,
        &document("input-snapshot.json")?,
        memory,
        128 * 1024 * 1024,
    )?;
    let token: Vec<u8> = serde_json::from_value(invocation["memory_token"].clone())
        .map_err(|error| error.to_string())?;
    if token != format!("+{}MiB", memory / (1024 * 1024)).as_bytes()
        || request["runtime"]["inputs"]["input_digest"]
            != crate::sha256(&raw("input-snapshot.json")?)
    {
        return Err("preparation actor changed original snapshot/resource operands".into());
    }
    if intent["format"] != "memcordon.current-original-frontend"
        || intent["revision"] != 1
        || original["format"] != intent["format"]
        || original["revision"] != 1
        || intent["request_sha256"] != digest
        || original["request_sha256"] != digest
        || original["creator"] != intent["creator"]
        || original["provider"] != invocation["provider"]
        || intent["provider"] != invocation["provider"]
        || original["process"] != action["frontend"]
        || intent["installed_cli"] != invocation["installed_cli"]
        || action["snapshot"]["process_id"] != action["frontend"]["pid"]
        || action["snapshot"]["birth"] != action["frontend"]["birth"]
        || action["frontend"]["pid"]
            .as_u64()
            .is_none_or(|pid| pid <= 1)
        || action["frontend"]["birth"]
            .as_u64()
            .is_none_or(|birth| birth == 0)
    {
        return Err(
            "input-open intervention lacks the original creation-held frontend identity".into(),
        );
    }
    let uid = invocation["caller_uid"]
        .as_u64()
        .filter(|uid| *uid > 0)
        .ok_or("ordinary preparation caller UID absent")?;
    if intent["caller_uid"] != uid
        || original["caller_uid"] != uid
        || action["credentials"]["uid"]
            .as_array()
            .is_none_or(|values| values.len() != 4 || values.iter().any(|value| *value != uid))
        || !manifest["components"].as_array().is_some_and(|components| {
            components.iter().any(|component| {
                component["id"] == "public-cli" && component["sha256"] == action["image"]["sha256"]
            })
        })
    {
        return Err(
            "kernel input-open process is not the actual ordinary caller/current CLI".into(),
        );
    }
    let blocked = &action["blocked"];
    let released = &action["released"];
    if action["format"] != "memcordon.current-before-preparation-action"
        || action["revision"] != 1
        || action["signal"] != 2
        || action["native_signal_result"] != 0
        || blocked["mechanism"] != "fanotify-open-permission"
        || blocked["scope_kind"] != "file"
        || blocked["record_read"] != false
        || blocked["pid"] != action["frontend"]["pid"]
        || blocked["device"] != bundle["device"]
        || blocked["inode"] != bundle["inode"]
        || blocked["file_uid"] != uid
        || blocked["file_length"] != bundle["length"]
        || blocked["allow_written"] != false
        || !blocked["allow_errno"].is_null()
        || bundle["uid"] != uid
        || bundle["readonly_descriptor"] != true
        || bundle["links"] != 1
        || bundle["length"].as_u64().is_none_or(|length| length == 0)
        || bundle["path"] != invocation["input_path"]
        || released["pid"] != blocked["pid"]
        || released["device"] != blocked["device"]
        || released["inode"] != blocked["inode"]
        || (released["allow_written"] != true
            && ![2, 3, 22]
                .iter()
                .any(|code| released["allow_errno"] == *code))
    {
        return Err(
            "cancellation was not the actual original caller bundle-open permission boundary"
                .into(),
        );
    }
    if wait["pid"] != action["frontend"]["pid"]
        || wait["birth"] != action["frontend"]["birth"]
        || wait["pidfd_readable"] != true
        || !(wait["raw_wait_status"] == 2
            || (wait["status"] == 130 && wait["raw_wait_status"] == (130 << 8)))
    {
        return Err("before-preparation original child did not actually retire from SIGINT".into());
    }
    validate_preparation_namespace_observation(&namespaces)?;
    if let Some(path) = evidence.raw_result.as_deref() {
        let report: Value = crate::wire::decode(&resolve(path)?)?;
        if report["format"] != "memcordon.result"
            || report["revision"] != 3
            || report["outcome"]["wrapper_status"] != wait["status"]
            || !report["workload_attempt"].is_null()
            || !report["outcome"]["native_termination"].is_null()
            || report["release"] != "not-released"
            || report["runtime"]["kind"] != "preparation-failed"
        {
            return Err("pre-input report invented native execution or contradicted the original direct wait".into());
        }
    }
    Ok(())
}

pub fn validate_preparation_namespace_observation(namespaces: &Value) -> VerificationResult<()> {
    if namespaces["format"] != "memcordon.current-preparation-native-observation"
        || namespaces["revision"] != 1
        || namespaces["before"] != namespaces["blocked"]
        || namespaces["before"] != namespaces["after"]
        || namespaces["events"] != json!([])
        || namespaces["observer_entries"] != json!([])
        || namespaces["locator_present"] != false
    {
        return Err("before-preparation cancellation allocated native state or omitted namespace event evidence".into());
    }
    validate_native_namespace_census(&namespaces["before"])
}
pub(super) fn validate_native_namespace_census(value: &Value) -> VerificationResult<()> {
    let roots = value
        .as_array()
        .ok_or("actual native namespace census absent")?;
    let expected = [
        ("journal", "/var/lib/memcordon/workload-attempts"),
        ("input-staging", "/var/lib/memcordon/workload-inputs"),
        ("footprint", "/var/lib/memcordon/workload-resources"),
        ("root-staging", "/run/memcordon"),
        ("cgroup", "/sys/fs/cgroup/memcordon-sealed"),
    ];
    if roots.len() != expected.len() {
        return Err("native zero-allocation census omitted a current resource namespace".into());
    }
    for (root, (role, path)) in roots.iter().zip(expected) {
        let mode = root["mode"]
            .as_u64()
            .ok_or("native namespace mode absent")?;
        if root["role"] != role
            || root["path"] != path
            || root["uid"] != 0
            || root["inode"].as_u64().is_none_or(|inode| inode == 0)
            || mode & 0o170000 != 0o040000
            || mode & 0o022 != 0
            || !root["entries"].is_array()
        {
            return Err(
                "zero-allocation census is not the actual protected native directory graph".into(),
            );
        }
    }
    Ok(())
}

fn verify_drain(
    evidence: &CaseEvidenceV2,
    captures: &BTreeMap<String, String>,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let raw = |name: &str| -> VerificationResult<Vec<u8>> {
        resolve(
            captures
                .get(name)
                .ok_or_else(|| format!("actual drain phase capture absent: {name}"))?,
        )
    };
    let document = |name: &str| -> VerificationResult<Value> { crate::wire::decode(&raw(name)?) };
    let proof = document("drain-phase.json")?;
    let before = document("drain-readback.json")?;
    let published = document("drain-record.json")?;
    let association = document("attempt.json")?;
    let action = document("action.json")?;
    super::linux_component_lifecycle::closed(
        &before,
        super::linux_component_lifecycle::JOURNAL_FIELDS,
    )?;
    super::linux_component_lifecycle::closed(
        &published,
        super::linux_component_lifecycle::JOURNAL_FIELDS,
    )?;
    let controlled = evidence.key.scenario == "during-drain";
    let actor = if controlled {
        "frontend"
    } else {
        evidence
            .key
            .scenario
            .strip_suffix("-drain")
            .ok_or("actual native drain actor suffix absent")?
    };
    if proof["format"] != "memcordon.current-owner-drain-phase"
        || proof["revision"] != 1
        || proof["association"] != association
        || proof["actor"] != actor
        || before["format"] != "memcordon.private-workload-journal"
        || before["revision"] != 1
        || before["association"] != association
        || before["phase"] != "execution-observed"
        || before["native"]["exec_observed"] != true
        || before["cleanup_cutoff_nanos"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || before["cleanup_boot_id"] != association["boot_id"]
        || published["format"] != before["format"]
        || published["revision"] != 1
        || published["association"] != association
        || published["phase"] != "retiring"
        || published["cleanup_cutoff_nanos"] != before["cleanup_cutoff_nanos"]
        || published["cleanup_boot_id"] != before["cleanup_boot_id"]
        || proof["cleanup_cutoff_nanos"] != before["cleanup_cutoff_nanos"]
        || published["request"] != before["request"]
        || published["native"] != before["native"]
    {
        return Err("drain phase did not publish the original Retiring record under the unchanged boot-bound cutoff".into());
    }
    let read = &proof["read_gate"];
    let rename = &proof["rename_exit"];
    let attempt: Vec<u8> = serde_json::from_value(association["attempt"].clone())
        .map_err(|error| error.to_string())?;
    if attempt.len() != 16 {
        return Err("original drain attempt width differs".into());
    }
    let attempt = hex::encode(attempt);
    let renamed_bytes: Vec<u8> = serde_json::from_value(rename["record_bytes"].clone())
        .map_err(|error| error.to_string())?;
    let (architecture, numbers) = if evidence.key.target == "aarch64-unknown-linux-gnu" {
        (0xc00000b7_u64, [38_u64, 276])
    } else if evidence.key.target == "x86_64-unknown-linux-gnu" {
        (0xc000003e, [264, 316])
    } else {
        return Err("unsupported native drain syscall ABI".into());
    };
    if read["mechanism"] != "fanotify-open-permission"
        || read["pid"] != before["worker"]["pid"]
        || read["record_sha256"] != crate::sha256(&raw("drain-readback.json")?)
        || read["allow_written"] != false
        || !read["allow_errno"].is_null()
        || rename["mechanism"] != "ptrace-native-rename-exit"
        || rename["pid"] != before["worker"]["pid"]
        || rename["birth"] != before["worker"]["start_time"]
        || rename["architecture"] != architecture
        || !numbers.iter().any(|number| rename["syscall"] == *number)
        || rename["source"] != format!("{attempt}.update")
        || rename["destination"] != attempt
        || rename["directory_device"] != read["directory_device"]
        || rename["directory_inode"] != read["directory_inode"]
        || rename["return_value"] != 0
        || rename["worker_stopped_before_userspace"] != true
        || rename["inode"] == read["inode"]
        || rename["inode"].as_u64().is_none_or(|value| value == 0)
        || renamed_bytes != raw("drain-record.json")?
    {
        return Err("native drain was not stopped at the exact successful original-worker rename syscall exit".into());
    }
    let manifest = document("provider-manifest.json")?;
    if !manifest["components"].as_array().is_some_and(|components| {
        components.iter().any(|component| {
            component["id"] == "sealed-agent"
                && component["sha256"] == proof["worker_image"]["sha256"]
        })
    }) {
        return Err("syscall phase process image differs from the selected provider".into());
    }
    if action["signal"] != if controlled { 2 } else { 9 }
        || action["victim"]
            != json!({"pid":before[actor]["pid"],"birth":before[actor]["start_time"]})
        || action["native_signal_result"] != 0
    {
        return Err("native drain action targeted another original actor or conflated cancellation with death".into());
    }
    if controlled {
        let recovery = document("recovery.json")?;
        let result: Value = crate::wire::decode(&resolve(
            evidence
                .raw_result
                .as_deref()
                .ok_or("controlled drain frontend report absent")?,
        )?)?;
        if recovery["native"]["native_wait_status"] != 0
            || recovery["outcome"]["kind"] != "exited"
            || recovery["outcome"]["code"] != 0
            || result["outcome"]["wrapper_status"] != 130
            || document("frontend-wait.json")?["status"] != 130
        {
            return Err("drain cancellation did not retain the known original native exit independently of the interrupted wrapper".into());
        }
    }
    Ok(())
}

fn verify_allocation(
    evidence: &CaseEvidenceV2,
    captures: &BTreeMap<String, String>,
    version: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let raw = |name: &str| -> VerificationResult<Vec<u8>> {
        resolve(
            captures
                .get(name)
                .ok_or_else(|| format!("actual allocation phase capture absent: {name}"))?,
        )
    };
    let document = |name: &str| -> VerificationResult<Value> { crate::wire::decode(&raw(name)?) };
    let original = document("phase-before.json")?;
    let association = document("attempt.json")?;
    let action = document("phase-action.json")?;
    let request = document("request.json")?;
    let digest = super::linux::request_digest(&raw("request.json")?)?;
    let actor = evidence
        .key
        .scenario
        .strip_suffix("-allocation")
        .ok_or("actual allocation actor suffix differs")?;
    let fields = [
        "format",
        "revision",
        "attempt_id",
        "boot_id",
        "phase",
        "release",
        "cleanup_cutoff_nanos",
        "cleanup_boot_id",
        "request_sha256",
        "association",
        "request",
        "native",
        "outcome",
        "terminal",
        "caller_uid",
        "frontend",
        "worker",
        "control",
        "intents",
        "guardian",
        "namespace_init",
        "target",
        "cgroup",
        "staging",
        "input_staging",
        "root",
        "network_namespace_inode",
        "output_files",
        "outstanding",
        "errors",
    ];
    let closed = |value: &Value, names: &[&str]| -> VerificationResult<()> {
        if value.as_object().is_none_or(|object| {
            object.len() != names.len() || object.keys().any(|key| !names.contains(&key.as_str()))
        }) {
            return Err("current allocation native object has unknown/missing fields".into());
        }
        Ok(())
    };
    closed(&original, &fields)?;
    let attempt: Vec<u8> = serde_json::from_value(association["attempt"].clone())
        .map_err(|error| error.to_string())?;
    if attempt.len() != 16 {
        return Err("original native attempt width differs".into());
    }
    let attempt = hex::encode(attempt);
    if original["format"] != "memcordon.private-workload-journal"
        || original["revision"] != 1
        || original["association"] != association
        || original["attempt_id"] != attempt
        || original["request_sha256"] != digest
        || original["boot_id"] != association["boot_id"]
        || original["phase"] != "guardian-ready"
        || original["release"] != "not-released"
        || original["intents"]["namespace_init"] != false
        || original["intents"]["target"] != false
        || original["intents"]["guardian"] != true
        || !original["namespace_init"].is_null()
        || !original["target"].is_null()
        || !original["native"].is_null()
        || !original["outcome"].is_null()
        || !original["terminal"].is_null()
    {
        return Err(
            "allocation gate was not the original incomplete pre-target native allocation".into(),
        );
    }
    super::linux_wire::verify_start(
        &raw("start.json")?,
        &request,
        &original["request"],
        &document("operands.json")?,
    )?;
    let manifest = document("provider-manifest.json")?;
    if manifest["format"] != "memcordon.runtime-manifest"
        || manifest["revision"] != 2
        || manifest["source_commit"] != evidence.source_commit
        || manifest["version"] != version
        || manifest["target"] != evidence.key.target
        || manifest["sealed"]["profile"] != "linux-private-workload-v1"
        || association["provider"]["runtime_manifest_sha256"]
            != crate::sha256(&raw("provider-manifest.json")?)
    {
        return Err(
            "allocation phase provider is not the selected current installed source".into(),
        );
    }
    let gate = &action["blocked"];
    if action["format"] != "memcordon.current-owner-phase-action"
        || action["revision"] != 1
        || action["phase"] != "allocation"
        || action["actor"] != actor
        || action["association"] != association
        || action["signal"] != 9
        || action["native_signal_result"] != 0
        || gate["mechanism"] != "fanotify-open-permission"
        || gate["pid"] != original["worker"]["pid"]
        || gate["record_sha256"] != crate::sha256(&raw("phase-before.json")?)
        || gate["allow_written"] != false
        || !gate["allow_errno"].is_null()
        || gate["inode"].as_u64().is_none_or(|value| value == 0)
        || gate["directory_inode"]
            .as_u64()
            .is_none_or(|value| value == 0)
    {
        return Err(
            "allocation intervention was not held by the actual native read permission event"
                .into(),
        );
    }
    let released = &action["released"];
    if released["record_sha256"] != gate["record_sha256"]
        || released["pid"] != gate["pid"]
        || released["inode"] != gate["inode"]
        || (released["allow_written"] != true
            && (actor != "worker"
                || ![2, 3, 22]
                    .iter()
                    .any(|code| released["allow_errno"] == *code)))
    {
        return Err("original native permission event was not explicitly released or its killed worker observed".into());
    }
    let held = document("held-before.json")?;
    let retired = document("held-after.json")?;
    let held = held.as_array().ok_or("original allocation holds absent")?;
    let retired = retired
        .as_array()
        .ok_or("original allocation retirements absent")?;
    if held.len() != 4 || retired.len() != 4 {
        return Err("original partial allocation process inventory differs".into());
    }
    for ((process, retirement), role) in held
        .iter()
        .zip(retired)
        .zip(["frontend", "worker", "control", "guardian"])
    {
        let pid = &original[role]["pid"];
        let birth = &original[role]["start_time"];
        if process["role"] != role
            || process["snapshot"]["process_id"] != *pid
            || process["snapshot"]["birth"] != *birth
            || process["pidfd_readable"] != false
            || retirement["role"] != role
            || retirement["pid"] != *pid
            || retirement["birth"] != *birth
            || retirement["pidfd_readable"] != true
        {
            return Err("partial allocation actor was not held before the actual fault and observed retired".into());
        }
        let component = if role == "frontend" {
            "public-cli"
        } else {
            "sealed-agent"
        };
        if !manifest["components"].as_array().is_some_and(|components| {
            components.iter().any(|entry| {
                entry["id"] == component && entry["sha256"] == process["image"]["sha256"]
            })
        }) {
            return Err(
                "partial allocation process image substituted another installed source".into(),
            );
        }
        let expected_uid = if role == "frontend" {
            &original["caller_uid"]
        } else {
            &json!(0)
        };
        if process["credentials"]["uid"]
            .as_array()
            .is_none_or(|values| {
                values.len() != 4 || values.iter().any(|value| value != expected_uid)
            })
        {
            return Err("partial allocation process UID columns differ".into());
        }
    }
    if action["victim"]
        != json!({"pid":original[actor]["pid"],"birth":original[actor]["start_time"]})
    {
        return Err("allocation fault targeted another original native actor".into());
    }
    let recovery = document("recovery.json")?;
    let after = document("journal-after.json")?;
    closed(&after, &fields)?;
    if recovery["format"] != "memcordon.linux-workload-terminal"
        || recovery["revision"] != 1
        || recovery["association"] != association
        || recovery["request"] != original["request"]
        || recovery["release"] != "not-released"
        || matches!(
            recovery["outcome"]["kind"].as_str(),
            Some("exited" | "signaled")
        )
        || document("recovery-process.json")?["status"] != 0
        || after["association"] != association
        || after["terminal"] != recovery
        || after["phase"] != "retired"
    {
        return Err("partial allocation recovery fabricated execution or changed the original native attempt".into());
    }
    if !recovery["native"].is_null()
        && (recovery["native"]["exec_observed"] != false
            || !recovery["native"]["native_wait_status"].is_null())
    {
        return Err(
            "allocation recovery invented a released executable or direct target wait".into(),
        );
    }
    super::linux_component_lifecycle::cleanup(&recovery["cleanup"])?;
    let resources = document("allocations-before.json")?;
    let absent = document("allocations-after.json")?;
    let resources = resources
        .as_array()
        .ok_or("original partial resource acquisitions absent")?;
    let absent = absent
        .as_array()
        .ok_or("original partial resource census absent")?;
    if resources.is_empty() || resources.len() != absent.len() {
        return Err("partial resource acquisition/absence inventory differs".into());
    }
    let mut paths = std::collections::BTreeSet::new();
    for resource in resources {
        let (prefix, field) = match resource["role"].as_str() {
            Some("cgroup") => ("/sys/fs/cgroup/memcordon-sealed/", Some("cgroup")),
            Some("root-staging") => ("/run/memcordon/private-root-", Some("staging")),
            Some("input-staging") => ("/var/lib/memcordon/workload-inputs/", Some("input_staging")),
            Some("footprint") => ("/var/lib/memcordon/workload-resources/", None),
            _ => return Err("unknown partial native resource role".into()),
        };
        let path = format!("{prefix}{attempt}");
        if resource["path"] != path
            || !paths.insert(path.clone())
            || resource["inode"].as_u64().is_none_or(|value| value == 0)
            || !absent
                .iter()
                .any(|entry| entry["path"] == path && entry["absent"] == true)
        {
            return Err("partial native resource path/inode was substituted or not retired".into());
        }
        if let Some(field) = field
            && (resource["device"] != original[field]["device"]
                || resource["inode"] != original[field]["inode"])
        {
            return Err(
                "partial native resource differs from the held original journal inode".into(),
            );
        }
    }
    if let Some(result) = evidence.raw_result.as_deref() {
        let result: Value = crate::wire::decode(&resolve(result)?)?;
        super::linux_component_lifecycle::verify_observed_result(
            &result,
            &association,
            &original["request"],
            &evidence.source_commit,
            version,
            false,
            &document("frontend-wait.json")?,
        )?;
    } else if actor != "frontend" {
        return Err("live frontend lost its actual current failed report".into());
    }
    let acknowledgment = document("acknowledgment-process.json")?;
    let bytes: Vec<u8> = serde_json::from_value(acknowledgment["stdout"].clone())
        .map_err(|error| error.to_string())?;
    let acknowledgment_body: Value = crate::wire::decode(&bytes)?;
    if acknowledgment["status"] != 0
        || acknowledgment_body["format"] != "memcordon.workload-acknowledgment"
        || acknowledgment_body["revision"] != 1
        || acknowledgment_body["association"] != association
        || acknowledgment_body["retired"] != true
    {
        return Err(
            "partial allocation original metadata was not authentically acknowledged".into(),
        );
    }
    let metadata = document("metadata-after.json")?;
    let metadata = metadata
        .as_array()
        .ok_or("partial metadata census absent")?;
    if metadata.len() != 2
        || ![attempt.clone(), format!("{attempt}.recovery-lock")]
            .iter()
            .all(|name| {
                metadata.iter().any(|item| {
                    item["path"] == format!("/var/lib/memcordon/workload-attempts/{name}")
                        && item["absent"] == true
                })
            })
    {
        return Err("partial attempt metadata remains after original acknowledgment".into());
    }
    Ok(())
}

fn verify_restart(
    evidence: &CaseEvidenceV2,
    receipt: &OwnerReceipt,
    version: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let raw = |captures: &BTreeMap<String, String>, name: &str| -> VerificationResult<Value> {
        crate::wire::decode(&resolve(
            captures
                .get(name)
                .ok_or_else(|| format!("original service phase capture absent: {name}"))?,
        )?)
    };
    let restart: Value = crate::wire::decode(&resolve(
        receipt
            .restart
            .as_deref()
            .ok_or("actual current service restart capture absent")?,
    )?)?;
    if restart["program"] != "/usr/bin/systemctl"
        || restart["arguments"] != json!(["restart", "memcordon-sealed-agent.service"])
        || restart["status"] != 0
        || restart["query"]["program"] != "/usr/bin/systemctl"
        || restart["query"]["arguments"]
            != json!([
                "show",
                "--property=MainPID",
                "--value",
                "memcordon-sealed-agent.service"
            ])
        || restart["query"]["status"] != 0
        || restart["service"]["held_before_fresh_request"] != true
        || restart["service"]["pidfd_readable_after_fresh_request"] != false
    {
        return Err(
            "actual current service was not restarted and held through the fresh request".into(),
        );
    }
    let stdout: Vec<u8> = serde_json::from_value(restart["query"]["stdout"].clone())
        .map_err(|error| error.to_string())?;
    let pid: u64 = std::str::from_utf8(&stdout)
        .map_err(|error| error.to_string())?
        .trim()
        .parse()
        .map_err(|_| "actual restarted service PID query invalid")?;
    let old_action = raw(&receipt.previous, "action.json")?;
    let fresh = raw(&receipt.captures, "attempt.json")?;
    let old = raw(&receipt.previous, "attempt.json")?;
    let manifest = raw(&receipt.captures, "provider-manifest.json")?;
    if pid <= 1
        || restart["service"]["pid"] != pid
        || restart["service"]["birth"]
            .as_u64()
            .is_none_or(|birth| birth == 0)
        || old_action["service"]["process"]["pid"] == pid
        || old == fresh
        || old["attempt"] == fresh["attempt"]
        || old["challenge"] == fresh["challenge"]
        || !manifest["components"].as_array().is_some_and(|components| {
            components.iter().any(|component| {
                component["id"] == "sealed-agent"
                    && component["sha256"] == restart["service"]["image"]["sha256"]
            })
        })
    {
        return Err(
            "fresh current request reused the dead service/attempt or another provider image"
                .into(),
        );
    }
    let mut previous = evidence.clone();
    previous.raw_result = receipt.previous.get("result.json").cloned();
    previous.request = receipt.previous.get("request.json").cloned();
    previous.recovery = receipt.previous.get("recovery.json").cloned();
    previous.attempt_observation = receipt.previous.get("attempt.json").cloned();
    previous.authenticated_terminal = receipt.previous.get("journal-after.json").cloned();
    previous.invocation = receipt
        .previous
        .get("start.json")
        .ok_or("original service invocation absent")?
        .clone();
    super::linux_component_lifecycle::verify_observations(
        &previous,
        "released-service-loss",
        &evidence.source_commit,
        &evidence.key.target,
        version,
        &receipt.previous,
        resolve,
    )
}

pub struct OwnerPreparationContext<'a> {
    pub source_commit: &'a str,
    pub version: &'a str,
    pub run: &'a str,
    pub target: &'a str,
    pub image_sha256: &'a str,
    pub image_size: u64,
}

/// Both origins are current preparation transports, never readiness certificates.
pub fn verify_owner_preparation(
    proof: &Value,
    context: &OwnerPreparationContext<'_>,
) -> VerificationResult<()> {
    let producer = match (proof["inputs"]["kind"].as_str(), context.target) {
        (Some("readiness"), "x86_64-unknown-linux-gnu") => "readiness-tools-linux-x64",
        (Some("readiness"), "aarch64-unknown-linux-gnu") => "readiness-tools-linux-arm64",
        (Some("private"), "x86_64-unknown-linux-gnu") => "private-linux-prepare-x64",
        (Some("private"), "aarch64-unknown-linux-gnu") => "private-linux-prepare-arm64",
        _ => return Err("unsupported current owner preparation origin/host".into()),
    };
    let controllers: Vec<_> = proof["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|file| file["path"] == "target/ci-runtime/current/memcordon-ci")
        .collect();
    if proof["format"] != 1
        || proof["inputs"]["producer"] != producer
        || proof["inputs"]["host"] != context.target
        || proof["inputs"]["source"]["commit"] != context.source_commit
        || proof["inputs"]["source"]["version"] != context.version
        || proof["inputs"]["invocation"]["run"] != context.run
        || controllers.len() != 1
        || controllers.first().is_none_or(|file| {
            file["sha256"] != context.image_sha256
                || file["size"] != context.image_size
                || file["executable"] != true
        })
    {
        return Err(
            "current owner preparation source/version/run/producer/controller differs".into(),
        );
    }
    Ok(())
}

fn verify_peer(
    evidence: &CaseEvidenceV2,
    captures: &BTreeMap<String, String>,
    version: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let raw = |name: &str| -> VerificationResult<Vec<u8>> {
        resolve(
            captures
                .get(name)
                .ok_or_else(|| format!("current peer capture absent: {name}"))?,
        )
    };
    let document = |name: &str| -> VerificationResult<Value> { crate::wire::decode(&raw(name)?) };
    let action = document("owner-intervention.json")?;
    let input = document("owner-input.json")?;
    let response = document("owner-response.json")?;
    let original = document("attempt.json")?;
    let scenario = evidence.key.scenario.as_str();
    let expected_operation = match scenario {
        "foreign-inspect" => "inspect",
        "foreign-cancel" => "cancel",
        _ => "recover",
    };
    let before = document("journal-before.json")?;
    let foreign = scenario.starts_with("foreign-");
    if action["format"] != "memcordon.current-owner-intervention"
        || action["revision"] != 1
        || action["scenario"] != scenario
        || action["original"] != original
        || action["held_before"] != action["held_after"]
        || action["held_before"]
            .as_array()
            .is_none_or(|processes| processes.len() != 5)
        || action["child"]["held_before_input"] != true
        || action["child"]["retired"] != true
        || action["child"]["raw_wait_status"] != 0
        || response["pid"] != action["child"]["pid"]
        || response["birth"] != action["child"]["birth"]
        || response["uid"] != action["uid"]
        || response["euid"] != action["uid"]
        || response["gid"] != action["gid"]
        || action["uid"] == 0
        || (response["uid"] != before["caller_uid"]) != foreign
        || input["format"] != "memcordon.current-owner-probe"
        || input["revision"] != 1
        || input["operation"] != expected_operation
        || response["format"] != "memcordon.current-owner-probe-receipt"
        || response["revision"] != 1
        || response["operation"] != expected_operation
        || response["association"] != input["association"]
    {
        return Err("peer intervention did not bind the actual foreign/current OS child and unchanged original native victim".into());
    }
    let mut expected_association = original.clone();
    if scenario == "stale-attempt" {
        let first = expected_association["attempt"][0]
            .as_u64()
            .ok_or("original attempt byte absent")?;
        expected_association["attempt"][0] = json!(first ^ 1);
    }
    if scenario == "request-substitution" {
        expected_association["request_sha256"] = json!(crate::sha256(b"different-current-request"));
    }
    if input["association"] != expected_association {
        return Err(
            "peer request changed more than the selected stale/substitution operand".into(),
        );
    }
    let image = raw("owner-probe.bin")?;
    let image_sha = crate::sha256(&image);
    let proof = document("owner-preparation.json")?;
    if action["probe_image"]["uid"] != 0
        || action["probe_image"]["mode"] != 0o555
        || action["probe_image"]["links"] != 1
        || action["probe_image"]["sha256"] != image_sha
    {
        return Err(
            "peer child is not the measured source-prepared readonly controller image".into(),
        );
    }
    verify_owner_preparation(
        &proof,
        &OwnerPreparationContext {
            source_commit: &evidence.source_commit,
            version,
            run: &evidence.run_id,
            target: &evidence.key.target,
            image_sha256: &image_sha,
            image_size: image.len() as u64,
        },
    )?;
    let arguments: crate::NativeArguments =
        serde_json::from_value(action["command"]["arguments"].clone())
            .map_err(|error| error.to_string())?;
    let crate::NativeArguments::UnixBytes(arguments) = arguments else {
        return Err("Linux peer argv encoding differs".into());
    };
    if action["command"]["executable"] != "/usr/bin/setpriv"
        || arguments.len() != 12
        || arguments[0] != b"--reuid"
        || arguments[1] != action["uid"].to_string().as_bytes()
        || arguments[2] != b"--regid"
        || arguments[3] != action["gid"].to_string().as_bytes()
        || arguments[4] != b"--init-groups"
        || arguments[5] != b"--"
        || !arguments[6].ends_with(b"/current-linux-owner")
        || arguments[7] != b"current-linux-owner-probe"
        || arguments[8] != b"--input"
        || arguments[9] != b"-"
        || arguments[10] != b"--output"
    {
        return Err(
            "peer child did not use actual user-database groups and the exact native probe argv"
                .into(),
        );
    }
    if scenario == "foreign-inspect" {
        if response["opened"] != false
            || response["errno"] != 13
            || response["connected"] != false
            || !response["request_bytes"].is_null()
            || !response["response_bytes"].is_null()
        {
            return Err("foreign inspection did not observe actual native EACCES".into());
        }
        return Ok(());
    }
    if response["connected"] != true || !response["errno"].is_null() {
        return Err("peer refusal never reached the actual service endpoint".into());
    }
    let sent: Vec<u8> = serde_json::from_value(response["request_bytes"].clone())
        .map_err(|error| error.to_string())?;
    let received: Vec<u8> = serde_json::from_value(response["response_bytes"].clone())
        .map_err(|error| error.to_string())?;
    let nonce: Vec<u8> = serde_json::from_value(expected_association["challenge"].clone())
        .map_err(|error| error.to_string())?;
    let attempt: Vec<u8> = serde_json::from_value(expected_association["attempt"].clone())
        .map_err(|error| error.to_string())?;
    for frame in [&sent, &received] {
        if frame.len() < 72
            || frame.len() > 65536
            || u32::from_be_bytes(frame[4..8].try_into().expect("bounded header")) as usize
                != frame.len()
            || frame[8..24] != nonce
            || frame[24..40] != attempt
            || hex::encode(&frame[40..72]) != crate::sha256(&frame[72..])
        {
            return Err("native peer raw frame header/digest/association differs".into());
        }
    }
    let request_kind = u16::from_be_bytes(sent[2..4].try_into().expect("bounded header"));
    let response_kind = u16::from_be_bytes(received[2..4].try_into().expect("bounded header"));
    if sent[..2] != 5_u16.to_be_bytes()
        || request_kind != if scenario == "foreign-cancel" { 35 } else { 40 }
    {
        return Err("peer sent another current native operation".into());
    }
    let rejected: Value = crate::wire::decode(&received[72..])?;
    if scenario == "foreign-cancel" {
        if sent.len() != 72 || response_kind != 106 || rejected["code"] != "MCSEALED-AUTHORIZATION"
        {
            return Err(
                "foreign cancellation did not receive actual standalone-session rejection".into(),
            );
        }
    } else {
        let sent_association: Value = crate::wire::decode(&sent[72..])?;
        let code = if scenario == "stale-attempt" {
            "native-unavailable"
        } else {
            "caller-identity-mismatch"
        };
        if sent_association != expected_association
            || received[..2] != 5_u16.to_be_bytes()
            || response_kind != 44
            || rejected["format"] != "memcordon.workload-rejection"
            || rejected["revision"] != 1
            || rejected["code"] != code
        {
            return Err(
                "foreign/stale/substituted recovery did not receive exact current native rejection"
                    .into(),
            );
        }
    }
    Ok(())
}
