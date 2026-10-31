//! Assert current replies and live native phase observations in their running test.
use super::linux_test_lifetime::Experiment;
use crate::{CiError, Result};
use memcordon_core::{
    PublicProviderBindingV1,
    result_v3::{LinuxWorkloadPreparedV1, LinuxWorkloadTerminalV1, ResultV3},
    workload_request::{
        WorkloadAcknowledgmentV1, WorkloadAttemptAssociationV1, WorkloadRequestV1, WorkloadStartV1,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn raw<'a>(experiment: &'a Experiment, name: &str) -> Result<&'a [u8]> {
    experiment
        .files
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            CiError::Message(format!("required native operation output missing: {name}"))
        })
}
fn doc(experiment: &Experiment, name: &str) -> Result<Value> {
    let bytes = raw(experiment, name)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(bytes)?)
}
fn bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::from_value(value.clone())?)
}
fn positive(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| fail("positive native identity absent"))
}
fn cleanup(value: &Value) -> Result<()> {
    if value["state"] != "complete" {
        return Err(fail("current native cleanup is incomplete"));
    }
    let mut resources = BTreeSet::new();
    for item in value["obligations"]
        .as_array()
        .ok_or_else(|| fail("native cleanup obligations absent"))?
    {
        let name = item["resource"]
            .as_str()
            .ok_or_else(|| fail("cleanup resource absent"))?;
        if item["settled"] != true || !resources.insert(name) {
            return Err(fail("native cleanup unsettled or duplicated"));
        }
    }
    for name in [
        "target",
        "aggregate",
        "guardian",
        "namespace-init",
        "relays",
        "control-handles",
        "root-references",
        "staging",
        "footprint",
    ] {
        if !resources.contains(name) {
            return Err(fail("native cleanup omitted owned resource"));
        }
    }
    Ok(())
}
fn acknowledged(experiment: &Experiment, association: &WorkloadAttemptAssociationV1) -> Result<()> {
    let process = doc(experiment, "acknowledgment-process.json")?;
    let ack = WorkloadAcknowledgmentV1::parse(&bytes(&process["stdout"])?)
        .map_err(|error| fail(&error.to_string()))?;
    if process["status"] != 0 || ack.association != *association {
        return Err(fail(
            "current metadata acknowledgment names another attempt",
        ));
    }
    Ok(())
}
fn allocations(experiment: &Experiment, before: &Value) -> Result<()> {
    let acquired = doc(experiment, "allocations-before.json")?;
    let removed = doc(experiment, "allocations-after.json")?;
    let acquired = acquired
        .as_array()
        .ok_or_else(|| fail("actual native allocations absent"))?;
    let removed = removed
        .as_array()
        .ok_or_else(|| fail("actual native resource absence observations missing"))?;
    if acquired.is_empty() {
        return Err(fail(
            "native allocation experiment never acquired a resource",
        ));
    }
    let mut names = BTreeSet::new();
    for item in acquired {
        let path = item["path"]
            .as_str()
            .ok_or_else(|| fail("native allocation path absent"))?;
        if !names.insert(path)
            || positive(&item["inode"])? == 0
            || !removed
                .iter()
                .any(|entry| entry["path"] == path && entry["absent"] == true)
        {
            return Err(fail("owned native allocation remains or changed identity"));
        }
        let field = match item["role"].as_str() {
            Some("cgroup") => Some("cgroup"),
            Some("input-staging") => Some("input_staging"),
            Some("root-staging") => Some("staging"),
            Some("footprint") => None,
            _ => return Err(fail("unknown actual native allocation")),
        };
        if let Some(field) = field
            && (item["device"] != before[field]["device"]
                || item["inode"] != before[field]["inode"])
        {
            return Err(fail("native allocation differs from actual durable owner"));
        }
    }
    Ok(())
}
fn held_retired(held: &Value, retired: &Value, before: &Value, roles: &[&str]) -> Result<()> {
    let held = held
        .as_array()
        .ok_or_else(|| fail("held native population absent"))?;
    let retired = retired
        .as_array()
        .ok_or_else(|| fail("native retirement observations absent"))?;
    for role in roles {
        let mut matches = held.iter().filter(|item| item["role"] == *role);
        let process = matches
            .next()
            .ok_or_else(|| fail("required native owner not held"))?;
        if matches.next().is_some() {
            return Err(fail("required native owner duplicated"));
        }
        let pid = positive(&process["snapshot"]["process_id"])?;
        let birth = positive(&process["snapshot"]["birth"])?;
        if before[*role]["pid"] != pid
            || before[*role]["start_time"] != birth
            || !retired.iter().any(|item| {
                item["pid"] == pid && item["birth"] == birth && item["pidfd_readable"] == true
            })
        {
            return Err(fail(
                "original native handle identity or retirement differs",
            ));
        }
    }
    Ok(())
}

pub(super) fn assert_experiment(
    experiment: &Experiment,
    facet: &str,
    provider: &PublicProviderBindingV1,
) -> Result<()> {
    let request = WorkloadRequestV1::parse(raw(experiment, "request.json")?)
        .map_err(|error| fail(&error.to_string()))?;
    let digest = String::from(request.digest().map_err(|error| fail(&error.to_string()))?);
    let manifest_bytes = raw(experiment, "provider-manifest.json")?;
    let manifest = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(manifest_bytes)
        .map_err(CiError::Message)?;
    if manifest
        .public_binding(manifest_bytes)
        .map_err(CiError::Message)?
        != *provider
    {
        return Err(fail("native experiment used another installed provider"));
    }
    if facet == "before-preparation" {
        return before_preparation(experiment, &digest, provider);
    }
    let association: WorkloadAttemptAssociationV1 =
        serde_json::from_slice(raw(experiment, "attempt.json")?)?;
    association
        .validate()
        .map_err(|error| fail(&error.to_string()))?;
    if association.provider != *provider
        || String::from(association.request_sha256.clone()) != digest
    {
        return Err(fail(
            "native experiment changed actual request/provider association",
        ));
    }
    let value = serde_json::to_value(&association)?;
    if facet == "allocation" {
        return allocation(experiment, &association, &value);
    }
    let prepared = LinuxWorkloadPreparedV1::parse(raw(experiment, "prepared.json")?)
        .map_err(CiError::Message)?;
    if prepared.association != association
        || String::from(prepared.request.request_sha256.clone()) != digest
    {
        return Err(fail("prepared gate differs from selected request/attempt"));
    }
    let prepared_value = serde_json::to_value(&prepared)?;
    let native = &prepared_value["native"];
    let start = WorkloadStartV1::parse(raw(experiment, "start.json")?)
        .map_err(|error| fail(&error.to_string()))?;
    if start
        .request
        .digest()
        .map_err(|error| fail(&error.to_string()))?
        != association.request_sha256
        || memcordon_core::workload_request::invocation_digest(
            &start.native_launch,
            start.working_directory.as_ref(),
        )
        .map_err(|error| fail(&error.to_string()))?
            != prepared.request.invocation_sha256
        || memcordon_core::workload_request::resource_policy_digest(
            &start.native_launch,
            start.attempt_deadline_millis,
        )
        .map_err(|error| fail(&error.to_string()))?
            != prepared.request.resource_policy_sha256
    {
        return Err(fail(
            "actual native Start invocation/resource operands differ",
        ));
    }
    let before = doc(experiment, "journal-before.json")?;
    let after = doc(experiment, "journal-after.json")?;
    let held = doc(experiment, "held-before.json")?;
    let action = doc(experiment, "action.json")?;
    if before["association"] != value
        || before["request"] != prepared_value["request"]
        || before["native"] != *native
        || before["release"] != "not-released"
        || held["association"] != value
        || held["native"] != *native
        || held["root"]["device"] != native["root_device"]
        || held["root"]["inode"] != native["root_inode"]
        || action["association"] != value
        || action["scenario"] != experiment.scenario
        || action["frontend"] != native["caller"]
        || after["association"] != value
        || after["request"] != prepared_value["request"]
    {
        return Err(fail("native prepared/journal/controller identities differ"));
    }
    held_retired(
        &held["processes"],
        &action["retired"],
        &before,
        &["worker", "control", "guardian", "namespace_init", "target"],
    )?;
    allocations(experiment, &before)?;
    if facet != "journal-barrier" {
        let ack = doc(experiment, "prepared-ack.json")?;
        let released = doc(experiment, "journal-released.json")?;
        if ack["association"] != value
            || ack["prepared_sha256"]
                != super::artifacts::checksum(raw(experiment, "prepared.json")?)
            || action["prepared_ack"] != true
            || raw(experiment, "released-stdout.bin")?.is_empty()
            || released["association"] != value
            || released["request"] != prepared_value["request"]
            || released["native"]["exec_observed"] != true
            || released["release"] != "released"
        {
            return Err(fail("native fault occurred before genuine target release"));
        }
    } else if action["prepared_ack"] != false {
        return Err(fail("journal barrier unexpectedly released target"));
    }
    if facet.starts_with("drain-") || facet == "controlled-drain-cancel" {
        drain(experiment, &value, &action)?;
    }
    let native_facet = match facet {
        "drain-frontend" => "lost-terminal-response",
        "drain-worker" => "released-worker-loss",
        "drain-guardian" => "released-guardian-loss",
        "drain-control" => "released-control-loss",
        other => other,
    };
    if facet == "release-barrier" {
        let result = ResultV3::parse(raw(experiment, "result.json")?).map_err(CiError::Message)?;
        let observed = serde_json::to_value(&result)?;
        if result.workload_attempt.as_ref() != Some(&association)
            || result.provider.as_ref() != Some(provider)
            || observed["request"] != prepared_value["request"]
            || observed["release"] != "released"
            || observed["outcome"]["kind"] != "completed"
            || observed["outcome"]["wrapper_status"] != 0
            || doc(experiment, "frontend-wait.json")?["status"] != 0
            || !action["signal"].is_null()
            || !action["victim"].is_null()
        {
            return Err(fail(
                "release barrier did not execute original target successfully",
            ));
        }
        cleanup(&observed["cleanup"])?;
    } else {
        let terminal = LinuxWorkloadTerminalV1::parse(raw(experiment, "recovery.json")?)
            .map_err(CiError::Message)?;
        let recovered = serde_json::to_value(&terminal)?;
        if terminal.association != association {
            return Err(fail(
                "current public recovery association differs from original durable attempt",
            ));
        }
        if terminal.request != prepared.request {
            return Err(fail(
                "current public recovery request differs from original durable attempt",
            ));
        }
        let recovery_process = doc(experiment, "recovery-process.json")?;
        let recovery_status = &recovery_process["status"];
        if recovery_process["status"] != 0 {
            return Err(fail(&format!(
                "current public recovery process failed; integer-status={:?}; status-is-null={}",
                recovery_status.as_i64(),
                recovery_status.is_null(),
            )));
        }
        if after["terminal"] != recovered {
            return Err(fail(&format!(
                "current public recovery terminal differs from original durable attempt; recovery-json-sha256={}; journal-after-json-sha256={}",
                hex::encode(Sha256::digest(raw(experiment, "recovery.json")?)),
                hex::encode(Sha256::digest(raw(experiment, "journal-after.json")?)),
            )));
        }
        cleanup(&recovered["cleanup"])?;
        for field in [
            "boot_id",
            "caller",
            "target",
            "namespace_init",
            "guardian",
            "target_uid",
            "target_gid",
            "root_device",
            "root_inode",
            "cgroup_device",
            "cgroup_inode",
            "mount_namespace",
            "pid_namespace",
            "network_namespace",
            "ipc_namespace",
        ] {
            if recovered["native"][field] != native[field] {
                return Err(fail(
                    "recovery rebound original native process or resource identity",
                ));
            }
        }
        let victim = match native_facet {
            "lost-terminal-response" | "controlled-drain-cancel" => action["frontend"].clone(),
            "released-guardian-loss" => {
                json!({"pid":before["guardian"]["pid"],"birth":before["guardian"]["start_time"]})
            }
            "released-control-loss" => {
                json!({"pid":before["control"]["pid"],"birth":before["control"]["start_time"]})
            }
            "released-service-loss" => action["service"]["process"].clone(),
            _ => json!({"pid":before["worker"]["pid"],"birth":before["worker"]["start_time"]}),
        };
        if action["victim"] != victim
            || action["signal"]
                != if facet == "controlled-drain-cancel" {
                    2
                } else {
                    9
                }
            || action["native_signal_result"] != 0
        {
            return Err(fail(
                "fault/cancellation targeted another original native owner",
            ));
        }
        if facet == "journal-barrier" && recovered["release"] != "not-released" {
            return Err(fail("pre-release journal loss manufactured execution"));
        }
        if facet == "repeated-recovery"
            && (doc(experiment, "recovery-repeat.json")? != recovered
                || doc(experiment, "recovery-repeat-process.json")?["status"] != 0)
        {
            return Err(fail("repeated recovery changed original durable outcome"));
        }
        if let Some(bytes) = experiment.files.get("result.json") {
            let result = ResultV3::parse(bytes).map_err(CiError::Message)?;
            if result.workload_attempt.as_ref() != Some(&association)
                || result.provider.as_ref() != Some(provider)
                || result.request.as_ref() != Some(&prepared.request)
                || doc(experiment, "frontend-wait.json")?["status"] != result.outcome.wrapper_status
            {
                return Err(fail(
                    "frontend reply differs from original native attempt or wait",
                ));
            }
        }
    }
    if experiment.files.contains_key("owner-intervention.json") {
        owner(experiment, &value, &before)?;
    }
    if experiment.scenario == "service-restart-fresh-request" {
        restart(experiment, &value)?;
    }
    acknowledged(experiment, &association)
}

fn before_preparation(
    experiment: &Experiment,
    digest: &str,
    provider: &PublicProviderBindingV1,
) -> Result<()> {
    let invocation = doc(experiment, "invocation.json")?;
    let action = doc(experiment, "action.json")?;
    let original = doc(experiment, "original-frontend.json")?;
    let intent = doc(experiment, "creation-intent.json")?;
    let bundle = doc(experiment, "bundle-held.json")?;
    let namespaces = doc(experiment, "namespace-proof.json")?;
    let wait = doc(experiment, "frontend-wait.json")?;
    if experiment.files.contains_key("attempt.json")
        || experiment.files.contains_key("recovery.json")
        || invocation["request_sha256"] != digest
        || invocation["provider"] != serde_json::to_value(provider)?
        || original["request_sha256"] != digest
        || intent["request_sha256"] != digest
        || original["creator"] != intent["creator"]
        || original["process"] != action["frontend"]
        || action["snapshot"]["process_id"] != action["frontend"]["pid"]
        || action["snapshot"]["birth"] != action["frontend"]["birth"]
    {
        return Err(fail(
            "preparation cancellation did not retain its actual caller before allocation",
        ));
    }
    let uid = positive(&invocation["caller_uid"])?;
    if original["caller_uid"] != uid
        || intent["caller_uid"] != uid
        || action["credentials"]["uid"]
            .as_array()
            .is_none_or(|values| values.len() != 4 || values.iter().any(|value| *value != uid))
    {
        return Err(fail(
            "preparation fixture is not the intended unprivileged caller",
        ));
    }
    let blocked = &action["blocked"];
    let released = &action["released"];
    if action["signal"] != 2
        || action["native_signal_result"] != 0
        || blocked["mechanism"] != "fanotify-open-permission"
        || blocked["scope_kind"] != "file"
        || blocked["record_read"] != false
        || blocked["pid"] != action["frontend"]["pid"]
        || blocked["device"] != bundle["device"]
        || blocked["inode"] != bundle["inode"]
        || blocked["file_uid"] != uid
        || blocked["allow_written"] != false
        || bundle["uid"] != uid
        || bundle["readonly_descriptor"] != true
        || bundle["links"] != 1
        || bundle["path"] != invocation["input_path"]
        || released["pid"] != blocked["pid"]
        || released["device"] != blocked["device"]
        || released["inode"] != blocked["inode"]
        || released["allow_written"] != true
            && ![2, 3, 22]
                .iter()
                .any(|code| released["allow_errno"] == *code)
    {
        return Err(fail(
            "before-preparation cancellation missed genuine held input-open boundary",
        ));
    }
    if wait["pid"] != action["frontend"]["pid"]
        || wait["birth"] != action["frontend"]["birth"]
        || wait["pidfd_readable"] != true
        || !(wait["raw_wait_status"] == 2
            || wait["status"] == 130 && wait["raw_wait_status"] == (130 << 8))
        || namespaces["before"] != namespaces["blocked"]
        || namespaces["before"] != namespaces["after"]
        || namespaces["events"] != json!([])
        || namespaces["observer_entries"] != json!([])
        || namespaces["locator_present"] != false
    {
        return Err(fail(
            "preparation cancellation retained child or allocated native state",
        ));
    }
    if let Some(bytes) = experiment.files.get("result.json") {
        let result = ResultV3::parse(bytes).map_err(CiError::Message)?;
        let value = serde_json::to_value(result)?;
        if value["release"] != "not-released"
            || !value["workload_attempt"].is_null()
            || !value["outcome"]["native_termination"].is_null()
            || value["runtime"]["kind"] != "preparation-failed"
            || value["outcome"]["wrapper_status"] != wait["status"]
        {
            return Err(fail("preparation cancellation invented target execution"));
        }
    }
    Ok(())
}

fn allocation(
    experiment: &Experiment,
    association: &WorkloadAttemptAssociationV1,
    value: &Value,
) -> Result<()> {
    let before = doc(experiment, "phase-before.json")?;
    let action = doc(experiment, "phase-action.json")?;
    let actor = experiment
        .scenario
        .strip_suffix("-allocation")
        .ok_or_else(|| fail("allocation actor absent"))?;
    if before["association"] != *value
        || before["phase"] != "guardian-ready"
        || before["release"] != "not-released"
        || before["intents"]["namespace_init"] != false
        || before["intents"]["target"] != false
        || before["intents"]["guardian"] != true
        || !before["namespace_init"].is_null()
        || !before["target"].is_null()
        || !before["native"].is_null()
        || !before["outcome"].is_null()
        || !before["terminal"].is_null()
    {
        return Err(fail(
            "allocation fault did not reach incomplete pre-target state",
        ));
    }
    let blocked = &action["blocked"];
    let released = &action["released"];
    if action["association"] != *value
        || action["actor"] != actor
        || action["signal"] != 9
        || action["native_signal_result"] != 0
        || action["victim"]
            != json!({"pid":before[actor]["pid"],"birth":before[actor]["start_time"]})
        || blocked["mechanism"] != "fanotify-open-permission"
        || blocked["pid"] != before["worker"]["pid"]
        || blocked["record_sha256"]
            != super::artifacts::checksum(raw(experiment, "phase-before.json")?)
        || blocked["allow_written"] != false
        || released["pid"] != blocked["pid"]
        || released["inode"] != blocked["inode"]
        || released["allow_written"] != true
            && (actor != "worker"
                || ![2, 3, 22]
                    .iter()
                    .any(|code| released["allow_errno"] == *code))
    {
        return Err(fail(
            "allocation fault changed held permission event or original victim",
        ));
    }
    held_retired(
        &doc(experiment, "held-before.json")?,
        &doc(experiment, "held-after.json")?,
        &before,
        &["frontend", "worker", "control", "guardian"],
    )?;
    let terminal = LinuxWorkloadTerminalV1::parse(raw(experiment, "recovery.json")?)
        .map_err(CiError::Message)?;
    let terminal_value = serde_json::to_value(&terminal)?;
    let after = doc(experiment, "journal-after.json")?;
    if terminal.association != *association
        || terminal_value["request"] != before["request"]
        || terminal_value["release"] != "not-released"
        || matches!(
            terminal_value["outcome"]["kind"].as_str(),
            Some("exited" | "signaled")
        )
        || doc(experiment, "recovery-process.json")?["status"] != 0
        || after["terminal"] != terminal_value
        || after["phase"] != "retired"
        || !terminal_value["native"].is_null()
            && (terminal_value["native"]["exec_observed"] != false
                || !terminal_value["native"]["native_wait_status"].is_null())
    {
        return Err(fail(
            "partial allocation recovery fabricated execution or rebound attempt",
        ));
    }
    cleanup(&terminal_value["cleanup"])?;
    allocations(experiment, &before)?;
    if let Some(bytes) = experiment.files.get("result.json") {
        let result = ResultV3::parse(bytes).map_err(CiError::Message)?;
        if result.workload_attempt.as_ref() != Some(association)
            || serde_json::to_value(&result.request)? != before["request"]
        {
            return Err(fail(
                "partial allocation frontend reply names another attempt",
            ));
        }
    } else if actor != "frontend" {
        return Err(fail(
            "live frontend failed to return actual allocation failure",
        ));
    }
    acknowledged(experiment, association)
}

fn drain(experiment: &Experiment, association: &Value, action: &Value) -> Result<()> {
    let phase = doc(experiment, "drain-phase.json")?;
    let before = doc(experiment, "drain-readback.json")?;
    let published = doc(experiment, "drain-record.json")?;
    let rename = &phase["rename_exit"];
    let read = &phase["read_gate"];
    if phase["association"] != *association
        || before["association"] != *association
        || before["phase"] != "execution-observed"
        || before["native"]["exec_observed"] != true
        || before["cleanup_boot_id"] != association["boot_id"]
        || positive(&before["cleanup_cutoff_nanos"])? == 0
        || published["association"] != *association
        || published["phase"] != "retiring"
        || published["cleanup_cutoff_nanos"] != before["cleanup_cutoff_nanos"]
        || published["cleanup_boot_id"] != before["cleanup_boot_id"]
        || published["native"] != before["native"]
        || published["request"] != before["request"]
        || phase["cleanup_cutoff_nanos"] != before["cleanup_cutoff_nanos"]
    {
        return Err(fail(
            "drain fault missed actual Retiring phase or renewed original cutoff",
        ));
    }
    if read["mechanism"] != "fanotify-open-permission"
        || read["pid"] != before["worker"]["pid"]
        || read["record_sha256"]
            != super::artifacts::checksum(raw(experiment, "drain-readback.json")?)
        || read["allow_written"] != false
        || rename["mechanism"] != "ptrace-native-rename-exit"
        || rename["pid"] != before["worker"]["pid"]
        || rename["birth"] != before["worker"]["start_time"]
        || rename["return_value"] != 0
        || rename["worker_stopped_before_userspace"] != true
        || rename["inode"] == read["inode"]
        || bytes(&rename["record_bytes"])? != raw(experiment, "drain-record.json")?
    {
        return Err(fail(
            "native drain was not held at original successful rename exit",
        ));
    }
    let actor = if experiment.scenario == "during-drain" {
        "frontend"
    } else {
        experiment
            .scenario
            .strip_suffix("-drain")
            .ok_or_else(|| fail("drain actor absent"))?
    };
    if action["victim"] != json!({"pid":before[actor]["pid"],"birth":before[actor]["start_time"]})
        || action["signal"]
            != if actor == "frontend" && experiment.scenario == "during-drain" {
                2
            } else {
                9
            }
    {
        return Err(fail("drain action targeted another native actor"));
    }
    Ok(())
}

fn owner(experiment: &Experiment, association: &Value, before: &Value) -> Result<()> {
    let action = doc(experiment, "owner-intervention.json")?;
    let input = doc(experiment, "owner-input.json")?;
    let response = doc(experiment, "owner-response.json")?;
    let foreign = experiment.scenario.starts_with("foreign-");
    if action["original"] != *association
        || action["held_before"] != action["held_after"]
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
        || response["association"] != input["association"]
    {
        return Err(fail(
            "owner refusal failed to exercise actual foreign/current caller and unchanged live victim",
        ));
    }
    let mut expected = association.clone();
    if experiment.scenario == "stale-attempt" {
        expected["attempt"][0] = json!(
            expected["attempt"][0]
                .as_u64()
                .ok_or_else(|| fail("attempt byte absent"))?
                ^ 1
        );
    }
    if experiment.scenario == "request-substitution" {
        expected["request_sha256"] =
            json!(super::artifacts::checksum(b"different-current-request"));
    }
    if input["association"] != expected {
        return Err(fail(
            "owner probe changed unintended request/attempt operands",
        ));
    }
    if experiment.scenario == "foreign-inspect" {
        if response["opened"] != false || response["errno"] != 13 || response["connected"] != false
        {
            return Err(fail(
                "foreign inspection did not reach actual native EACCES",
            ));
        }
        return Ok(());
    }
    if response["connected"] != true || !response["errno"].is_null() {
        return Err(fail("owner refusal did not reach live provider endpoint"));
    }
    let received = bytes(&response["response_bytes"])?;
    let header = std::mem::size_of::<u16>() * 2
        + std::mem::size_of::<u32>()
        + std::mem::size_of::<[u8; 16]>() * 2
        + std::mem::size_of::<[u8; 32]>();
    let payload = received
        .get(header..)
        .ok_or_else(|| fail("owner reply frame truncated"))?;
    let sent = bytes(&response["request_bytes"])?;
    let mut cursor = std::io::Cursor::new(received.as_slice());
    use std::io::Read;
    let mut version = [0; 2];
    let mut kind = [0; 2];
    let mut length = [0; 4];
    let mut challenge = [0; 16];
    let mut attempt = [0; 16];
    let mut digest = [0; 32];
    cursor.read_exact(&mut version)?;
    cursor.read_exact(&mut kind)?;
    cursor.read_exact(&mut length)?;
    cursor.read_exact(&mut challenge)?;
    cursor.read_exact(&mut attempt)?;
    cursor.read_exact(&mut digest)?;
    let mut sent_cursor = std::io::Cursor::new(sent.as_slice());
    let mut sent_prefix = [0; 8];
    let mut sent_challenge = [0; 16];
    let mut sent_attempt = [0; 16];
    sent_cursor.read_exact(&mut sent_prefix)?;
    sent_cursor.read_exact(&mut sent_challenge)?;
    sent_cursor.read_exact(&mut sent_attempt)?;
    let cancellation = experiment.scenario == "foreign-cancel";
    if u16::from_be_bytes(version) != if cancellation { 3 } else { 5 }
        || u16::from_be_bytes(kind) != if cancellation { 106 } else { 44 }
        || u32::from_be_bytes(length) as usize != received.len()
        || challenge != sent_challenge
        || attempt != sent_attempt
        || hex::encode(digest) != super::artifacts::checksum(payload)
    {
        return Err(fail(
            "current refusal frame changed original request or payload bytes",
        ));
    }
    let rejection: Value = serde_json::from_slice(payload)?;
    let expected_code = match experiment.scenario.as_str() {
        "foreign-cancel" => "MCSEALED-AUTHORIZATION",
        "stale-attempt" => "native-unavailable",
        _ => "caller-identity-mismatch",
    };
    if rejection["code"] != expected_code {
        return Err(fail(
            "foreign/stale/substituted caller got wrong current refusal",
        ));
    }
    Ok(())
}
fn restart(experiment: &Experiment, association: &Value) -> Result<()> {
    let restart = doc(experiment, "restart.json")?;
    let previous = doc(experiment, "previous-attempt.json")?;
    if restart["status"] != 0
        || restart["query"]["status"] != 0
        || restart["service"]["held_before_fresh_request"] != true
        || restart["service"]["pidfd_readable_after_fresh_request"] != false
        || positive(&restart["service"]["pid"])? <= 1
        || previous["attempt"] == association["attempt"]
    {
        return Err(fail(
            "service restart did not retain a live restarted service and fresh actual attempt",
        ));
    }
    Ok(())
}
